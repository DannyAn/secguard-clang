# SGRE 万级函数仓库全仓扫描架构设计提案（Phase 2）

> 状态：**设计提案，待确认后实施**（按操作者指示，跳过现场 profile，直接基于 Phase 0/1 报告中的三个强怀疑热点推进）。
> 本文只做设计，不含任何代码改动。所有改动映射到现有源码路径与符号，不引入与项目不兼容的新架构。
> 前提：继续采信 Phase 0/1 报告（`SGRE_FULL_REPO_SCAN_OOM_ANALYSIS.md`）对三个热点的源码定位，并把“强怀疑”作为设计输入（而非待 profile 的结论）。

---

## 0. 三个热点 → 设计目标

| 热点（Phase 0/1） | 源码位置 | 设计目标 |
|---|---|---|
| H1 无界 AST 缓存 | `parser/parser.go:40-118`（`ParseCached`/`CloseAll`） | 解析树缓存**有界**、可淘汰、可借还 |
| H2 无界 CFG 缓存 | `graph/cfg_cache.go:17-58` | CFG 缓存**有界 LRU**、按需重建 |
| H3 无内存感知并发 + 全量重复加载 | `pipeline.go:149-173,324`、`registry.go:116`、`db/crud_functions.go:62` | **共享只读索引** + **内存感知有界调度** + **图写批量化** |

---

## 1. 设计总原则（与 Issue 4.2 对齐）

1. **Single Repository Context**：一次扫描一个统一 DB，内部可分批，不要求用户拆目录。
2. **Bounded Memory**：所有随仓库规模增长的缓存/队列/批次/并发都有明确上限。
3. **On-demand Construction**：CFG/子图/函数内流状态按需构建、可重建。
4. **Incremental Persistence**：Facts/候选/证据按批次落库。
5. **Explicit Lifecycle**：每个大型对象有明确的创建者、所有者、有效期、释放边界。
6. **Cross-file Correctness**：分区/按需调度不破坏跨文件、跨目录、跨模块语义。
7. **Observable Degradation**：预算耗尽/降级/跳过必须显式记录为 `incomplete/limited`。
8. **Detection Parity**：优化前后用固定回归集验证检测能力不退化。

---

## 2. 三个热点的设计

### 2.1 H1：把无界解析树缓存改为「有界 + 可淘汰 + 借还引用」

**现状**：`ParseCached` 把每个文件的 `sitter.Tree`（C 分配）+ `src []byte` + 一个专用 `sitter.Parser` 写进 `cache`/`parsers` 两个 map，只在 `CloseAll()` 释放（`parser.go:82-118`）。graph/detector/planner 约 19 处调用 `ParseCached`，全部共享这一个缓存，因此全仓 AST 全程常驻。

**设计**：

1. `Parser` 增加可配置预算字段：`MaxCachedTrees int` 与 `MaxCachedBytes int64`（默认值由规模测试定，例如先取“按文件数上限 + 按估算字节上限”双阈值）。
2. `ParseCached` 返回的 `*Tree` 由“缓存全权拥有、`Close` 为 no-op”改为**引用计数 + 借出**语义：
   - 调用方取得 tree 后在用完后 `Release()`（或 `defer`）；
   - 缓存对每个 tree 维护 `refs` 计数与最近使用时间；
   - 超过预算时，只淘汰 `refs==0` 的最久未用 tree，淘汰动作 = `t.tree.Close()` + 对应 `parsers[filename].Close()` + 从两个 map 删除。
   - 淘汰只发生在没有调用方借用时，从而避免“关闭 C 树后仍有 `parser.Node` 悬空”。
3. **修复 `repofacts.Build` 的“持全树”模式**（`repofacts/repofacts.go:64-84`）：它把 `trees []fileNode{root parser.Node}` 整体保留到两遍遍历结束，会钉住所有 AST、使 LRU 无法淘汰。改为**流式两遍**：
   - 第一遍只合并宏值（`addTree` 里 `parser.CollectMacroValues`），不保留 root；
   - 第二遍用 `ParseCached` 逐文件重读（命中缓存或从磁盘重读）做 struct/union/array 聚合；
   - 由于 `ParseCached` 按文件名去重，重读命中即复用；若被 LRU 淘汰则从磁盘重读，语义不变，仅多一次 I/O。
4. 对工作区头文件的解析（`repofacts.go:100-116`）同样走有界缓存（它们进入同一个 `cache`，天然受预算约束）。

**收益**：AST 驻留从“全仓文件数”收敛到“预算上限”，是三个热点中绝对量最大的收敛项。
**代价/风险**：引入借还语义需要改动 19 处 `ParseCached` 调用点（大多是 `forEachFile` 回调内 `defer` 一处即可覆盖）；淘汰触发重解析带来 wall-clock 回归（用阶段计时基线对照）。**风险点**：若某处漏 `Release` 导致 refs 永不归零，缓存不再淘汰、退化为无界——必须用单测断言“缓存大小在预算内”。
**改动范围**：`internal/parser/parser.go`（核心）、`internal/repofacts/repofacts.go`（流式化）、其余调用点加 `Release`。

### 2.2 H2：把无界 CFG 缓存改为「有界 LRU」

**现状**：`CFGCache.byFn map[int64]*StmtCFG` 只增不减（`cfg_cache.go:32-58`），`pipeline.go:185` 注入共享实例，detector+plan 全程累积到全函数规模（10,627 个 `StmtCFG`）。

**设计**：

1. `CFGCache` 增加 `MaxEntries int`（默认如 4096，可配置）。
2. `GetOrBuild` 在超出上限时按 LRU 淘汰最久未命中的 `StmtCFG`。
3. **淘汰是纯 Go 安全操作**：`StmtCFG`/`StmtNode` 全是 Go 对象，无 C 指针；`StmtNode.Stmt parser.Node` 引用的 `src []byte` 由 Go GC 管理，淘汰只丢 Go 对象。因此 CFG 缓存是三个热点中**风险最低、可最先落地**的一项。
4. `BuildStmtCFGWithCache`（`cfg_cache.go:86-93`）已把构建集中在一个入口，加淘汰逻辑改动面很小。

**收益**：CFG 驻留从“全函数数”收敛到固定预算；确定性重建保证命中率下降只影响耗时、不影响结果。
**代价/风险**：极低；唯一风险是淘汰频繁导致重建墙钟上升，需用命中率（现有 `Stats()` 的 builds/hits）观测并调预算。
**改动范围**：`internal/graph/cfg_cache.go` 单文件（+ 配置项）。

### 2.3 H3：共享只读索引 + 内存感知有界调度 + 图写批量化

**现状**：7 个 graph builder 无信号量并行（`pipeline.go:149-173`）、detector 固定 8 并发（`registry.go:116`）、plan 固定 8 并发（`pipeline.go:324`），全为硬编码常量、不感知内存；`ListFunctions`（`crud_functions.go:62`）/`ListFiles`（`crud_files.go:57`）被 7 builder + 大量 detector + 29 plan 各自全量重读，`forEachFile` 还逐文件 `GetFileByID`（`helpers.go:46`、`detector.go:66`）。

**设计分三块**：

#### (a) 共享只读仓库索引 `repoIndex`

- index 阶段结束、graph 阶段开始前，一次性 `ListFunctions` + `ListFiles`（+ `ListFileScopeVariables`、`ListFuncPtrWrites`）装入不可变快照：`funcsByID`、`funcsByName`、`filesByID`、`fileScopeByFile`、`slotTargets`。
- 用现有 ctx 注入范式传递：仿照 `graph.WithAliasGraph`（`alias_ctx.go:11-15`）与 `withCFGCache`（`evidence/cfg_cache_ctx.go:17-21`），新增 `graph.WithRepoIndex(ctx, ri)`。
- `graph.forEachFile` 与 `evidence.forEachFile`（及 `forEachIndexedFile`/`forEachFileIncludingEmpty`）改为从快照取 functions/files，替代每次 `ListFunctions` + 逐文件 `GetFileByID`；graph builder 里的 `funcMap`/`slotTargets`/`paramsByFunc` 也从快照构建。
- 快照只读、一次构建，天然消除 70+ 次全量重读与各自复制的 map。

#### (b) 内存感知有界调度

- 把三处硬编码并发改为可配置项：`[scan] graph_builders_concurrency`、`[scan] detector_concurrency`、`[scan] plan_concurrency`（默认维持 7/8/8 兼容现状，避免无谓行为变化）。
- 新增一个轻量 `scheduler`（或直接复用 `sem chan struct{}`），在**准入新任务前**轮询 `runtime.ReadMemStats().HeapAlloc`（可选叠加读 `/proc/self/status` VmRSS）：
  - 低于阈值 → 正常准入；
  - 超过阈值 → 停止准入新任务（让在跑任务完成、flush 缓冲），必要时把并发上限降到 1；
  - 回到安全水位后恢复。阈值与安全水位可配置，默认关闭（保守）。
- 任务完成后“立即持久化结果 + 释放局部图/状态”维持现有语义（graph 边已即时落库、事件经 `eventBatch` 分批）。

#### (c) 图写批量化

- `GetOrCreateGraphNode` 现为两次往返（`INSERT OR IGNORE` + `SELECT`，`crud_graph.go:38-55`）、`InsertGraphEdge` 逐条 autocommit（`crud_graph.go:93-105`）。
- 改为**每个 builder 一个缓冲批次**，累计到阈值（如 500 条）后用 `WithImmediateTx` 一次提交；`GetOrCreateGraphNode` 在批内用内存去重表（`entity_type+entity_id+properties → id`）避免同批重复 upsert。
- 7 个 builder 并行写同一 `graph_nodes/graph_edges` 表时仍靠 `WithImmediateTx` 单点串行写锁（现有 `WithImmediateTx` 已实现“锁获取一次”），批量化减少锁获取次数与 WAL 增长。

**收益**：H3 同时解决“峰值叠加”与“重复加载”两个子问题；索引快照 + 图写批量化还带来显著墙钟收益。
**代价/风险**：共享索引快照必须在 index 之后、graph 之前构建，且要保证函数表在 graph 阶段不变（当前确实不变，`ClearGraph` 只清 graph 表）。调度器的内存回压逻辑需谨慎，避免误把正常峰值当压力导致吞吐骤降——先落地配置化并发（低风险），再落地回压（中风险）。
**改动范围**：`internal/graph`（快照 + 注入 + 两个 `forEachFile`）、`internal/evidence/detector.go`（`forEachFile` 系列）、`internal/db/crud_graph.go`（批写）、`internal/cli/pipeline.go` + `internal/config`（并发配置）。

---

## 3. 十个方向评估（收益 / 代价 / 风险 / 改动范围）

> 结论列 = 本提案是否采纳及理由。

| # | Issue 方向 | 收益 | 代价 | 风险 | 改动范围 | 结论 |
|---|---|---|---|---|---|---|
| 1 | 统一仓库上下文与稳定 ID | 已有（`graph_nodes/graph_edges` 稳定 ID） | 低 | 低 | 无/少量 | ✅ 沿用，无需新建 |
| 2 | 轻量仓库级索引 + Facts 持久化 | 消除 70+ 次全量重读 | 中（一次构建 + ctx 注入） | 低 | graph/evidence | ✅ 采纳（2.3a） |
| 3 | 解析后释放不用的解析对象 | AST 驻留有界，最大收敛项 | 中（借还引用） | 中（漏 Release 退化） | parser + 19 调用点 | ✅ 采纳（2.1） |
| 4 | CFG/语义图按需构建 | CFG 驻留有界 | 低 | 低 | cfg_cache 单文件 | ✅ 采纳（2.2） |
| 5 | detector 共享只读事实 | 随 2 一起实现 | 低 | 低 | 随 2.3a | ✅ 采纳 |
| 6 | 有界任务队列 + 内存感知调度 + 背压 | 峰值收敛 | 中 | 中（误判压力） | pipeline/config | ⚠️ 分两步：先配置化并发，再回压 |
| 7 | 缓存容量/作用域/淘汰策略 | 随 2.1/2.2 一起落地 | 低 | 低 | parser/cfg_cache | ✅ 采纳 |
| 8 | Facts/候选/证据分批写 SQLite | 事件已分批（`InsertEventBatch`）；图边改批写 | 中 | 低 | crud_graph | ✅ 采纳（2.3c） |
| 9 | 检查点/失败恢复/统一汇总 | 长期价值高，但**不属本轮三个热点** | 高 | 高 | 多包 | ⏸️ 本期不做，列入 M3/M4 |
| 10 | 跨分区符号/调用/全局/函数指针/回调/资源生命周期保留 | 通过稳定 ID + `AliasGraph`/`function_summary` 边界摘要保留 | 低 | 低 | 沿用现有 | ✅ 保持现有语义，回归验证 |

---

## 4. 七个架构问题的回答

1. **哪些必须常驻，为什么**：稳定的仓库级轻量索引——函数 `ID/Name/Signature`、文件 `ID/Path`、file-scope 变量存储类、func-ptr 写表、宏索引（`symbols.MacroIndex`，已有 50000 上限）。它们是紧凑整数/字符串，且被几乎所有阶段随机访问，重读成本远高于常驻成本。
2. **哪些可落库或按需重建**：解析树 AST、语句 CFG（`BuildStmtCFG` 确定性）、函数内数据流/路径状态、别名图（`BuildInterproceduralAlias` 可重建）、taint 摘要（`taintSummaryCache` 可重建）。这些都**不常驻**，改有界缓存或按需构建。
3. **局部图边界**：默认边界 = “目标函数 + 其直接 callee 的摘要 + 必要的 caller 摘要”。跨函数规则（null-flow/UAF/double-free/taint）通过 `graph_edges` 的 `CALL/RETURN/PARAM_BINDING` 按需取子图，而非整仓物化。
4. **跨文件/跨函数语义如何保留**：稳定 ID + 持久化 `graph_edges` + `AliasGraph`/`function_summary` 边界摘要；分区调度只改变“何时分析”，不改变“查得到的关系”。
5. **内存预算触发时如何暂停/背压/恢复**：调度器在准入前查 `HeapAlloc`/RSS，超阈值停发新任务、flush 缓冲、必要时降并发；回落到安全水位后恢复。**只暂停，不丢弃**。
6. **如何避免静默漏检**：任何预算降级/跳过/超时都落 `scan_runs`/`scan_stats` 显式状态位并在报告头渲染为 `incomplete/limited`；沿用现有 `PlanErrors/DetectorErrors/DisabledTypes/SkippedDetectors` 的“显式不完整”范式（`pipeline.go:25-48`）。
7. **SQLite 是否够用**：WAL + 单写者批事务可支撑当前规模与索引查询。风险点是 `ReachableFromEntries` 的递归 CTE（`crud_graph.go:163-190`）在高连通度调用图上可能膨胀，需在 20K/40K 规模验证；必要时把递归可达性迁到内存 worklist + visited 去重。

---

## 5. 目标架构与现有实现的映射（落地顺序）

| 阶段 | 现有实现 | 目标改动 | 归属热点 |
|---|---|---|---|
| M2.1 | `CFGCache`（`cfg_cache.go`） | 加 `MaxEntries` + LRU | H2 |
| M2.2 | `parser.ParseCached`（`parser.go`） | 加预算 + 借还引用 + 淘汰；`repofacts.Build` 流式化 | H1 |
| M2.3 | `ListFunctions`/`ListFiles`/`GetFileByID` 重读 | 共享只读 `repoIndex` 快照 + ctx 注入 | H3 |
| M2.4 | 7/8/8 硬编码并发 | 配置化并发（默认不变） | H3 |
| M2.5 | `GetOrCreateGraphNode`/`InsertGraphEdge` 逐条 | 每 builder 分批 `WithImmediateTx` | H3 |
| M3.1 | — | 内存感知回压（准入前查堆/RSS） | H3 |
| M3.2 | `eventBatch` 两次 flush | 分批定容 flush | （H5 次热点） |
| M3.3 | — | 检查点/失败恢复/统一汇总 | 方向 9（本期不强制） |

> 建议顺序：**M2.1 → M2.3 → M2.5 → M2.4 → M2.2**。
> 理由：H2（CFG LRU）风险最低先落地；H3 的索引快照与图写批量化收益大且低风险；配置化并发不改默认行为；H1（AST 借还）改动面最大、需谨慎放最后。每个 M2 都是独立小提交、可单独 revert、语义不变。

---

## 6. 分阶段实施、风险与回滚

**每步的统一纪律**（Issue 阶段 3）：说明问题 → 列涉及文件/函数 → 先补测试 → 最小修改 → 跑单测/集成/静态检查 → 对比内存/耗时/结果 → 说明回滚方式。

| 步 | 问题 | 涉及文件 | 测试 | 回滚 |
|---|---|---|---|---|
| M2.1 | CFG 全量常驻 | `graph/cfg_cache.go` | 新增 LRU 淘汰单测（预算内） | revert 单文件 |
| M2.2 | AST 全量常驻 | `parser/parser.go`、`repofacts/repofacts.go`、19 调用点 | 新增“预算内”断言 + `TestDeclarationFactInvariance` 保持绿 | revert 提交 |
| M2.3 | 70+ 次全量重读 | `graph/helpers.go`、`evidence/detector.go`、`pipeline.go` | 快照与 `ListFunctions` 等价性单测 | revert 提交 |
| M2.4 | 并发硬编码 | `pipeline.go`、`registry.go`、`config.go` | 配置解析单测 + 默认值不变断言 | revert 提交 |
| M2.5 | 图写逐条 | `db/crud_graph.go` + 各 builder | 批写后图边数量/内容不变（`builders_test.go`） | revert 提交 |
| M3.1 | 峰值叠加 | `pipeline.go` 调度器 | 回压阈值单测 | 默认关闭，配置回滚 |

**风险总览**：
- 最高风险：H1 借还引用漏 `Release`（缓存退化为无界）与 `repofacts` 流式化（影响检测事实）。
- 中风险：内存回压误判（吞吐骤降）。
- 缓解：每步独立提交 + 固定回归集（GTPv2 / `Policy_Acc_*` / `atoi`）+ 23 分区候选对照。

---

## 7. 待确认的问题

1. **预算默认值**：H1 AST 缓存与 H2 CFG 缓存的上限（文件数 / 条目数）初始值定多少？建议先按“当前基准仓库可跑完”给保守值，规模测试后调。
2. **回压开关**：内存感知回压（M3.1）默认关闭、配置启用，是否符合预期？还是默认开启？
3. **实施节奏**：是否按 M2.1 → M2.3 → M2.5 → M2.4 → M2.2 的顺序分步提交、每步可回滚？
4. **回归基线**：能否提供 23 分区候选基线数据（目录清单 + 各分区候选分布），供 M2 完成后做等价校验？
5. 确认后我先落地 **M2.1（CFG LRU）** 与 **M2.3（共享索引）** 这两个低风险项，再继续其余 M2。
