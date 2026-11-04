# SGRE 全仓扫描架构设计提案 — 第二轮审查记录

> 本轮范围：仅修订设计文档，不实施代码。逐项分析独立审查的 11 条意见（P0×3、P1×5、P2×3）。
> 每条结论标注：原设计是否正确 / 风险 / 修改建议 / 源码依据；无法从源码证实的标「待验证」。

---

## P0-1 AST 与 CFG 生命周期冲突 —— 原设计【不正确】，必须重构

### 判定与源码依据（已证实）

原设计（`SGRE_FULL_REPO_SCAN_ARCH_DESIGN.md` §2.2）写了「CFG 淘汰是纯 Go 安全操作、CFG 与 AST 相互独立」，**这是错误的**。

证据链（全部已从源码核实）：

1. `StmtNode` 直接持有语句节点：`newNode` 把 `stmt parser.Node` 存进 `StmtNode.Stmt`（`graph/control_flow.go:296-311`，第 308 行）。
2. `parser.Node` = `{node sitter.Node; src []byte}`（`parser/parser.go:146-149`）；`sitter.Node` 是 tree-sitter 的 C 指针（go-tree-sitter v0.25.0 `node.go`）。
3. CFG 的 `body` 来自缓存树：`fileParseCache` 持有 `roots/bodies/defs` 三个 `map[..]parser.Node`（`planner/null_flow.go:2686-2729`），其数据来自 `Parser.ParseCached`；随后 `BuildStmtCFGWithCache(..., body, ...)`（`null_flow.go:388`）把 `body` 里的语句节点写进 CFG。
4. 下游**大量解引用这些 C 节点**：
   - `n.Stmt.Kind()`（`null_flow.go:483`、`guard_model.go:49,61`、`free_summary.go:475`、`filter_contract_gap.go:165`）
   - `n.Stmt.ChildByFieldName("condition"/"consequence")`（`null_flow.go:1106`、`guard_model.go:62`、`filter_contract_gap.go:168-169`）
   - `n.Stmt.FindAll("update_expression"/"call_expression")`（`range_flow.go:204`、`filter_uninit_flow.go:287`）
   - `directAssignments(n.Stmt)` / `assignsVar(n.Stmt, ...)`（`null_flow.go:430`、`uninit_variable.go:996`）——内部走 `NamedChildren`/`Text`，同样是 C 调用。

**结论**：`StmtCFG` 的每个 `StmtNode.Stmt` 都是指向缓存 Tree 的 C 节点指针。**若 AST 缓存关闭该 Tree，CFG 里的节点立即悬空**，`Kind()/FindAll()/Text()` 触发 use-after-free，且这是 C 段错误——`recover()` 拦不住（见 `parser.go:152-154` 对 `isNull` 的说明，同为 C 指针解引用）。

因此原设计的三处都错了：(a)「CFG 淘汰纯 Go 安全」错——CFG 内部有 C 节点；(b)「CFG LRU 与 AST LRU 相互独立」错——CFG 依赖 Tree 存活；(c)「只加 `Release()`」不成立——Release 只是借用计数的一环，缺的是 CFG↔Tree 的引用协调。

### 修改方案：`TreeHandle` 引用计数 + 协调淘汰

引入 `TreeHandle` 作为 Tree 的唯一所有者，引用计数 = 缓存持有(1) + 活跃借用 + 活 CFG 引用：

- `StmtCFG` 持有 `*TreeHandle` 引用（而不是让 `StmtNode.Stmt` 裸持 C 节点）。
- CFG 被 LRU 淘汰时 drop 该引用；AST 缓存 LRU 淘汰时只 drop 缓存的 +1；真正的 `tree.Close()` + `parser.Close()` **只在 refcount==0 时执行**。
- 两个缓存预算因此是**加性**的：AST 驻留 ≤ AST 预算 + 被活 CFG 钉住的树数（受 CFG 预算约束）。
- 补充：CFG 消费者也必须以「借用」语义持有 `*StmtCFG`（或等价地保证消费者用完前 CFG 不被淘汰、树不被关闭），否则「另一 goroutine 已取得 `*StmtCFG` 指针、树却被关闭」仍会 UB。

### 完整对象生命周期（创建 → 借用 → 释放 → 淘汰）

```
ParseCached(file)                 → TreeHandle(ref=1, 归 AST cache)
BuildStmtCFG(body)                → StmtCFG.StmtNode.Stmt 引用该 TreeHandle(ref++)
detector/filter 借用 body 或 CFG   → ref++ （同步回调结束 ref--）
CFG LRU 淘汰                      → 释放 StmtCFG（Go 对象交给 GC，ref--）
AST LRU 淘汰                      → 从 cache 删条目（ref--）
ref==0                            → tree.Close() + parser.Close()  ← 唯一真正释放 C 内存的点
```

**不可违反的顺序**：借用结束 → CFG 淘汰 → AST 淘汰 → `Close`；`Close` 只能发生在 ref==0。任何「先关树、后仍有 CFG/借用」的顺序都是 UB。

### 替代方案（记录，不作为首选）

把 `StmtNode.Stmt` 从「C 节点」改为「Go 侧快照」（statement kind + 起止行列 + 源文本 + 最小子结构），彻底解耦 CFG 与 Tree 生命周期。代价：下游约 20 处 `FindAll/ChildByFieldName/Kind/Text/directAssignments` 都要改用新快照 API，属于重写语句级 AST 消费面，改动大、风险高。**记录为后续可选，不在本轮落地。**

---

## P0-2 真实内存预算 —— 原设计【不完整】，需补三层内存模型

### 判定与依据（已证实）

- go-tree-sitter v0.25.0 的 `Tree` **没有任何字节大小访问器**（已核对模块 `tree.go`：仅 `RootNode/Language/Edit/Walk/ChangedRanges/IncludedRanges/PrintDotGraph/Close/Clone`）。因此 AST 缓存的「字节预算」无法直接测量，**也不能用源码字节数推算**。
- 当前 SQLite DSN 未设 `cache_size`/`mmap_size`（`db/connection.go:31-37`），WAL 与 page cache 也计入 RSS/cgroup。
- tree-sitter 的 C 分配、SQLite、WAL 均不在 Go `HeapAlloc` 内。

### 修改：三层内存模型 + 可观测预算

| 层 | 采集 | 覆盖内容 |
|---|---|---|
| Go Heap | `runtime.ReadMemStats`（`HeapAlloc/HeapInuse/HeapSys/HeapObjects/NumGC`） | 仅 Go 对象（Candidate、CFG Go 结构、map、`src []byte`、properties 字符串） |
| 进程 RSS | `/proc/self/status` `VmRSS` 或 `/proc/self/smaps_rollup` `Rss` | Go heap + C 分配（tree-sitter/SQLite/cgo）+ 栈 + mmap |
| cgroup v2 | `memory.current` / `memory.max` / `memory.peak` / `memory.events{oom_kill}` | OOM 的真正边界，含 page cache |

- **AST 缓存主预算 = 树数量上限**（`maxCachedTrees`，可观测 = `len(cache)`，确定性）。
- **字节数只作估算报告**：一次性校准——可控地 `Close` N 棵树、量 RSS 差值得到 `estBytesPerTree`，报告 `estASTBytes = count × estBytesPerTree`，**明确标注为估算而非测量**。
- **权威反压阈值 = RSS + cgroup `memory.current`** 对配置上限（例如 34GB cgroup 内设 30GB 工作上限，留 headroom 给 SQLite/WAL/page cache 与瞬时尖峰）。
- 每个 `runPipeline` 阶段边界打印：三层内存 + `len(parser.cache)` + `len(cfgCache.byFn)` + 图节点/边/事件计数。

---

## P0-3 内存感知调度 —— 原设计【不完整】，需明确 cgroup 监控与单大任务

### 判定与依据（已证实）

原设计只写了 `runtime.ReadMemStats().HeapAlloc`。现有代码**没有任何内存读取**（全仓 grep `pprof/MemStats/RSS/cgroup` 零命中），因此该能力需全新增。

### 修改

- **准入信号优先级**：cgroup v2 `memory.current`（权威）→ VmRSS（无 cgroup 时回退）→ `HeapAlloc`（仅辅助，不作为唯一依据）。
- **高/低水位（可配置）+ 滞回**：`≥high` 停止准入新任务、flush 缓冲、并发降到 1；`≤low` 恢复。中间带不抖动。
- **并发预算按阶段可配**：`graph_builders_concurrency` / `detector_concurrency` / `plan_concurrency`（默认 7/8/8 不变）。
- **单一大函数超剩余预算**：当前 CFG 以函数为最小分析单元，不支持语句级拆分。既定行为——
  1. 先降并发到 1 串行执行该任务；
  2. 仍放不下 → 该分析单元标记 `limited`/`incomplete`，记录（函数名 + 规模 + 阶段）并落 checkpoint 供恢复；
  3. **绝不静默跳过**，报告中显式呈现为不完整。
  - 「单函数就超 34GB」在真实 C 代码中几乎不存在，但必须定义此降级路径以满足「预算耗尽不静默漏检」。

---

## P1-4 `repoIndex` 成本 / 重复 / 字段 / 增长

- **字段与用途**：`funcsByID`/`funcsByName`（`db.Function`：`Name/Signature/ReturnType/FileID/StartLine/EndLine/IsStatic`）、`filesByID`（`db.File`：`Path/Checksum/LOC/Language`）、`fileScopeByFile`（供 alias 全局别名判定）、`slotTargets`（供间接调用解析）。
- **内存量级**：10,627 函数 ×（两个 struct + 签名字符串）≈ 数 MB；1,745 文件 ≈ <1MB；40K 函数 ≈ 十几 MB。**线性增长，可接受**。
- **数据重复**：当前 `ListFunctions` 每次调用新建 `*db.Function`（被 7 builder + 大量 detector + 29 plan 重复调用 70+ 次）；快照去重为 1 份，同时消除重复分配。
- **不变性**：index 之后函数/文件表不再变化（`ClearGraph` 只清 graph 表），快照可安全共享只读。
- **待验证**：40K 档的签名字符串总字节需运行数据确认（预估十几 MB 量级，但需实测而非臆断）。

---

## P1-5 CFG LRU 并发 / 淘汰引用 / 重复构建 / AST 依赖

- **并发安全**：现有 `CFGCache` 用 `sync.RWMutex`（`cfg_cache.go:18-58`），LRU 的 last-use 更新在锁内即可，并发安全可保持。
- **淘汰时的使用者引用**：Go 对象 `*StmtCFG` 从 map 删除后，若其它 goroutine 仍持指针，GC 会保活 Go 对象本身——**真正的风险不是 Go 对象，而是它内部 `parser.Node` 指向的树被关闭**（回到 P0-1）。因此 CFG 淘汰与树关闭必须经 `TreeHandle` refcount 协调。
- **重复构建**：LRU 淘汰后再次 `GetOrBuild` 会重建（`BuildStmtCFG` 确定性，结果一致），只影响耗时，用现有 `Stats()` 的 builds/hits 观测。
- **AST 依赖**：本条的核心结论就是 P0-1——CFG 依赖 Tree 存活，不能独立淘汰。

---

## P1-6 图写批量化：跨 builder 去重 / 唯一性 / 事务 / 重试 / 幂等

- **节点**：`graph_nodes` 有 `UNIQUE(entity_type, entity_id, properties)`（`schema.go:104-110`），`GetOrCreateGraphNode` 用 `INSERT OR IGNORE` + `SELECT`（`crud_graph.go:38-55`）——节点去重正确、并发安全。
- **边**：`graph_edges` **无唯一约束**（`schema.go:112-123`），`InsertGraphEdge` 是裸 INSERT（`crud_graph.go:93-105`）。当前靠每扫描 `ClearGraph`（`crud_graph.go:107-127`）兜底，**不保证批内/重试去重**。
- **事务一致性**：`WithImmediateTx`（`store_impl.go:63-83`）已提供原子性——失败 rollback，批不会半提交。
- **幂等/重试缺口**：进程在 COMMIT 后、调用方确认前崩溃，重试会重复插边。
- **修改建议**：本轮批量化**保持现状语义**（每扫描一次构建、`ClearGraph` 兜底），不引入跨扫描幂等；**若后续引入 checkpoint/重试**，则必须给 `graph_edges` 加 `UNIQUE(src_id, dst_id, edge_type, properties)` 并改 `INSERT OR IGNORE`（或批内按该四元组去重）。这是把「幂等」当作后续显式需求，而不是本轮默认承诺。

---

## P1-7 跨文件/跨函数语义保持 —— 原设计【过于乐观】

原设计「稳定 ID + graph_edges 就保证语义完整」**不成立**。现状语义分散在多个机制，且不是单表可覆盖：

- 调用/间接调用：`CALL`/`ADDR_TAKEN`（`call_graph.go`）
- 跨函数数据流：`PARAM_BINDING`/`RETURN`（`interproc.go`）
- 所有权：`OWNERSHIP_TRANSFER`/`RELEASE`（`ownership.go`）
- 死锁：`LOCK_ORDER`（`lock_order.go`）
- 数据竞争：`GLOBAL_ACCESS`（`shared_access.go`）
- 别名：`AliasGraph`（`alias_graph.go`，当前**仅 double_free 直接消费** `CanonicalKey/AliasesOf`）
- 跨文件类型/宏：`repofacts`/`symbols`
- 返回可空性：`function_summary`

**修改**：把「语义保持」从**声明**降级为**验证项**——用 23 分区对照 + 专项回归（跨目录调用、函数指针、回调注册、全局变量、资源释放配对）逐项证明；无法证明的边界显式标 `incomplete`，不得宣称完整。

---

## P1-8 detector 分析上下文映射

按「需要什么分析上下文」分类（全部从源码消费关系核实）：

| 上下文 | 消费者 | 说明 |
|---|---|---|
| 局部语句 CFG（`SetCFGCache`） | null-deref（`filter_nullable_source`）、UAF（`filter_lifetime`）、double-free（`filter_double_free`）、uninit（`filter_uninit_flow`/`filter_uninit_heapstruct`）、divide-by-zero（`filter_range`）、buffer OOB（`filter_range_oob`/`filter_buffer_range`/`filter_buffer_flow`）、int-overflow（`filter_int_overflow`）、contract-gap（`filter_contract_gap`）、taint（`filter_taint_source`） | 函数内路径/区间/状态 |
| callee summary（返回可空性/释放/出参） | `null_flow` 的 `computeRetNullable`、`function_summary`、`OwnershipTransferFilter`/`ReleaseFilter`、`resolveCalleeDefs`（内嵌 callee body） | 跨函数「被调方」摘要 |
| caller summary（入口/可达/链根） | `filter_call_reach`（`ReachableFromEntries` 递归 CTE）、`caller_null` 开链 fixpoint、null-deref `chainDedupCandidates` | 跨函数「调用方」摘要 |
| 跨函数图（全仓） | `filter_lock_order`（环）、`shared_access`（GLOBAL_ACCESS）、taint summary（PARAM_BINDING/RETURN fixpoint）、double-free（AliasGraph） | 全仓级关系 |

**结论**：绝大多数 detector 只需「局部 CFG + 定向 callee/caller 摘要」；只有 lock_order、shared_access、taint summary、call_reach 需要跨函数索引。这支持「按需子图 + 边界摘要」的架构方向，但**必须按上表逐类型验证**，不能一刀切。

---

## P2-9 测试：基础事实一致性 / 检测一致性 / 跨边界回归

- **基础事实一致性**：`repoIndex` 快照 vs 直接 `ListFunctions/ListFiles` 结果等价；`graph_edges` 批写前后数量/内容不变（用 `builders_test.go` 断言）。
- **检测一致性**：固定回归集（GTPv2 越界写、`Policy_Acc_*` 泄漏、`atoi` 未校验）优化前后 candidate 集（文件/行/变量/CWE/来源）逐项一致。
- **跨边界专项回归**：跨目录调用、函数指针表、回调注册、全局变量读写、资源释放配对、`static` 同名函数区分——每类一个最小 fixture，断言不因按需构图/分区调度丢失。

## P2-10 10K/20K/40K 规模指标

每档记录：Go Heap（`HeapAlloc/HeapInuse/HeapSys`）、进程 RSS、cgroup `memory.current`/`memory.peak`、`len(parser.cache)` 与 `estASTBytes` 峰值、`len(cfgCache.byFn)` 峰值、图节点/边数、候选数、各阶段耗时、以及「完整/降级/incomplete」状态。目标：峰值内存受预算约束、增长可解释、无非线性膨胀。

## P2-11 23 分区 3788 候选仅为辅助基线

**同意**：23 个独立 DB 的分区扫描**切断了跨目录语义**（跨目录调用/全局变量/函数指针/回调在分区内不可解析），因此不能作为全仓扫描的严格等价基线。用途限定为：
- 高价值漏洞回归（GTPv2 / `Policy_Acc_*` / `atoi` 必须仍检出）；
- 单分区内的候选覆盖对照（辅助排查「某类 detector 是否退化」）；
- **不作为**「finding 总数相等即等价」的依据。

---

## 待验证清单（无法从源码证实，需运行数据）

1. 三个热点的**真实内存占比**（AST 树 vs CFG vs 事件缓冲 vs 并发副本）——需 RSS/cgroup profile。
2. 40K 档 `repoIndex` 签名字符串总字节与 AST 缓存峰值。
3. `ReachableFromEntries` 递归 CTE 在 20K/40K 高连通度调用图上的耗时/临时表规模。
4. LRU 命中率与重建墙钟的权衡（CFG 预算取多大）。
5. tree-sitter C 树 per-tree 字节（`estBytesPerTree` 校准值）。

## 本轮设计决策汇总（修正后）

1. **P0-1（关键修正）**：放弃「CFG 与 AST 独立淘汰」，改为 `TreeHandle` 引用计数 + 协调淘汰 + 显式生命周期顺序；`StmtNode.Stmt` 不再裸持 C 节点（改为经 handle 引用）；「只加 Release()」明确否决。
2. **P0-2**：AST 预算用「树数量上限」，字节数只作估算报告；反压阈值用 RSS + cgroup `memory.current`。
3. **P0-3**：准入读 cgroup v2 → RSS → HeapAlloc（辅助）；高/低水位滞回；单大任务「串行 → 显式降级 → 不静默跳过」。
4. **P1-6**：图写批量化保持「每扫描一次 + ClearGraph 兜底」，幂等作为后续显式需求。
5. **P1-7/8**：语义保持降级为验证项；detector 上下文按上表分四类，按需子图 + 边界摘要。
6. **P2-11**：23 分区仅作辅助回归基线。

## 未解决问题（待操作者确认）

1. `TreeHandle` 引用计数方案与「CFG 消费者借用语义」的侵入范围较大（约 20 处 CFG 消费点 + 19 处 ParseCached 调用点）；是否接受该侵入度，还是优先采用「相位作用域缓存 + 文件/模块分批调度」的保守路径？
2. AST 缓存 `maxCachedTrees` 与 CFG 缓存 `MaxEntries` 的初始默认值。
3. 内存上限（cgroup 内工作上限）取 34GB 的多少比例留 headroom。
4. 是否把 `graph_edges` 唯一索引 + 幂等写入纳入本轮，还是推迟到 checkpoint/重试需求出现时。
