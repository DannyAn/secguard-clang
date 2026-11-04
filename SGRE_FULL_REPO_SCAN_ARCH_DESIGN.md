# SGRE 万级函数仓库全仓扫描架构设计提案（Phase 2 · 修订版 v2）

> 状态：**设计提案，待确认后实施**。本版为第二轮审查后的修订稿，修正了 P0-1 的生命周期错误，并补入 P0-2/P0-3 与 P1/P2 结论。
> 逐项审查结论见 `SGRE_FULL_REPO_SCAN_ARCH_REVIEW.md`；本文只保留结论与修正后的设计，不含代码改动。
> 前提：跳过现场 profile，采信 Phase 0/1 报告（`SGRE_FULL_REPO_SCAN_OOM_ANALYSIS.md`）对三个强怀疑热点的源码定位。

---

## 0. 三个热点 → 设计目标（v2 修正）

| 热点 | 源码位置 | v2 设计目标 |
|---|---|---|
| H1 无界 AST 缓存 | `parser/parser.go:40-118` | 解析树缓存**有界**，经 `TreeHandle` 引用计数 + 协调淘汰 |
| H2 无界 CFG 缓存 | `graph/cfg_cache.go:17-58` | CFG 缓存**有界 LRU**，但**与 AST 生命周期协调**（不能独立淘汰） |
| H3 无内存感知并发 + 全量重复加载 | `pipeline.go:149-173,324`、`registry.go:116`、`crud_functions.go:62` | 共享只读索引 + **cgroup/RSS 驱动的有界调度** + 图写批量化 |

---

## 1. 设计总原则（与 Issue 4.2 对齐）

1. Single Repository Context；2. Bounded Memory；3. On-demand Construction；4. Incremental Persistence；
5. Explicit Lifecycle；6. Cross-file Correctness；7. Observable Degradation；8. Detection Parity。
（详见 Phase 0/1 报告与审查记录。）

---

## 2. 三个热点的设计（v2）

### 2.1 H1+H2：AST 与 CFG 的统一生命周期（关键修正）

> **v1 错误**：把 CFG 缓存当作「纯 Go、可独立 LRU」，并把 AST 缓存当作「加 Release() 即可」。二者都错——`StmtNode.Stmt` 持有指向缓存 Tree 的 C 节点（`control_flow.go:308`），下游 `n.Stmt.Kind()/ChildByFieldName()/FindAll()/Text()` 直接解引用该 C 节点（`null_flow.go:483,1106`、`range_flow.go:204`、`guard_model.go:49,62` 等）。关掉 Tree 即 use-after-free。

**v2 方案：`TreeHandle` 引用计数 + 协调淘汰。**

- `TreeHandle` 是 Tree 的唯一所有者，`refcount = 缓存持有(1) + 活跃借用 + 活 CFG 引用`。
- `ParseCached` 返回 `*TreeHandle`；调用方在同步回调内借用（`ref++/ref--`）。
- `StmtCFG` 持有一个 `*TreeHandle` 引用（`StmtNode.Stmt` 经 handle 访问，而非裸持 C 节点）。
- `CFGCache` LRU 淘汰 → drop CFG 的 handle 引用（`ref--`）。
- `Parser` LRU 淘汰 → 只从 cache 删条目（drop 缓存 +1）；**真正的 `tree.Close()` 仅在 `ref==0` 时执行**。
- 内存上界：AST 驻留 ≤ AST 预算 + 被活 CFG 钉住的树数（受 CFG 预算约束）——**两个预算加性，而非独立**。

**对象生命周期（顺序不可违反）**：

```
ParseCached(file)                 → TreeHandle(ref=1, 归 AST cache)
BuildStmtCFG(body)                → StmtCFG 引用该 TreeHandle(ref++)
detector/filter 借用 body/CFG      → ref++ （同步回调结束 ref--）
CFG LRU 淘汰                      → 释放 StmtCFG（Go 对象交 GC，ref--）
AST LRU 淘汰                      → 从 cache 删条目（ref--）
ref==0                            → tree.Close() + parser.Close()   ← 唯一释放 C 内存的点
```

- **否决「仅加 Release()」**：Release 只是借用计数，缺的是 CFG↔Tree 的引用协调与「先借用结束→CFG 淘汰→AST 淘汰→Close」的强制顺序。
- `repofacts.Build` 的 `trees []fileNode`（`repofacts.go:64-84`）会钉住所有 root 节点，必须流式化（两遍逐文件，`ParseCached` 命中复用），否则破坏淘汰。
- 替代方案（记录、非首选）：把 `StmtNode.Stmt` 改为 Go 侧快照，彻底解耦 CFG 与 Tree；代价是重写约 20 处 `FindAll/ChildByFieldName/Kind/Text` 消费面，改动大、风险高，留作后续可选。

### 2.2 H1：有界 AST 缓存（预算用「树数量」，非字节）

- `Parser` 增加 `maxCachedTrees`（可观测 = `len(cache)`）作为**确定性主预算**。
- 淘汰策略 LRU，只淘汰 `ref==0` 的树，经 `TreeHandle` 计数（见 2.1）。
- **字节数只作估算报告**：go-tree-sitter v0.25.0 `Tree` 无大小 API（已核对），用一次性校准（可控 Close N 棵树量 RSS 差值 → `estBytesPerTree`）得到 `estASTBytes = count × estBytesPerTree`，标注为估算。
- 工作区头文件（`repofacts.go:100-116`）进入同一缓存，天然受同一预算约束。

### 2.3 H3：共享只读索引 + cgroup/RSS 驱动的有界调度 + 图写批量化

#### (a) 共享只读 `repoIndex`

- index 后一次性 `ListFunctions`+`ListFiles`（+`ListFileScopeVariables`/`ListFuncPtrWrites`）装入不可变快照：`funcsByID`/`funcsByName`/`filesByID`/`fileScopeByFile`/`slotTargets`。
- 用现有 ctx 范式传递（仿 `graph.WithAliasGraph` `alias_ctx.go:11-15`、`withCFGCache` `evidence/cfg_cache_ctx.go:17-21`），新增 `graph.WithRepoIndex(ctx, ri)`。
- `graph.forEachFile` 与 `evidence.forEachFile`（及变体）改从快照取 functions/files，替代 70+ 次全量重读与逐文件 `GetFileByID`。
- 内存：10,627 函数 ≈ 数 MB、1,745 文件 <1MB、40K ≈ 十几 MB，线性增长（待实测确认签名字符串总量）。

#### (b) 内存感知有界调度（cgroup v2 优先）

- 并发预算按阶段可配：`graph_builders_concurrency`/`detector_concurrency`/`plan_concurrency`（默认 7/8/8 不变）。
- 准入信号优先级：**cgroup v2 `memory.current`（权威）→ VmRSS（回退）→ `runtime.ReadMemStats().HeapAlloc`（仅辅助）**。
- 高/低水位 + 滞回：`≥high` 停发新任务、flush 缓冲、并发降到 1；`≤low` 恢复；中间带防抖。
- **单大函数超剩余预算**：先降并发到 1 串行；仍放不下 → 该单元标 `limited`/`incomplete` + 落 checkpoint，**绝不静默跳过**。当前 CFG 以函数为最小单元，不支持语句级拆分，此为既定降级路径。

#### (c) 图写批量化（去重/事务/幂等边界）

- 每 builder 一个缓冲批次，累计阈值后 `WithImmediateTx` 一次提交；批内用内存去重表避免重复 `GetOrCreateGraphNode`。
- `graph_nodes` 已 `UNIQUE(entity_type,entity_id,properties)` + `INSERT OR IGNORE`，节点去重正确；`graph_edges` **无唯一约束**（`schema.go:112-123`），批量化**保持现状语义**（每扫描一次 + `ClearGraph` 兜底）。
- **幂等**：本轮不承诺；若后续引入 checkpoint/重试，需给 `graph_edges` 加 `UNIQUE(src_id,dst_id,edge_type,properties)` + `INSERT OR IGNORE`。`WithImmediateTx` 已保证批内原子回滚。

---

## 3. 十个方向评估（v2，结论不变，详见审查记录）

| 方向 | 结论 |
|---|---|
| 1 统一仓库上下文与稳定 ID | ✅ 沿用 |
| 2 轻量仓库级索引 + Facts 持久化 | ✅ 采纳（2.3a） |
| 3 解析后释放不用的解析对象 | ✅ 采纳，改 `TreeHandle`（2.1/2.2） |
| 4 CFG/语义图按需构建 | ✅ 采纳，但**与 AST 协调淘汰**（2.1） |
| 5 detector 共享只读事实 | ✅ 随 2.3a |
| 6 有界任务队列 + 内存感知调度 + 背压 | ⚠️ 分两步：先配置化并发，再 cgroup/RSS 回压（2.3b） |
| 7 缓存容量/作用域/淘汰策略 | ✅ 采纳（2.1/2.2） |
| 8 Facts/候选/证据分批写 | ✅ 采纳（2.3c） |
| 9 检查点/失败恢复/统一汇总 | ⏸️ 本期不做，列入 M3/M4 |
| 10 跨分区语义保留 | ✅ 保持，作为验证项（见下） |

## 4. 七个架构问题回答（v2 不变，摘要）

1. **必须常驻**：函数/文件/符号/调用边的紧凑只读索引 + 宏索引（已有 50000 上限）。2. **可落库/重建**：AST、CFG、函数内流状态、别名图、taint 摘要。3. **局部图边界**：目标函数 + 直接 callee/caller 摘要。4. **跨文件语义**：稳定 ID + `graph_edges` + `AliasGraph`/`function_summary` 边界摘要，**作为验证项而非声明**（见 P1-7）。5. **预算触发**：停发新任务 + flush + 降并发；恢复后再继续。6. **避免漏检**：显式 `incomplete/limited` 状态，沿用 `PlanErrors/DetectorErrors/...` 范式。7. **SQLite 是否够用**：是，但 `ReachableFromEntries` 递归 CTE（`crud_graph.go:163-190`）需 20K/40K 验证。

## 5. detector 分析上下文映射（P1-8，节选）

- **局部 CFG**：null-deref、UAF、double-free、uninit、divide-by-zero、buffer OOB、int-overflow、contract-gap、taint（`SetCFGCache` 消费者清单见审查记录）。
- **callee summary**：null_flow `computeRetNullable`、`function_summary`、ownership/release filter、`resolveCalleeDefs`。
- **caller summary**：`filter_call_reach`、`caller_null` 开链 fixpoint、null-deref `chainDedupCandidates`。
- **跨函数图**：`filter_lock_order`、`shared_access`、taint summary、double-free（AliasGraph）。
- 结论：绝大多数类型只需「局部 CFG + 定向摘要」，按需子图 + 边界摘要可行，但须逐类型验证。

---

## 6. 分阶段实施、风险与回滚（v2）

| 步 | 问题 | 涉及 | 回滚 |
|---|---|---|---|
| M2.1 | 共享只读索引（H3a） | `graph/helpers.go`、`evidence/detector.go`、`pipeline.go` | revert 提交 |
| M2.2 | 图写批量化（H3c） | `db/crud_graph.go` + builder | revert 提交 |
| M2.3 | 配置化并发（H3b 第一步） | `pipeline.go`、`registry.go`、`config.go` | 默认不变，revert |
| M2.4 | CFG 有界 LRU（H2） | `graph/cfg_cache.go` + `TreeHandle` 衔接 | revert 提交 |
| M2.5 | AST 有界缓存 + `TreeHandle`（H1） | `parser/parser.go`、`repofacts/repofacts.go`、调用点 | revert 提交 |
| M3.1 | cgroup/RSS 回压（H3b 第二步） | `pipeline.go` 调度器 | 默认关闭，配置回滚 |
| M3.2 | `eventBatch` 分批定容 flush | `evidence/detector.go` | revert 提交 |
| M3.3 | 检查点/失败恢复 | 多包 | 本期可选 |

> 顺序说明：**M2.1 → M2.2 → M2.3 → M2.4 → M2.5**。索引与批写、配置化并发风险低先落地；CFG/AST 有界缓存因涉及 `TreeHandle` 生命周期重构放最后。每步独立提交、可单独 revert、语义不变。

**风险总览**：最高风险是 `TreeHandle` 生命周期重构（M2.4/M2.5，侵入约 19 处 ParseCached + 20 处 CFG 消费点）；中风险是回压误判。缓解：每步独立提交 + 固定回归集 + 23 分区对照。

---

## 7. 待确认的问题（v2）

1. 是否接受 `TreeHandle` 引用计数的侵入度，还是优先采用「相位作用域缓存 + 文件/模块分批调度」的保守路径？
2. `maxCachedTrees` 与 CFG `MaxEntries` 的初始默认值。
3. 内存工作上限取 34GB cgroup 的多少比例留 headroom。
4. `graph_edges` 唯一索引 + 幂等写入是否纳入本轮，还是推迟到 checkpoint 需求出现。
5. 确认后先落地 M2.1（共享索引）+ M2.2（图写批量化）两个低风险项。
