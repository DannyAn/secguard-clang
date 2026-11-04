# SGRE 全仓扫描架构重构 · 检视报告（DSFlash · Round 1）

> **检视对象**：`SGRE_FULL_REPO_SCAN_ARCH_DESIGN.md`（v4 最终修订）及其实现提交 `59358e2..70f8129`（M2.1–M3.2）。
> **检视基线**：HEAD `70f8129`，工作区干净；设计文档 v4 + 第二轮~第四轮审查记录（`SGRE_FULL_REPO_SCAN_ARCH_REVIEW.md`）。
> **检视方式**：设计逐条对照 → 源码走查 → 构建/测试/vet/race → 端到端复现 → 迁移复现。
> **本轮产出**：只出报告，不改代码。问题编号可直接作为后续优化任务号。
> **结论一句话**：M2.1/M2.2/M2.3/M3.2 的“配置化、批量化、快照化”落地质量尚可，但 **§8 的核心 P0（TreeHandle/CFGLease、总驻留预算、incomplete 语义、AST 有界缓存安全）没有按设计实现**；其中 `max_cached_trees>0` 在 6 个 C 文件的小仓上即可稳定触发 SIGSEGV（已复现），因此本分支 **不能宣称“OOM 已修复”**，也不满足“不静默漏检”的发布门槛。
>
> **Round 3 更新（2026-11-04）**：补 1700 文件 / 1.02 万与 5.1 万函数实测（§10.5）；`free_summary` 改为逐文件 phase 2，修复 10,200 个 CFG lease 击穿预算；planner 全链路（range/null/lifetime/double-free/taint/uninit/contract-gap/race）恢复 CFG 缓存；新增 `go_mem_limit_mb`/`go_gc_percent`。
>
> **Round 2 实施更新（2026-11-04）**：已按阶段 A/B 修复 P0-1..P0-6 与大部分 P1（AST 借用生命周期、CFGLease/锁外构建、transient 释放即关闭、fileParseCache 全量 Close、incomplete 闭环、迁移回填、背压/边批/事件批/观测/默认值/repofacts 流式化）。59 文件压力扫描在 `max_cached_trees=5 + CFG 上限` 下 exit 0 且无借用泄漏；`go test ./...`、`go vet`、`-race`（核心包）全绿。**逐项状态与剩余工作见文末 §10。**

---

## 0. 先看整体：五个判断

| # | 判断 | 依据 |
|---|---|---|
| 1 | **“有界 AST 缓存”目前是崩溃开关，不是内存上限** | 启用 `max_cached_trees=1` 后，`graph.forEachFile → SharedAccessBuilder → parser.Node.FindAll` 在 cgo 内 SIGSEGV；默认配置同一仓扫描正常 |
| 2 | **CFG 与 Tree 的生命周期协调没有实现** | 没有 `TreeHandle`/`CFGLease`/`refs`/singleflight；`build()` 在全局锁内；9 处 CFG 构建不持 Tree 引用 |
| 3 | **“总驻留预算”被两处实现反向击穿** | transient 列表只增不减（实测 100 棵）；`fileParseCache` 只 Acquire 不 Release（`Close` 零调用），planner 读过的树永久 pin |
| 4 | **incomplete 语义只有存储层，没有闭环** | 扫描失败不留 `scan_runs` 行；`incomplete` 从不写入；`scan_incomplete_tasks` 零写入；报告/指标不渲染 |
| 5 | **所有新开关默认 0/false，默认行为与旧版一致** | `max_cached_trees`/`cfg_cache_max_*`/`event_batch_size`/`memory_pressure_enabled` 全部默认关闭；测试还显式断言 “unbounded by default” |

> 一句话给决策者：**本轮的净收益主要是“把 OOM 相关旋钮做出来了”，而不是“把 OOM 解决了”。在 P0-1..P0-4 修完之前，建议把新开关标记为 experimental 并默认强制关闭；P0-5/P0-6 修完之前，不要把 `completion_state` 作为“扫描完整性”的依据。**

---

## 1. 检视范围与验证结果

### 1.1 变更范围

- 9 个实现提交：`10d94ac`(M2.1) → `f45b962`(M2.2) → `1af84ad`(M2.3) → `d1f0667`(M2.4) → `0949d44`(M2.5) → `993f091`(M3.1) → `c830b53`(§8.3) → `8ee90ad`(tests) → `70f8129`(M3.2)。
- 73 个文件，约 +1667/−325 行；核心集中在 `parser/`、`graph/`、`evidence/detector.go`、`cli/pipeline.go`、`cli/mempressure.go`、`db/schema.go`、`db/crud_scan_runs.go`。

### 1.2 构建与测试基线（本机复跑）

| 检查 | 结果 |
|---|---|
| `go build -buildvcs=false ./...` | ✅ 通过 |
| `go test -buildvcs=false ./...` | ✅ 全部通过 |
| `go test -race ./internal/parser ./internal/graph ./internal/evidence` | ✅ 通过（但未覆盖“淘汰 vs 使用中”的竞态，见 P1-9） |
| `go vet`（变更包） | ✅ 无告警 |
| 端到端：默认配置扫 6 文件小仓 | ✅ exit 0 |
| 端到端：`max_cached_trees=1` 扫同一仓 | ❌ **SIGSEGV**（见 P0-1；Round 2 已修复，见 §10） |
| 迁移：旧库（无 `completion_state`）→ 新库 | ❌ 历史 `complete` 行变 `running`，下次扫描变 `failed`（见 P0-6；Round 2 已修复，见 §10） |

### 1.3 设计条目 vs 实现对照

| 设计条目 | 设计要求 | 实现现状 | 判定 |
|---|---|---|---|
| §2.1 / §8.1 `TreeHandle` | 唯一所有者、refcount = 缓存+借用+CFG、`Close` 仅 ref==0 | 仍是 `*parser.Tree` + `atomic.Int64`，无 handle、无 once、无借用语义 | ❌ 未实现 |
| §8.1 `CFGLease` | `Acquire/Release`、building/live 状态机、单飞、锁外 build | 无 Lease；`GetOrBuild` 返回裸 `*StmtCFG`；build 在锁内 | ❌ 未实现 |
| §2.2 有界 AST | `maxCachedTrees` 主预算；LRU 只淘汰 refs==0 | LRU 有，但淘汰会关掉别人正在用的树；bypass 退化成无界 transient 列表 | ⚠️ 半实现且不安全 |
| §8.2 总驻留预算 | bypass 用非缓存 Parse、用完即关；`activeTreeHandles` 有上限 | transient 只增不减；`fileParseCache` 只 Acquire 不 Release | ❌ 反向击穿 |
| §8.2 `maxTotalCFGNodes` | 按总节点数 LRU | 已实现，计数/淘汰逻辑正确 | ✅ 单 goroutine 语义正确 |
| §2.3a RepoIndex | 共享只读快照，替换 70+ 次重读 | 主体已实现；缺 `funcsByName`/`fileScopeByFile`/`slotTargets`；仍有大量 `ListFunctions/ListFiles` 未迁移 | ⚠️ 部分 |
| §2.3b 配置化并发 | graph/detector/plan 三阶段可配 | graph/plan 已配；detector 仍硬编码 8 | ⚠️ 部分 |
| §2.3b cgroup/RSS 回压 | 高/低水位、滞回、降并发、flush、单大任务降级 | 仅“准入前 sleep”，无降并发/无 flush/无 detector 阶段；`low=0` 会永久卡死 | ⚠️ 不完整（含卡死风险） |
| §2.3c 图写批量化 | 每 builder 一批、事务提交、保持语义 | 事务批写已实现；**整批回滚丢边**，与“保持现状语义”不符 | ⚠️ 有语义回归 |
| §8.3 incomplete | running 起步、失败/降级落库、报告渲染 | 只建表 + CRUD；不写、不判、不渲染 | ❌ 未闭环 |
| §8.4 风险与测试 | §8.1.4/§8.2.4/§8.3.4 测试矩阵 | 只有零散单测；关键路径全缺 | ❌ 缺口大 |

### 1.4 做得好的部分（应保留）

- `RepoIndex` 快照构造函数、ctx 注入、`ri == nil` 的旧路径回退都干净；`forEachFile`/`forEachIndexedFile`/`forEachFileIncludingEmpty` 三个变体都接入了快照。
- `InsertGraphEdgeBatch`/`InsertEventBatch` 的 `BEGIN IMMEDIATE` 事务边界清晰；`edgeBatchWriter` 每 builder 独立实例，无共享状态。
- `CFGCache` 的 `MaxEntries`/`MaxTotalCFGNodes` 计数、LRU 时间戳刷新、`Invalidate/Reset` 的引用释放逻辑，在“无并发共享”的前提下是正确的。
- `MemoryMonitor` 的信号优先级（cgroup v2 → VmRSS → HeapAlloc）与采样/滞回骨架正确。
- `completion_state` 的 DDL、`UpsertScanRun`、`Get/ListScanRuns` 的读写列、`agentSchemaTables` 同步是完整的“存储层”。
- 构建、vet、全量测试均通过，说明机械改动（`forEachFile` 签名扩展等）没有破坏既有路径。

---

## 2. P0 问题（阻断合并 / 阻断“OOM 已修复”的对外声明）

### P0-1 `max_cached_trees>0` 会稳定 SIGSEGV：AST 淘汰缺少“借用”保护

**结论**：这是本轮最严重的问题。`ParseCached` 返回的 `parser.Node` 在回调期间没有被借用；另一个 goroutine 的 `ParseCached` 可以把它所属的 Tree 淘汰并 `ts_tree_delete`，随后 `Node.Kind()/FindAll()` 解引用悬空 C 指针，**SIGSEGV 无法被 `recover` 捕获**。

**证据链**：

1. `ParseCached` 返回 `*Tree`（`sgre/internal/parser/parser.go:133-158`）；淘汰路径直接 `t.tree.Close()`（`parser.go:163-190`），没有检查“是否还有回调正在使用”。
2. `graph.forEachFile`（`sgre/internal/graph/helpers.go:60-78`）在回调 `fn(file, root, funcs)` 执行期间只持有 `root parser.Node`，**不 Acquire**；`evidence.forEachFile`（`sgre/internal/evidence/detector.go:96-104`）、`forEachIndexedFile`（113-148）、`forEachFileIncludingEmpty`（154-199）同样是这个模式。
3. 设计 §2.1 明确要求 “detector/filter 借用 body/CFG → ref++（同步回调结束 ref--）”；实现只给 CFG cache 和 `fileParseCache` 加了 Acquire，**迭代回调这一层完全没有**。

**复现 A（最小单测）**：

```go
p := NewParser(); p.SetMaxCachedTrees(1)
t1, _ := p.ParseCached([]byte("int a(void){return 1;}"), "a.c")
root := t1.RootNode()                       // 未 Acquire，与 forEachFile 一致
_, _ = p.ParseCached([]byte("int b(void){return 2;}"), "b.c") // 淘汰 a.c 并 Close
root.Kind()                                 // SIGSEGV: ts_node_type
```

结果：`SIGSEGV: segmentation violation ... signal arrived during cgo execution`，栈顶 `_Cfunc_ts_node_type`。

**复现 B（端到端，6 个 C 文件）**：

```toml
# <project>/.codeagent/secguard.toml
[scan]
max_cached_trees = 1
```

```bash
secguard scan <project>/src --db <project>/.agent/sgre.db
```

结果：exit code 2，栈：

```
graph.(*SharedAccessBuilder).Build.func1  shared_access.go:34
  → parser.Node.FindAll                   parser.go:432
  → _Cfunc_ts_node_named_child            SIGSEGV
graph.forEachFile                          helpers.go:78
```

同一仓、默认配置（`max_cached_trees=0`）扫描 exit 0；只开 `cfg_cache_max_entries=2/cfg_cache_max_total_nodes=50` 或 `event_batch_size=4` 均不崩。**崩溃由 AST 淘汰触发，与 CFG/事件开关无关。**

**影响**：

- 7 个 graph builder 并发 + 8 个 detector 并发，任何一个 `ParseCached` 都可能淘汰别人正在遍历的树；当缓存容量小于工作集时（本轮 6 文件 + `max=1` 稳定复现）**高概率崩溃**。
- 设计 §8.4 说的“Tree-sitter C 指针生命周期必须用真实并发测试验证”在本轮没有做到；`go test -race` 也测不到 cgo UAF。

**修复建议（按优先级）**：

1. **立刻熔断**：在 P0-1/P0-3/P0-4 修完前，`SetMaxCachedTrees(n>0)` 要么直接拒绝并返回错误/告警，要么强制 0；同时在 scan 日志/JSON 标注 “AST cache bound disabled (experimental)”。
2. **正确实现借用**：让 `ParseCached` 在返回时**已经持有 +1 借用**（在 `p.mu` 内完成 lookup + ref++），调用方必须 `Release`；`forEachFile` 等迭代器在调用 `fn` 前后 `Acquire/Release`，而不是让回调自己管。
3. 或者按设计 §2.1 的 `TreeHandle` + `TreeLease` 重做；`Acquire` 不能再是裸 `atomic.Add`（见 P0-4 的 TOCTOU）。

---

### P0-2 CFG↔Tree 生命周期没有按 §8.1 实现

**结论**：设计 §8.1 的 `CFGLease`、`building/live` 状态机、singleflight、锁外 build、`refs` 淘汰门槛，全部没有落地；实现仍是 `GetOrBuild` 返回裸 `*StmtCFG`。这既留下 UAF 风险，也把 CFG 构建退化成全局串行。

**证据**：

1. `CFGCache` 没有 `refs` 字段，`cfgEntry` 只有 `{cfg, tree, last, nodeCount}`（`sgre/internal/graph/cfg_cache.go:41-46`）。
2. `GetOrBuild` 在 `c.mu` 内直接执行 `builder()`（`cfg_cache.go:60-68`）；`GetOrBuildWithTree` 同样（`185-197`）。设计 §8.1.2 第 1 点明确要求 **“build() 永不在锁内执行”**；实现把 8 个 detector + 8 个 plan 的 CFG 构建全部串行化到一把锁上。
3. 淘汰 `evictOldestLocked`（`96-118`）只看 LRU 时间戳，**不看该 CFG 是否正被其他 goroutine 使用**；淘汰即 `tree.Release()`，parser 下一次淘汰就可能 `Close` 该树。
4. **9 处 CFG 构建没有传 tree**（条目因此不持 Tree 引用）：
   - `planner/range_flow.go:161`
   - `planner/filter_contract_gap.go:162`
   - `planner/filter_uninit_heapstruct.go:70`
   - `planner/filter_uninit_flow.go:235`
   - `planner/null_flow.go:388,409`
   - `evidence/race_condition.go:578`
   - `evidence/free_summary.go:250,466`（通过 choke point 显式传 `nil`）
5. `GetOrBuildWithTree` 的命中路径（`cfg_cache.go:191-196`）**不执行 `tree.Acquire()`**；如果一个条目先由无 tree 的 `GetOrBuild` 建立，后续再传 tree 也无法“升级”。`free_summary` 与其他 detector 并发时，谁先建谁决定该条目是否被 pin。
6. 设计 §8.1.4 的 7 项测试（Acquire/Release 幂等、活跃租约不被淘汰、singleflight、锁外构建、Close 只一次、`-race`、迁移一致性）**全部缺失**。

**影响**：

- 开启 `max_cached_trees>0` 时，CFG 条目可能引用已被关闭的 Tree → 任何 `n.Stmt.Kind()/ChildByFieldName()/FindAll()` 都可能 UAF。
- 开启 `cfg_cache_max_entries/max_total_nodes` 时，淘汰正在被其他 goroutine 使用的 CFG 会提前 `Release` 树；若该树同时被 parser 淘汰，同样是 UAF。
- 即使不开任何上限，CFG 构建的全局锁也抵消了 plan/graph 的并发收益（性能回归）。

**修复建议**：按 §8.1 实现 `CFGLease`（`refs`+`building`+`done`+`sync.Once`），或最小可行版：条目加 `refs`，`Acquire` 锁内 `refs++` 并返回 lease，`Release` 幂等 `refs--`；LRU 只选 `refs==0`；**所有** CFG 消费点（9 处）改为 `Acquire/Release` 并传 tree；`build()` 移到锁外 + per-key singleflight。

---

### P0-3 有界 AST 缓存的 “bypass” 退化为无界 transient 列表

**结论**：设计 §8.2.2 要求“缓存满且全被钉住时，回退到非缓存 `Parse`，同步消费、用完 `Close`、不进入任何缓存”。实现改成了“把新树 append 到 `transientTrees`，返回 `cached: true`”，而 `cached == true` 时 `Tree.Close()` 是 no-op（`parser.go:252-258`）——**transient 树在 `CloseAll` 之前永不释放，且会重复解析同一文件**。

**证据**：

- `parser.go:148-154`：无可淘汰条目时 `p.transientTrees = append(...)`，返回 `t`（`cached: true`）。
- `parser.go:195-225`：`CloseAll` 才统一关闭 `transientTrees`。
- `parser.go:252-258`：`cached` 树的 `Close()` 直接 return，调用方无法“用完即关”。
- `p.cache` 中没有该文件，下一次 `ParseCached` 同文件会**再解析一遍并再 append**；detector 每轮遍历都会重复。

**实测**：`maxCachedTrees=1` + 1 棵 Acquired 树 + 100 个新文件 → `cached=1, transient=100`（全部驻留到 `CloseAll`）。

**更糟的放大路径**：`repofacts.Build` 先对每个文件 `tree.Acquire()` 并保存 root（`repofacts.go:96-100`），导致 cache 中已有的树都不可淘汰；随后所有文件走 transient（`repofacts.go:120-129` 的 header pass 同样）。于是**整个仓库的 AST 在 repofacts 期间常驻，且之后仍留在 transient 列表**——H1（无界 AST）在“有界缓存”下反而被放大。

**影响**：`max_cached_trees` 既不能限制总驻留，又会重复解析（CPU 回归）；再叠加 P0-1 的 UAF，启用即不可用。

**修复建议**：实现设计要求的 bypass 语义：每个瞬态文件用**独立的 `sitter.Parser`** 解析（`Parser.Parse` 的共享 parser 不是并发安全的，见设计问题 DD-1），返回一个可 `Close()` 的租约；调用方在回调结束（或同步消费结束）时 `Close` 树 + parser；**绝不注册进 `fileParseCache`/`CFGCache`**。若做不到，先不要提供 `max_cached_trees` 开关。

---

### P0-4 `fileParseCache` 只 Acquire 不 Release；Acquire 与淘汰存在 TOCTOU

**结论**：`fileParseCache` 是 planner 里最广泛使用的 AST 持有者；本轮加了 `trees` map 和 `Close()`，但 **`Close()` 在生产代码中零调用**。结果是任何被 planner 读过的文件树 `refs` 永远 >0，parser LRU 永远淘汰不掉；同时 `Acquire` 发生在 `ParseCached` 返回之后，存在“淘汰后再 Acquire”的竞态窗口。

**证据**：

- `null_flow.go:2726-2735`：`prime` 调 `functionBodiesForFile`（内部 `ParseCached`，`2818`），返回后才 `tree.Acquire()`（`2732`）。
- `null_flow.go:2744-2751`：`Close()` 逐个 `Release`；全仓 grep `fileParseCache.Close`/`fc.Close` **无生产调用点**。
- 全仓 `newFileParseCache(...)` 有 26 处（每个 filter/querier/summary 都新建），均未 defer `Close`。
- 同类 TOCTOU：`repofacts.go:99`/`127` 也是 `ParseCached` 返回后才 `Acquire`；`Acquire` 只是 `atomic.Add`，无法阻止另一个 goroutine 已经执行的 `t.tree.Close()`。

**影响**：

- AST 预算被 planner 单独击穿：只要任何 filter 用 `fileParseCache` 读过某文件，该树就永久 pin；`maxCachedTrees` 对这类文件完全失效。
- 若将来把 `fileParseCache.Close()` 接上（这是正确方向），上述 TOCTOU 会立刻变成 UAF；因此“补 Close”不能单独做，必须同时把 Acquire 变成原子借用。

**修复建议**：

1. `ParseCached` 返回时即持有借用（或新增 `AcquireCached(file)` 在 `p.mu` 内完成 lookup+ref++）。
2. `fileParseCache` 生命周期内 `defer Close()`（每个 `newFileParseCache` 的调用点都要接）；或者按设计 §8.2.2 改成“存 TreeHandle + 行号区间，在借用作用域内派生 Node”。
3. `repofacts.Build` 的 `Acquire` 同样改为原子借用，或改成设计要求的流式两遍（不留 root）。

---

### P0-5 incomplete 语义没有闭环：只建了表，不写、不判、不渲染

**结论**：§8.3 的核心承诺是“超预算/超时/部分失败 → 持久化 incomplete，报告显式显示不完整，绝不谎报完成”。实现只完成了 DDL/CRUD，**没有一处业务代码写入 `incomplete`，也没有任何消费方读取**。

**证据**：

1. **失败扫描不留记录**：`scan_runs` 只在扫描末尾 `UpsertScanRun`（`sgre/internal/cli/scan.go:595`）；`SetScanRunCompletionState` 的 defer（`166-178`）只 UPDATE 已存在的行。实测扫不存在的路径 exit 1，DB 里没有任何新行。
2. **没有 running 起步**：全仓 `UpsertScanRun` 只有 scan.go:595 一处；设计 §8.3.2 要求的“启动即建 running 行”不存在。因此“默认 running / 启动清理遗留 running”只在“扫描尾声到 defer 之间”的极小窗口有意义。
3. **部分失败仍写 complete**：`DetectorErrors`/`PlanErrors` 只写入 JSON（`scan.go:451-465`），`scanSucceeded = true`（`623`）无条件置 complete。
4. **`incomplete` 从不落库**：`SetScanRunCompletionState` 的唯一生产调用只传 `"complete"` 或 `"failed"`（`scan.go:169-170`）；`InsertIncompleteTask`/`ListIncompleteTasks`（`crud_scan_runs.go:115/129`）**零生产调用点**。
5. **报告/指标不渲染**：生产代码里 `completion_state` 只出现在 `db/`、`cli/scan.go` 与 `cli/schema.go`（schema 元数据）；`report` 的 summary/标题渲染、`cli/metrics.go` 的 `metricsView`（111 起）、`scan` 的 JSON 输出均无该字段；`secguard schema` 的 note 却宣称 “Query by scan_id to find what a resume needs to re-run”（`cli/schema.go:119`），属于过度承诺。
6. **reason 枚举未约束**：DDL 无 CHECK，测试里用了 `timeout/panic/oom`，设计与代码都没有统一枚举。

**影响**：OOM/panic/预算降级后，DB 仍可能写着 `complete`；agent 若按 `scan_runs.completion_state` 判断，会把不完整结果当完整结果使用——这正是 §8.3.2 警告的“比失败更危险”的场景。

**修复建议**：

- 在 scan 启动、`store` 打开后立即插入 running 行（可在 `UpsertScanRun` 前 `CreateScanRun`，或提供 `BeginScanRun`）。
- 收尾时按 `scanSucceeded && len(DetectorErrors)==0 && len(PlanErrors)==0 && 无 incomplete 任务` 才写 `complete`；否则 `incomplete`（部分失败）或 `failed`（不可恢复）。
- 所有降级点（CFG 预算、AST bypass、event flush 失败、parse 失败、背压放弃）写 `scan_incomplete_tasks`；reason 统一枚举并在写入处校验。
- report 头/`metricsView`/scan JSON 输出 `completion_state` 与未完成任务清单；`complete` 只由显式收尾写入。

---

### P0-6 迁移回填把历史 complete 扫描变成 running，下一次扫描变 failed（已复现）

**结论**：`ensureColumn` 给旧库加 `completion_state TEXT NOT NULL DEFAULT 'running'`，SQLite 会用默认值回填**所有历史行**；随后 `MarkStaleRunningAsFailed` 全局把它们置为 `failed`。这是数据完整性回归。

**证据**：

- `sgre/internal/db/schema.go:440` 的 `ensureColumn(... TEXT NOT NULL DEFAULT 'running' CHECK ...)`。
- `sgre/internal/db/crud_scan_runs.go:103-113`：`UPDATE scan_runs SET completion_state='failed' WHERE completion_state='running'`（无 owner、无时间窗）。
- 实测：复制一个含 `complete` 扫描的库 → `ALTER TABLE DROP COLUMN completion_state` 模拟旧库 → 跑 `secguard metrics` 触发 `InitSchema` → 该行变为 `running` → 再跑一次 `secguard scan` → 该行变为 `failed`，新行 `complete`。

**影响**：升级后历史 metrics/status 全被标 failed；多进程/多 agent 共享一个 DB 时，还会把**正在运行**的扫描标失败（见设计问题 DD-8）。

**修复建议**：

- 迁移时先加**可空**列，`UPDATE` 历史行为 `complete`（或 `unknown`），再按需 `NOT NULL`；不要用 `DEFAULT 'running'` 回填历史。
- `MarkStaleRunningAsFailed` 增加 owner/PID/心跳或“创建时间早于本次启动”条件；不要做全局 sweep。

---

## 3. P1 问题（应在本轮或紧随修复）

### P1-1 所有新开关默认关闭，OOM 目标对现有用户未生效

`config.go:151-202`：`GraphBuildersConcurrency/PlanConcurrency` 默认 0→用旧值 7/8；`CFGCacheMaxEntries/MaxTotalCFGNodes/MaxCachedTrees/EventBatchSize` 默认 0；`MemoryPressureEnabled` 默认 false。`pipeline.go:78` 只在 `MaxCachedTrees>0` 时设上限；`pipeline.go:216-217/249` 同理。测试还显式断言：

- `internal/parser/parser_lru_test.go:43-63` `TestParseCached_UnboundedByDefault`
- `internal/graph/cfg_cache_test.go:206-220` `TestCFGCache_UnboundedByDefault`

**结论**：默认扫描的内存曲线与改造前基本一致；设计 §7/§8.4 把默认值留作 TBD，实现选了“0=关闭”，等价于把“OOM 修复”变成 opt-in。**建议**：要么给安全默认（如 `max_cached_trees=2000`、`event_batch_size=2000`），要么在启动时检测到“全部 unbounded”打印显式 warning，并在 release notes 里写清楚“默认未启用”。

### P1-2 CFG 构建在全局锁内 → 并发退化

见 P0-2 第 2 点。`GetOrBuild`/`GetOrBuildWithTree` 在 `c.mu` 内跑 `BuildStmtCFG`；8 detector + 8 plan 共享一个 cache。设计第四轮专门修的就是这一点（“build 移出锁”），实现又退回去了。

**建议**：`building` 占位 + `done` 通道 + 锁外 build + 双重检查回填；至少先做 per-key 单飞，避免“不同 fnID 也互相阻塞”。

### P1-3 背压调度不完整，且 `low=0` 会永久卡死

**证据**：

- `mempressure.go:70-85`：`pressured=true` 后，只有 `cur <= m.lowBytes` 才清除；`lowBytes` 默认 0，`readMemoryBytes()` 在 cgroup/RSS/HeapAlloc 三条路径上都不会返回 0 → **一旦触发压力，永不恢复**。
- `pipeline.go:181-186`（graph）与 `375-379`（plan）：`for memMon.Pressured() { time.Sleep(100ms) }` 不 select `ctx.Done()`；Ctrl-C 也无法退出，`bwg.Wait()/pwg.Wait()` 会挂住。
- 配置无 `low < high` 校验；`config.go` 的示例只给了 `memory_high_watermark_mb`，用户很容易只配 high。
- **graph 阶段的门实际上无效**：7 个 builder 在启动时（pressure 尚未采样）全部通过检查并占满 `builderSem`；监控 2s 才采第一次，之后不会再“降并发”。
- 没有设计要求的“flush 缓冲、并发降到 1、恢复后渐升”；detector 阶段完全不受监控（`registry.go:116` 硬编码 8，无 `detector_concurrency` 配置）。
- 没有 `memory.max`/`memory.peak`/`oom_kill` 读取；阈值是绝对 MB，跨部署不可移植。

**建议**：校验 `low>0 && low<high`；压力时用 ctx-aware 等待；真正把 sem 容量降到 1（或分批重启 worker）；覆盖 detector 阶段；增加 `detector_concurrency`；优先从 `memory.max` 推导 high/low；在任何“压力下放弃任务”时写 incomplete（P0-5）。

### P1-4 图边批写改变了失败语义，且计数虚高

- `edge_batch.go:55-66`：一次 `InsertGraphEdgeBatch` 失败 → 整个 batch（最多 500 条）回滚并清空，只记一条 Warn。
- 旧行为：逐边 autocommit，单边失败只丢该边，其余边保留。
- `crud_graph.go:111-127`：`inserted` 在 `tx.InsertGraphEdge` 成功时自增，但事务失败回滚后仍返回部分 `inserted`；`edgeBatchWriter.flushed += n` 因此虚高。
- `call_graph.go:154-158` 等 builder 的 `result.EdgesCreated++` 在 `add` 之后无条件执行，flush 失败也不回退。
- 设计 §2.3c 说“批量化保持现状语义”，这与“整批原子回滚”矛盾（见 DD-6）。

**建议**：batch 失败时降级为逐边重试（保持旧语义），或用 `INSERT OR IGNORE` + 唯一索引（设计 §2.3c 已给后续方案）；`inserted` 只在 COMMIT 成功后计入。

### P1-5 RepoIndex 只覆盖了一部分调用点

- `repo_index.go:16-24` 的字段只有 `functions/files/funcsByID/filesByID/funcsByFile/fileOrder`；设计要求的 `funcsByName`/`fileScopeByFile`/`slotTargets` 没有。
- 仍在直接查库的（非测试）：
  - graph：`call_graph.go:35`、`interproc.go:40`、`alias_builder.go:26/30/47`、`funcptr_writes.go:33`、`call_graph.go:275`
  - evidence：`argument_type.go:440`、`interprocedural.go:45`、`race_condition.go:228`、`null_source.go:455/495`、`dangerous_function.go:348`、`caller_null.go:427/440`、`free_summary.go:177`、`data_representation.go:158`、`typedefs.go:65/90`、`bounded_return.go:452`、`unchecked_return.go:1305`
- `scanHasEntryPoint`、`forEachFile` 等已迁移，但 `ListFunctions` 的 70+ 次重读只消除了一部分。

**建议**：补齐 RepoIndex 字段并把上述调用点迁移；至少把每个 detector 一次的 `ListFunctions/ListFiles` 收敛到快照。

### P1-6 `repofacts.Build` 仍然全量钉住 AST（设计明确要求流式化）

设计 §2.1 原文：“`repofacts.Build` 的 `trees []fileNode` 会钉住所有 root 节点，必须流式化（两遍逐文件，ParseCached 命中复用），否则破坏淘汰。”实现：`repofacts.go:76-84` 仍把每个 `fileNode`（含 root）追加到 `trees`，`142` 行再二次遍历；`96-100`/`120-129` 还显式 `Acquire()` 所有树，`defer` 到 Build 结束才 Release（`64-70`）。**这等于在 repofacts 期间把所有 AST 都钉死**，与“有界缓存”直接冲突。

**建议**：按设计做两遍流式：第一遍只收集宏/路径等轻量事实，第二遍逐文件 `ParseCached` → 消费 → 立即释放；不要保存 root。

### P1-7 事件批默认关闭，flush 失败会静默丢事件

- `config.go:196` 默认 `EventBatchSize=0`；`pipeline.go:249` 设置后 `emitEvent` 不自动 flush，整阶段事件累积在内存（H3 的“事件缓冲”热点仍在）。
- `flushEventBatch`（`detector.go:320-336`）失败只 Warn，然后 `events=nil`（`327` 前已 swap）；`InsertEventBatch` 回滚后这批事件彻底丢失，且不写 incomplete、不进 `DetectorErrors`。
- `emitEvent` 返回 true 只代表“入缓冲成功”，不代表落库；`DetectResult.EventsCreated` 会虚高。

**建议**：默认给一个安全批大小（如 2000）；flush 失败要么重试、要么把事件数/失败写进 `DetectorErrors`/incomplete，不能只 Warn。

### P1-8 可观测性缺口：设计要求的指标一个都没有

- 设计 §8.2.2 要求 `activeLeaseCount`、`activeTreeHandles`、`pinnedTrees`、`estASTBytes`、阶段边界打印、`estBytesPerTree` 校准——全仓 grep 只有 `CacheStats`/`StatsFull` 两个计数，**没有 pinned/lease/估算字节**。
- 设计 §8.2.2 的硬性不变式 `activeTreeHandles ≤ maxCachedTrees + 并发度` 没有断言/观测；transient 列表也没有计数上限。
- `completion_state`/`scan_incomplete_tasks` 没有任何 report/metrics 消费者（见 P0-5）。
- `secguard schema` 的 note 过度承诺 “resume”（`cli/schema.go:119`）。

**建议**：在 phase 边界打印三层内存 + `len(cache)` + `len(transient)` + `pinnedTrees` + `cfg entries/totalNodes` + 图/事件规模；给 `metricsView` 加 `completion_state`；`schema` note 改成“ledger for diagnosis”（本期无 resume）。

### P1-9 测试缺口：没有一条测试能抓住本轮的核心问题

- **无** `max_cached_trees>0` 的端到端/并发测试（如果有，P0-1 会立刻暴露）。
- `parser_lru_test.go`：`TestParseCached_MaxCachedTrees_LRU` 只断言 `cached<=2`，不断言 transient 有界；`TestParseCached_Concurrent_WithBound` 只用 2 个文件名、`max=10`，**从不触发淘汰**；`TestParseCached_ReferencedTreeNotEvicted` 只验证 1 棵被 pin 的树不被淘汰，不验证“使用中的树”。
- `cfg_cache_test.go`：没有 `Acquire/Release`、singleflight、锁外 build、Close-once；`TestCFGCache_UnboundedByDefault` 反而把“无界”固化为期望。
- **无** `RepoIndex` 等价性测试、**无** edge batch 失败/去重测试（`InsertGraphEdgeBatch` 只有真实实现与 mock 实现，没有任何测试覆盖失败/去重语义）。
- **无** 迁移测试（旧库 → 新库的历史行状态）；**无** `incomplete` 端到端测试。
- 设计 §8.1.4（7 项）/§8.2.4（3 项）/§8.3.4（4 项）基本未落地。

**建议**：先加三个“会失败”的回归测试，再修实现：① `max_cached_trees=1` 扫描不崩；② transient 数量有上限；③ 旧库迁移后历史行为 complete。然后补 §8 的测试矩阵 + `-race` 淘汰压测。

### P1-10 `MarkStaleRunningAsFailed` 没有 scan 所有权，会误伤并发扫描

`scan.go:144` 在每次 scan 启动时全局 `running → failed`。多 agent/多进程共享一个 DB（项目已支持并发 `report --write-json`）时，一个扫描启动会把另一个正在运行的扫描标 failed。见设计问题 DD-8。

---

## 4. P2 / 细节问题

| ID | 问题 | 位置 | 建议 |
|---|---|---|---|
| P2-1 | `CloseAll` 无视 `refs>0` 强关树，且没有设计 §8.1.2 #6 的泄漏诊断/延迟关闭；`p.parser` 被 Close 后二次 `CloseAll` 可能 double-close | `parser.go:195-225` | 加 `closing` 标志；refs>0 时记录 `file+refs` 并延迟到 Release 归零再关；CloseAll 幂等 |
| P2-2 | `SetMaxCachedTrees` 不校验负数；`0` 与 `-1` 都表示无界 | `parser.go:102-106` | `<0` 报错；`0` 明确为“无界（legacy）”并在启动日志标注 |
| P2-3 | RepoIndex 注释称“不可变”，但 `Functions()/Files()/FuncsByFile()` 返回内部 slice；调用方一旦 `sort` 就污染共享快照 | `repo_index.go:57-77` | 返回拷贝，或文档+测试约束“只读”；至少给 `FuncsByFile` 的调用方加只读约定 |
| P2-4 | `forEachFile` 的 fallback 路径把 `GetFileByID` 的错误静默成 `nil`（旧版会 Warn） | `evidence/detector.go:73-76`、`graph/helpers.go:52-56` | 保留 Warn，避免“文件消失”无 trace |
| P2-5 | `config.go` 注释里的示例默认值（28000/20000）与实际默认 0 不一致；且只给 high 的示例会触发 P1-3 的卡死 | `config.go:186-195` | 注释写“0=disabled”，示例同时给 low；加载时校验 |
| P2-6 | `scan_incomplete_tasks.reason` 无 CHECK/枚举，测试里已出现 `panic/oom` 等设计外值 | `schema.go:234-246`、`crud_scan_runs.go:115` | 定义枚举常量 + 写入校验 |
| P2-7 | `secguard schema` 的 `agentSchemaTables` 是手写副本，新增列/表靠人工同步；本次已手工加对，但无一致性测试 | `cli/schema.go:29-120` | 加一个测试：`agentSchemaTables` ⊆ `PRAGMA table_info`，索引一致 |
| P2-8 | mockStore 的 `InsertGraphEdgeBatch` 保存 `&edges[i]` 指针，而 `edgeBatchWriter` flush 后会 `edges[:0]` 复用底层数组 → mock 里的边会被后续写入覆盖 | `planner/mockstore_test.go:253-262` | mock 里 copy 一份；或 `append` 值而非指针 |
| P2-9 | `GetOrBuildWithTree` 命中 nil-tree 条目无法“升级”为持 tree；先由 `free_summary` 建的条目永远不 pin | `cfg_cache.go:191-196` | 命中时若 `e.tree==nil && tree!=nil`，补 `Acquire` 并赋值 |
| P2-10 | 单条 CFG 超过 `MaxTotalCFGNodes` 时：插入后立刻被淘汰，返回的 CFG 已无 tree 引用（且 `GetOrBuild` 返回的裸指针仍被调用方使用） | `cfg_cache.go:83-118` | 超预算的单条不应缓存且应保持 tree 借用到调用方释放；或直接走“不缓存 + 同步借用”路径 |
| P2-11 | `eventBatch` 是包级全局，`batchMode` 是全局原子；同进程内并发扫描会互相污染 | `detector.go:299-318` | 长期改为 per-run 对象；至少加注释/断言 |
| P2-12 | `secguard plan` 独立命令（`cli/plan.go:49`）不设 `MaxCachedTrees`/CFG 上限，配置项只对 `scan` 生效 | `cli/plan.go` | 若这些是全局安全预算，应在 `plan`/`query` 同样生效 |

---

## 5. 设计问题（不是实现偏差，是设计本身需要修订）

> 这一节按“设计文档需要改”的口径写；即使实现完全照做，下列问题仍会存在。

### DD-1（P0）§8.2.2 的 bypass 路径在并发下不安全，且“用完 Close”在 `ParseCached` 层不可实现

设计原文让 bypass “回退到现有的非缓存 `parser.Parse` 路径（设计引用 `parser/parser.go:66-69`；当前文件为 `112-115`，indexer 已在用）”。但 `parser.Parse` 使用**共享的 `p.parser`**，其自身注释明确写着 “only safe for sequential callers that finish using (and Close) the returned tree before the next Parse on this parser”（`parser.go:108-111`）。detector 是 8 并发调用，直接走 `parser.Parse` 是数据竞争/树损坏。

更根本的是：`ParseCached` 无法知道调用方何时“用完”返回的 Node；如果它在返回前就 `Close`，调用方立刻 UAF；如果等调用方 Close，就必须把 lease 交给调用方。**设计需要明确：bypass 返回一个 `TreeLease`（含独立 parser），由调用方在同步作用域结束 `Release`；或者干脆不提供“缓存满时 bypass”，改为阻塞/降级。** 实现的 transient 列表正是这个设计缺口的产物。

### DD-2（P0）“任何 `parser.Node` 不得逃逸 TreeHandle 生命周期”没有可强制 API

§8.2.2 说“API 层面用「Node 只经由 TreeHandle 的 borrow 返回」来强制，而不是靠注释提醒调用者”，但设计里 `TreeHandle.RootNode()` 仍返回裸 `parser.Node`，没有借用 token、没有 region 类型、没有生命周期检查。Go 没有生命周期类型，唯一可行的强制是：`TreeLease.WithNodes(func(nodes))` 只在 lease 有效期内回调，且不把 Node 暴露到回调外；或者把 Node 改成纯 Go 快照（设计已列为“后续可选”，但那是唯一能真正强制的路径）。当前设计属于“写了不变式，但没有强制手段”。

### DD-3（P1）`Acquire` 的 `bool` 返回值语义自相矛盾

§8.1.1 签名 `Acquire(...) (*CFGLease, bool)`；§8.1.2 第 2 点说预算满时“不淘汰、不拒绝”，§8.2.2 说 bypass “不等待、不拒绝、不阻塞”；但 §8.1.2 #7 的迁移示例又写 `if !ok { /* 预算耗尽 */ }`。到底 `ok=false` 表示什么？设计必须二选一：要么 `Acquire` 永不拒绝（去掉 bool），要么定义“预算耗尽时返回 false 且调用方走 incomplete 降级”。实现选择了“没有 Acquire”，把矛盾留给了未来。

### DD-4（P1）“消费点都在同步作用域，所以不需要异步持有”是错误论据

§8.1.2 #7 原文：“现有消费点全部在同步函数作用域内使用 `*StmtCFG`（无跨 goroutine 持引用），故 lease 模式可直接套用，无异步持有改造。” 这句话混淆了“同一 goroutine 内同步使用”与“缓存被多 goroutine 共享”：goroutine A 同步持有 `*StmtCFG` 时，goroutine B 完全可以淘汰该 entry 并 `Release` 树。**lease 恰恰是为了这个场景**。设计应删掉这个论据，并明确“共享 cache 的任意条目在返回给调用方期间都必须有 lease”。

### DD-5（P1）总驻留不等式与 `fileParseCache` 的跨调用 pin 自相矛盾

§8.2.1 写 `activeTreeHandles ≤ maxCachedTrees + 并发度`，但 §8.2.2 又允许 `fileParseCache` 跨调用持有 `TreeHandle`（设计还专门说“它也必须持 TreeHandle 引用，与 CFG 条目并列计入 pinnedTrees”）。这些 pinned 树不在 `maxCachedTrees` 里，也不受“并发度”约束；只要 planner 读过的文件多，`activeTreeHandles` 就可以远大于该上界。设计要么给 pinned 树单独预算（例如 `maxPinnedTrees`），要么禁止跨调用 pin（每次借用结束即释放）。

### DD-6（P1）图边批写“保持现状语义”不成立

§2.3c 说“批量化保持现状语义（每扫描一次 + ClearGraph 兜底）”“`WithImmediateTx` 已保证批内原子回滚”。但旧语义是**逐边 best-effort**：一条边失败，其余边仍写入；批量化后一条边失败，整批（最多 500 条）回滚。这不是“保持语义”，而是把“单边丢失”放大成“批量丢失”。设计需要明确：批失败时是否逐边重试、是否接受整批丢失、是否把失败计入 incomplete。

### DD-7（P1）`incomplete` 的 “timeout” 没有来源，成本准入没有落到阶段

§8.3.1/§8.3.3 把 `timeout` 列为 reason，并要求“准入前预估任务成本（LOC/CFG 节点/AST 估算）→ 先降并发到 1 → 仍超 → incomplete”。但设计没有定义：哪个阶段设 deadline（per function？per type？per phase？）、由谁执行 `ctx.WithTimeout`、LOC 超多少算“超预算”、`scale` 字段单位是什么。实现因此只建表不写入。**设计需要给出可执行的准入算法与阈值来源**，否则“绝不静默跳过”无法验收。

### DD-8（P1）启动清理没有 scan 所有权模型

§8.3.2 要求“扫描启动时检查上一次遗留的 running 记录，将其置 failed”。在单进程单扫描下没问题；但本项目支持多 agent/多进程共享 DB（`report --write-json` 并发写是既有场景）。全局 `running → failed` 会误杀另一个正在跑的扫描。需要：scan owner（PID/agent id）、心跳/租约、或只清理“创建时间早于本次启动且 owner 已死”的行。

### DD-9（P1）生命周期缺“启动即建 running 行”的显式步骤

§8.3.2 只规定了“默认值 running”和“终态”，没有规定**何时插入行**。实现因此在扫描末尾才 `Upsert`，导致：
- 进程被 OOM kill → DB 里没有行（不是 running，也不是 failed）；
- “默认 running”只覆盖“Upsert 之后到 defer 之前”的毫秒级窗口。
设计应把“step 0: 创建 running 行”写成强制步骤，并明确“任何提前 return 都必须能更新到该行”。

### DD-10（P1）singleflight 的 panic/ctx 取消状态未定义

§8.4 风险说“builder 协程 panic/退出时等待者会永久阻塞——必须 `defer close(done)` 并约定「构建失败也提交一个空/错误 entry」唤醒等待者”。但“空 entry”与现有 `GetOrBuild` 的“builder 返回 nil 不缓存”（`cfg_cache.go:70-72`）冲突：如果 panic 后提交一个 nil cfg 的 live entry，后续所有 Acquire 会拿到 nil 并被缓存，永久毒化。设计需要第三种状态（`failed`）或“删除占位 + 广播 + 让等待者重试”，并覆盖 `ctx` 取消（不只是 panic）。

### DD-11（P2）`maxTotalCFGNodes` 是事后淘汰，挡不住单函数构建瞬时峰值

§8.2.2 用 `len(cfg.Nodes)` 作预算，但 `BuildStmtCFG` 先构建、后插入；巨型函数在构建期间同时占用 AST + 完整 CFG，预算来不及淘汰。设计说“让最坏驻留不再由单个巨型函数决定”，但实际只在“构建完之后”生效。需要准入前预估（DD-7）或语句级分段，否则该结论不成立。

### DD-12（P2）默认值全部 TBD，实现自然选了“全关”

§7/§8.4 把 `maxCachedTrees`/`MaxEntries`/`maxTotalCFGNodes`/内存高水位都留作“待确认”。实现选择 0/false，等于“功能默认不存在”。设计应给出安全默认值（或“默认开启 + 自动推导”）与升级策略，否则“OOM 修复”无法在默认部署上验收。

### DD-13（P2）SQLite page cache / WAL 计入 RSS，但设计没有预算

第二轮审查 P0-2 已指出“SQLite DSN 未设 `cache_size`/`mmap_size`，WAL 与 page cache 也计入 RSS/cgroup”，但 §2.3/§8.2 没有对应措施，实现也未动 DSN（`db/connection.go:31` 只有 busy_timeout/foreign_keys/WAL/synchronous）。在大仓上，page cache 可能占据 cgroup `memory.current` 的很大一部分，导致 high watermark 误判。设计需要把 SQLite 缓存纳入预算（`PRAGMA cache_size`/`mmap_size`）或明确排除并解释。

### DD-14（P2）§8.2.2 的 “activeTreeHandles ≤ …” 是观察项，不是不变式

该不等式依赖“瞬态树受并发度约束、生命周期短”，但实现里瞬态树进入全局列表、生命周期到 `CloseAll`，且 `fileParseCache` 可以跨调用 pin。设计把一个不可验证的观察写成“硬性不变式”，会给出虚假的安全感。建议要么删除该断言，要么把它变成代码级计数器 + 阶段断言（超过就 Panic/降级并写 incomplete）。

---

## 6. 建议的优化改进安排

> 原则：先“止血”（不崩、不谎报），再“闭环”（incomplete），最后“提效”（默认值/RepoIndex/测试）。每一步都可独立提交、独立回滚；不要在一个 PR 里同时改生命周期和默认值。

### 阶段 A（阻断，最高优先级，建议 1 个 PR）

**目标：任何配置下不再 SIGSEGV，且不把未验证的“有界缓存”暴露给用户。**

1. `SetMaxCachedTrees(n>0)` 在生命周期修好前拒绝/强制 0；scan 日志和 JSON 输出 “ast_cache_bound=disabled(experimental)”。
2. 实现 `ParseCached` 返回即持有借用（`p.mu` 内 ref++），`forEachFile`/`forEachIndexedFile`/`forEachFileIncludingEmpty`/`graph.forEachFile` 在回调前后 Acquire/Release；`fileParseCache` 所有调用点 `defer Close()`；`repofacts` 的二遍遍历改为流式或至少不长期 Acquire。
3. 实现 `CFGLease`（或最小 refs+lease）：LRU 只淘汰 `refs==0`；9 处 CFG 构建全部传 tree；`build()` 移出锁 + singleflight。
4. 迁移修复：历史行回填为 `complete`/`unknown`；`MarkStaleRunningAsFailed` 加 owner/时间条件。

**验收**：`max_cached_trees=1` 的 6 文件端到端扫描 exit 0；`go test -race` 覆盖“淘汰 vs 使用中”；旧库迁移后历史行不是 running/failed。

### 阶段 B（语义闭环，1 个 PR）

**目标：`completion_state` 可信，报告不谎报完成。**

1. scan 启动即建 running 行；`complete` 只在“无 detector/plan 错误、无 incomplete 任务”时写。
2. 所有降级点写 `scan_incomplete_tasks`（CFG 预算、AST bypass、event flush 失败、parse 失败、背压放弃）；reason 枚举化。
3. `report` 头 + `metricsView` + scan JSON 渲染 completion_state 与未完成清单。
4. `secguard schema` 的 note 改为“ledger for diagnosis”，去掉 resume 承诺。

**验收**：注入一个 plan panic / 一个 parse 失败，`completion_state=incomplete` 且报告头显示 N 项未完成；正常扫描仍 complete。

### 阶段 C（调度与可观测，1–2 个 PR）

1. 背压：`low>0 && low<high` 校验；ctx-aware 等待；真正降并发到 1；覆盖 detector 阶段；`detector_concurrency` 配置；从 `memory.max` 推导阈值。
2. 观测：phase 边界打印三层内存 + `len(cache)`/`len(transient)`/`pinnedTrees`/`cfg entries/nodes`/事件数；`estASTBytes` 校准值标注为估算。
3. 事件批/边批：默认安全值；flush 失败重试或写 incomplete；batch 失败逐边回退。

**验收**：`memory_pressure_enabled=true` + 小 high 值不再挂死；40K 档压测能给出预算内/降级结论。

### 阶段 D（性能与覆盖，1–2 个 PR）

1. RepoIndex 补齐 `funcsByName`/`fileScopeByFile`/`slotTargets`，迁移 P1-5 列表。
2. `repofacts` 流式化。
3. 测试矩阵：§8.1.4（7 项）、§8.2.4（3 项）、§8.3.4（4 项）、RepoIndex 等价性、edge/event batch 失败语义、迁移测试。
4. 更新 README/QUICKSTART/config 示例（新开关、默认值、experimental 标注）。

**验收**：默认配置 40K 扫描 peak 受预算约束；`go test ./...` + `-race` 全绿；设计条目逐条有测试对应。

### 最小可行修复顺序（如果时间只够做一件事）

> **先做阶段 A 的第 1 条（熔断）+ 第 3 条（CFG lease）**：这两条能同时消除“启用即崩”和“CFG 生命周期悬空”，并且不改变默认行为。`fileParseCache` 的 Close 与 RepoIndex 补全可以紧随其后。

---

## 7. 复现步骤（附录）

### 7.1 AST 淘汰 UAF（最小单测）

在 `sgre/internal/parser` 下临时加：

```go
func TestTmpEvictedTreeNodeUseAfterFree(t *testing.T) {
    p := NewParser(); defer p.CloseAll()
    p.SetMaxCachedTrees(1)
    t1, _ := p.ParseCached([]byte("int a(void){ return 1; }"), "a.c")
    root := t1.RootNode()
    _, _ = p.ParseCached([]byte("int b(void){ return 2; }"), "b.c")
    _ = root.Kind() // SIGSEGV
}
```

### 7.2 端到端（6 文件小仓）

```bash
cd sgre && go build -buildvcs=false -o /tmp/secguard ./cmd/secguard
D=/tmp/sgre-repro && rm -rf "$D" && mkdir -p "$D/.codeagent" "$D/src"
for i in 1 2 3 4 5 6; do
  printf '#include <stdlib.h>\n#include <string.h>\nstatic int h%d(char *p,int n){if(n>0){strcpy(p,"abc");}return n+%d;}\nint e%d(void){char *p=malloc(4);char b[8];if(!p)return -1;memcpy(b,p,16);return h%d(p,%d);}\n' $i $i $i $i $i > "$D/src/f$i.c"
done
printf '[scan]\nmax_cached_trees = 1\n' > "$D/.codeagent/secguard.toml"
/tmp/secguard scan "$D/src" --db "$D/.agent/sgre.db"; echo "exit=$?"
# 预期：SIGSEGV，栈 graph.forEachFile → SharedAccessBuilder.Build.func1 → parser.Node.FindAll
```

把 `max_cached_trees = 1` 删掉再跑同一仓，exit 0。

### 7.3 迁移回填

```bash
cp <db-with-complete-scan> /tmp/mig.db
sqlite3 /tmp/mig.db "ALTER TABLE scan_runs DROP COLUMN completion_state;"
/tmp/secguard metrics --db /tmp/mig.db >/dev/null      # 触发 InitSchema
sqlite3 /tmp/mig.db "SELECT scan_id, completion_state FROM scan_runs;"  # 历史行变 running
/tmp/secguard scan <src> --db /tmp/mig.db >/dev/null   # 下一次扫描启动
sqlite3 /tmp/mig.db "SELECT scan_id, completion_state FROM scan_runs;"  # 历史行变 failed
```

---

## 8. 问题索引（按修复优先级）

| ID | 级别 | 一句话 | 关键位置 |
|---|---|---|---|
| P0-1 | 阻断 | `max_cached_trees>0` AST 淘汰 UAF/SIGSEGV | `parser.go:133-190`；`graph/helpers.go:60-78`；`evidence/detector.go:96-104` |
| P0-2 | 阻断 | 无 CFGLease/refs/单飞，build 在锁内，9 处不传 tree | `graph/cfg_cache.go:56-118,185-211`；9 处 call site |
| P0-3 | 阻断 | bypass 退化为无界 transient，`Close` no-op | `parser.go:148-154,195-225,252-258` |
| P0-4 | 阻断 | `fileParseCache` 只 Acquire 不 Release + TOCTOU | `planner/null_flow.go:2732,2744-2751`；`repofacts.go:99,127` |
| P0-5 | 阻断 | incomplete 只建表，不写/不判/不渲染 | `cli/scan.go:166-178,595,623`；`crud_scan_runs.go:95-160` |
| P0-6 | 高 | 迁移把历史行回填 running→failed（已复现） | `db/schema.go:440`；`crud_scan_runs.go:103-113` |
| P1-1 | 高 | 新开关默认全关，OOM 未修 | `config/config.go:151-202` |
| P1-2 | 高 | CFG build 全局锁串行 | `graph/cfg_cache.go:60-68,189-197` |
| P1-3 | 高 | 背压 low=0 永久卡死 / 无 ctx / 覆盖不全 | `cli/mempressure.go:70-85`；`cli/pipeline.go:181-186,375-379` |
| P1-4 | 中 | 边批整批回滚丢边 + 计数虚高 | `graph/edge_batch.go:55-66`；`db/crud_graph.go:111-127` |
| P1-5 | 中 | RepoIndex 只覆盖一部分 | `graph/repo_index.go:16-24` + P1-5 清单 |
| P1-6 | 中 | repofacts 全量钉住 AST | `repofacts/repofacts.go:64-129` |
| P1-7 | 中 | event batch 默认关 + flush 失败静默丢 | `evidence/detector.go:320-336`；`config.go:196` |
| P1-8 | 中 | 无 pinned/lease/estAST 观测；completion 不渲染 | `parser.go:227-232`；`graph/cfg_cache.go:157-164` |
| P1-9 | 中 | 测试矩阵缺失（含能抓住 P0-1 的测试） | 见 §P1-9 |
| P1-10 | 中 | stale running 全局 sweep 无所有权 | `cli/scan.go:144`；`crud_scan_runs.go:103-113` |
| P2-1..12 | 低 | 细节/一致性/测试基础设施 | 见 §4 |
| DD-1..14 | — | 设计本身需修订 | 见 §5 |

---

## 9. 给 GLM5.2 / 后续实现者的 5 条硬约束

1. **`build()` 永不在缓存锁内执行**；共享 cache 的条目在返回给调用方期间必须有 lease。
2. **任何 `parser.Node` 的持有周期必须 ≤ 其 Tree 的借用周期**；Acquire 必须与 lookup 原子，不能“先返回再 Acquire”。
3. **transient 树必须可 Close，且不得进入 `fileParseCache`/`CFGCache`**；同一文件不得因 bypass 被重复解析。
4. **`complete` 只在“无错误、无 incomplete 任务”时显式写入**；任何失败/降级都要在 `scan_incomplete_tasks` 留痕，并在报告头渲染。
5. **默认值要么安全，要么显式标注“unbounded/experimental”**；不能让用户以为“默认已受预算约束”。

---

*报告结束。下一轮（Round 2）建议在阶段 A 的修复提交后，按 §8 的测试矩阵逐项复核，并补一次 10K/20K/40K 的 RSS/cgroup 实测。*

---

## 10. Round 2 实施记录（2026-11-04）

> 本轮按 §6 的阶段 A/B 优先实施，工作区改动未提交（便于逐项 review）。所有状态以本机 `go build ./...`、`go test ./...`、`go vet ./...`、`go test -race`（parser/graph/evidence/planner/db）与 59 文件压力扫描为准。

### 10.1 P0 状态

| ID | 状态 | 实现要点 | 验证 |
|---|---|---|---|
| P0-1 AST 淘汰 UAF | ✅ 已修 | `ParseCached` 返回即持有借用（`parser.go`），`forEachFile`/`forEachIndexedFile`/`forEachFileIncludingEmpty`/`graph.forEachFile` 在回调前后 Acquire/Release；所有直接调用点改用 `WithParseCached` 或显式 Release/所有权转移 | `max_cached_trees=1` 的 6 文件扫描 exit 0；59 文件 `max=5` 压力扫描 exit 0；不再 SIGSEGV |
| P0-2 CFG↔Tree 生命周期 | ✅ 已修（主路径） | 新增 `CFGCache.Acquire` + `CFGLease` + `refs`；build 在锁外、per-key 占位/`done` 单飞；LRU 只淘汰 `refs==0`；evidence choke point 持租约到使用结束；`BuildStmtCFGWithTree`/`GetOrBuildWithTree` 改为不缓存，避免创建无法租约的条目 | 新增 singleflight / 锁外构建 / refs 防淘汰测试；59 文件 + CFG 上限压力扫描通过 |
| P0-3 transient 无界 | ✅ 已修 | 缓存满且全被借用时返回 transient 借用，`Release` 归零即关闭树 + 专用 parser；删除 `transientTrees` 列表；`transientOrigins` 仅作泄漏诊断 | `TestParseCached_TransientClosesOnRelease` / `TransientNoAccumulation`；压力扫描 `transient=0` |
| P0-4 fileParseCache 泄漏/TOCTOU | ✅ 已修 | 26 处构造点全部 `defer Close()`（3 个结构体持有者加 `Close` 并接入调用方）；`prime` 不再二次 Acquire；`liveFileParseCaches` 诊断未 Close 的 cache | 59 文件扫描无 “fileParseCache(s) not closed”；无 “trees still borrowed” |
| P0-5 incomplete 闭环 | ✅ 已修（主路径） | 扫描启动 `BeginScanRun` 建 running 行；失败/超时用 `context.WithoutCancel` 写 failed；DetectorErrors/PlanErrors 写 `scan_incomplete_tasks` 并置 incomplete；report 头 / metrics / scan JSON 渲染 | 新增 `BeginScanRun`/stale 排除/迁移测试；`--timeout 1` 扫描落库 `failed`；report 不完整 warning 测试 |
| P0-6 迁移回填 | ✅ 已修 | `completion_state` 改为可空 + 回填 `complete`（不再 `DEFAULT running`）；`Get/List` 用 `COALESCE`；stale sweep 排除当前 scan_id | `TestStore_CompletionStateMigrationBackfillsComplete`；手工迁移验证历史行保持 complete |

### 10.2 P1 状态

| ID | 状态 | 说明 |
|---|---|---|
| P1-1 默认关闭 | ✅ 改安全默认 | `applyScanDefaults`：AST 4000、CFG 4000 / 400000 节点、event batch 2000；负值保留 legacy unbounded；`MaxCachedTrees<=0` 启动 warning |
| P1-2 全局锁构建 | ✅ 已修 | `Acquire` 用 building 占位 + `done` 单飞，`build()` 在 `c.mu` 外；panic 时删除占位并唤醒等待者 |
| P1-3 背压 | ⚠️ 部分 | `low<=0/>=high` 归一化到 75% high；`Wait(ctx)` 可取消；启动即采样；新增 `detector_concurrency` 与 detector throttle；**未实现“并发降到 1”的 sem 缩容与恢复渐升** |
| P1-4 边批语义 | ✅ 已修 | 批失败逐边重试；`InsertGraphEdgeBatch` 失败返回 0（不再虚报 inserted）；`flushed` 只计成功 |
| P1-5 RepoIndex | ⚠️ 部分 | 新增 `FuncsByName`；alias/call_graph/interproc/funcptr builders 改用快照；evidence 侧部分 detector 仍直接 `ListFunctions/ListFiles` |
| P1-6 repofacts 流式 | ✅ 已修 | 两遍逐文件：pass1 只收宏/路径，pass2 重新 ParseCached 后处理布局/全局数组，不保存 root |
| P1-7 event batch | ✅ 已修 | 默认 2000；flush 失败计数并转成 `DetectorError{event_batch}` → incomplete；日志 Error 级 |
| P1-8 观测 | ⚠️ 部分 | phase 边界打印 cached/transient/pinned/active + CFG stats；metrics 增加 completion_state；parser/fileParseCache 泄漏诊断；**`estASTBytes` 校准未实现** |
| P1-9 测试 | ⚠️ 部分 | 新增 parser 生命周期/CFG 租约/单飞/锁外/refs、DB begin+迁移+stale 排除、report 不完整、mempressure；**缺 10K/20K/40K 实测与“整扫描端到端”回归** |
| P1-10 stale 所有权 | ✅ 已修 | `MarkStaleRunningAsFailed(ctx, excludeScanID)`；但仍未引入 owner/PID，跨宿主并发扫描的极端场景仍需 owner 模型（DD-8） |

### 10.3 仍未完成 / 下一轮建议

1. **planner CFG 缓存性能回退（已修复）**：range/interval/int-overflow、null-deref/lifetime/double-free、taint、uninit（含 heapStructFlow）、contract-gap、race 全部改为 `CFGLease`/`Acquire` + 几何快照或函数内立即释放；51K 函数扫描从 415s 降到 156s。仍需清理 `planner/cfg_cache_ctx.go` 的死代码（无调用者）。
2. **背压降并发（已修复）**：新增 `internal/concurrency.Gate`，graph/detector/plan 三阶段改为可缩容准入：超过 high 后 inflight 上限变 1（不是暂停准入），降回 low 恢复；检测器延迟阶段同样过 gate；`memory_pressure_enabled=true` + 1MB high 的 6 文件端到端扫描 exit 0。
3. **RepoIndex 剩余调用点（已修复）**：`argument_type`/`interprocedural`/`race_condition`/`free_summary` 改用 `RepoIndex`；`fileScopeByFile` 与 func-ptr slot→targets 进入 `RepoIndexWithFacts`，alias/call_graph/interproc 共享快照（加载失败自动回退逐 stage 查询）；`secguard plan` 独立命令也继承 CFG 上限与 RepoIndex。
4. **`estASTBytes`/`pinnedTrees` 校准与更大规模实测**：本轮已做 1700 文件 / 1.02 万与 5.1 万函数的 RSS 实测（见 §10.5）；`estASTBytes` 校准、40K+ 重文件形态与 cgroup 观测仍未做。
5. **设计文档修订（部分）**：DD-13（SQLite page cache 预算）已通过 `sqlite_cache_mb` / `sqlite_mmap_mb` 落地并有 PRAGMA 测试；DD-2（Node 借用无强制 API）、DD-3（Acquire bool）、DD-7（timeout 来源）、DD-8（scan owner）、DD-10（singleflight 失败状态）仍需在设计中定稿。
6. **P2 细节（部分）**：`secguard plan` 已继承 CFG 上限与 RepoIndex；`GetOrBuild` 仍为 test-only 的旧 API，mockStore 的 `InsertGraphEdgeBatch` 指针复用、`agentSchemaTables` 一致性测试仍待补。

### 10.4 Round 2 验证命令

```bash
cd sgre
GOCACHE=$PWD/.tmpcache TMPDIR=$PWD/.tmpcache go build -buildvcs=false ./...
GOCACHE=$PWD/.tmpcache TMPDIR=$PWD/.tmpcache go test -buildvcs=false ./...
GOCACHE=$PWD/.tmpcache TMPDIR=$PWD/.tmpcache go vet -buildvcs=false ./...
GOCACHE=$PWD/.tmpcache TMPDIR=$PWD/.tmpcache go test -race -buildvcs=false \
  ./internal/parser/ ./internal/graph/ ./internal/evidence/ ./internal/planner/ ./internal/db/
```

压力扫描（59 文件，`max_cached_trees=5` + CFG 上限）exit 0，且 scan 日志无 `trees still borrowed` / `fileParseCache(s) not closed`。

---

## 10.5 Round 3：1700 文件规模实测（本轮补充）

> 针对“59 文件摸不到门槛”的反馈，用仓库自带 `testdata/perf/gen_codebase.go` 生成 1700 文件的两档合成仓，并用 `/usr/bin/time -l` 记录进程峰值 RSS。所有对比均单独 DB/输出目录串行执行，避免并发扫描互相污染。

### 10.5.1 结果

| 场景 | 文件 / 函数 | 配置 | 峰值 RSS | 墙钟 | 结果 |
|---|---|---|---|---|---|
| 1700 文件 / 1.02 万函数 | 1700 / 10,200 | 默认（AST 4000 / CFG 4000） | **536 MB** | 26.5s | complete，无泄漏 |
| 1700 文件 / 5.1 万函数 | 1700 / 51,000 | 默认 | **3.72 GB** | 156s | complete，无泄漏 |
| 5.1 万 + 仅 AST 上限 | 1700 / 51,000 | `max_cached_trees=200` | 4.22 GB | 463s | complete；峰值**未降反升** |
| 5.1 万 + AST/CFG 双上限 | 1700 / 51,000 | AST 200 + CFG 500 + event 500 | 4.29 GB | 392s | complete；缓存条目被压到 500/200，但峰值仍不降 |
| 5.1 万 + Go 内存预算 | 1700 / 51,000 | `GOGC=50 GOMEMLIMIT=6GiB`（flow lease 前对照） | **3.35 GB** | 158s | complete，候选数不变 |

> 注：第一行是更接近现网文件数/函数数的档位；第三/四行是旧二进制上做的“只压缓存”对照，用于说明缓存上限不是 51K 档的峰值来源；第五行是最终代码 + Go 运行时预算。

### 10.5.2 关键结论

1. **1700 文件本身不是 OOM 的充分条件**：1.02 万函数档只有 ~544MB；34GB 更可能来自“单文件/单函数 AST 很重”或 Go heap（候选/事件/检测器临时结构），而不是文件数本身。
2. **只压 `max_cached_trees` 会适得其反**：CFG 条目持有 AST 引用，parser 淘汰不动被 CFG 钉住的树；把 AST 缓存压到 200 只增加重解析，峰值从 3.72GB 升到 4.22GB、耗时 463s。
3. **组合压 AST+CFG 也不能决定峰值**：条目最终被压到 500/200，但 51K 档峰值仍是 4.29GB——此时峰值已由 Go heap/分配率决定，而不是缓存条目。
4. **Go 运行时预算有效但有限**：`GOGC=50 + GOMEMLIMIT=6GiB` 把峰值从 3.72GB 降到 3.35GB（约 -10%），耗时 +7%；对 34GB 现网，`GOMEMLIMIT` 应设为 cgroup 上限减去 SQLite/页缓存/瞬时尖峰后的值（例如 34GB cgroup → 24–28GB），并配合 `GOGC=50`。
5. **`free_summary` 是 51K 档的一个真实峰值源（已修）**：旧实现在第二遍 fixpoint 前持有每个函数一个 CFG lease；实测 `cfg_cache_max_entries=500` 时日志仍是 `entries=10200`（预算被 refs>0 击穿）。本轮改为“phase 1 只算直接事实、phase 2 逐文件重解析并在函数级释放 lease”，51K 默认扫描从 415s 降到 156s、候选数保持 34,000 不变。
6. **planner CFG 缓存已全面恢复**：range/interval/int-overflow + null-deref/lifetime/double-free/taint/uninit 的 `flowResult` 用 `CFGLease` + 几何快照（`spans/startLines`，不再持有 cfg/AST），`heapStructFlow` 同样快照化，contract-gap/race 检测器用 `Acquire`+立即释放；是 415s→156s 的主要来源之一。

### 10.5.3 新增配置（针对现网 OOM）

```toml
[scan]
# Go heap 软上限（MB）：建议 cgroup 上限 - SQLite/页缓存/瞬时尖峰余量
go_mem_limit_mb = 24000
# 更积极的 GC（CPU 换峰值）
go_gc_percent = 50
# AST / CFG 预算：先按实测调，不要只压其中一个
max_cached_trees = 1000
cfg_cache_max_entries = 1000
cfg_cache_max_total_nodes = 200000
```

> 注意：`go_mem_limit_mb` 是 Go 运行时软上限，不限制 tree-sitter/SQLite 的 C 内存；`max_cached_trees`/CFG 预算才限制 C AST/CFG。现网 34GB 建议先用 `GODEBUG=gctrace=1` + `secguard metrics` 判断峰值是 Go heap 还是 C 内存，再分别调这两组旋钮。

### 10.5.4 仍未复现 34GB 的原因

合成生成器的函数只有约 6 行，1700 文件 × 5.1 万函数仅 33 万 LOC；现网 1500–1700 文件若总 LOC 在 1.5M–4M，按本轮 8–11KB/LOC 的实测比例，确实可能到 12–34GB。**要精确复现，需要用一份脱敏的真实仓（或按真实文件平均 LOC/宏/结构体密度生成的“重文件”fixture）**；仅靠文件数无法判定。

### 10.5.5 给现网 1500–1700 文件仓库的建议配置

> 前提：先用 `GODEBUG=gctrace=1` + `secguard metrics` 跑一次，确认峰值是 Go heap 还是 C（AST/CFG/SQLite）；下面的值只是保守起点。

```toml
[scan]
# Go heap 软上限：cgroup 上限的 ~70%，给 SQLite/tree-sitter/瞬时尖峰留余量
go_mem_limit_mb = 24000
# 更低 GC 阈值，CPU 换峰值；先 50，观察 scan 墙钟
go_gc_percent = 50

# C AST / CFG 预算：1700 文件不要用 4000 让所有文件都常驻；
# 1000 左右让 AST 可淘汰，代价是重解析（默认 4000 在 1700 文件时等于不设上限）
max_cached_trees = 1000
cfg_cache_max_entries = 1000
cfg_cache_max_total_nodes = 200000

# 可选：cgroup/RSS 回压（阈值按 cgroup 上限设置）
memory_pressure_enabled = true
memory_high_watermark_mb = 26000
memory_low_watermark_mb = 20000
```

补充注意：

- `go_mem_limit_mb` 只约束 Go heap，**不约束 tree-sitter C 内存、SQLite page cache/WAL**；后者计入 cgroup，已提供 `sqlite_cache_mb`/`sqlite_mmap_mb` 显式预算（DD-13），但不会自动从 `go_mem_limit_mb` 推导。
- `max_cached_trees` 与 `cfg_cache_max_entries` 必须一起调：CFG 条目持有 AST 引用，只压 AST 会被 CFG 钉住（见 §10.5.2 第 2 条）。
- `max_cached_trees=1000` 在 1700 文件仓会导致重解析，墙钟可能上升；如果实测 Go heap 是主因，优先用 `go_mem_limit_mb`/`go_gc_percent`，不要把 AST 压得过低。
- 需要一份脱敏的现网样本（或按真实平均 LOC/宏/结构体密度生成的“重文件”fixture）才能复现 34GB；本轮 1700 文件合成仓只有 536MB（1.02 万函数）/3.72GB（5.1 万函数），不足以证明 34GB 已被解决。
