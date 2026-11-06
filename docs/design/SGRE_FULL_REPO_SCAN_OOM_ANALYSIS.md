# SGRE 万级函数仓库全仓扫描 OOM 根因分析与架构评估报告（Phase 0/1）

> 交付阶段：本报告只完成 Issue 指定的 **Phase 0（仓库现状摸底）** 与 **Phase 1（复现与内存根因分析的静态部分）**。
> 未修改任何生产代码；未进入 Phase 2/3 的架构重构。
>
> 证据等级声明：本机 checkout 只有 `secguard-clang` 自身源码，**没有** 1,745 文件 / 10,627 函数的基准仓库、没有 34 GB cgroup、没有现场 profile。
> 因此本文所有“根因”均为**源码静态分析得出的假设**，证据等级标注为「强怀疑 / 待验证」，而不是「已证实」。
> 已证实的部分仅限：**当前代码中确实存在**的无界缓存、全量常驻结构、无内存感知的并发等**可被源码直接证明的结构性问题**。
> 复现与 profile 采集所需的操作者侧步骤见第 6 节。

---

## 1. 当前真实扫描执行链路

入口 `cmd/secguard/main.go` → `internal/cli/root.go` → `internal/cli/scan.go`，
全量扫描的核心是 `internal/cli/pipeline.go` 的 `runPipeline`（第 67 行起），链路固定为：

```
parser.NewParser()                      // 共享解析器 p（pipeline.go:76）
  └ indexer.Index()                     // 逐文件解析→按文件事务写 Layer-1 facts（pipeline.go:81-94）
      └ indexer.indexFile(): os.ReadFile → parser.Parse(非缓存) → defer tree.Close()（indexer.go:110-252）
  └ store.ClearGraph()                  // 清空上一轮 graph_nodes/graph_edges（pipeline.go:98）
  └ graph.NewFuncPtrWriteBuilder.Build() // 顺序、可选（indirect_call_resolution 开关，pipeline.go:109-113）
  └ 7 个 graph builder【并行、无并发上限】(pipeline.go:115-173)
      call_graph / data_flow / alias / ownership / interproc / lock_order / shared_access
  └ store.ClearSecurityEvents()          // pipeline.go:177
  └ sharedCFGCache := graph.NewCFGCache() // 全函数 CFG 缓存，detector+plan 共享（pipeline.go:185）
  └ graph.BuildInterproceduralAlias() → ctx 注入全仓 AliasGraph（pipeline.go:190-195）
  └ evidence.RunAllDetectorsWithSkip()   // 38 个 detector，8 路并发（pipeline.go:217；registry.go:116）
  └ planner.EnsureFunctionSummaries()    // 每个函数回填一行 function_summary（pipeline.go:234）
  └ planner.Plan(vulnType)               // 29 个漏洞类型，8 路并发（pipeline.go:257-360）
  └ report 渲染（SARIF/markdown，在 scan.go 中，不在 runPipeline 内）
```

关键时序事实（都已从源码核实）：

1. **index 阶段是流式的、内存友好的**：`indexFile` 逐文件 `os.ReadFile` → `Parse`（`parser.Parse`，非 `ParseCached`）→ `defer tree.Close()` → 单文件事务写库。每棵解析树用后即释放，不进入共享缓存（`indexer.go:134-138`、`parser.go:66-69`）。**index 阶段本身不是 OOM 的主嫌**。
2. **graph 阶段是并行 + 全量重读**：7 个 builder 各起一个 goroutine（`pipeline.go:149-165`），没有信号量/并发上限；每个 builder 内部各自 `store.ListFunctions()`（全量函数表）+ `forEachFile`（逐文件 `os.ReadFile` + `ParseCached`）（`call_graph.go:33-66`、`graph/helpers.go:27-73`）。`ParseCached` 命中同一个共享 `p.cache`，所以 AST 只建一次，但 **7 个 builder 同时遍历全仓**、各自持有全量 `funcMap`/`byFile`/`slotTargets` 及每个文件的 `FindAll` 中间切片。
3. **detector 阶段**：38 个 detector 8 路并发（`registry.go:116` `maxConcurrent=8`），事件写入一个**共享无上限缓冲** `eventBatch.events`，只在独立 detector 全部跑完后、以及 interprocedural 跑完后各 flush 一次（`registry.go:165/176`）。
4. **plan 阶段**：29 个漏洞类型 8 路并发（`pipeline.go:324` `planConcurrency=8`），每个 `Plan` 各自 `ListEventsByType`（全量 seed 事件）+ `ListFiles`（全量文件）+（必要时）`ListFunctions`，构造大号 `Candidate` 切片并跑 filter 链（`planner.go:126-301`、`planner.go:455-699`）。

---

## 2. 关键数据结构和对象生命周期

| 结构 | 类型/源码位置 | 作用域 | 释放时机 | 是否全仓常驻 |
|---|---|---|---|---|
| `parser.Parser.cache` | `map[string]*Tree`，`parser/parser.go:40` | 整个 scan | 仅 `CloseAll()`（pipeline 结束时） | **是**：全文件 AST + 源码 |
| `parser.Parser.parsers` | `map[string]*sitter.Parser`，`parser/parser.go:41` | 整个 scan | 仅 `CloseAll()` | **是**：每个缓存文件一个专用 parser |
| `Tree.src` | `[]byte`，`parser/parser.go:44-48` | 整个 scan | 仅 `CloseAll()` | **是**：全文件源码字节 |
| `graph.CFGCache.byFn` | `map[int64]*StmtCFG`，`graph/cfg_cache.go:17-22` | detector+plan | 从不显式清理，随 GC | **是**：全函数语句 CFG |
| `graph.AliasGraph` | `edges`/`edgeKinds` map，`graph/alias_graph.go:57-66` | detector+plan | 随 ctx 结束 | **是**：全仓别名图 |
| `eventBatch.events` | `[]db.BatchEvent`，`evidence/detector.go:268-273` | detector 阶段 | 仅 flush 两次 | 阶段内无上限累积 |
| indexer 单文件 `Tree` | `indexer.go:134-138` | 单文件 | `defer tree.Close()` | 否（**正确模式**） |
| 各 builder 的 `funcMap`/`byFile`/`slotTargets`/`paramsByFunc` | `call_graph.go:42-64`、`interproc.go:43-68` 等 | 单 builder 生命周期 | builder 返回后 | 阶段内全量副本 |
| `repofacts.Facts` + 内部 `trees` 切片 | `repofacts/repofacts.go:46-84` | 每次 `Build` 调用 | `Build` 返回后 | 调用期间全仓根节点引用 |
| `planner.macroIndex`（`symbols.MacroIndex`） | `planner.go:49` + `symbols/macros.go:45-48` | plan 阶段 | `sync.Once` 建一次 | **是**：项目 #define 全量索引（有 50000 上限） |
| `planner.taintCache`/`callReachCache` | `planner.go:25-28` | plan 阶段 | 随 Planner 结束 | 共享摘要（跨类型） |

**已证实的结构性结论**（源码可直接证明，非推测）：

- `ParseCached` **无容量上限、无淘汰**：`p.cache[filename] = t` 后只在 `CloseAll()` 释放（`parser/parser.go:82-118`）。因此全仓每一份被 graph/detector/planner 触碰过的文件的 **tree-sitter AST + 源码字节 + 专用 parser** 在整个 scan 期间全部同时驻留。
- `CFGCache.byFn` **无容量上限**：`GetOrBuild` 只增不删（`cfg_cache.go:32-58`），10,627 个函数的语句级 CFG 在 detector+plan 全程驻留。
- 并发（7 builder / 8 detector / 8 plan）**全部是硬编码常量，无配置、无内存感知背压**（`pipeline.go:149-165,324`、`registry.go:116`；`config.go` 无任何 concurrency/memory 开关）。
- `eventBatch.events` **无上限**：flush 前整个 detector 阶段的事件全部积压在内存（`detector.go:216-238,268-291`）。

---

## 3. 现有内存观测能力与缺口

**现状**：全仓 `grep`（`pprof`、`runtime.MemStats`、`ReadMemStats`、`SetMemoryLimit`、`SetGCPercent`、`GOGC`、`GOMEMLIMIT`）**零命中**。当前唯一的观测是：

1. 阶段级 wall-clock 计时日志：`logger.Info("phase timing", ...)`（`pipeline.go:94/175/224/315/350`）与 detector 计时（`registry.go:157`）。
2. 计数类指标落库：`scan_runs` / `scan_stats`（文件数、函数数、候选数、耗时、收敛率），见 `internal/cli/metrics.go` / `internal/db/crud_scan_runs.go`。**只记录耗时与数量，不记录内存。**
3. SQLite 侧：WAL、`synchronous=NORMAL`、`busy_timeout(10000)`、`foreign_keys(1)`、`db.SetMaxOpenConns(4)`（`db/connection.go:31-37`）。**没有** `cache_size` / `mmap_size` / `temp_store` 显式设置。

**缺口**（对应 Issue P0 的表）：

| Issue P0 要求的指标 | 现状 |
|---|---|
| 阶段级 RSS / cgroup memory.current / memory.peak | ❌ 完全缺失 |
| Go heap alloc / inuse / objects / GC 次数 | ❌ 完全缺失 |
| pprof heap / alloc / cpu / goroutine profile | ❌ 完全缺失 |
| goroutine 数 | ❌ 缺失 |
| 每阶段节点数/边数/Facts 数/候选数的**内存换算** | ⚠️ 只落库计数，不换算内存 |
| 各 detector 临时状态规模 | ❌ 缺失 |
| SQLite 缓冲区/事务耗时 | ⚠️ 只有事件批量 flush，无缓冲量级观测 |
| Go heap 与 RSS 的差异（mmap/CGO/子进程） | ❌ 缺失 |

**必须重点补齐的一条**：tree-sitter 的解析树是 **C 分配的堆外内存**（`sitter.Tree` 包装 C 对象），它计入进程 RSS / cgroup，但**不计入 Go heap profile**。这正是 Issue 反复强调“退出码 137 不能直接证明 Go heap 泄漏”的原因——若只抓 Go heap profile，会系统性低估 `parser.cache` 里 AST 的真实内存。

---

## 4. OOM 根因假设及证据等级

按 Issue 第 3 节的 8 类逐一给出。等级：**已证实**（源码结构可直接证明）/**强怀疑**（源码结构指向 + 需 profile 定量）/**待验证**（需运行数据）。

| # | 假设 | 证据等级 | 源码依据 |
|---|---|---|---|
| H1 | 全文件 tree-sitter AST + 源码 + 专用 parser 全程常驻（`parser.cache`） | **强怀疑**（结构已证实，量级待测） | `parser/parser.go:40-48,82-118`；graph/detector/planner 全走 `ParseCached` |
| H2 | 全函数语句 CFG 全程常驻（`CFGCache.byFn`） | **强怀疑** | `graph/cfg_cache.go:17-58`；`pipeline.go:185` 注入共享 |
| H3 | 7 builder + 8 detector + 8 plan 无上限并发导致峰值叠加 | **强怀疑** | `pipeline.go:149-165,324`、`registry.go:116`；常量硬编码 |
| H4 | 全量 `ListFunctions`/`ListFiles` 被数十次重复加载 + 各自复制 map | **已证实**（重复性） | `ListFunctions` 定义 `db/crud_functions.go:62`；7 builder、大量 detector（`forEachFile`）、29 plan 各自全量重读 |
| H5 | `eventBatch.events` 阶段内无上限累积（全部 Layer-3 事件驻内存） | **待验证**（取决于事件总量） | `evidence/detector.go:268-291` |
| H6 | 全仓 `AliasGraph` + `repofacts` 全仓 `trees` 切片重复构建 | **强怀疑** | `graph/alias_builder.go:21-109`、`repofacts/repofacts.go:64-116` |
| H7 | 图算法非线性（`ReachableFromEntries` 递归 CTE、taint fixpoint、null-flow 状态） | **待验证** | `db/crud_graph.go:163-190`、`planner/filter_taint_source.go`、`planner/filter_nullable_source.go` |
| H8 | 非 Go heap：tree-sitter C 分配、SQLite 页缓存/WAL、GC 滞后 | **待验证** | `parser/parser.go`（C 树）、`db/connection.go`（无 cache_size 上限） |

> 关于“Go GC 不及时”：Issue 明确不接受“可能是 GC 不及时”作为无 profile 支撑的结论。
> 本报告同样不把它列为独立根因；它只在 H1/H2/H3 的真实保留量被 profile 证实后，作为“为什么 RSS 峰值远高于 heap inuse”的解释之一（与 H8 的非 Go heap 并列），而不是第一性原因。

---

## 5. 最可能的前三个内存热点及源码依据

> 排序依据是“源码可证明的、随仓库规模线性/超线性增长、且在整个 scan 生命周期驻留”的权重大小。
> 定量占比必须由第 6 节的 profile 确认后才可宣称为已证实。

### 热点 1：`parser.Parser.ParseCached` 的全文件 AST + 源码常驻缓存

- 位置：`internal/parser/parser.go:82-95`（写入）、`100-118`（唯一释放点 `CloseAll`）。
- 机制：每个文件首次被 graph/detector/planner 解析即写入 `p.cache[filename]`，**永不淘汰**；每个缓存文件还保留一个专用 `sitter.Parser`（`parsers` map，第 41 行）与一份 `src []byte`（`Tree.src`，第 44-48 行）。
- 规模推演：1,745 个源文件 + `repofacts` 还会把工作区内**所有未索引的 .h**也 `ParseCached` 进来（`repofacts.go:100-116`）。tree-sitter C 语法树的驻留内存通常是源码字节数的数倍（C 分配，非 Go heap），加上源码字节与每文件一个 parser，全仓驻留可达数百 MB～GB 量级。
- 为何是首嫌：这是唯一一个**把“全仓解析对象”整体、无上限、全程**留在内存的结构；与 Issue 描述“图构建/检测阶段 OOM”的阶段完全吻合（`ParseCached` 从 graph 阶段开始填充，检测阶段继续增长）。

### 热点 2：`graph.CFGCache` 全函数语句 CFG 常驻

- 位置：`internal/graph/cfg_cache.go:17-58`；注入点 `pipeline.go:185`、`planner.go:135`、`registry.go:79`。
- 机制：`byFn map[int64]*StmtCFG` 以函数 ID 为键，`GetOrBuild` 只增不减；`StmtCFG` 每个 `StmtNode` 带 `Succs/TrueSuccs/FalseSuccs` 三个 `[]int` 及一个 `parser.Node`（`control_flow.go:41-51`）。10,627 个函数的 CFG 在 detector+plan 全程驻留。
- 这是“按需构建”方向最明确的改造点：CFG 是**可重建的中间数据**（`BuildStmtCFG(body, funcEnd)` 确定性），不应无条件全量常驻；应改成 LRU/按活跃分析单元淘汰，或 detector 用完即释放。

### 热点 3：无上限并发 + 全量 `ListFunctions` 重复加载叠加峰值

- 位置：`pipeline.go:149-165`（7 builder 无信号量并行）、`registry.go:116`（8 detector 并行）、`pipeline.go:324`（8 plan 并行）；`db/crud_functions.go:62`（`ListFunctions` 全量扫描）。
- 机制：三个阶段的并发度都是**硬编码常量、只按 CPU 核数/固定值、不感知内存压力**。每个并发单元都会 `ListFunctions()`（或 `ListFiles()`）拉全量行、构造各自的 `map`（`funcMap`/`byFile`/`paramsByFunc`），graph 阶段 7 个 builder 还同时 `ParseCached` 全仓 + 逐文件 `FindAll`。大量文件遍历型 detector 各调一次 `forEachFile`→`ListFunctions`，29 个 `Plan` 又各调 `ListEventsByType`+`ListFiles`。
- 后果：单任务可控，但并发总峰值 = 并发数 × 单任务全量副本，且存在大量重复 I/O 与 GC 压力。

**热点 4-6（次优先，待定量）**：`eventBatch.events`（H5）、全仓 `AliasGraph` 与 `repofacts` 的 `trees` 切片（H6）、`ReachableFromEntries` 的递归 CTE 与 taint/null-flow fixpoint（H7）。

---

## 6. 需要补充的 profile、日志或复现步骤

在进入 Phase 2 设计前，必须先把上述“强怀疑”变成“已证实”。建议按此顺序在**有基准仓库 + 34 GB cgroup 的环境**执行：

1. **复现基线**（与分区扫描对照）：
   - 在 34 GB cgroup 内跑一次全仓 `secguard scan <repo>`，记录退出码、`dmesg` 的 OOM kill 记录、`cgroup memory.peak` / `memory.current`。
   - 对照组：23 子目录各自扫描，记录同样的曲线（Issue 7.3 要求的结果差异分析也需要这份对照）。

2. **进程级内存采样**（区分 Go heap 与 RSS）：
   ```bash
   # 每 1s 采样 cgroup 与进程 RSS（RSS 才包含 tree-sitter 的 C 分配）
   while :; do
     cat /sys/fs/cgroup/<cg>/memory.current /sys/fs/cgroup/<cg>/memory.peak
     grep -E 'VmRSS|VmSize' /proc/$PID/status
     sleep 1
   done
   ```

3. **Go heap / alloc / cpu / goroutine profile**（后台抓，扫描结束或 OOM 前保留）：
   ```bash
   # 在 secguard 进程内开启 net/http/pprof（当前代码没有，需要 Phase 1 先补最小观测口）
   curl -o heap.0.heap http://127.0.0.1:6060/debug/pprof/heap   # 多次采样
   curl -o alloc.0.pprof http://127.0.0.1:6060/debug/pprof/allocs
   curl -o cpu.pprof http://127.0.0.1:6060/debug/pprof/profile?seconds=60
   curl -o goroutine.pprof http://127.0.0.1:6060/debug/pprof/goroutine
   ```
   - 用 `go tool pprof -top/-list/-peek` 定位 `parser.(*Parser).ParseCached`、`graph.(*CFGCache).GetOrBuild`、`ListFunctions`、`scanEvents` 的分配占比与保留路径。
   - 重点对比 **heap inuse 与 RSS** 的差值 → 估算 tree-sitter C 分配占比（`go tool pprof -sample_index=inuse_space`）。

4. **GC 行为**：`GODEBUG=gctrace=1`（观察 GC 频率/触发原因）；尝试 `GOMEMLIMIT=…`（如 30 GiB）看是否能把 OOM 从“被杀”转成“可控 GC”，但**只作为观测手段，不作为最终方案**（Issue 明确禁止把调大限制/频繁 GC 当完成标准）。

5. **阶段级埋点**（Issue P0 表）：当前只有 wall-clock。需在 `runPipeline` 各阶段边界打印 `runtime.ReadMemStats()` 的 `HeapAlloc/HeapInuse/HeapSys/HeapObjects/NumGC` + 读取 `/proc/self/status` 的 VmRSS + cgroup memory.current，并记录 `graph_nodes`/`graph_edges`/`security_events` 的 `COUNT(*)`。

6. **图规模与算法线性度**：记录 10K/20K/40K 三档的节点数、边数、候选数，拟合“内存 vs 函数数/边数”看是否线性；若出现超线性，重点查 `ReachableFromEntries` 递归 CTE 与 null/taint fixpoint。

> **需要操作者侧提供**：基准仓库访问方式、34 GB cgroup 的创建方式（`systemd-run --scope -p MemoryMax=34G` 或 cgroup v2 目录）、以及分区扫描时的 23 个 DB 与 3,788 个候选的分区分布（供 7.3 对照）。

---

## 7. 推荐的目标架构及其与现有实现的映射

> 这是 Phase 2 的**预研方向**（Issue 4.1 的 7 段流水线），此处只做“目标 ↔ 现有实现”的映射与可行性判断，不落地。

| Issue 目标流水线 | 现有实现 | 差距 / 建议方向 |
|---|---|---|
| [1] Repository Discovery | `indexer.WalkCFiles` + `SetExcludeDirs/Paths` | 已具备；补“模块边界/编译单元”识别用于后续分区调度 |
| [2] Incremental Fact Extraction | `indexer.indexFile`（逐文件事务） | **已是流式**；保持，只需确认解析树释放（已 `defer tree.Close()`） |
| [3] Repository Index（统一 ID、符号/类型/调用） | `graph_nodes/graph_edges`（SQLite）+ `ListFunctions/ListFiles` | 缺“**常驻的轻量只读索引**”；当前每次 `ListFunctions` 全量重读 |
| [4] On-demand Graph Builder（局部 CFG/子图） | `graph.CFGCache`（全量常驻）+ 7 个全仓 builder | 把 CFGCache 从“全量常驻”改“按分析单元 + LRU/淘汰”；builder 按函数/文件流式构建 |
| [5] Bounded Scheduler（有界队列/内存背压） | 硬编码 7/8/8 并发，无队列上限 | 引入内存预算 + 背压（见第 8 节 M2） |
| [6] Detection & Evidence Persistence | `eventBatch`（2 次全量 flush）+ graph 边逐条 autocommit | 事件改**分批定容 flush**；graph 边改**事务批写** |
| [7] Result Aggregation | `planner.Plan` 29 路 + report | 已具备单库汇聚；需补“分区调度→统一汇总 + 跨区关系摘要” |

**必须回答的 7 个架构问题（Issue 9）的当前结论**：

1. **哪些必须常驻**：稳定的仓库级轻量索引——函数 ID/名/签名、文件 ID/路径、符号→类型、调用边、宏索引、文件级作用域变量表（这些是紧凑整数/字符串，可落 SQLite + 热缓存）。**解析树 AST、语句 CFG、函数内数据流状态、别名图、taint 摘要属于“可按需重建/可淘汰”**，不应无条件全量常驻。
2. **哪些可落库或按需重建**：AST（可重解析）、CFG（`BuildStmtCFG` 确定性）、函数内 flow 状态（单调格，局部）。
3. **局部图边界**：以“函数 + 其直接 callee/直接 caller 摘要”为默认边界；跨函数规则（null-flow、UAF、double-free、taint）通过仓库索引的 `CALL/RETURN/PARAM_BINDING` 边取“必要的子图”，而不是整仓物化。
4. **跨文件语义保留**：依赖统一的 `graph_nodes/graph_edges`（稳定 ID）+ `AliasGraph`/`function_summary` 的**边界摘要**，而不是把整仓 AST 同时驻内存。
5. **内存预算触发**：调度器轮询 `MemStats.HeapAlloc`/RSS，超阈值即暂停新任务、缩小批次、flush 缓冲；**不静默跳过**，未完成任务标记 `incomplete/limited`（Issue 4.2 原则 7）。
6. **避免静默漏检**：任何预算降级/跳过都要落 `scan_runs`/`scan_stats` 的显式状态位，并在报告头渲染为“不完整”，沿用现有 `PlanErrors/DetectorErrors/DisabledTypes/SkippedDetectors` 的“显式不完整”范式（`pipeline.go:25-48`）。
7. **SQLite 是否够用**：WAL + 单写者批事务可支撑当前规模；风险点在于 `ReachableFromEntries` 的递归 CTE（`crud_graph.go:163-190`）在高连通度调用图上可能膨胀，需在 M1 用 20K/40K 规模验证；必要时把递归可达性从 SQL 迁到内存 worklist + visited 去重。

---

## 8. 分阶段改造计划、风险和回滚策略

> 严格遵循 Issue 第 8 节里程碑顺序，**先可观测、再低风险治理、再按需构图、最后验收**。每步可独立回滚。

### M1：可观测性（Phase 1 落地的最小改动）
- 改动：`runPipeline` 阶段边界加 `runtime.ReadMemStats` + `/proc/self/status` VmRSS + cgroup 采样日志；可选的 `net/http/pprof` 门（受 `--profile-addr` 开关控制，默认关）。
- 涉及：`internal/cli/pipeline.go`（新增少量埋点）、`internal/cli/root.go`（flag）。
- 测试：`go build ./...` + 现有 `go test ./...`；对 memstats 埋点加单测（断言各阶段 `HeapAlloc` 非负且采样顺序正确）。
- 回滚：纯新增日志/开关，删除即回滚；不改任何分析语义。

### M2：低风险内存治理（无语义变化）
- 改动：
  1. `Parser.ParseCached` 加**容量上限 + LRU 淘汰**（或在 graph 阶段与 detector/plan 阶段之间按阶段作用域重建缓存），保证 AST 驻留不再随文件数无界增长。
  2. `CFGCache` 加**容量上限 + LRU**（`cfg_cache.go`），或按“detector 单函数处理完即释放”调整生命周期。
  3. `eventBatch` 改**分批定容 flush**（每 N 条 / 每 M MB 强制 flush），取代“整个 detector 阶段一次 flush”。
  4. graph 边写入从逐条 autocommit 改**按批次事务**（`GetOrCreateGraphNode` 的 2 次往返也可用批量 upsert 收敛）。
  5. 缓存 `ListFunctions`/`ListFiles` 结果为**只读共享索引**（`sync.Once` + 只读切片），消除 75+ 次全量重读。
- 风险：LRU 淘汰 AST 会让后续 detector 重新 `ParseCached`（命中回填），有 wall-clock 回归风险——**用 M1 的耗时基线对比验证**；CFG 淘汰同理。
- 回滚：每项都是独立小提交，逐项 revert；语义不变（仍产出相同 candidates），用 23 分区候选集做等价校验。

### M3：按需构图 + 有界调度
- 改动：CFG/子图按函数/模块按需构建 + 生命周期治理；把 7/8/8 硬编码并发改为**内存感知的有界调度**（全局并发预算 + 任务权重 + 背压）；补跨分区关系摘要与统一汇总。
- 风险：**最高**——涉及调度与构图生命周期，可能引入漏检或结果漂移。必须先有 M1 的完整观测 + 23 分区对照基线，再动并发模型。
- 回滚：分阶段开关（配置项默认关，逐环境灰度）；跨区语义用 7.3 的跨目录调用/函数指针/全局变量回归集验证。

### M4：规模与质量验收
- 改动：10K/20K/40K 规模测试 + 23 分区结果差异分析 + GTPv2 / `Policy_Acc_*` / `atoi` 漏洞回归。
- 回滚：无代码改动，纯验收。

---

## 9. 测试与验收计划

1. **安全回归（Issue 7.3）**：固定样本覆盖 GTPv2 解码器越界写（`buffer-overflow`/`out-of-bounds` 类别）、`Policy_Acc_*` 内存泄漏、`atoi` 未校验返回值（`unchecked-return`），确保 M2/M3 后仍检出且证据（文件:行、变量、CWE、来源）一致。
2. **23 分区对照基线**：以优化前 23 个 DB 的候选为基线，逐项比较**文件/函数/符号/调用边/候选**的覆盖差异，重点验证跨目录调用、函数指针、全局变量、回调、资源释放配对；不以 finding 总数相同当作等价（Issue 7.3 明确禁止）。
3. **规模扩展（10K/20K/40K）**：用 `testdata/perf/gen_codebase.go` 或真实仓库构造**有真实调用/数据流/跨文件关系**的样本（禁止纯空函数），记录峰值 RSS、Go heap、节点/边数、候选数、耗时，拟合增长曲线证明无非线性膨胀。
4. **完整性断言**：预算超限/超时/跳过必须显式落为 `incomplete/limited` 状态，报告中不得把降级扫描报成“完整成功”。
5. **一致性守卫**：`go test ./...`（含 `TestVulnTypeSkillConsistency`、`TestDeclarationFactInvariance`、`zz_ai_judgment_boundary_test.go`）全绿；`go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 保持绿。

---

## 10. 需要操作者决策的问题

1. **基准仓库与复现环境**：能否提供 1,745 文件基准仓库的访问方式与 34 GB cgroup 的创建方式？没有它，Phase 1 的“复现 + profile”只能停留在静态分析与第 6 节的待办命令。
2. **最小观测能力小 PR 的授权**：是否同意先在 M1 落一个**纯观测**的改动（阶段级 RSS/MemStats 日志 + 可选 pprof 开关，零语义变化）？这是把“强怀疑”升为“已证实”的前置。
3. **内存预算目标值**：在 34 GB cgroup 内，期望的峰值内存预算定多少（如 heap inuse ≤ 某值 / RSS ≤ 某值）？这决定 M2 的 LRU/批次/背压阈值怎么配。
4. **23 分区基线数据**：能否提供 23 个分区的目录清单、各自 DB 路径、以及 3,788 个候选的（分区、类型）分布？7.3 的差异分析依赖它。
5. **第二模型独立审查**：当前 DSH 未配置多模型子代理路由。按开工提示词第七节，请操作者决定是否切换另一模型，用本报告作为输入做独立架构审查；审查意见交回后再修订设计、进入实施。

---

### 附：本文引用的关键源码位置索引

- `sgre/internal/cli/pipeline.go:67-376`（`runPipeline` 全链路）
- `sgre/internal/parser/parser.go:40-118`（`ParseCached` 无界缓存与 `CloseAll`）
- `sgre/internal/graph/cfg_cache.go:17-58`（无界 `CFGCache`）
- `sgre/internal/graph/cfg_cache.go` + `control_flow.go:41-51`（`StmtCFG`/`StmtNode`）
- `sgre/internal/evidence/registry.go:77-179`（38 detector、8 并发、2 次 flush）
- `sgre/internal/evidence/detector.go:216-291`（`emitEvent` 批量缓冲与 flush）
- `sgre/internal/graph/call_graph.go:30-158`、`interproc.go:35-163`、`helpers.go:27-73`（builder 全量重读）
- `sgre/internal/graph/alias_builder.go:21-109`（全仓 `AliasGraph`）
- `sgre/internal/repofacts/repofacts.go:46-116`（全仓 `trees` + 工作区头文件）
- `sgre/internal/planner/planner.go:126-301`（`Plan` 与候选构造）
- `sgre/internal/db/crud_graph.go:38-105`（`GetOrCreateGraphNode` 双查询、`InsertGraphEdge` 逐条 autocommit）
- `sgre/internal/db/crud_functions.go:62-70`（`ListFunctions` 全量）
- `sgre/internal/db/connection.go:31-37`（SQLite DSN 与连接池）
- `sgre/internal/symbols/macros.go:45-48,93-133`（`MacroIndex` 与 50000 上限）
