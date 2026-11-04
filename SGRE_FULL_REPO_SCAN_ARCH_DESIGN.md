# SGRE 万级函数仓库全仓扫描架构设计提案（Phase 2 · 最终修订版 v4）

> 状态：**设计提案，待确认后实施**。v2 经操作者整体认可，v3 解决三个遗留问题，v4 做小范围修正：Acquire 锁粒度（build 移出锁）、CFG 淘汰状态机去矛盾、`completion_state` 默认改 `running`、非缓存 Parse 生命周期不变式。
> 逐项审查结论见 `SGRE_FULL_REPO_SCAN_ARCH_REVIEW.md`；本文不含代码改动。
> 前提：跳过现场 profile，采信 Phase 0/1 报告（`SGRE_FULL_REPO_SCAN_OOM_ANALYSIS.md`）对三个强怀疑热点的源码定位。
> **§8 为 v3/v4 最终修订，对 §2.1/§2.3b/§6 的相关段落起覆盖作用；冲突处以 §8 为准。**

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

---

## 8. 第三轮最终修订（CFG Lease / 总驻留预算 / incomplete 语义）

### 8.1 P0-1：CFG Lease 并发生命周期 API

#### 8.1.1 API 形态（沿用现有 `CFGCache`/ctx/`parser` 机制，不引入通用框架）

```go
// internal/graph/cfg_cache.go（在现有 CFGCache 上扩展，不新建框架）
type CFGLease struct {
    c    *CFGCache
    key  int64
    cfg  *StmtCFG
    once sync.Once   // Release 幂等
}
func (l *CFGLease) CFG() *StmtCFG          // 租约内的 CFG，只读
func (l *CFGLease) Release()               // 幂等；重复调用 no-op

// Acquire 取得 fnID 的 CFG 租约；build 负责在缺失时构建。
// 租约期内保证 CFG 及其底层 Tree 存活。
func (c *CFGCache) Acquire(ctx context.Context, fnID int64,
    tree *parser.TreeHandle, build func() *StmtCFG) (*CFGLease, bool)
```

- `Acquire` 的 `tree *parser.TreeHandle` 是**必须**参数：CFG 的 `StmtNode.Stmt` 是 Tree 内的 C 节点，因此每个缓存条目都必须持有对应 Tree 的引用（见 §8.1.2）。
- **锁只保护缓存元数据，不保护 build()**：`build()`（CFG 构建）在锁外执行，用 per-key singleflight 去重（见 §8.1.2 第 1、8 点）。
- 内部结构（在现有 `byFn map[int64]*StmtCFG` 上扩展为 entry，新增 `building` 占位态）：

```go
type entryState uint8
const (
    stateBuilding entryState = iota // 单飞构建中：done 未关闭，cfg==nil
    stateLive                        // 正常缓存条目
    // 无 retiring 态：淘汰只选 refs==0 的 live 条目（见 §8.1.2 第 3 点）
)

type cfgEntry struct {
    cfg   *StmtCFG
    tree  *parser.TreeHandle // 该 CFG 引用的 Tree 的句柄（ref 由本条目持有）
    refs  int                // 活跃租约数（借用计数）
    state entryState         // building | live
    done  chan struct{}      // building 态：构建完成后 close，唤醒等待者
    last  uint64             // LRU 时间戳
}
```

#### 8.1.2 七个问题的结论

1. **Acquire 成功后如何保证 CFG 与 Tree 存活（锁粒度修正）**：`Acquire` **不在锁内执行 build()**，分五步：
   (1) 加锁查缓存：命中 `state==live` → `refs++` 并立即返回 lease（锁内只做计数）；
   (2) 命中 `state==building` → 记入等待者，释放锁，`<-done` 等待构建完成，再回到 (1)；
   (3) 未命中 → 插入 `building` 占位（`done` 通道），释放锁；
   (4) **锁外** `build()` 构建 CFG；
   (5) 加锁回填：若期间无他人提交（仍为 building 占位），把 `cfg`/`tree` 写入 entry、`tree.ref++`、`state=live`、`close(done)` 唤醒等待者；若他人已提交（双重检查），丢弃本次构建结果、改用已提交的 entry。
   之后只要 `entry.refs > 0`，该 entry 不被淘汰、其 `tree` 引用不掉，parser 缓存不会 `Close` 该 Tree。**8 个 detector 各自构建 8 个不同函数的 CFG 时，build() 在锁外并行执行，互不阻塞。**
2. **LRU 淘汰遇到活跃租约**：LRU 只选 `refs==0 && state==live` 的条目淘汰。若预算已满且所有条目 `refs>0`（全部被借用），**不淘汰**——预算暂时溢出，由 §8.2 的总驻留预算 + §2.3b 的背压（停止准入新任务→新 lease 停止产生→既有 lease 释放）兜底回收。
3. **淘汰状态机（去掉 retiring 的矛盾）**：不再设计 `refs>0` 的 `retiring` 路径（按规则 LRU 本就选不中 refs>0 条目，该转换无触发条件）。状态机简化为：

   | 状态 | 接受新 Lease | 允许回收 | 说明 |
   |---|---|---|---|
   | `building` | 否（等待者挂起在 `done`） | 否 | 单飞构建中 |
   | `live` | 是 | 仅 `refs==0` 且被 LRU 选中 | 正常缓存条目 |
   | （removed） | 否 | 已从 map 删除 | 终结态 |

   同一 fnID **不会同时存在两个条目**：单飞保证「未命中→占位→构建→回填」是唯一的；旧条目释放前若再次 Acquire 同一 fnID，要么命中 `live`（refs++），要么命中 `building`（等待），不存在「新旧双 entry」。
4. **Release 防重复释放**：`CFGLease.Release()` 用 `sync.Once` 包裹 `refs--`，第二次调用 no-op；保证引用计数只减一次。
5. **Tree.Close() 只执行一次**：`parser.TreeHandle` 内部用 `sync.Once` 包 `tree.Close()+parser.Close()`；refcount 归零触发 `once.Do`。parser 缓存对 Tree 持有「缓存所有权 +1」，条目/借用各持 +1，Close 只在所有引用释放后执行一次。
6. **Parser.CloseAll() 遇到活跃租约**：`CloseAll()` 在 pipeline 的 `pwg.Wait()` 之后调用，正常应无活跃租约。防御性处理：`CloseAll` 先置「closing」禁止新 `ParseCached`，再 drop 每个 Tree 的缓存所有权；仍有 `refs>0` 的 Tree **不强制 Close**，记录为泄漏诊断（函数/文件 + 剩余引用数），延迟到 refcount 归零再关，绝不产生悬空 C 节点。
7. **~20 个 CFG 消费点迁移**：真实代码收敛为**两个 choke point** + 少量直调：
   - `planner/cfg_cache_ctx.go:39-44` `buildStmtCFGFromCtx`
   - `evidence/cfg_cache_ctx.go:36-41` `buildStmtCFGFromCtx`
   - 直调 `graph.BuildStmtCFGWithCache` 的 `race_condition.go:578`、`range_flow.go:161`、`filter_contract_gap.go:162`、`filter_uninit_heapstruct.go:70`、`filter_uninit_flow.go:235`、`null_flow.go:388,409`。
   迁移模式统一为：
   ```go
   lease, ok := cache.Acquire(ctx, fn.ID, tree, func() *StmtCFG { return graph.BuildStmtCFG(body, fn.EndLine) })
   if !ok { /* 预算耗尽：走降级/记录 incomplete，见 §8.3 */ }
   defer lease.Release()
   cfg := lease.CFG()
   ```
   现有消费点全部在**同步函数作用域内**使用 `*StmtCFG`（无跨 goroutine 持引用），故 lease 模式可直接套用，无异步持有改造。

#### 8.1.3 并发时序图（goroutine 级）

```
G1(detector)          CFGCache(c.mu)                    Parser.cache / TreeHandle
   |  Acquire(fnA, treeA, build)                          |
   |-- lock -->| 未命中 → 插入 building 占位(doneA)        |
   |<-- unlock (锁外) |                                    |
   |  build() 构建 CFG-A（锁外，不阻塞他人）              |
G2(plan)  Acquire(fnB, treeB, build)                       |
   |-- lock -->| 未命中 → 插入 building 占位(doneB)        |
   |<-- unlock | build() 构建 CFG-B（与 G1 并行）          |
G3(detector) Acquire(fnA, treeA, build)                    |
   |-- lock -->| 命中 building → 记等待者，unlock          |
   |<-- 等待 doneA --------------------------------------->|
G1  build() 完成 → -- lock -->| 回填 cfgA/treeA、tree.ref++  |
   |                          | state=live、close(doneA)   |
   |<-- lease(fnA, refs=1) --|                            |
G3  被 doneA 唤醒 → -- lock -->| state==live → refs=2      |
   |<-- lease(fnA, refs=2) --|（同一 CFG，无重复构建）      |
G2  build() 完成 → -- lock -->| 回填 cfgB/treeB、close(doneB)|
G1  lease.Release() --lock--> refsA=1                       |
G3  lease.Release() --lock--> refsA=0                       |
   (预算超限，LRU 选中 fnA) -- lock -->| refsA==0 && live → 删 entry |
   |                          |  drop treeA 引用 --> treeA.ref=1（cache 仍持有）|
   |                          |  若 treeA.ref==0 → TreeHandle.once.Do(Close)
```

关键不变式：**`build()` 永不在锁内执行；`entry.refs==0` 是淘汰的必要条件；`TreeHandle.ref==0` 是 `Close` 的充要条件；同一 fnID 至多一个条目（单飞保证）。**

#### 8.1.4 测试方案

1. 单测：`Acquire`/`Release` 幂等（两次 `Release` 后 `refs` 只减一次）。
2. 单测：`Acquire` 后立刻并发 `evict`，断言 `refs>0` 的 entry 不被淘汰、Tree 不被 Close。
3. 单测（singleflight）：同一 fnID 并发 `Acquire`，断言 `build()` 只执行一次、所有等待者拿到同一 `*StmtCFG`。
4. 单测（锁外构建）：不同 fnID 并发 `Acquire`，用 build 内埋点断言构建在锁外并行（无全局锁串行化）。
5. 单测：`Tree.Close()` 只执行一次（并发多路 `Release` + parser 淘汰，断言 `close` 计数 ==1）。
6. 竞态测试：`go test -race` 覆盖并发 Acquire/Release/evict。
7. 一致性测试：lease 迁移前后，固定回归集 candidate 集（文件/行/变量/CWE/来源）逐项一致。

### 8.2 P0-2：AST/CFG 总驻留预算

#### 8.2.1 区分两类上限

| 概念 | 含义 | 默认信号 |
|---|---|---|
| **缓存条目上限** | `parser.cache` 的 `maxCachedTrees`、`CFGCache` 的 `MaxEntries`/`maxTotalCFGNodes` | 条目数/节点数 |
| **进程总驻留对象上限** | 活跃 `TreeHandle`（= 缓存中的树 + 被 CFG/`fileParseCache` 钉住的树 + 瞬态树） | cgroup `memory.current`/RSS 高水位 |

**总驻留 = 缓存条目 + 被引用钉住对象**，二者不是一回事：`maxCachedTrees` 达到后，仍可能有额外树被活 CFG 钉住（`pinnedTrees`）。

#### 8.2.2 关键行为定义

- **AST 缓存达 `maxCachedTrees` 且所有树都被 CFG 引用时的 `ParseCached` 行为**：**不等待、不拒绝、绕过缓存**。回退到现有的**非缓存 `parser.Parse`** 路径（`parser/parser.go:66-69`，即 indexer 已在用的路径）：临时解析、同步消费、用完 `Close`，**不进入缓存**。从该瞬态树构建的 CFG 也不缓存（其 Tree 即将关闭）。代价是一次性重解析（墙钟），但**正确性不变、无阻塞、无拒绝**。
- **限制活跃 TreeHandle 数**：`activeTreeHandles ≤ maxCachedTrees + 并发度`（瞬态树受并发度约束、生命周期短）。此不等式写入阶段观测断言。
- **限制 CFG 大小不均衡**：`MaxEntries` 只限条目数，不同函数 CFG 大小可差百倍。增补 **`maxTotalCFGNodes`**（以 `len(cfg.Nodes)` 为廉价大小代理，`StmtNode` 含 `Succs/TrueSuccs/FalseSuccs` + `parser.Node`）：总节点数超预算时按 LRU 淘汰（优先大条目）。这让最坏驻留不再由「单个巨型函数」决定。
- **统计指标**：
  - `activeLeaseCount` = Σ `entry.refs`（running counter）。
  - `activeTreeHandles` = `len(parser.cache)` + 瞬态树计数。
  - `pinnedTrees` = Tree 引用计数 > 缓存所有权(1) 的树数（即被 CFG/`fileParseCache` 钉住的树）。
  - 阶段边界打印以上三项 + `estASTBytes` + 图规模。
- **P1 硬性不变式（代码级保证，非调用者纪律）**：**任何 `parser.Node` 都不得逃逸其所属 `TreeHandle` 的有效生命周期。**
  - **bypass 的瞬态树绝不能被 `fileParseCache` 持有**：bypass 走 `parser.Parse`（非缓存），其 Tree 严格「解析 → 同步消费 → 立即 `Close`」，**不注册进 `fileParseCache` 的 `roots/bodies/defs`**，也不注册进 `CFGCache`。
  - 若某个消费者需要跨调用保留 body/def 节点，它必须走 `ParseCached` 得到 `TreeHandle` 并持有引用；`fileParseCache` 存储的是 `*TreeHandle`（+ 函数体行号区间），在**借用作用域内**按需派生 `parser.Node`，派生出的 Node 不逃逸借用作用域。
  - API 层面用「Node 只经由 TreeHandle 的 borrow 返回」来强制，而不是靠注释提醒调用者。

#### 8.2.3 源码依据

- 非缓存回退路径已存在：`parser.Parse`（`parser/parser.go:66-69`），`indexer.indexFile` 用它并 `defer tree.Close()`（`indexer.go:134-138`）。
- CFG 大小代理：`len(cfg.Nodes)`（`StmtCFG.Nodes`，`control_flow.go:41-51`）。
- 钉住源：`fileParseCache` 持有 `roots/bodies/defs` 的 `parser.Node`（`null_flow.go:2686-2729`），同样指向缓存 Tree——**它也必须持 TreeHandle 引用**，与 CFG 条目并列计入 `pinnedTrees`。

#### 8.2.4 测试方案

1. 单测：`maxCachedTrees=1` 时并发 `ParseCached` 第二个文件 → 走 bypass（不 panic、不阻塞），`len(cache)` 不超限。
2. 单测：`maxTotalCFGNodes` 触发后按 LRU 淘汰，`activeLeaseCount`/`pinnedTrees`/`activeTreeHandles` 计数正确。
3. 规模测试：构造 1 个巨型函数 + N 个小函数，断言总驻留受 `maxTotalCFGNodes` 约束而非被单函数撑爆。

### 8.3 P0-3：统一 checkpoint 与 incomplete 语义

#### 8.3.1 决策：本期不实现 checkpoint（断点恢复），只持久化 incomplete 状态

统一口径，删除 v2 中「超预算落 checkpoint」与「M3.3 checkpoint 本期不做」的自相矛盾：

- **超预算/超时/降级 = 持久化 `incomplete` 状态**，不承诺自动断点恢复。
- 记录字段：函数 ID、文件、规模（LOC 或 CFG 节点数或 AST 估算）、失败阶段、原因。
- 报告头部显式显示「扫描不完整」，列出未完成任务清单。

#### 8.3.2 数据模型（沿用现有 CRUD/迁移机制，不引入新框架）

- **`complete` 不能是 DB 默认值**：进程可能被 cgroup OOM Killer 直接杀死，没有机会执行清理/更新逻辑；若默认 `complete`，中断的扫描会在库中留下「完整」记录，比扫描失败更危险。默认必须是 `running`。
- `scan_runs` 增加一列（沿用 `InitSchema` 的 `ALTER TABLE` 迁移原语，见 `schema.go:505` 附近）：
  `completion_state TEXT NOT NULL DEFAULT 'running' CHECK (completion_state IN ('running','complete','incomplete','limited','failed'))`。
- **扫描终态生命周期**：
  ```
  创建扫描记录 → running
      ├─ 正常完成 → complete        （扫描成功后显式提交，绝不靠默认值）
      ├─ 捕获部分任务失败 → incomplete
      ├─ 主动限制范围 → limited
      └─ 不可恢复错误 → failed
  ```
- **启动清理**：扫描启动时检查上一次遗留的 `running` 记录（上一进程 OOM 被杀留下的），将其置为 `failed`（原因 `interrupted`）；**不得把遗留 running 当作完整结果使用**。`complete` 只在扫描成功收尾时显式 UPDATE。
- 新增表 `scan_incomplete_tasks`（走现有 `crud_*.go` 模式）：

```sql
CREATE TABLE IF NOT EXISTS scan_incomplete_tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL,
    phase       TEXT NOT NULL,       -- 'graph' | 'detector' | 'plan'
    function_id INTEGER,
    file_path   TEXT,
    scale       INTEGER,             -- LOC / CFG 节点数 / AST 估算
    reason      TEXT NOT NULL,       -- 'budget_exceeded' | 'timeout' | 'degraded' | 'parse_failed'
    detail      TEXT,
    created_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_incomplete_scan ON scan_incomplete_tasks(scan_id);
```

- 报告渲染读取 `scan_runs.completion_state` + `scan_incomplete_tasks`；`completion_state != complete` 时在报告头渲染「⚠️ 扫描不完整（N 项未完成）」，`running/failed` 则渲染「扫描未完成/失败」，绝不声称完成。

#### 8.3.3 替换「单函数超 34GB 几乎不存在」的臆断

删除该假设，改为**成本预估 + 任务准入保护**：

- 准入前预估任务成本：`LOC = Function.EndLine - Function.StartLine`（`db.Function` 已有字段），或 CFG 节点数，或 AST 估算字节。
- 准入门：`预估成本 > 剩余预算` → 先降并发到 1 串行重试；仍超 → 记录 `incomplete`（§8.3.2），**绝不静默跳过**。
- 不再对「多大概率发生」做任何陈述；机制对任意规模成立。

#### 8.3.4 测试方案

1. 单测：`completion_state` 默认 `running`；正常收尾显式置 `complete`；触发降级后 `incomplete`/`limited` 落库。
2. 单测：插入一条遗留 `running` 记录后重启，断言被置 `failed`（原因 `interrupted`），且不会被当作完整结果读取。
3. 单测：`scan_incomplete_tasks` 记录函数 ID/文件/规模/阶段/原因，报告头正确渲染不完整清单。
4. 一致性测试：不完整任务不影响已完成任务的结果（candidate 集不因另一任务失败而丢失）。

### 8.4 v4 剩余风险与待确认

- **风险**：`TreeHandle` 需同时被 `CFGCache` 条目与 `fileParseCache`（`null_flow.go:2686`）持引用，两处都要改；漏改任一处会在淘汰后产生悬空 C 节点。
- **风险**：`maxTotalCFGNodes` 用节点数作字节代理，巨型函数仍可能单节点携带大源文本（`parser.Node.src` 引用）；需在规模测试中用 RSS 校准代理精度。
- **风险**：singleflight 的 `building` 占位若 builder 协程 panic/退出，等待者会永久阻塞——必须 `defer close(done)` 并约定「构建失败也提交一个空/错误 entry」唤醒等待者。
- **验证边界（操作者提醒）**：本文档是设计，不是正确性证明。Tree-sitter 的 C 指针生命周期必须在 Phase 3 用真实并发测试、`go test -race`、压力测试与 RSS/cgroup 观测验证，不能靠文档自证。
- **待确认**：`maxCachedTrees`/`MaxEntries`/`maxTotalCFGNodes`/内存高水位 四个默认值。
- **待确认**：`graph_edges` 唯一索引 + 幂等（与 checkpoint 解耦后，可独立决定是否纳入本轮）。
