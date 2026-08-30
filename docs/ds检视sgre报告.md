# sgre 引擎检视报告

> 检视目标：消除低级错误，提升 Go 程序的性能与稳定性。
> 检视范围：`sgre/` 全量 Go 源码（非测试源码约 2.7 万行，199 个 .go 文件）。
> 检视姿态：**只检视，不修改代码**。本报告供后续修复 Agent 直接定位使用。
> 结论状态标签沿用英文约定：`confirmed` / `suspected` / `dismissed`。

---

## 0. 结论摘要

| 严重度 | 数量 | 核心指向 |
|--------|------|----------|
| Critical | 2 | 并发 map 写（进程崩溃）、跨类型缓存失效（性能回归） |
| High | 4 | 错误被吞导致静默降级 / 数据丢失 |
| Medium | 10 | 错误吞噬、N+1 查询、可观测性缺失 |
| Low | 7 | 手写轮子、微优化、边界情况 |

**最关键的三个问题**（建议最先修）：

1. `internal/cli/pipeline.go:136` —— `planErrors` map 被多个 goroutine 并发写，无任何同步，存在 `fatal error: concurrent map writes` 崩溃风险。**confirmed**
2. `internal/cli/pipeline.go:141` —— 每个 vuln type 都 `NewPlanner`，使 `callReachCache`（sync.Once 跨 Plan 缓存）**从未跨类型共享**，`computeCallReach` 实际被重复执行 ~15 次，与代码注释宣称的优化意图直接矛盾。**confirmed**
3. `internal/planner/planner.go:244` 与 `internal/db/crud_summary.go:70` —— DB 批量查询错误被 `_` 吞掉，分别造成候选丢失位置信息、函数摘要字段被零值覆盖。**confirmed**

---

## 1. Critical

### C1. `planErrors` map 并发写（data race → 进程崩溃）

- 位置：`sgre/internal/cli/pipeline.go:136`、`:148`
- 状态：`confirmed`

```go
planErrors := map[string]string{}          // 第 125 行附近
...
go func(idx int, vt string) {
    defer pwg.Done()
    defer func() {
        if r := recover(); r != nil {
            planErrors[vt] = ...            // 第 136 行 —— goroutine 内写
        }
    }()
    ...
    if err != nil {
        planErrors[vt] = err.Error()        // 第 148 行 —— goroutine 内写
        return
    }
    ...
}(i, vulnType)
```

`planConcurrency = 4`，即最多 4 个 goroutine 并发执行。每个 goroutine 写入的是**不同 key**（`vt` 互不相同），但 Go 的 map 对并发写（即使是不同 key）是未定义行为，任何一个 vuln type 出现错误或 panic 且与另一个失败并发时，会触发 `fatal error: concurrent map writes`，整个进程崩溃且无法被 `recover` 捕获。

- 影响：一次扫描中只要 ≥2 个 vuln type 同时失败/panic，进程即崩溃。
- 修复建议：改用 `sync.Mutex` 保护写，或每个 goroutine 返回局部错误再由主协程聚合；也可 `planErrors := sync.Map{}`。注意 `plans[idx] = result` 这种 slice 不同下标写入是安全的，无需改动。

### C2. `callReachCache` 跨类型缓存失效（性能回归，与设计意图矛盾）

- 位置：`sgre/internal/cli/pipeline.go:141`；`sgre/internal/planner/planner.go:22-29`；`sgre/internal/planner/filter_call_reach.go:22-38`
- 状态：`confirmed`

`filter_call_reach.go` 的注释明确写着：

> All 15 vulnerability types run the call-reach filter over the same graph, so recomputing it per type was the dominant scan wall-time cost ... sync.Once makes the cache safe even if Plan is ever driven concurrently.

即缓存的**设计目的就是跨 `Plan()` 调用共享**。但 `pipeline.go` 每个 vuln type 都执行了：

```go
pl := planner.NewPlanner(store, p, logger)   // 每个 type 新建一个 Planner
```

而 `NewPlanner` 每次都 `callReachCache: &callReachCache{}`（planner.go:27），导致每个 Planner 的 cache 只被其唯一的 `Plan()` 消费一次。结果 `computeCallReach`（`ListFunctions` + `ListGraphNodesByEntityType("function")` + `ListGraphEdgesByType("CALL")` + 全量 BFS）仍然对 ~15 个 vuln type 各执行一遍。

- 影响：与注释宣称的优化完全相反，大代码库上 call-reach（recursive/BFS over 全量 CALL 边）成为重复开销。
- 修复建议：在 `runPipeline` 中**复用同一个 `*planner.Planner`**（`callReachCache` 已用 `sync.Once` 保证并发安全），或将 `callReachCache` 提升为 pipeline 级共享对象注入每个 filter。

---

## 2. High

### H1. `seedCandidatesByType` 吞掉批量查询错误 → 全部候选丢失文件/行号

- 位置：`sgre/internal/planner/planner.go:244-245`
- 状态：`confirmed`

```go
funcsByID, _ := p.store.ListFunctionsByIDs(ctx, funcIDs)   // 错误被丢弃
locsByID, _  := p.store.ListLocationsByIDs(ctx, locIDs)     // 错误被丢弃
```

这两个方法出错时返回 `(nil, err)`。错误被吞后 `funcsByID`/`locsByID` 为 nil，后续所有 seed 候选的 `FunctionName`、`FileID`、`Line` 全为 0，最终产出一批**无文件路径、无行号**的 finding（或 dedup key 失真）。这是典型的静默降级——安全工具报不出位置等于白报。

- 影响：DB 查询异常时全量候选静默损失位置信息，非 fail-fast。
- 修复建议：至少 `p.logger.Warn(...)` 记录降级；更稳妥是直接返回 error 让 `Plan` 失败（该类型在 `status --per-type` 中体现为 failed/unknown，而不是错误地写出 0 行 finding）。

### H2. `UpdateReturnNullable` 吞错误 → 函数摘要字段被零值覆盖

- 位置：`sgre/internal/db/crud_summary.go:70`
- 状态：`confirmed`

```go
existing, _ := s.GetSummaryByFunction(ctx, functionID)   // 错误被丢弃
sum := &FunctionSummary{FunctionID: functionID, ReturnNullable: nullable}
if existing != nil {
    sum.ParameterNullable = existing.ParameterNullable
    ...
}
return s.UpsertSummary(ctx, sum)
```

`GetSummaryByFunction` 在非 `ErrNoRows` 错误时返回 `(nil, err)`。错误被吞后 `existing == nil`，`sum.ParameterNullable` / `SideEffect` / `SummaryJSON` 全为**零值**，`UpsertSummary` 会用这些零值覆盖数据库里已有的字段，造成**参数可空性 / 副作用 / 摘要 JSON 永久丢失**。

- 影响：静默数据损坏，直接影响跨函数 null 传播与摘要正确性。
- 修复建议：区分 `sql.ErrNoRows` 与真实错误；真实错误直接 `return err`，绝不覆盖已有行。

### H3. `buildNullModel` 吞错误 → NULL_VALUE 源行号全 0

- 位置：`sgre/internal/planner/null_analysis.go:54`
- 状态：`confirmed`

```go
locsByID, _ := store.ListLocationsByIDs(ctx, locIDs)   // 错误被丢弃
```

与 H1 同模式。错误后 `line` 全为 0，`hasSource` 按 `s.line == 0 || s.line <= line` 逻辑退化为"任何源都命中"的过近似，可能导致 null-deref 误报增加（或配合 CFG 路径分析后行为漂移）。

- 修复建议：显式处理错误，至少 warn；或 fail-open 前明确记录退化语义。

### H4. `array_oob_precedence` 过滤器 N+1 查询

- 位置：`sgre/internal/planner/filter_array_oob_precedence.go:29`、`:40`
- 状态：`confirmed`

```go
for _, e := range bofEvents {
    ...
    loc, _ := f.store.GetLocationByID(ctx, e.LocationID)   // 每个 BUFFER_ACCESS 事件一次点查
    ...
}
...
func(c Candidate) bool {
    loc, _ := f.store.GetLocationByID(ctx, c.LocationID)   // 每个 candidate 又一次点查
    ...
}
```

对比 `planner.go:244` 与 `null_analysis.go` 已经采用 `ListLocationsByIDs` 一次批量加载，此过滤器仍在两层循环里做逐条 `GetLocationByID`，在 BUFFER_ACCESS 事件多（redis 级代码库上万条）时产生上万次点查询。

- 影响：null-deref 链首个 filter 阶段的显著 DB 开销。
- 修复建议：`ListLocationsByIDs` 一次性取回 `file_id/line`，用内存 map 替换两处点查。

---

## 3. Medium

### M1. graph builders 普遍吞掉 `json.Marshal` 错误

- 位置（多处）：`alias.go:79`；`call_graph.go:68,95`；`data_flow.go:70,98`；`interproc.go:142,147,166`；`ownership.go:133,152,158`；`lock_order.go:85`；`shared_access.go:106`
- 状态：`confirmed`

`props, _ := json.Marshal(...)` 遍布 graph 层。虽然被序列化的对象都是 `map[string]string` / `map[string]interface{}`，几乎不可能失败，但契约上吞掉错误会让值静默变成 `nil`/空串，且与项目"DB/I/O 边界必须检查错误"的约束不一致。

- 修复建议：统一封装一个 `mustJSON`/`marshalProps` 辅助函数集中处理（如失败即跳过该边并 warn），消除散落的 `_`。

### M2. graph builders 吞掉 `InsertGraphEdge` / `GetOrCreateGraphNode` 错误且多数无日志

- 位置：`alias.go:71-86`；`data_flow.go:62-79`；`call_graph.go:49-85`；`interproc.go:137-174`；`ownership.go:117-165`；`lock_order.go:76-92`；`shared_access.go:97-113`
- 状态：`confirmed`

这些 builder 在 `persistXxx` 里对 DB 写入错误一律 `return false`/`continue`，其中 `alias.go`、`data_flow.go`、`ownership.go` **连日志都没有**（仅 `call_graph.go` 部分路径 log）。边写入失败会被静默吞掉，`result.EdgesCreated` 不增长，最终表现为静默 false-negative，且事后无法区分"没有这条边"与"写边失败"。

- 修复建议：仿照 `evidence/detector.go:emitEvent` 的做法，写失败时经 `b.logger.Warn` 记录 `edge_type`、`function`、`error`。

### M3. 多个 flow filter 的按函数 N+1 点查询

- 位置：
  - `filter_return_check.go:43,49`
  - `filter_int_overflow.go:104,108` / `:126,130`
  - `filter_lifetime.go:69,73`
  - `filter_double_free.go:70,74`
  - `filter_range.go:77,81`
  - `filter_uninit_flow.go:111,115` / `:338`
  - `filter_taint_source.go:185,189` / `:261` / `:327` / `:628,632` / `:692`
- 状态：`confirmed`

这些 filter 在 `byFunc` 循环内逐个调用 `GetFunctionByID(ctx, fid)` + `GetFileByID(ctx, fn.FileID)`。对比 `filter_nullable_source.go:121-127` 已经用 `ListFunctionsByIDs` + 一次 `ListFiles` 批量加载（并有注释说明避免 N+1），其余 filter 未跟进。

- 影响：按函数数量的 N+1 查询，中等代码库上放大 DB 往返。
- 修复建议：统一抽取一个"按 funcIDs 批量加载 fn + file"的辅助函数，供上述 filter 复用。

### M4. `RankCandidates` 的 `GetEventByID` N+1

- 位置：`sgre/internal/planner/ranker.go:52-54`
- 状态：`suspected`

```go
if apiName == "" && store != nil && candidates[i].DerefEventID > 0 {
    event, err := store.GetEventByID(ctx, candidates[i].DerefEventID)  // 逐个点查
    ...
}
```

`APIName` 在 `seedCandidatesByType` 已从 properties 提取，多数非空，此分支属于兜底。但当 properties 缺 `function`/`api` 字段的候选成批出现时，会退化为逐事件点查。

- 修复建议：若确需兜底，改为批量 `ListEventsByType` 预建 `eventID -> apiName` map。

### M5. 手写字符串包含 `contains/searchString`

- 位置：`sgre/internal/db/connection.go:126-137`
- 状态：`confirmed`

```go
func contains(s, sub string) bool { ... }         // 多余包装
func searchString(s, sub string) bool {           // 手写 O(n*m) 子串匹配
    for i := 0; i <= len(s)-len(sub); i++ { ... }
}
```

`isLockedErr` 用它们判断 `database is locked`。手写循环正确但既慢又可读性差，标准库 `strings.Contains` 用高效算法。

- 修复建议：删除 `contains`/`searchString`，`isLockedErr` 直接用 `strings.Contains`。

### M6. config 解析错误静默吞掉

- 位置：`sgre/internal/config/config.go:57`
- 状态：`confirmed`

```go
_ = toml.Unmarshal(data, cfg)
```

`secguard.toml` 若存在语法错误或类型不匹配，会被静默忽略，用户拿到的是一条"看似生效实则部分失效"的配置（trusted-macros allowlist 可能静默失效）。

- 修复建议：至少 warn（config 包目前不依赖 log 层，可返回 error 或 `fmt.Fprintf(os.Stderr, ...)`）。

### M7. `cli/report.go` 多处批量读错误吞掉

- 位置：`sgre/internal/cli/report.go:142`、`:170`、`:391`、`:642`
- 状态：`confirmed`

```go
files, _ = store.ListFiles(ctx)                       // :142
files, _ := store.ListFiles(ctx)                      // :170
allFiles, _ := store.ListFiles(ctx)                   // :391
scanFindings, _ := store.ListFindingsByScanID(ctx, scanID)  // :642
```

其中 `:642` 直接影响审计报告（`--audit` 输出真值源）——查询失败时静默得到空列表，报告内容丢失而非失败。

- 修复建议：区分"空结果"与"错误"，错误向上返回或写入 `failed_details`。

### M8. `detector.emitEvent` 中 `json.Marshal` 失败无日志

- 位置：`sgre/internal/evidence/detector.go:105-107`
- 状态：`confirmed`

`InsertLocation` 失败会 warn，但紧随其后的 `json.Marshal(props)` 失败只 `return false`，无任何日志，事件静默丢失且不可追踪。

- 修复建议：`return false` 前同样 `logger.Warn`。

### M9. `generateScanID` 极端情况下产出无后缀 scanID

- 位置：`sgre/internal/report/protocol.go:79-82`
- 状态：`suspected`

```go
if _, err := rand.Read(b); err != nil {
    return "sc_" + ts   // 缺少 6 位后缀
}
```

`rand.Read` 失败属极端情况，但返回的 scanID 不满足 `cli/scan.go:26` 的 `scanIDPattern`（要求 `_[0-9A-Za-z]{6}$`）。虽然自生成路径不经该校验，但后续若被 `--output-dir` 复用会不一致。

- 修复建议：失败时用时间/pid 派生的确定性后缀兜底，保证格式一致。

### M10. `UpsertReviewSession` 不更新 `status`（设计确认项）

- 位置：`sgre/internal/db/crud_review_sessions.go:21-31`
- 状态：`suspected`（需确认是否有意）

`ON CONFLICT(review_id) DO UPDATE SET` 列表不含 `status`。重跑同一 diff 时 `status` 保持旧值（例如保持 `done` 而非重置为 `running`）。结合注释"re-running the same diff converges on one row, so the review is resumable"，可能是有意避免覆盖完成态；但首次插入默认 `running`，与更新路径语义不对称。

- 修复建议：若为有意，请在注释中显式说明 `status` 不进入 upsert 的理由，避免后续维护者误判。

---

## 4. Low

### L1. graph builders 的 `O(functions × nodes)` 嵌套扫描

- 位置：`alias.go:44-66`；`data_flow.go:26-34`；`call_graph.go:45-88`；`ownership.go:54-109`；`interproc.go:74-133`；`shared_access.go:30-93`；`lock_order.go:41-71`
- 状态：`confirmed`

各 builder 先在文件级 `root.FindAll(...)` 一次，然后 `for _, f := range funcs { for _, n := range nodes { funcLineRange(f, n.StartLine()) ... } }`，即每个文件的整棵表达式列表被每个函数重复遍历，复杂度 `O(函数数 × 列表长)`。相比早期的"每函数重读+重解析"已大幅改善，但对单文件多函数场景仍可继续优化。

- 修复建议：将节点按 `StartLine` 排序后线性扫描，或按函数的 `[StartLine, EndLine]` 区间二分定位，降为 `O(函数数 + 列表长)`。

### L2. `countLines` 二次拷贝

- 位置：`sgre/internal/indexer/indexer.go:220`
- 状态：`confirmed`

```go
return strings.Count(string(data), "\n") + 1   // 把整个文件 []byte 转成 string（一次拷贝）
```

用 `bytes.Count(data, []byte{'\n'}) + 1` 避免整文件字符串转换。

### L3. `Parse`（非缓存版）不管理 tree 生命周期

- 位置：`sgre/internal/parser/parser.go:66-69`
- 状态：`confirmed`（注释已自述，属设计约束而非遗漏）

`Parse` 每次在共享 `p.parser` 上 parse，旧 tree 被下次 parse 复用内存，因此调用方必须在下一次 `Parse` 前 Close。注释已说明这一约束，但存在被后续调用者违反的隐患（project-wide 仅 indexer 与 planner lifetime filter 走此路径）。

- 修复建议：可考虑为 `Parse` 返回 `runtime.SetFinalizer` 兜底，或新增 `ParseOwned` 语义更明确的方法；至少保持现状约束的文档可见性。

### L4. `getFilters` 中 `default` 链覆盖所有未注册类型

- 位置：`sgre/internal/planner/planner.go:111-121`
- 状态：`suspected`

`default` 分支静默回退为 `call_reach + safe_function`，对拼写错误的 filter chain 不会报错。若注册表新增类型却漏配 chain，会静默落到默认链。属稳健性可选项。

- 修复建议：对未知 chain 名 return error 而非静默默认，避免未来新增 vuln type 漏配时无告警。

### L5. `GetLatestScanID` 依赖秒级时间戳排序

- 位置：`sgre/internal/db/crud_scan_stats.go:46`
- 状态：`suspected`

```go
SELECT scan_id FROM scan_stats ORDER BY created_at DESC LIMIT 1
```

`created_at = time.Now().Unix()`（秒级），同一秒内多个 scan 的 latest 判定不稳定，且乱序执行会误选。以 id 作为稳定 tiebreaker 更稳。

- 修复建议：`ORDER BY created_at DESC, id DESC`。

### L6. `buildFor` 空 body 时 update 节点无入边

- 位置：`sgre/internal/graph/control_flow.go:412-441`
- 状态：`suspected`（CFG 正确性边角，超出本轮"性能/稳定"主线，备注供 correctness 轮跟进）

`for (init; cond; update) ;` 这类空循环体时 `bodyLast == -1`，`update` 节点仅保留 `upd -> header` 出边而无任何入边，`continue` 目标为其自身亦不可达，导致空 body 循环的 update 语义在 CFG 中缺失。

- 修复建议：`body` 为空时让 `header` 直接连到 `upd`（或 `header`），补齐 back-edge。

### L7. 字符串/文件读取类零散吞错

- 位置：`sgre/internal/cli/diff.go:110,175`；`scan.go` 多处 `json.MarshalIndent` `_`；`git/git.go:121` `strconv.Atoi` `_`
- 状态：`confirmed`（低危）

这些吞错要么影响小（路径分隔、格式输出），要么有上下文保证（`scanIDPattern` 保证 `m[3]` 非空），列为 low。建议统一审视 `grep -n "_, _ :=" sgre/internal -g '!*_test.go'` 的余量，凡是 DB/I/O 边界一律显式处理。

---

## 5. 修复优先级建议

1. **先修 C1**（并发 map 写）——一行锁即可消除崩溃风险，收益/成本比最高。
2. **再修 C2**（复用 Planner / 共享 callReachCache）——直接兑现注释宣称的性能承诺。
3. **接着修 H1/H2/H3/H4**——消除静默降级与数据丢失，恢复正常 fail-fast 语义。
4. **M 级**按模块顺序清一遍：先 `db`（M5、M7），再 `graph`（M1、M2），再 `planner`（M3、M4），最后 config/cli。
5. **L 级**可顺手清掉 L1/L2/L5，其余按需排期。

> 说明：所有行号以检视时的工作区快照为准；修复前请用 `cd sgre && go build -buildvcs=false ./...` 与 `go test -buildvcs=false ./...` 复验基线。