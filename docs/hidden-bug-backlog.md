# 隐藏缺陷专项 · 遗留清单（Backlog）

> 由 2026-08-20 的排查专项（4 个并行审计 + 手工追踪）产出。已修复 14 项（见 `git log`：
> `d8e5bb1` / `2091058` / `4a8c13e`），本文档记录**未修复的遗留项**，作为下一版冲刺的明确输入。
>
> 总原则：**每一处静默吞错都是"平时不爆、DB 抖动就漏报"的隐性假阴性**；**每一处把 0-CFA 名字解析拿去做"丢弃决策"都是精度陷阱**。修的时候必须配针对性测试夹具，否则会引入新的假阳性/漏报。

## 进度（2026-08-20 开始执行）

- ✅ **I~N（MINOR 清单）全部完成** —— `231ffd9`：status/scan/plan 的读错误透出、`computeParamTainted` 错误 fail-closed、planner short-circuit 补齐统计。
- ✅ **E（injection ConvergeKey）完成** —— `f416e8d`：key 改为 `(file,func,category,variable)`，SQL 事件带 `variable`（buffer），独立 sink 不再合并。
- 🚧 **A+B（检测器吞错）进行中** —— `7dac0db`：新增 `emitEvent` 共享 helper + 迁移了 `path_traversal.go` 作为模板；其余 ~21 个检测器按同一模式机械迁移（见下）。
- ⬜ **C / D / F / G / H** 未开始。

---

## 优先级总览

| # | 严重度 | 位置 | 问题 | 影响 | 建议顺序 |
|---|--------|------|------|------|---------|
| A | BLOCKER | `evidence/*.go` 42 处 | 检测器吞 `InsertEvent` 错误 | 单条 finding 静默丢失 | 1 |
| B | BLOCKER | `evidence/*.go` 42 处 | `InsertLocation` 错误 → `locID=0` → 外键违规 → 事件丢弃 | 同上 + 行号损坏 | 1（与 A 一起） |
| C | MAJOR | `evidence/detector.go` / `graph/helpers.go` | `forEachFile` 静默跳过读/解析失败文件 | 整文件证据缺失 | 2 |
| D | MAJOR | `graph/*.go` | 图构建器吞边/节点写错误 | 部分语义图 → 下游漏报 | 2 |
| E | MAJOR | `planner/registry.go` injection ConvergeKey | 去重 key 过粗，合并独立 sink | 丢失独立 finding | 3（风险最低） |
| F | MAJOR | `planner/filter_taint_source.go` | `computeDirectTaintParams` 按函数名解析，跨文件同名 static 误标 | 假阳性 + 假 confirmed | 4 |
| G | MAJOR | `planner/filter_taint_source.go` | 直接 `f(get_path())` 返回污点漏算 | 假阴性（漏报） | 5（与 F 相关） |
| H | MAJOR | `planner/filter_taint_source.go` + `null_flow.go` | `snprintf("%s:%s", a, b)` 多源拷贝塌缩 | 假阴性（漏报） | 6（改动最大） |
| I~N | MINOR | 多处 | 见"MINOR 清单" | 审计/可观测性 | 收尾 |

---

## A + B — 检测器静默吞写错误（BLOCKER，一起修）

**位置**：22 个检测器的 42 处 `InsertEvent`，以及同样多的 `InsertLocation`。代表：`dereference.go:102,111-119`、`buffer_overflow.go:140,146-154`、`null_source.go:77-86`、`sizeof_misuse.go:65,71-79` 等。

**现状**：
```go
locID, _ := d.store.InsertLocation(ctx, &db.Location{...})  // 错误吞掉，失败→locID=0
_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{..., LocationID: locID, ...})
if err == nil { result.EventsCreated++ }                    // err 只用于计数，从不日志
```

**影响**：
1. `InsertLocation` 失败 → `locID=0` → 生产库开了 `foreign_keys(1)`（`connection.go:26`），`security_events.location_id` 有 `REFERENCES locations(id)`（`schema.go:122`）→ **插入事件撞外键约束失败** → 事件被静默丢弃。
2. `InsertEvent` 失败（磁盘满、非 busy 的 SQLite 错误）→ 静默丢弃该候选，无任何日志。
3. `EventsCreated` 计数器只写不读（`detector.go:17`），是死代码。
4. `connection.go:22-26` 的注释已承认此风险，但只缓解了 `SQLITE_BUSY` 一种。

**修复方案**：
在 `evidence/detector.go` 加一个**包级共享 helper**（避免 42 处各自为政、再次漂移）：

```go
// emitEvent 插入 location + event，失败时记日志并返回 false。调用方据此跳过。
func emitEvent(ctx context.Context, store db.Store, logger *log.Logger,
    fileID int64, entityID int64, line, column int,
    eventType string, props map[string]string) bool
```

- 内部先 `InsertLocation`，**失败就返回 false**（不再产生 `locID=0` 的孤儿事件）。
- 再 `InsertEvent`，失败时 `logger.Warn("insert event failed", ...)` 并返回 false。
- 22 个检测器把 `locID,_ := ...; props,_ := ...; _,err := ...; if err==nil {...}` 四行替换成一行 `emitEvent(...)`。

**测试夹具**：用一个会触发 `InsertLocation` 失败的 mock store（返回 `(0, err)`），断言 `emitEvent` 返回 false 且**不**产生 `location_id=0` 的事件；再用一个 mock 让 `InsertEvent` 失败，断言日志被调用。

---

## C — `forEachFile` 静默跳过文件（MAJOR）

**位置**：`evidence/detector.go:52-62`、`graph/helpers.go:34-45`。

**现状**：
```go
file, err := store.GetFileByID(ctx, fid)
if err != nil || file == nil { continue }   // 静默跳过
source, err := os.ReadFile(file.Path)
if err != nil { continue }                  // 静默跳过
tree, err := p.ParseCached(source, file.Path)
if err != nil { continue }                  // 静默跳过
```

**影响**：某个已索引（有 function 行）的文件后续读失败 / 解析失败（新 C 语法、宏）时，该文件的**全部**安全证据和语义图边静默缺失，且下游（function 行还在）无法察觉。属于整文件级假阴性。

**修复方案**：`forEachFile` 回调改成能返回错误，或至少 `logger.Warn("skip file", "file", file.Path, "reason", ...)`。graph 的 `helpers.go` 同理。理想情况下把"跳过文件"计入一个计数器，最终在 scan 摘要里体现。

**测试夹具**：一个索引后不可读（或包含解析失败语法的）文件，断言有日志输出。

---

## D — 图构建器吞边/节点写错误（MAJOR）

**位置**：`graph/call_graph.go:70-72,81-83`、`graph/data_flow.go:58-69,98-105,107-115,126-143`、`graph/alias.go:71-86`、`graph/ownership.go:110-156`、`graph/interproc.go:125-161`。

**现状**：所有 `InsertGraphEdge` / `GetOrCreateGraphNode` 错误都是 `continue` / `return err == nil`，从不日志。

**影响**：部分调用图/数据流/别名/所有权图缺失 → 下游 flow 过滤器（`NullableSourceFilter`、`LifetimeFilter`、`TaintSourceFilter`、`OwnershipTransferFilter`）静默漏掉可达性/数据流 → 把真实候选误判为"无源可达"而丢弃。

**修复方案**：与 A/B 同类——给 graph 包加共享 helper，或在 `Build()` 里收集错误并 `errors.Join` 返回（`RunAllDetectors` 已做了这个范式，照抄即可）。注意 graph 构建器有并行分支，需带锁收集错误。

**测试夹具**：mock store 让 `InsertGraphEdge` 失败，断言 `Build()` 返回非 nil 错误。

---

## E — injection ConvergeKey 过粗（MAJOR，风险最低，建议先修）

**位置**：`planner/registry.go:243-245`；交互点在 `planner.go:281-284`（保留最早行，且整体替换候选）。

**现状**：
```go
ConvergeKey: func(c Candidate) string {
    return fmt.Sprintf("injection:%d:%s:%s", c.FileID, c.FunctionName, c.Category)
},
```

**影响**：同一函数内两个**独立** sink（`system(getenv("CMD1"))` 在 L10、`system(getenv("CMD2"))` 在 L20）被合并成一个 finding，第二个永远看不到。且 `deduplicateCandidates` 的"保留最早行"是**整体替换**，若早期候选是 `suspected`、后期是 `confirmed`，合并后会**丢失 confirmed + taint 证据**。

**修复方案**：把 key 加 `Line`（或 `VariableName`），同时保留"`sprintf`+`sqlite3_exec` 一个 SQL 注入的源+sink"合并意图——即把 key 从 `(file, func, category)` 改为 `(file, func, category, sinkLine)`，让源（sprintf）与 sink（sqlite3_exec）仍按 sink 行归并，但两个独立 sink 不再合并。

**测试夹具**：一个函数内两个 `system(getenv(...))` 调用，断言产出 2 个候选（不是 1 个）。

---

## F — computeDirectTaintParams 按名解析跨文件误标（MAJOR）

**位置**：`planner/filter_taint_source.go:599-632`。

**现状**：
```go
funcByName := map[string][]int64{}  // name → 所有同名函数（含不同文件、static）
...
calleeIDs := funcByName[callName(call)]  // 只按名
for _, calleeID := range calleeIDs {
    result[calleeID][i] = true           // 标记每一个同名函数
}
```

**影响**：文件 A 里的 `f(getenv(...))` 会把**文件 B 里同名 static 的 `f`** 也标成"参数被污染"，导致：假阳性（B 的 f 不该丢弃却没丢）+ 假 confirmed（挂了 taint_source 证据）。这是把 0-CFA 名字摘要用在了"丢弃决策"上的精度陷阱。

**修复方案**：`computeDirectTaintParams` 应按**文件作用域 + static 语义**消歧。最干净的做法是复用 PARAM_BINDING fixpoint 的**节点 ID 解析**（`computeParamTainted` 已用 `argFunc`/`paramFunc`/`paramIndex` 精确到节点），把"直接污染源实参"也转成图节点（或至少按 `calleeID` 的 `FileID` + `IsStatic` 过滤：static 同名函数只看同文件调用点）。

**测试夹具**：两个文件各有一个 `static void f(const char *path){ open(path); }`，文件 A 里 `f(getenv("HOME"))`、文件 B 里 `f("/etc/x")`，断言 B 的 f 被丢弃、A 的 f 被 confirmed。

---

## G — 直接 `f(get_path())` 返回污点漏算（MAJOR）

**位置**：`planner/filter_taint_source.go:619-632`（`isTaintSourceExpr(arg)` 门） + `:737-738`。

**现状**：`computeDirectTaintParams` 只认 `taintSourceFuncs` 里的字面污染源（getenv/argv/...），**不查 `retTainted`/`returnsParam`**。因此 `open_wrapper(get_path())`（`get_path` 返回 `getenv(...)`）不产生 PARAM_BINDING 边，也不被 `computeDirectTaintParams` 识别 → 静态 `open_wrapper` 被丢弃 → **假阴性**。

> 注：中间变量形式 `char *p = get_path(); f(p)` 已被 PARAM_BINDING fixpoint 正确处理（`TestTaintSourceFilter_Interprocedural` 锁住了），缺口只在**内联**形式。

**修复方案**：把 `retTainted` / `returnsParam` 传进 `computeDirectTaintParams`，标记实参时增加一条：`retTainted[callName(arg)]` 为真（或 arg 是 `returnsParam` 直通调用）也视为污染。

**测试夹具**：`char *get_path(void){ return getenv("HOME"); }` + `static void open_wrapper(const char *path){ open(path); }` + `open_wrapper(get_path())`，断言 open_wrapper 被 confirmed（不被丢弃）。

---

## H — 多源拷贝塌缩（MAJOR，改动最大）

**位置**：`planner/filter_taint_source.go:398-424`（`formatCopies`/`passthroughCopiesFor` 生成同 lhs 的多个 `copyPair`）+ `null_flow.go:154`（`copy map[string]string`）+ `null_flow.go:213-215`（后写覆盖前写）。

**现状**：`snprintf(cmd, "%s@%s", user, host)` 生成 `{cmd←user}`、`{cmd←host}` 两个 copy，但 `collectNodeEffects` 把 `copy["cmd"]="host"` 覆盖掉 `user`。`transfer` 里 `out["cmd"]=in["host"]`，于是 `user` 的污染被丢弃 → 下游 sink 漏报。

**修复方案**：把 flow 引擎的 copy 从 `map[string]string` 改成 `map[string][]string`（或 `map[string]map[string]struct{}`），`transfer` 里对多源做**并集**（`out[lhs] = union(in[rhs_i])`）。这是对 `null_flow.go` 数据结构的改动，牵一发动全身，**必须单独做 + 全量回归**（尤其 null-deref / uninit / use-after-free 的 flow 语义不能破坏）。

**测试夹具**：`snprintf(cmd, "%s:%s", tainted_user, safe_host)` → `system(cmd)`，断言 cmd 被判污染（confirmed）。

---

## MINOR 清单（收尾时批量处理）

| # | 位置 | 问题 | 建议 |
|---|------|------|------|
| I | `planner/planner.go:120-130` | short-circuit 时 `summary.Filters` 缺后续 filter 的 `0/0` 统计，形状不一致 | 补齐剩余 filter 的 skipped 统计 |
| J | `planner/filter_taint_source.go:474-484` | `computeDirectTaintParams` 错误被 `if err==nil` 吞掉，破坏 fail-closed 约定 | 与其它 summary 一致：出错返回 `candidates,nil,nil` |
| K | `cli/scan.go:247` | `InsertScanStat` 错误丢弃（无赋值） | 记日志；失败会破坏 `--write` 的 scan_id 校验 |
| L | `cli/scan.go:292,326,543-556` | `List*` 读错误吞掉，仍 `return 0` + 零计数 | 记日志或返回非 0 |
| M | `cli/plan.go:33` | `ListFunctions` 错误被吞，误报"未索引" | 把真实 DB 错误透出 |
| N | `cli/report.go:229,487` | `RewritePerFinding` 错误吞掉 | 记日志（finding 已落库，非致命） |

---

## 建议执行顺序

1. **A + B**（检测器吞错）：影响最大、最隐蔽，用共享 helper 一次性收口。
2. **E**（injection 去重 key）：风险最低、修复最独立，先摘桃子。
3. **C + D**（文件/图吞错）：跟着 A+B 的 helper 范式一起做。
4. **F + G**（污点名字作用域 + 返回污点）：互相关联，一起改 `computeDirectTaintParams`。
5. **H**（多源拷贝）：独立专项 + 全量回归。
6. **I~N**（MINOR）：收尾清账。

> 每修一项都要加对应测试夹具（见各节"测试夹具"），并在 `go test ./...` + `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 双跑绿。
