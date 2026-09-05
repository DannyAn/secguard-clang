# sgre 引擎源码检视报告（glm-5.3-flash）

> **基线**：commit `5b26b01`（v0.5.9）。本文所有 `文件:行号` 以该基线为准，修复时请先确认函数名匹配，不要盲信行号。
> **检视范围**：`sgre/` 全部 Go 源码（cli / planner / db / report / evidence / graph / indexer / parser / log / agent），对照 `extension/shared/` 编排契约。
> **severity 定义**：
> - `confirmed` — 已逐行核实，逻辑/行为与注释或设计不变量矛盾，必须修复。
> - `suspected` — 缺陷机制属实，但触发条件受限或影响方向为 accuracy；建议修复，至少需要防御。
> - `observation` — 非缺陷但应顺手改进（漂移风险 / dead code / 注释失真）。

**修复优先级建议**：C1 → C2 → C4 → C5 → C6 → C3 → C7 → S 组。C1/C5/C6 的错误方向是**假阴性**（漏报真实漏洞），对安全工具是最不可接受方向，优先级最高。

---

## C1 `confirmed` | buffer-overflow 常量索引分析忽略二次赋值 → OOB 漏报

**位置**：`sgre/internal/evidence/buffer_overflow.go:803-841`（`constantIndexBefore`）

**现状**：函数注释（799-802 行）声称 *"A non-literal assignment or a second assignment makes the value ambiguous (ok=false)"*，但实现做不到：

- `check` 闭包中，遇到对 `indexVar` 的赋值但 RHS **不是 number_literal** 时（821-823 行），直接 `return false`——只跳过该节点，**外层 `value/assigned` 状态不变**；
- 遇到对 `indexVar` 的**第二个字面量赋值**时（828-830 行 `if assigned { return false }`），同样只跳过，不重置状态。

**root cause**：`check` 把"该节点与我无关"和"该节点证伪我的结论"混为同一个 `return false` 出口。遍历是线性的、无路径敏感性（注释声明意图是"constant definitely holds on every path"，即任一后续重赋值都应使结论失效），但实现没有实现"证伪即失效"。

**影响**（假阴性方向）：

```c
int buf[16];
int n = 12;
n = read_index();   // 非字面量赋值被忽略
buf[n] = x;         // 判定 n==12 → 豁免 OOB，真实越界漏报

int m = 12;
m = 20;             // 第二次字面量赋值被忽略
buf[m] = x;         // 判定 m==12 → 豁免，20 越界漏报
```

**推荐修复**：引入 `ambiguous` 状态，把"对 indexVar 的赋值"单独立为判定分支：

```go
check := func(node parser.Node) bool {
    if node.StartLine() >= useLine || !funcLineRange(f, node.StartLine()) {
        return false
    }
    children := node.NamedChildren()
    if len(children) < 2 {
        return false
    }
    if assignedVariable(children[0]) != indexVar {
        return false // 与 indexVar 无关节点：跳过，状态不变
    }
    // 到这里说明是对 indexVar 的赋值：
    if assigned || children[1].Kind() != "number_literal" {
        ambiguous = true
        return true // 主动终止遍历
    }
    value, assigned = parseConstantIndex(children[1].Text()), true
    if value < 0 {
        ambiguous = true
    }
    return true
}
// ...遍历后：
return value, assigned && !ambiguous
```

**验证建议**：在 `buffer_overflow_test.go` / `overflow_sizeof_test.go` 增加上述两个 fixture（`n=read(); buf[n]` 不得豁免；`n=12; n=20; buf[16数组]` 必须报 OOB），并跑 `go test ./internal/evidence/ -run TestSecurity`。

---

## C2 `confirmed` | interprocedural treeFor 三处静默吞错 → 跨过程证据静默丢失

**位置**：`sgre/internal/evidence/interprocedural.go:199-209`（`treeFor`）

**现状**：

```go
file, _ := d.store.GetFileByID(ctx, fileID)   // DB 错误被 _ 丢弃
if file == nil { return nil }
source, err := os.ReadFile(file.Path)
if err != nil { return nil }                  // 读文件失败：无日志
tree, err := d.parser.ParseCached(source, file.Path)
if err != nil { return nil }                  // 解析失败：无日志
```

**root cause**：`treeFor` 把"查无此文件"（正常 nil）与"查询失败/读盘失败/解析失败"（异常）折叠成同一个 `return nil`。同包 `detector.go` 的 `forEachFile` 对每类 skip 都有 `logger.Warn`，此函数没有跟进——属于历史遗留路径未纳入统一纪律。

**影响**：某文件读取/解析失败时，该文件所有函数的 `paramsByFunc`/`callsByFunc` 缺失 → 跨过程 null-deref 证据（caller 传 NULL 给 unguarded 参数）静默丢失，且**日志无法追溯**，线上排查无从下手。另外失败结果不进 cache（196 行 cache 命中才返回），同一 fileID 会反复走失败路径（轻微性能浪费）。

**推荐修复**（最小改动，保持返回 nil 语义）：

```go
file, err := d.store.GetFileByID(ctx, fileID)
if err != nil {
    d.logger.Warn("treeFor: get file failed", "file_id", fileID, "error", err)
    return nil
}
if file == nil { return nil }
source, err := os.ReadFile(file.Path)
if err != nil {
    d.logger.Warn("treeFor: read file failed", "path", file.Path, "error", err)
    return nil
}
tree, err := d.parser.ParseCached(source, file.Path)
if err != nil {
    d.logger.Warn("treeFor: parse failed", "path", file.Path, "error", err)
    return nil
}
```

**验证建议**：注入一个不可读文件路径（chmod 000 或不存在），确认 scan.log 出现对应 Warn 且扫描不中断。

---

## C3 `confirmed` | memory_leak funcMap 单值 map 遮蔽同名 static 函数

**位置**：`sgre/internal/evidence/memory_leak.go:34-37`

**现状**：

```go
funcMap := make(map[string]*db.Function, len(funcs))
for _, f := range funcs {
    funcMap[f.Name] = f   // 同名函数只保留最后一个
}
```

**root cause**：C 允许不同 `.c` 文件存在同名 `static` 函数（如每个模块各自的 `buf_destroy`）。`graph/call_graph.go:35-39` 的注释已明确记录并修复过同一问题（*"a name->single-ID map silently shadows all but the last one"*），但 memory_leak 这条路径未同步跟进——两处代码演化不同步。

**影响**：RAII create/destroy 配对豁免判定（`raiiCreateFuncs`，通过 `getDestroyCounterpart` 查 `funcMap`）会查到错误（或缺失）的 destroy 函数 → create 函数被错误豁免（**漏报 leak**）或错误报告（误报 leak）。

**推荐修复**：参照 call_graph.go 的修复模式，改为多值映射；判定 destroy 存在性时按"任一同名函数"放宽，配对时优先同 `file_id` 的实例：

```go
funcMap := make(map[string][]*db.Function, len(funcs))
for _, f := range funcs {
    funcMap[f.Name] = append(funcMap[f.Name], f)
}
// destroy 存在性：len(funcMap[destroyName]) > 0 即视为存在；
// 精确配对：在同 file_id 的候选中查 freeFuncs[f.ID]。
```

**验证建议**：构造两个文件各含同名 static `obj_create/obj_destroy`，其中一份 destroy 不含 free 调用，确认豁免判定不串。

---

## C4 `confirmed` | uninit 顶层吞错 → 宏写入信息丢失引发误报洪流

**位置**：`sgre/internal/evidence/uninit_variable.go:73`（`collectMacroWrites`）

**现状**：

```go
_ = forEachIndexedFile(ctx, ...)   // 顶层错误被完全丢弃
```

**root cause**：per-file 级别的 skip 有日志（forEachFile 内部），但整次遍历的**顶层失败**（如 `ListFiles` DB 错误）被 `_` 吞掉。作者只考虑了单文件失败的可降级性，没有考虑"整体失败时降级行为等于功能关闭"。

**影响**：顶层失败一次 → `macroWrites` 整体为空 → 所有经头文件宏（`POOL_FOR`、`LIST_FOR_EACH` 类）初始化的变量全部被误报 `stack_uninit` → 误报洪流涌入 AI 审核批次，浪费 step budget（extension 编排按候选数分批，误报直接放大成本）。方向虽是误报而非漏报，但量级是"整类全灭"，不可接受。

**推荐修复**：

```go
if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(...) { ... }); err != nil {
    d.logger.Warn("collect_macro_writes: top-level traversal failed; macro-based initialization whitelist is INCOMPLETE", "error", err)
}
```

（保持降级继续的行为，但必须留下可观测记录；若希望更严格，可在该 detector 返回值中带上"whitelist incomplete"标记供编排层提示。）

**验证建议**：对 mock store 注入 ListFiles 错误，确认 Warn 落日志、扫描不中断。

---

## C5 `confirmed` | CFG：while(1) 与 for(;;) 建模不一致 → may 分析漏报

**位置**：`sgre/internal/graph/control_flow.go:390`（`buildWhileDo`）对照 `:497-504`（`buildFor`）

**现状**：

- `buildFor`（497-504 行）：`for(;;)` 无 condition 时**不加** header→join 退出边，注释精确说明原因——*"adding a header→join edge there would fabricate a path that skips the body and lets a kill inside the body be bypassed (false negative in the may analysis)"*。
- `buildWhileDo`（390 行）：`b.edge(header, join)` **无条件**添加，包括 `while(1)`。

**root cause**：`while(1)` 的 condition 字段非 nil（是 `parenthesized_expression` 包裹的 `number_literal 1`），因此搬用 `buildFor` 的 `if cond != nil` 判断并不能自动解决——需要额外的**常量真**识别。`while(1)` 与 `for(;;)` 在 C 中语义完全等价，作者在 buildFor 处已想清楚 phantom 退出边的危害，但 while 分支没有应用同样的推理。

**影响**：`while(1) { ...kill... }` 循环体外的消费点会经由 phantom 退出边"看到"body 内的 kill 被绕过 → `hasLeakingPath`（memory-leak）、`hasUnassignedPath`（uninit）、`null_flow` reaching 分析得到与等价 `for(;;)` 代码不一致的结论，方向**漏报**。

**推荐修复**：在 `buildWhileDo` 中识别常量真条件，为真时不加退出边：

```go
// while_statement 的 condition: parenthesized_expression → 内层数字/表达式
cond := stmt.ChildByFieldName("condition")
if !isConstantTrue(cond) {
    b.edge(header, join) // condition false → exit loop
}
```

`isConstantTrue` 最小实现：剥开 `parenthesized_expression` 后，`number_literal` 值非 `0` 即真（覆盖 `while(1)`/`while(2)`）；其余情况保守返回 false（加退出边，over-approximation 安全方向）。注意 `break` 经 `breakTo` 栈直达 join，不受退出边缺失影响。

**验证建议**：同一 kill-inside-infinite-loop 场景分别用 `while(1)` 与 `for(;;)` 构造 fixture，断言 planner 结论一致（跑 `go test -tags nosqlite -bench=. ./internal/planner/` 回归收敛基线）。

---

## C6 `confirmed` | indexer 单文件索引非原子 → 崩溃窗口产生永久假阴性

**位置**：`sgre/internal/indexer/indexer.go:103-123`（`indexFile`）

**现状**：文件变更时的处理顺序：

1. `UpdateFileChecksum`（103 行）— 写入新 checksum；
2. `DeleteFunctionsByFile`（110 行）— 删旧函数；
3. 逐个 `InsertFunction`（152 行）— 插新函数。

三步**无事务包裹**，且 `UpdateFileChecksum` 失败仅 Warn 不回滚流程。

**root cause**：增量索引以 checksum 为跳过依据，但 checksum 更新与内容重建是两个独立写操作。进程在 1 之后、3 完成前崩溃/被 kill（agent 场景下并不罕见），DB 中留下"checksum 已新、functions 不完整"的状态；下次扫描 `existing.Checksum == checksum` 命中（95 行）**永久跳过**——没有任何自愈机制。

**影响**：受影响文件的部分函数从此缺席索引 → graph/evidence/detector 全链路对它们不可见 → **永久性检测假阴性**，且无任何告警。

**推荐修复**：用 `db.Store` 已有的 `WithTx`（`cli/report.go:488` 已在用）把单文件重建包成原子操作，事务内任一步失败即整体回滚（回滚后 checksum 保持旧值，下次扫描自动重试，方向正确）：

```go
err = idx.store.WithTx(ctx, func(tx db.Store) error {
    if err := tx.UpdateFileChecksum(ctx, existing.ID, checksum, loc); err != nil {
        return err // 失败即中止：不再带病继续删/插
    }
    if err := tx.DeleteFunctionsByFile(ctx, existing.ID); err != nil {
        return err
    }
    for _, fnNode := range funcNodes { ... tx.InsertFunction(ctx, funcRecord) ... }
    return nil
})
```

注意两点：(1) 现有 152-158 行"单条 InsertFunction 失败仅 Warn+continue"的行为在事务内应改为返回错误（部分插入的文件宁可下次重扫）；(2) 解析 tree 需在事务外先完成（避免长事务持锁）。

**验证建议**：测试中在 InsertFunction 第 N 条注入错误，断言事务回滚后 `GetFileByPath` 的 checksum 仍为旧值、functions 表无残留行，下次索引重新全量重建。

---

## C7 `confirmed` | planner ListFiles 吞错，违反同文件确立的 fail-closed 哲学

**位置**：`sgre/internal/planner/planner.go:229-234`（`Plan`）

**现状**：

```go
filePathByID := map[int64]string{}
if files, ferr := p.store.ListFiles(ctx); ferr == nil {   // ferr 被静默丢弃
    for _, f := range files { filePathByID[f.ID] = f.Path }
}
```

**root cause**：同一文件 262-265 行刚写明批量加载的纪律——*"A batch load failure must not be swallowed: with nil maps every seed candidate loses its FunctionName/FileID/Line ... Fail the type instead. 不允许报告无位置的缺陷"*。`ListFiles` 是同一性质的批量加载（丢失的恰是定位所需的文件路径），却走了相反的 fail-open。两段代码相距 60 行、注释相互引用，属于同一作者两种哲学并存。

**影响**：`ListFiles` 失败 → 所有候选 `Target.File == ""` → 下游连锁：`autoConfirmFindings` 跳过（见 S2）、`scopeToTarget` 全保留、per-finding markdown 无法落盘、AI 收到无定位的候选。与 S2 叠加时 pipeline-proved 的 confirmed 候选**整体静默消失**。

**推荐修复**：与 funcsByID/locsByID 同样处理，fail 该 type：

```go
files, ferr := p.store.ListFiles(ctx)
if ferr != nil {
    return nil, fmt.Errorf("planner: list files: %w", ferr)
}
```

**验证建议**：mock store 注入 ListFiles 错误，断言 `Plan` 返回错误（planErrors 有该 type 记录）而非产出空路径候选。

---

## S1 `suspected` | InsertEvent 无应用层 busy retry

**位置**：`sgre/internal/db/crud_events.go:10-22`；对照 `connection.go:29-30` 的注释声明

**现状**：`withBusyRetryID` 只覆盖 `InsertFinding`/`UpsertFinding`；`InsertEvent` 直接 `ExecContext`，仅靠 `busy_timeout(10000)`。而 `connection.go` 注释宣称 *"the application-layer retry in UpsertFinding/InsertFinding engages"*，未提 events。

**风险场景**：`RunAllDetectors` 以 4 并发跑 detector（`evidence/registry.go:48-49`），加上 graph builder 尾部写入，WAL 单写者竞争下若 10s 耗尽，`emitEvent`（`detector.go:127-154`）Warn 后丢弃该条事件——安全证据静默丢失（有日志、无 metric、无重试）。

**推荐修复**：与 findings 一致，包一层重试（成本极低）：

```go
return withBusyRetryID(ctx, 3, func() (int64, error) { ...原有逻辑... })
```

同时把 `connection.go:26-30` 注释中 "InsertEvent errors are swallowed" 的历史描述更新为现状。

---

## S2 `suspected` | autoConfirmFindings 静默跳过无坐标候选

**位置**：`sgre/internal/cli/scan.go:500-502`

**现状**：

```go
if c.Target.File == "" || c.Target.Line <= 0 {
    continue   // 不写库、不回流、无日志
}
```

**root cause**：防御式分支把"无效候选"当成不可能发生的数据，直接丢弃。但 C7/S8 表明 `Target.File == ""` 在上游读失败时是**批量发生**的，此时该分支等于把整批 pipeline-proved 的 confirmed 候选静默蒸发——既不在 findings，也不在候选文件里。

**推荐修复**：无效坐标候选不丢弃，回流 AI 复核并留日志：

```go
if c.Target.File == "" || c.Target.Line <= 0 {
    if logger != nil { logger.Warn("auto-confirm skipped: candidate has no location", "vuln_type", vulnType, "event_id", c.DerefEventID, "variable", c.VariableName) }
    unwritten = append(unwritten, c)   // 复用现有降级回流通道
    continue
}
```

（调用处 `scan.go:202-208` 已把 `autoUnwritten` 追加回 `needsReview`，无需改动。）

---

## S3 `suspected` | scopeToTarget 的 isUnder 对路径形式不对称

**位置**：`sgre/internal/cli/scan.go:578-595`

**现状**：`it.Target.File == ""` 的候选**保留**（581 行），但 `filepath.Rel` 失败的候选**丢弃**（`isUnder` 返回 false）。已核实 indexer 从 `filepath.Abs` 起 walk、候选 file 为绝对路径，正常运行不触发；但一旦未来 Target.File 来源改变（或混合分隔符），`Rel` 失败即成批量假阴性源，且方向与空路径分支相反。

**推荐修复**：`isUnder` 在 `Rel` 失败时退化为前缀比对而非丢弃：

```go
rel, err := filepath.Rel(dir, path)
if err != nil {
    return strings.HasPrefix(path, dir+string(filepath.Separator))
}
```

---

## S4 `suspected` | dedup 合并可能用低 suspicion 覆盖 confirmed

**位置**：`sgre/internal/planner/planner.go:343-360`（`deduplicateCandidates`）

**现状**：同 `dedupKey` 的候选按 `c.Line < result[idx].Line` 保留**行号较小**者，不比较 `SuspicionLevel`。在带 `CategoryConfidence`（detector-proved 类别 → confirmed）且用默认 key 的类型上，存在"行号小的 possible 覆盖行号大的 confirmed"的可能——confirmed 候选降级为 needsReview，auto-confirm 通道漏掉本应机器证实的缺陷。

**触发面**（已核实）：现有 20 类中仅 buffer-overflow / sizeof-misuse / signed-compare 等少数类型同时具备 `CategoryConfidence` + 默认 dedup key，且需同 (file,line,function,variable) 双事件异类别，触发面窄但机制存在。

**推荐修复**：合并时先比 suspicion 等级（confirmed > suspected > possible），等级相同再按行号保留较早者。可在 `planner` 内加一个 `suspicionRank(s string) int` 纯函数。

---

## S5 `suspected` | buildDo 的 firstID 快照在首语句不建节点时错连

**位置**：`sgre/internal/graph/control_flow.go:402-438`

**现状**：`pre := len(b.cfg.Nodes)` 在 `b.build(s, last)` 之前取快照，假设 build 一定创建新节点。但 `labeled_statement`、空体 `case_statement` 等语句可能直接 `return from` 不建节点，此时 `firstID = pre` 指向的是**后续语句才创建**的节点，`b.edge(cond, firstID)` 回边错连。

**影响**：do-while 罕见形态下 CFG 边错连，`Reaches` 判定失真（以误报方向为主）。

**推荐修复**：仅在节点数实际增长时更新 firstID：

```go
pre := len(b.cfg.Nodes)
next := b.build(s, last)
if first && len(b.cfg.Nodes) > pre {   // 该语句确实创建了入口节点
    firstID = pre
    first = false
}
```

---

## S6 `suspected` | walkNode 缺少 null-node 防护（cgo segfault 风险）

**位置**：`sgre/internal/parser/parser.go:316-331`

**现状**：包内 `isNull()`（148-150 行）的注释明确警告：对 null node 调用 `Kind()/Children()` 会 cgo segfault 且 **recover 无法捕获**；所有包装方法都有 isNull 前置检查。但 `walkNode` 直接调用 `node.node.NamedChildCount()`，是唯一没有防护的遍历入口。

**现状安全性**：当前调用方传入的 root 均来自真实 tree，不触发；但 `planner/null_flow.go` 的 fileParseCache 正是 null node 的已知来源（isNull 注释自述），未来 flow-filter 式新调用一旦传 null 即进程级崩溃。

**推荐修复**：`walkNode` 入口加 `if node.node.IsNull() { return }`（或包内等价检查），并补一条与 isNull 注释一致的警示注释。

---

## S7 `suspected` | --write 单条路径的 status 校验弱于 --write-json

**位置**：`sgre/internal/cli/report.go:267`（单条）对照 `:444-452`（批量）

**现状**：

- `--write-json` 批路径：严格三态白名单（confirmed/suspected/dismissed），`false-positive` 同义归一化，非法值拒绝整批（444-452 行，注释明确说"pipeline 中间态 open 立即拒绝"）。
- `--write` 单条路径：仅 `strings.ToLower`（267 行），无白名单。schema CHECK 兜底（status IN 五值），但 **`open` 本身在 CHECK 白名单内**——AI 经单条路径可写入"无判定"的中间态 finding。

**root cause**：两条写路径由不同迭代加入（批路径晚于单条），新纪律只在批路径落地。

**推荐修复**：把批路径的 status switch 抽成共享函数（如 `normalizeAIVerdict(raw string) (string, error)`），`--write` 单条路径复用；非法值 `WriteErrorJSON` 返回 1。

---

## S8 `suspected` | --write-json 批处理 ListFiles 吞错 → 路径解析静默退化

**位置**：`sgre/internal/cli/report.go:414`

**现状**：

```go
allFiles, _ := store.ListFiles(ctx)
```

**影响**：ListFiles 失败 → `resolveFindingFilePath`（478 行）拿不到索引文件列表 → 相对/截断路径**原样入库**（160-180 行的退化分支），与 `uq_finding_loc` 幂等键中的绝对路径变体产生重复行，result.sarif/xlsx 双计同一缺陷（`dedupeAndNormalizeFindings` 的注释 186-188 行描述的正是这类历史事故）。

**推荐修复**：fail-fast（写操作幂等，重跑安全）：

```go
allFiles, ferr := store.ListFiles(ctx)
if ferr != nil {
    WriteErrorJSON(fmt.Sprintf("failed to list files for path resolution: %v", ferr))
    return 1
}
```

---

## S9 `suspected` | isLoopBoundOverflow 复合条件提取所有数字 → 误报

**位置**：`sgre/internal/evidence/buffer_overflow.go:896-909`

**现状**：`extractNumbers(condText)` 对循环条件做全文数字提取，`i < N && flag > 5` 中与索引无关的 `5` 也参与"任一数字 ≥ arrSize 即判 OOB"的判定。

**推荐修复**：只处理单一关系比较（无 `&&`/`||`）的条件；复合条件保守返回"不确定"（不做越界判定，交给其他 filter），避免无关数字触发误报。

---

## O1 `observation` | status 命令硬编码辅助事件类型列表

**位置**：`sgre/internal/cli/scan.go:675-682`

`runStatusCmd` 在 `planner.AllSeedEventTypes()` 之外硬编码 `[]string{"NULL_VALUE","NULL_GUARD","MEMORY_RELEASE","RESOURCE_RELEASE","VALUE_INIT"}` 追加计数。已核实与 seed 集合（19 种）**无交集、不重复计数**，当前正确；但列表写死在 cli 层，未来 evidence 层新增辅助事件类型时必然漂移。建议移入 planner 包导出（如 `planner.AuxEvidenceEventTypes()`），与 AllSeedEventTypes 并列维护。

## O2 `observation` | agent.WriteFinding 是绕过 UPSERT 协议的 dead code

**位置**：`sgre/internal/agent/finding.go:18-31`

`WriteFinding` 在整个仓库（含测试）**无任何调用方**，且内部走 insert-only 的 `InsertFinding`——若未来被误用，并发写同 key 时会撞 `uq_finding_loc` 唯一约束报错（而非幂等 upsert）。建议直接删除；若保留，加 `// Deprecated: use cli report --write-json (UpsertFinding) instead` 注释。

## O3 `observation` | 两处并发模型注释失真

- `sgre/internal/cli/pipeline.go:160-164`：称 callReachCache 是 "the sync.Once cache"，实际实现是 `sync.Mutex + done flag`（`filter_call_reach.go:29-47`，语义等价且支持失败重试）。
- `sgre/internal/parser/parser.go:62-65`：称 "the planner lifetime filter follows that pattern"（指无锁 `Parse()`），实际 planner 全部 filter 走 `ParseCached`。

线程安全性本身**已验证属实**，仅注释描述与实现脱节，顺手更正避免误导后续维护者。

---

## 修复纪律提醒（与仓库既有约定对齐）

1. **吞错红线**（AGENTS.md）：`InsertEvent`/`InsertFinding`/`Build` 的写错误不可静默吞掉——C2/C4/C7/S1/S2/S8 均属此类，修复时一律"有日志、可降级、可追溯"三选一起步。
2. **方向哲学**：过滤器/分析失败的 fail-open（假阳性方向）可以接受（`planner.go:174-180` 既有模式）；数据读取失败的 fail-closed（fail-fast 该 type）是 `planner.go:262-265` 已确立的纪律。修复时不要把两者混用。
3. **测试要求**：`sgre` 的 nosqlite 子集命令 `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 必须保持绿色；evidence/graph 修复需带 fixture（testdata/tc*.c 模式）；C5/C6 修复需回归 `go test -tags nosqlite -bench=. ./internal/planner/` 收敛基线。
4. **不新增并行 CWE/事件类型映射表**：O1 的修复应导出自 planner，不要在 cli 层再加一份静态列表。