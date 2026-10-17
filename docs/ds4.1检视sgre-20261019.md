# sgre 最近修改方案代码检视清单（ds4.1）

- **检视日期**：2026-10-19
- **检视基线**：`v0.9.2 .. HEAD(be21864)`，共 12 个提交
- **变动主题**：agent-native re-review 重构（删除 `sgre/internal/review` + external-AI provider）、memory-leak / divide-by-zero / uninit 误报修复、`constant_symbols` / `global_invariants` 新增推理、report 文案调整、benchmark Phase 15/16
- **方法**：`git diff` 全量审读 + 回源验证关键项 + 实测 testdata/benchmark 行号；`go build ./...` 通过，相关单测全绿（说明下列反例路径均未被现有测试覆盖）。未跑端到端 CLI scan。
- **性质**：本清单只产出问题，修复由其他 AI Agent 执行。

---

## 零、变动概览

| 模块 | 主要变动 |
|------|---------|
| review 重构 | 删除 `sgre/internal/review/`（coordinator/payload/persist/report/reviewer/selector/types/aireview）、删除 `sgre/internal/cli/review_autoconfirmed.go`、`config.AIReview`；新增 `report --list-auto-confirmed` / `--review-json`、`extension/opencode/tools/secguard_review.ts`、agent-body/command-instructions 指令 |
| evidence | `memory_leak.go`(+150)、`divide_by_zero.go`、`uninit_variable.go`、`resource_leak.go` |
| parser | `constant_symbols.go`(+143) |
| planner | `global_invariants.go`(+102)、`filter_range.go`、`filter_uninit_flow.go`、`registry.go`(+`VulnTypesToRuleIDs`)、`return_summary.go`、`planner.go` |
| report | markdown/overview/summary 去除 "no AI review" 文案 |
| benchmark | `expected-results.json` Phase 15/16 + `p15_container_escape_fp.c` / `p16_nonzero_source_divisor_fp.c` |

---

## 一、Review 重构链路（RV）

### RV-01 · MAJOR · 已验证
**位置**：`sgre/internal/cli/report.go:954` + `:980` + `:1143`
```go
if f.Status == db.StatusAutoConfirmed {
    countsByVuln[vt].autoConfirmed++
    continue
}
```
**问题**：auto-confirmed 计数只判 `f.Status == StatusAutoConfirmed`，**不看 `FinalStatus()`**。被 re-review 判 `dismissed` 的 finding 其 `status` 仍是 `auto-confirmed`（verdict 只写进 `review_status`），于是被继续计入 `audits[].AutoConfirmed` → `buildScanOverview` 的 `ov.AutoConfirmed` → audit-report 的 `Auto-confirmed by pipeline` 与 `Actionable findings (confirmed) = totalAutoConfirmed+totalConfirmed`。而 `report.md`（`report/markdown.go:52-58` 用 `FinalStatus()` 重算）与 `result.sarif`（只含 confirmed）已正确排除 dismissed。
**影响**：同一份 scan 的 `report.md` 与 `audit-report.md`/`summary` 的 auto-confirmed、confirmed_total、dismissed 口径三处不一致；dismissed 的机器误报被当成 confirmed 计入终态数字，违反"confirmed 精准"。
**建议**：audit 计数改为以 `FinalStatus()` 为准（`confirmed && status==auto-confirmed` 才计 autoConfirmed；`dismissed` 归入 dismissed），与 `markdown.go` 统一；`ov.AIDismissed` 应把 re-review dismissed 也纳入。

### RV-02 · MAJOR · 已验证
**位置**：`extension/shared/agent-body.md`（新增 "Re-review auto-confirmed findings" 段）vs `extension/shared/command-instructions.md:474-478`
- agent-body / `secguard_review.ts` 描述：*"omit the entries you agree with (an unreviewed auto-confirmed finding stays confirmed)"*
- command-instructions：*"`--list-auto-confirmed … should return count: 0` (every auto-confirmed finding got a review_status); a nonzero count means some machine findings are unreviewed"*
**问题**：两条指令直接冲突。按 agent-body"省略同意的条目"执行，`review_status` 永远为空 → `ListAutoConfirmedForReview` 永远返回非空 → 编排按 command-instructions 校验 `count: 0` **必然失败**，误报"有未复核项"。
**建议**：二选一并对齐——要么要求 agent 对**每条**都写 verdict（含 `confirmed`），要么把编排校验改为"`count` 相对复核前下降/仅要求 dismissed 已处理"。三处（agent-body / tool description / command-instructions）须一致。

### RV-03 · MINOR · 已验证
**位置**：`sgre/internal/cli/report.go:280`（`ListAutoConfirmedForReview(ctx, scanID, ruleIDs, 0)`，limit=0 即无上限）
**问题**：`--list-auto-confirmed` 一次性返回该类型**全部** auto-confirmed findings（含 `snippet` + `reasoning`），无 limit/分页参数暴露，`secguard_review` 工具也未分批。
**影响**：auto-confirmed 规模大时单次工具返回可能撑爆 agent context。
**建议**：暴露 `--limit` 并在 agent-body 要求分批拉取。

### RV-04 · MINOR · 已验证
**位置**：`sgre/internal/cli/report.go:842`（`tx.UpdateFindingReview(ctx, in.ID, ...)`）
**问题**：`--review-json` 对任意 finding id 都更新 `review_status`，不校验该 id 是否为 `auto-confirmed`；`EffectiveStatus()` 会让任意 `review_status` 覆盖原 status。
**影响**：误传 id 可篡改非目标 finding 的终态（当前候选不落库，风险有限）。
**建议**：写前校验目标行 `status == 'auto-confirmed'`（或在 SQL WHERE 中限定）。

---

## 二、Evidence 层（memory-leak / divide-by-zero / uninit）

### EL-01 · MAJOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak.go:552`
```go
if base != "" && (!localVars[base] || allocVarNames[base]) {
    lines = append(lines, assign.StartLine())   // *container = p 判为 escape
}
```
**问题**：只要 `container` 函数内出现过分配，`*container = p` 就无条件算 `p` 的 escape；但 `container` 最终若只被 `free(container)`，并不释放成员 `p` → `p` 真泄漏被静默抑制。
**建议**：仅当 `container` 本身也 escape/transfer（被 return / 存入更大容器 / 交给 escape 函数）时才把 `*container=p` 当 `p` 的 escape。

### EL-02 · MAJOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak.go:592`（field/subscript escape 分支）
```go
if (lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression") && isMallocExpr(rhs, allocReturns) {
    base := ""
    for _, child := range lhs.NamedChildren() { if child.Kind()=="identifier" { base = child.Text(); break } }
    if base != "" && !localVars[base] { lines = append(lines, assign.StartLine()) }   // 缺 base==varName 守卫
}
```
**问题**：该分支本意是"varName 自身被存入非 local 容器"，但缺 `base == varName` 守卫（对比同函数 `:577` 的 pointer 分支有 `base == varName`）。函数体内任何无关的 `global->field = malloc()` 都会被算作**当前 varName** 的 escape，抑制其泄漏。
**影响**：`char *p = malloc(10); g->buf = malloc(20);` 中 `p` 的泄漏被抑制（false negative）。
**建议**：补 `base == varName` 守卫。

### EL-03 · MAJOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak.go:968` + `sgre/internal/apikb/apikb.go:770`
```go
if len(findEscapeLines(assigns, calls, f, v, localVars, nil, nil)) > 0 { continue }  // 判为 getter-borrow
```
`IsEscapeFunction` 用 `_add/_store/_send/_put/_push/...` 子串启发式。
**问题**：新增的 getter-borrow 判定把"`findEscapeLines` 非空"当充分条件，而 call 分支依赖宽泛命名启发式。真实 allocator wrapper 只要调用过 `log_add(p)`/`stats_store(p)`（不接管所有权）就被判 borrow → 不加入 `allocReturns` → 调用方 `x=wrapper()` 不再视为分配点 → **漏报调用方泄漏**。与 EL-02 叠加放大。
**建议**：getter 判 borrow 只认强证据（下标/字段存到非 local、赋给非 local 标识符、返回调用方）；纯命名启发式不得单独作为排除依据。

### EL-04 · MINOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak.go:968`（传 `nil, nil`）vs `:89`（传 `allocVarNames, allocReturns`）
**问题**：同一 `findEscapeLines` 两处传入不同容器/包装信息，getter 判定与 Detect 语义不一致（getter 侧 `*local容器=p` 分支不激活）。
**建议**：对齐参数或注释显式说明刻意差异。

### EL-05 · MAJOR · 已验证
**位置**：`sgre/internal/parser/constant_symbols.go:334-337`（经 `sgre/internal/evidence/divide_by_zero.go:69` 消费）
```go
case "*":  return foldNonZeroConstant(left, env) && foldNonZeroConstant(right, env)
case "<<": return foldNonZeroConstant(left, env)
```
**问题**：注释断言"两非零相乘/非零左移必非零"在固定宽度整型下不成立——`(1u<<16)*(1u<<16)` 回绕为 0，`1u<<32` 为 UB/0。会把真 `x/0` 抑制。
**建议**：折叠 `*`/`<<` 时带类型宽度与溢出/移位量判断（≥宽度即判未知）；tc80 补溢出用例。

### EL-06 · MINOR · 已验证（已知取舍）
**位置**：`sgre/internal/evidence/memory_leak.go:721`（`hasScalarBaseType` 只认 `primitive_type`/`sized_type_specifier`）
**问题**：`typedef int Status; Status st = foo_new();` 的 `type_identifier` 不进 `scalarVars`，仍可能被当分配点误报。注释已声明 fail-open。
**建议**：解析同 TU typedef→builtin 标量映射，只对"确定标量"收紧。

### EL-07 · MINOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak.go:233`（`scalarVars` 以裸名为键，无作用域）
**问题**：块级同名遮蔽（外层 `int ret;` + 内层 `char *ret = malloc()`）会被 `scalarVars[ret]` 直接 `return` 抑制，真泄漏漏报。
**建议**：键携带声明行/作用域，或遮蔽时按 fail-open 保留候选。

### EL-08 · MAJOR · 已验证
**位置**：`sgre/internal/evidence/uninit_variable.go:2010-2016`（新增 `localtime_r/gmtime_r/localtime_s/gmtime_s/strptime`）+ `:2254`
```go
case knownInit:
    initialized[name] = true   // 对所有 &identifier 实参无条件标记
```
**问题**：`knownInit` 不区分输入/输出参数——`localtime_r(&now, &tm)` 会把纯输入参数 `&now` 也标记为 initialized，掩盖 `time_t now;` 未初始化即读的真实 uninit（CWE-457）。
**建议**：把 `outputParamInitializers` 从 `函数名→bool` 升级为 `函数名→输出参数下标集合`，只标记真输出实参。

### EL-09 · MINOR · 待验证
**位置**：`sgre/testdata/tc131_uninit_macro_context.c`
**问题**：全仓库 Go 代码无引用（对应测试 `zz_uninit_macro_context_test.go` 用内联源码 + TempDir），该 fixture 不参与任何断言。
**建议**：让测试以该 fixture 为输入，或删除。

### EL-10 · MINOR · 已验证
**位置**：`sgre/internal/evidence/memory_leak_test.go:505`
**问题**：`TestMemoryLeak_ContainerEscape` 只断言"存在 MEMORY_RELEASE"，未断言"不产生 MEMORY_ALLOC(leak)"；实现若既发 release 又发 leak，测试仍通过（EL-01 场景正是缺此反向断言）。
**建议**：补 `if leakVars[...] { t.Errorf }` 反向断言。

### EL-11 · MINOR
**位置**：`sgre/testdata/tc130_memory_leak_container_escape.c` 末尾缺换行。

### EL-12 · MINOR
**位置**：`sgre/internal/evidence/divide_by_zero.go:69` `NonZero(divisor) || NonZeroExpr(divisor)` 冗余（`NonZeroExpr` 叶子分支已覆盖裸名）。

### EL-13 · MINOR
**位置**：`sgre/internal/evidence/zz_uninit_production_fp_test.go:1` 有 `//go:build !nosqlite`，而 `memory_leak_test.go` 新增测试同依赖 SQLite 却无 tag —— 同包 build tag 策略不一致。

---

## 三、Parser / Planner 层

### PP-01 · **CRITICAL** · 已验证
**位置**：`sgre/internal/planner/global_invariants.go:99` + `:114-118`
```go
target := assignTargetText(lhs)     // 裸标识符 → 变量名文本
...
targets[target] = info              // key 无 文件/函数/作用域
for target, info := range targets {
    if info.hasAssignment && info.allNonZero { inv.nonZeroVars[target] = true }
}
```
**问题**：`nonZeroVars` 的 key 是**变量名文本，跨函数/跨文件共享**。任一函数里 `d = 5;` 就使所有同名 `d` 命中 `invariants.NonZero(divisor)`（`filter_range.go:110`）被 dismiss —— `int d = x; return 10/d;` 的真除零被抑制。现有测试因 fixture 里恰好有 `d = d + 1;` 把 `allNonZero` 置 false 而"巧合掩盖"。
**建议**：key 改为 `fileID:funcName:target`，只对全局/static/结构体字段做跨函数推理；补"不同函数同名局部变量"回归用例。

### PP-02 · MAJOR · 已验证
**位置**：`sgre/internal/planner/global_invariants.go:140`
```go
if strings.Contains(text, "sizeof") { return true }
```
**问题**：把任何**含** `sizeof` 子串的 RHS 当非零源（`sizeof(A)-sizeof(B)`、`x % sizeof(int)` 可为 0），而 `NonZeroConstantValue` 已正确覆盖纯 `sizeof`。多余且危险。
**建议**：删除该行。

### PP-03 · MAJOR · 已验证
与 EL-05 同根（`foldNonZeroConstant` 的 `*`/`<<` 忽略溢出/移位越界），此处从 planner 不变量角度复述：经 `return_summary.go:190`（新增 `binary_expression` 折叠）传导到 divide-by-zero 抑制。

### PP-04 · MAJOR · 已验证
**位置**：`sgre/internal/planner/global_invariants.go:91-93` + `:123-130`（`isSimpleAssign` 只认 `=`）
**问题**：`g += k`、`g -= 100`、`g /= k`、`g++/g--` 被 `continue` 跳过而非令 `allNonZero=false`。`g=100; g-=100; x/g;` 的真除零被抑制。
**建议**：任何非 `=` 的写操作都应把 target 的 `allNonZero` 置 false。

### PP-05 · MAJOR · 已验证
**位置**：`sgre/internal/planner/global_invariants.go:90`（只扫 `assignment_expression`，忽略 `init_declarator` 初值与 calloc/静态零初值）
**问题**：`static uint32_t g = 0;` 虽初值为 0，只要后续显式赋值都非零就标 `nonZeroVars`。`zz_global_invariants_test.go` 甚至把此行为固化为"应抑制"（`g_thread_count=0`，`init_threads` 未调用时是真除零）。
**建议**：把 init 初值 / calloc / BSS 零初始化纳入评估，存在任何可能为 0 的来源即不得标非零；修正该测试的期望。

### PP-06 · MINOR · 已验证
**位置**：`sgre/internal/planner/macro_context.go:23,86-101`（`macroContextWindow = 8`）
**问题**：候选行前后 ±8 行内出现任意 ALL_CAPS 宏调用即 `MacroContext=true` → `filter_uninit_flow.go:121/154` 把本可 confirmed 的 uninit 降级 suspected。
**影响**：不过滤候选，但显著抬高 AI 复核量（过滤条件过宽）。
**建议**：要求宏调用与候选同一 AST 表达式；收窄窗口。

### PP-07 · MINOR · 已验证
**位置**：`sgre/internal/planner/filter_range.go:14-21`（类型注释）vs `:34-39`（实现注释）**自相矛盾**；`isConfigFieldDivisor`（`:276-282`）为死代码（无调用者）；测试 `TestDivideByZero_ConfigFieldConfirm`（`zz_range_filter_test.go:483`）命名与断言相反。
**建议**：修正注释、删死代码、重命名测试。

### PP-08 · MINOR · 已验证
**位置**：`sgre/internal/planner/registry.go:96`
```go
return nil, fmt.Errorf("planner: %w", err)   // GetVulnTypeSpec 已带 "planner:" 前缀
```
**问题**：错误信息重复前缀（CLI 再包一层 → `planner: planner: unsupported...`）；`CategoryCWEs` 是 map，`ruleIDs` 输出顺序不确定；无单测。
**建议**：`return nil, err`；对 CategoryCWEs 排序；补单测（含 injection 多 CWE 与未知类型报错）。

### PP-09 · MINOR · 待验证
**位置**：`global_invariants.go:289-302`（key 用 `lhs.Text()` 保留源空格）vs `filter_range.go:199-205`（`rawDivisor` 来自 event props）
**问题**：两侧空格/规范化不一致时 `invariants.NonZero(raw)` 不命中，抑制失效（保守方向）。
**建议**：统一规范化（去 `->`/`.` 两侧空格）。

### PP-10 · MINOR · 已验证
**位置**：`sgre/internal/planner/global_invariants.go:48-60` + `:75-79`
**问题**：`buildGlobalInvariants` 已 `ListFiles`+解析全部文件，`scanNonZeroSourceAssignments` 又 `ListFiles` 并新建 `fileParseCache` **重复解析全部 TU**；且 `RangeFilter.Apply` 每次全量重建。
**建议**：复用同一 `files`/`cache`。

### PP-11 · MINOR · 已验证
**位置**：`sgre/internal/parser/constant_symbols.go:322`
```go
if strings.HasPrefix(strings.TrimSpace(t), "sizeof") { return true }
```
**问题**：把标识符 `sizeof_x`/`sizeofvar` 误判为 sizeof 表达式。另 `parseConstantInt` 对超 int64 字面量返回未知（保守可接受）。
**建议**：用"关键字后随 `(`/空白/结束"判定；`ParseUint` 兜底。

### PP-12 · MINOR · 待验证
**位置**：`constant_symbols.go:343-408`（`topLevelBinaryOp` 同优先级取最左，注释未说明；未识别 `& | ^ && || == !=` 等，退回保守）。
**影响**：仅注释/覆盖范围，无正确性风险。

---

## 四、Benchmark 与测试

### BM-01 · 高 · 已验证（实测行号）
**位置**：`examples/c-vuln-benchmark/expected-results.json` 条目 `P16-01`（`line: 22`）
**问题**：p16 中 `offset / graph->gran_time` 实际在**第 32 行**（第 22 行是 `};`）。validator 容差 ±3，差 10 → 该 no_finding 守卫**完全失效**（回归时不会被判 FAIL）。
**建议**：`line` 改 32。

### BM-02 · 高 · 已验证（实测行号）
**位置**：同上条目 `P16-02`（`line: 30`）
**问题**：`index % g_thread_count` 实际在**第 42 行**（第 30 行为空行），且 30 距 field 场景（32 行）仅 2 行，落入容差会造成**误归因**。
**建议**：`line` 改 42。

### BM-03 · 高 · 已验证（实测行号）
**位置**：条目 `ML-05`（`line: 24`，`code` 描述 `pchBuf=malloc(100)`）
**问题**：pchBuf 的 malloc 实际在**第 28 行**，第 24 行是 `pduInfo` 的 malloc，差 4 > 容差 3 → container-escape 核心反证失效。
**建议**：`line` 改 28（或逃逸写行 34），与 `code` 一致。

### BM-04 · 中 · 已验证
**位置**：条目 `ML-06`（`line: 25`）
**问题**：第 25 行是 `if (!pduInfo)`，`pduInfo` malloc 在**第 24 行**；与 ML-05 的 24 行重叠、语义错位。
**建议**：ML-06 改 24，ML-05 改 28。

### BM-05 / BM-06 · 中 · 已验证
**位置**：`src/p15_container_escape_fp.c:15`（注释称 "line 24 and line 25"）与 `src/p16_nonzero_source_divisor_fp.c:13`（注释称 "lines 22 and 30"）
**问题**：两文件头注释行号与实际不符（应为 24&28 / 32&42），与 BM-01~BM-04 同源。
**建议**：同步更正注释。

### BM-07 · 中 · 已验证
**位置**：`expected-results.json:39-41`
```json
"memory_leak_cases": 6, "memory_leak_finding": 3, "memory_leak_no_finding": 3,
```
**问题**：实际 ML-01..06 为 **finding 4 / no_finding 2**（ML-01~04 finding，ML-05/06 no_finding）。`3+3=6` 表面自洽掩盖了 `finding` 少算 1（既有 stale）。
**建议**：改 `finding=4, no_finding=2`。

### BM-08 · 中 · 已验证
**位置**：`sgre/internal/cli/contract_test.go:613-664`（`TestAutoConfirmedReReviewLoop`）
**问题**：注释称经 `--review-json` 写回，实际直接调 `db.UpdateFindingReview` 绕开 CLI；全仓库**无任何测试调用 `--list-auto-confirmed`**。CLI 层 `--list-auto-confirmed`（含 `--type`→`VulnTypesToRuleIDs`、snippet、count）完全无契约测试。
**建议**：改为经 `runReportCmd` 走 `--list-auto-confirmed` + `--review-json`。

### BM-09 · 中 · 已验证
**位置**：`contract_test.go:653-663`
**问题**：断言止于 DB 状态；未验证"dismissed 不出现在 verdict SARIF"及 `syncPerFindingAfterWrite` 从 `findings/` 移除文件的端到端路径。
**建议**：补"写库→list→review-json dismissed→`report --audit`→断言 SARIF/findings 已排除"。

### BM-10 · 低
**位置**：`examples/c-vuln-benchmark/benchmark.md`（用例表止于 Phase 13）
**问题**：未同步 Phase 15/16；该文档第 390 行强调"TN 行号须离同类型 TP ≥4 行"，恰好是 BM-01/BM-02 违反的口径。
**建议**：补 Phase 15/16 小节。

### BM-11 · 低 · 既有
**位置**：`expected-results.json:6` / `:17`（`total_test_cases:131`、`expected_no_finding:55`）
**问题**：实际 `test_cases=137`（finding 74 / no_finding 63），长期少算（差 6/8），非本次引入但本次沿用。
**建议**：修正或由脚本从 `test_cases` 派生。

---

## 五、优先级建议（给修复 Agent）

1. **PP-01（CRITICAL）**：`global_invariants` 无作用域 → 高频 divide-by-zero 漏报。
2. **EL-05 / PP-03**：`*`/`<<` 折叠溢出 → 真除零漏报。
3. **EL-02 + EL-03**：memory-leak getter/escape 守卫缺失与命名启发式 → 调用方泄漏漏报。
4. **EL-08**：`localtime_r` 输入参数误标 initialized。
5. **RV-01 + RV-02**：audit 计数口径不一致 + re-review 指令矛盾（影响编排正确性）。
6. **BM-01~BM-04**：benchmark 行号错误 → 回归防线失效（修复后最能自检）。
7. **PP-02 / PP-04 / PP-05、EL-01、EL-10** 等 MAJOR 项。

---

## 六、统计与说明

| 模块 | CRITICAL | MAJOR/高 | MINOR/低 | 合计 |
|------|:--------:|:--------:|:--------:|:----:|
| RV（review 链路） | 0 | 2 | 2 | 4 |
| EL（evidence） | 0 | 5 | 8 | 13 |
| PP（parser/planner） | 1 | 4 | 7 | 12 |
| BM（benchmark/测试） | 0 | 3（高） | 8 | 11 |
| **合计** | **1** | **14** | **25** | **40** |

> 说明：EL、PP、BM 系列为源码静态分析 + testdata/benchmark 实测行号核对；RV 系列已回源验证。EL-09 / PP-09 / PP-12 标注"待验证"。当前 `go build ./...` 通过、相关单测全绿，说明上述反例路径均未被现有测试覆盖。