# GLM5.3 sgre 检视结果 —— candidates → AI Agent 研判举证链路专项

- **基线**：`173cadc`（fix(unchecked-return): 全局变量存 _new 工厂函数误报）
- **检视日期**：2026-10-16
- **检视范围**：候选（candidates）交给 AI Agent 研判的举证链路——`detector props → DB SecurityEvent → planner Candidate → EvidenceItem/Hint → candidates/<type>/_index.md + NNN_*.md → MCP 工具层 → 指令文件（command-instructions.md / agent-body.md / SKILL.md）→ AI 研判 → report --write-json 回写`
- **方法**：只读源码区（`sgre/`、`extension/shared/`、`extension/opencode/`），全链路静态走查 + 指令承诺与实现的逐条回源比对；`go build ./...` 与 `internal/report`、`internal/planner` 包测试全绿作为基线背书。**端到端扫描未跑**，所有行号引用以 HEAD 为准。
- **核心结论**：链路架构（表格先行、Hint 预判、证据文件兜底、≤5 source-read 预算、二元判决）是健全的；主要缺口集中在**"管线已算出的语义事实没有送达 AI"**与**"指令承诺与实际证据不符"**两类，共 11 项（1 CRITICAL / 5 MAJOR / 5 MINOR），每项都直接影响 AI 研判的 confirmed/dismissed 准确度。

---

## 一、举证链路全景（检视时实证的现状）

```
C 源码树
  │ secguard scan（cli/scan.go runPipeline：index → graph → detectors）
  ▼
DB 种子 SecurityEvent（detector 写 props：expression/variable/category/…）
  ▼ planner.seedCandidatesByType（planner/planner.go:288，props.go 解析后装进 Candidate）
  ▼ FilterChain 多层收敛 → dedup → Rank（不截断）
  ▼ newEvidenceItem（planner/evidence_package.go:200）
  │    ├─ spec.BuildEvidence(c)   → []EvidenceFragment（registry.go 26 处闭包）
  │    ├─ buildHint(c, spec)      → Hint 事实串（evidence_package.go:115）
  │    └─ Target{File,Function,Line,Variable} + Signature + Contract
  ▼ cli/scan.go:249 splitBySuspicion
  │    ├─ confirmed && !macro-context → autoConfirmFindings（直接落 findings 表，不进候选）
  │    └─ suspected / possible / macro-context / 写失败回流 → needsReview
  ▼ report/markdown.go writeCandidates + writeTypeIndex
  │    ├─ candidates/<type>/NNN_<file>_<line>.md（9 个 section）
  │    └─ candidates/<type>/_index.md（# | Function | File:Line | Variable | Suspicion | Hint | Source | Evidence 表格）
  ▼ MCP secguard_scan 返回 output_dir + 计数（候选明细刻意走文件系统，不进上下文）
  ▼ AI 子代理：_index.md 表格行研判 → Hint 不足开候选文件（±8 行 Code Context）→ 仍不足 ≤5 次 source read
  ▼ secguard report --write-json（normalizeAIVerdict 二元化：confirmed | dismissed，suspected 强制归 dismissed）
  │    ├─ confirmed → UPSERT findings → findings/<type>/NNN_*_confirmed.md + annotateCandidate 回注
  │    └─ dismissed → 不入库，仅 annotateCandidate 注记回候选文件
  ▼ secguard report --audit 终审 → report.md / result.sarif / result.xlsx
```

AI 实际能看到的举证，全部由三处 Go 代码决定：
1. `_index.md` 表格行（`markdown.go:309-336`）：单行 Source、Hint 串、Suspicion；
2. 候选文件（`markdown.go:220-301`）：±8 行 Code Context（`snippet.go:29`）、Location（含 Signature）、Failure Contract（仅 unchecked-return）、Evidence fragments；
3. ≤5 次原始 source read 兜底。

**这正是本轮所有问题的落点：管线的语义分析成果（区间、guard、taint 链、callee 契约）只有被"翻译"进这三处才能影响研判准确度，翻译层的遗漏 = AI 看不见 = 白算。**

---

## 二、问题清单

### E-01 [CRITICAL] 指令承诺 integer-overflow 全函数窗口，实现是统一 ±8 行 —— AI 被系统性误导

| 项 | 内容 |
|---|---|
| 承诺处 | `extension/shared/command-instructions.md:402-407`："**integer-overflow** embeds the WHOLE function span (signature → candidate, up to ~200 lines)… it never exceeds ~200 lines, so opening it cannot exhaust your context"；`extension/shared/agent-body.md:101`："the WHOLE function span for `integer-overflow`, whose verdict needs the parameter types, the entry guard…" |
| 实现处 | `sgre/internal/report/markdown.go:261` 对**所有**类型统一传 `candidateContextLines`（`snippet.go:29`，=8），无任何 per-type 分支；`candidateContextLines` 的注释（snippet.go:22-28）也只描述了统一小窗口的动机 |
| 矛盾处 | `extension/shared/skills/integer-overflow/SKILL.md:54` 自述 "`## Code Context` (±8 lines)" —— **三个指令源两个说全函数、一个说 ±8，互相矛盾；实现是 ±8** |
| 影响 | integer-overflow 的研判恰恰最依赖函数全貌：SKILL 的判定规则（`guard@none + rhs@param` → confirm 除非跨函数不变量）要求核对**函数入口 guard** 与**操作数累积链**，而 BuildEvidence（`registry.go:647-656`）只有 2 条泛泛 fragment（"unsigned subtraction can underflow…" + call_path），Hint 的 `lhs@/rhs@` 只有来源**分类**（param/local/deref）而无表达式**文本**。±8 窗口装不下"signature → candidate"链。结果是：读了两份顶层指令的 AI 预期证据充分、实际打开才发现不足，要么在残缺证据上硬判（FP/FN 双向风险），要么把 integer-overflow 的 source-read 预算率先耗尽（挤占其他候选的兜底机会） |
| 修复方向 | 推荐**实现侧补齐**而非改指令：`writeCandidates` 对 integer-overflow 用函数 span 窗口（函数起止行在 Functions 表已有，`maxContextLines=200` 上限现成，`snippet.go:32`）；SKILL.md:54 同步改口径。若走指令侧回退（删掉 whole function 承诺），则 SKILL 的"Signature/Source columns are your inputs before any raw source READ"规则实际不可执行，研判质量仍受限 |

### E-02 [MAJOR] out-of-bounds 的 BuildEvidence 断链：props → Candidate 已通，渲染层全丢弃

| 项 | 内容 |
|---|---|
| 链路断点 | detector 侧 `emitOOB`（`evidence/buffer_overflow.go:877-890`）props 写齐 `array` / `index` / `expression` / `size`；planner 侧 Candidate 也装载了 `Array/Index/Size`（`planner/planner.go:410-412`）；但 out-of-bounds 的 `BuildEvidence`（`planner/registry.go:776-781`）只输出 2 条泛泛 fragment（"out-of-bounds access in function %s at line %d" + call_path），**不引用任何一个已装载字段** |
| 对照 | 同一 detector、同一 BUFFER_ACCESS 事件源分流的 buffer-overflow 类型，其 BuildEvidence（`registry.go:395-419`）渲染 buffer（容量）/index/copy_size/dst_capacity/size_argument 全套条件 fragment——这是 dfaafab（候选 md 证据丰富化）只富化了 9 类、**漏了 out-of-bounds** |
| 影响 | OOB 的 `array_oob_read/heap_oob_read` 是 CategoryConfidence=confirmed，多数走 auto-confirm 不受影响；但 **macro-context 的 OOB 候选会回流 AI**（`scan.go:594-603` 的 splitBySuspicion 只对 confirmed && !MacroContext 走机器确认），此时 AI 判断 `arr[i]` 是否越界所需的 array 名、容量、index 表达式**全部缺失**，只有一句无信息量的"out-of-bounds access"——macro-context 恰是 FP 风险最高、最需要证据的类型 |
| 修复方向 | OOB 的 BuildEvidence 对齐 buffer-overflow：输出 `buffer: %s (capacity: %d)` 与 `access index: %s` fragment（字段现成，纯渲染层补齐） |

### E-03 [MAJOR] unchecked-return `contract@unknown` 要求 AI 证明 callee 契约，却不给 callee 定义定位

| 项 | 内容 |
|---|---|
| 指令要求 | 三方一致地要求："Prove the callee returns a failure sentinel (NULL / -1 / error code) on the unchecked path. If you cannot prove it from the Code Context, **dismiss**"（候选文件 Failure Contract 段 `markdown.go:273`、_index.md 引导块 `markdown.go:320-321`、`skills/unchecked-return/SKILL.md` Failure Contract 表） |
| 举证现实 | 事件 props 只有 `function`（callee 名）/`expression`/`category`/`contract_known`（`evidence/unchecked_return.go:228-232`）；BuildEvidence（`registry.go:813-818`）只有 callee 名 + call_path。**callee 的定义 file:line、函数签名、函数体均不在证据里**。callee 是跨文件 static 函数时（企业代码常态：`obj_pool_new` 定义在 pool.c，调用在 server.c），±8 行 Code Context 物理上证明不了 callee 行为 |
| 影响 | AI 只能消耗 ≤5 次 source read 去定位 callee 定义；预算耗尽按指令只能 dismiss —— **contract@unknown 候选面临系统性 FN（真实失败工厂函数被批量误 dismiss）**，或者 AI 违规凭名字猜测（FP）。这与 173cadc 刚修复的"_new 工厂函数误报"是同一片雷区：管线把最难证的候选推给 AI，却没给定位材料 |
| 修复方向 | planner 侧复用 `funcsByID` 批量 join 模式（`planner.go:312` 已有先例）解析 callee 定义：callee 是本项目函数时，fragment 附 `callee %s defined at <file>:<line> (signature: …)`；callee 是外部库函数时显式标注 `external callee, no body in scan`，让 AI 明确知道该走 apikb/外部知识而非死磕源码 |

### E-04 [MAJOR] divide-by-zero 的语义分析成果零传递：区间引擎算了等于白算

| 项 | 内容 |
|---|---|
| 管线已有能力 | detector 在发射前完成 4 层语义排除（`evidence/divide_by_zero.go:60-97`）：NonZeroExpr 常量折叠、浮点除法豁免、`divisionGuarded` guard 识别、`bounds.NonZeroAt` 区间非零证明。planner 侧还有 RangeFilter 的 definite-zero auto-confirm 与跨函数非零 summary |
| 证据现实 | 通过排除后落入 props 的只有 `expression/divisor/variable/category/definitely_zero` 四键（`divide_by_zero.go:100-108`）；BuildEvidence（`registry.go:798-803`）只输出 2 条泛泛 fragment。**除数的取值区间（如 `d ∈ [1, +inf)` vs `d ∈ [0, +inf)`）、"被调方保证非零"的跨函数 summary、guard 存在但被判 weak 的条件文本——这些真正能一锤定音的事实一条都没进证据** |
| 影响 | AI 拿到的举证信息量与 detector 的语义能力严重不匹配：除已知 `divisor@bare/call/compound` 形状外，只能靠 Source 列单行（`a / b`）+ ±8 窗口重推管线已经算过的东西，或直接 dismiss。对"区间上界为正"这类可判定候选产生系统性 FN，对"区间含 0 但被调方 summary 保证非零"的候选产生 FP |
| 修复方向 | detector 把已算出的区间结论写入 props（如 `divisor_range=[1,+]`、`nonzero_summary=gurantees_nonzero`），BuildEvidence 渲染成 fragment；至少把 `bounds.NonZeroAt` 判定失败时的区间事实带上 |

### E-05 [MAJOR] taint 类 fragment 自相矛盾：让 AI 在 ±8 窗口里找不在窗口里的东西

| 项 | 内容 |
|---|---|
| 矛盾指令 | injection / format-string / path-traversal 的 taint_source fragment 一律写 "user-controlled value (from getenv/scanf/recv/argv or similar taint source — **identify the specific source in Code Context**) reaches the sink at line %d"（`registry.go:484/616/834`） |
| 举证现实 | 污点源行（`SourceLine`，Hint 里的 `src@N`）距离 sink 完全可能超过 8 行——跨函数传播时甚至在**另一个函数**。±8 窗口物理上看不到 N 行；`filter_taint_source.go` 的 taintSummary fixpoint（returnsParam/retTainted/paramTainted）明明算出了跨函数污点链，但链路细节不进任何证据 |
| 影响 | AI 按指令在窗口里找污点源 → 找不到 → 以为证据不存在 → 按指令只能 dismiss（或违规猜）。跨函数 taint 候选（恰恰是真实 injection 的主体形态）面临系统性 FN |
| 修复方向 | fragment 携带确定事实而非探索指令：`taint source at line N: '<该行文本>'`（report 侧 `sourceLineText` 现成可取）；跨函数时附传播链摘要（`param #i of f ← tainted return of g`，taintSummary 已有此数据） |

### E-06 [MAJOR] Code Context 只锚定 Target.Line，"源→汇"区间不覆盖

| 项 | 内容 |
|---|---|
| 现状 | 候选文件的 Code Context 一律围绕报告行 ±8（`markdown.go:261`）。而多类候选的**决定性源行**在另一处：use-after-free 的 `FreeLine`、double-free 的 `FirstFree/SecondFree`、uninit 的 `DeclLine`、null-deref 的 `SourceLine`、implicit-contract 的 guard 行。fragment 有行号文字（"free(%s) at line %d"，`registry.go:554-558`）但**无源码**——距离 >8 行时（长函数里 free 与 use 相隔几十行是常态）AI 只能信管线的文字描述，或耗一次 source read 去核对源行 |
| 讽刺点 | dfaafab 已把这些行号字段全部传到了 Candidate（FreeLine/FirstFree/SecondFree/DeclLine…），**只差 markdown.go:261 渲染窗口时用它们**——数据到了最后一公里没接 |
| 影响 | 每个远距离源候选多耗 0~1 次 source read（预算挤压），或在未核对源码时误信/误弃文字描述（FP/FN 双向） |
| 修复方向 | 窗口升级为 span 策略：源行存在且 ≠ Target.Line 时取 `[min(src,sink)-3, max(src,sink)+3]`（clamp 到 maxContextLines）；或渲染双窗口（sink 窗口 + source 窗口）。Hint 的 `src@N` 与 Code Context 的可见性从此自洽 |

### E-07 [MINOR] Source 列单行截取 + props.Expression 丢弃：多行语句失真

- `sourceLineText`（`snippet.go:206-219`）只取目标行**单行**；企业代码 80 列换行惯例下，多实参调用在 _index.md 里只剩首行（`memcpy(dst,\n  src,\n  n)` 只见 `memcpy(dst,`）。
- detector 已把跨行完整语句原文存入 `props.expression`（`call.OriginalText()`，如 `unchecked_return.go:230`），但 planner 只把它用作 varName fallback（`planner.go:364-367`），**不进 EvidenceItem、不进候选文件**。
- unchecked-return 类型因 props 无 `variable` 键，Variable 列实际就是 expression 文本（fallback），再叠 `markdownCell` 120 字符截断（`markdown.go:368-370`）——Variable 列与 Source 列双重失真。
- 修复方向：EvidenceItem 增加 `Expression` 字段（从 props 直传），候选文件 Location 段渲染完整表达式；Source 列可保留单行（表格紧凑性优先）。

### E-08 [MINOR] Hint 的 `api@` 排在 token 串尾部，最易被 120 截断丢弃

- `buildHint` 拼接顺序（`evidence_package.go:170-193`）：类型专属 → `src@N` → null 确定性 → `tainted` → `weak-guard` → `macro-context` → **`api@<name>` → `cat@<name>`**。
- unchecked-return 的 hint 最长（`contract@unknown src@123 maybe-null api@obfuscated_pool_allocator_factory cat@unchecked_return`），而 `api@`（callee 名）恰是该类型研判的核心输入，排尾部极易被 `markdownCell` 的 120 截断吃掉。
- 修复方向：`api@` 提前到类型专属 token 之后；或 Hint 列渲染单独放宽限额（120 是给 Source 列设计的，Hint 是研判核心不应同限）。

### E-09 [MINOR] Code Context 静默缺失，无任何降级提示

- `readCodeContext` 返回 nil（文件不存在 / 行号超界，`snippet.go:124-141`）时，候选文件的 `## Code Context` 整段静默消失；同场景 Source 列也为空串。候选仍留在 _index.md 表格里，AI 无从得知"为什么这个候选没有源码"。
- 触发场景：扫描与研判之间源文件被改动（行号漂移）、多 root 解析失败。对 diff/增量扫描工作流这是现实风险。
- 修复方向：缺失时渲染一行 `- source unavailable at index time (file changed since scan?)`，让 AI 明确知道证据缺失而非误以为该候选无源码语义。

### E-10 [MINOR] hardcoded-secret name-only 候选不携带字面值

- props 已存 `value`（三个发射分支都写，`hardcoded_secret.go:73-77/221-225/255-259`），但 Candidate / EvidenceItem 无对应字段，`match_kind` fragment（`registry.go:704-709`）只说 "judge whether it is a real credential, a placeholder, or a test value"——判断 placeholder（`"REPLACE_ME"`/`"test123"`）最需要的**值**缺失。
- 缓解：Source 列通常包含该行（值就在声明行内）单行可见；多行结构体初始化器场景失效。
- 修复方向：BuildEvidence 加 value fragment（注意脱敏：只展示前缀 + 长度/熵特征，不回显完整 secret）。

### E-11 [MINOR] null-deref SKILL 的 Evidence Pattern 与 BuildEvidence 漂移

- SKILL 列举 5 种 fragment（nullable_source/caller_null/call_path/data_flow/guard，`skills/null-deref/SKILL.md:33-40`），实际输出还有 **definite_null**（`registry.go:311-316`，最关键的确定性证据）、**weak_guard**（`evidence_package.go:230-235`）与 **dereference** 兜底（`registry.go:346-352`）。definite_null 不在 SKILL 清单里。
- 修复方向：SKILL Evidence Pattern 补全（definite_null/weak_guard），与 dfaafab 后的 BuildEvidence 现状对齐。

---

## 三、做得对的部分（修复时请勿破坏）

1. **表格先行的上下文预算设计**：候选明细走文件系统而非 MCP 返回值（`secguard_scan.ts:100` description + L192-194 注释），避免 100KB+ evidence packages 触发平台截断——这是正确的架构取舍。
2. **Hint 语义词典的一致性**：`_index.md` 引导块（`markdown.go:313-324`）、`agent-body.md` L182-191、`command-instructions.md` L310-316 三处的 token 释义保持一致，且 `TestVulnTypeSkillConsistency` 机器校验三平行类型清单防漂移。
3. **nullableSourceDetail 的 loop-carried 修正**（`registry.go:1035-1047`）：源行在报告行之后时明确说"only through a loop back-edge"，消灭了自相矛盾的旧措辞——这类"证据措辞精确性"的迭代方向完全正确。
4. **二元判决 + dismissed 举证契约**：`normalizeAIVerdict`（`report.go:29-41`）严格两态、suspected 强制 dismissed 与"AI 研判后不遗留 suspected"的产品决策一致；agent-body.md L382-389 要求每个 dismissed 引用具体证据，使"是否真研判"可审计。
5. **Failure Contract 段的三方一致**（E-03 只质疑举证缺口，不质疑机制本身）：markdown.go:268-275、_index.md 引导、SKILL 的 contract 表措辞一致，是各类型可复制的契约化模板。
6. **种子装载的 fail-fast**（`planner.go:308-319`）：batch load 失败直接 fail 整个类型而非静默吞掉位置信息，符合"安全工具报缺陷必带位置"的底线。

---

## 四、修复优先级建议

| 优先级 | 编号 | 理由 |
|---|---|---|
| P0 | E-01 | 指令与实现矛盾是"信任级"缺陷：AI 对证据完备性的预期被系统性破坏，影响 integer-overflow 全类型研判；且是纯局部修复（一处渲染逻辑 + 两处指令措辞） |
| P1 | E-03、E-05、E-06 | 三者同属"让 AI 拿到管线已算出的事实"：callee 定位、taint 源行文本、源→汇 span 窗口。修复后 ≤5 read 预算的消耗结构会显著改善，contract@unknown / 跨函数 taint / 远距离 free-use 三类候选的 FN 率应直接下降 |
| P2 | E-02、E-04 | OOB fragment 补齐是纯渲染层五分钟改动（字段全现成）；divide-by-zero 区间传递需动 detector props，稍大 |
| P3 | E-07 ~ E-11 | 失真/提示类小修，可随上述批次顺带 |

验证提醒：以上均为静态分析结论（单测基线绿、端到端未跑）。按既往经验（null-deref 单测绿但生产漏报的教训），每个修复项落地时须构建本地 CLI 二进制 + 在 `examples/c-vuln-benchmark` 补对应 fixture 跑端到端，并把复现用例转正为 pinned 回归测试。