# OpenCode 扫描样例项目自检问题分析与改进建议

> 自检对象：`examples/c-vuln-benchmark/opencode-ds4.1-free-session-ses_eb71-round1.md`（下称"会话日志"，7144 行）——OpenCode + DeepSeek V4.1 Flash Free 对样例项目 `examples/c-vuln-benchmark` 的一轮完整 `/secguard` 扫描会话。
> 方法：逐段通读会话日志，对每一条判断回源核对实现代码（`extension/opencode/tools/`、`extension/shared/`、`sgre/internal/cli/`、`sgre/internal/db/`）与扫描产物。**每条问题均附证据坐标**（日志行号 `日志:NNNN` 或源码 `file:line`）；无法从现有工件证实的推断明确标注为【高概率假设】。
> 本轮只做检视，不改代码。

---

## 1. 事实基线

| 维度 | 数值 | 证据 |
|---|---|---|
| 扫描规模 | 34 文件 / 244 函数 / 2961 行 | 日志:854-855, :955 |
| AI 工作量 | 57 candidates + 135 auto-confirmed；22 个 type 需 AI 处理 → PARALLEL 路径（6 批并行派发） | 日志:964-967, :1113, :1641 |
| 自动分析耗时 | **0.793 s**（索引+建图+检测+收敛+机器确认） | 日志:3385 |
| AI 研判耗时 | **1360 s（约 22.7 分钟）** | 日志:3162, :3378-3379 |
| —— 第一波 6 任务并行派发 turn | 797.6 s | 日志:1500 |
| —— 第二波 4 任务重派 turn | 509.4 s | 日志:2165 |
| 最终结果 | 169 confirmed（123 auto + 46 AI）、11 dismissed（AI 候选）、12 条 auto-confirmed 经复核剔除、unclassified 0 | 日志:3166, :3214, :3242, :5024-5031 |

**会话日志工件的可见性边界（影响下文多个结论的取证力度）**：该日志只包含**编排器（主会话）侧**的工具调用与 thinking；**子代理内部的工具调用不入日志**（子代理只回传一段最终文本）。因此"每个子代理具体读了哪些文件、调了哪个工具"无法从本工件直接取证，只能通过子代理自述与 DB 状态侧写。详见 P6。

---

## 2. 问题清单（按严重度排序）

### P1【CRITICAL】`secguard_review` MCP 工具参数拼接 bug：`--type` / `--scan-id` / `--limit` 三个过滤**全部静默失效**

**现象**：子代理调用 `secguard_review` 的 `list_auto_confirmed` 时，即使传了 `type=<自己的类型>`，返回的仍是**跨类型、全扫描范围**的未复核 auto-confirmed 列表（初始 135 条）。三个独立子代理各自撞上并留下记录：

- path-traversal worker："`secguard_review list_auto_confirmed` returned a truncated **cross-type** page (it listed other types' entries despite `type=path-traversal`); resolved via direct DB query rather than context-heavy paging"——日志:2283
- race-condition worker："the `secguard_review` list returned an **unscoped set of other types' rows**"——日志:2317
- signed-compare worker："the earlier large MCP list was **unscoped scan-wide output** belonging to other workers' types"——日志:2384

**根因（代码层机制完整闭环）**：

`extension/opencode/tools/secguard_review.ts:116-123`（List 路径）把可选 flag **预拼接成带前导空格的字符串**再整体插值：

```ts
const typeArg = args.type ? ` --type ${args.type}` : ""      // " --type path-traversal"
const scanArg = args.scan_id ? ` --scan-id ${args.scan_id}` : ""
const limitArg = args.limit && args.limit > 0 ? ` --limit ${args.limit}` : ""
Bun.$`${secguardBin} report --db ${dbPath} --list-auto-confirmed${scanArg}${typeArg}${limitArg}`
```

Bun shell 模板中每个 `${}` 占位符成为**单个 argv 元素**（不做 word-splitting），因此 `" --type path-traversal"` 整体（含前导空格）是**一个**参数。而 Go CLI 侧 `sgre/internal/cli/report.go:66-78` 的 `parseStringFlag` 只认两种形式：`--type` 精确匹配（作为独立 argv 后跟取值）或 `--type=` 前缀匹配。带前导空格的单 argv 两种都匹配不上 → **`--type`、`--scan-id`、`--limit` 三个过滤全部被静默丢弃**。

佐证一（SQL 无辜）：`sgre/internal/db/crud_findings.go:259-294` 的 `ListAutoConfirmedForReview` 过滤逻辑本身正确——子代理绕过 MCP 工具直查 DB 后即刻得到正确结果（日志:2283/:2317/:2384），bug 只在 MCP 工具层。
佐证二（兄弟工具传参正确，唯 review 中招）：
- `secguard_status.ts:47`：`--scan-id=${scanId}`（flag 字面量留在模板内，`=紧贴`形式）✓
- `secguard_report.ts:121/125/168`：`--scan-id ${scanId}`（独立插值）✓
- `secguard_review.ts:95`（同文件 Write 路径）：`--review-json ${tmpFile}`（独立插值）✓ —— 所以 **review 写回路径是好的，只有 List 路径坏**。

**影响**：
1. **上下文洪泛**：每个做 re-review 的子代理被灌入全量 135 条（含 snippet/reasoning 的大 JSON），`--limit` 分页保护同时失效。这是本轮扫描中**已证实的最大性能与稳定性放大器**（详见第 3 节）。
2. `--scan-id` 失效在本例侥幸无害（CLI 缺省回退 latest scan，`report.go:260-263`；该 DB 只有本次扫描），但多扫描共库场景下列表可能混入其他扫描的行。
3. "Re-list until count 0"协议被破坏：子代理复核完自己类型后，unscoped 列表仍非 0，逻辑上永远到不了终点（子代理只能靠自觉或绕道 DB 自救）。

**改进建议**：
1. **修 `secguard_review.ts` List 路径**（推荐数组插值，可选 flag 场景最干净）：
   ```ts
   const cmd = [secguardBin, "report", "--db", dbPath, "--list-auto-confirmed"]
   if (args.scan_id) cmd.push("--scan-id", args.scan_id)
   if (args.type) cmd.push("--type", args.type)
   if (args.limit && args.limit > 0) cmd.push("--limit", String(args.limit))
   Bun.$`${cmd}`.cwd(workDir).quiet().text()
   ```
   （数组插值时 Bun 将每个元素展开为独立 argv；或参照 `secguard_status.ts:47` 的按分支拼接。）
2. **CLI 侧防御**：`report` 命令解析前检测"疑似拼接参数"——argv 以空白开头且内含 ` --`，立即报错（如 `argument " --type path-traversal" looks like concatenated flags; pass each flag as a separate argument`）。该检测可精确捕获此类 bug 而非静默降级。
3. **回归测试**：Go 侧已有 `--list-auto-confirmed --type ...` 的 e2e（`report_test.go`，日志:1297-1311 引用的用例），但缺"带前导空格参数必须报错/不生效"的负向用例；TS 侧建议补一个 seed 双类型 DB 的 smoke 断言（list 只返回本类型）。
4. **CI 静态防护**：在 `release/check-extension-consistency.py` 加一条规则——扫描 `extension/opencode/tools/*.ts` 中 Bun 模板插值是否存在 `` ` --`` 开头的预拼接 flag 字符串模式，命中即 fail。

---

### P2【HIGH】`secguard report` 无 flag 兜底 = 全量倾倒，放大 P1 类事故

`sgre/internal/cli/report.go:1130-1162`：`report` 子命令在**无任何识别 flag** 时默认 `ListFindings` 输出全部 findings。任何参数损坏（如 P1 的拼接 bug、或子代理手滑拼错 flag）都会退化成"倾倒整库"。子代理上下文被无界输出灌爆是可预期后果。

**改进建议**：无 flag 时打印 usage 并以非零码退出；列出 findings 必须显式（如 `--list --status confirmed`）。宁可让调用方立刻看到报错，也不要静默全量输出。

---

### P3【HIGH】F5 的 PARTIAL 判定规则在 `--complete-type` 之前**不可实现**（DB 缺 dismissed 维度）

**现象**：编排器在 DB 校验阶段陷入规则自相矛盾，被迫手工推理（日志:2172-2193）：

> "F5 says `0 < written_count < candidate_count` → PARTIAL (context-overflow)... but dismissed candidates are not persisted, so written_count < candidate_count is **NORMAL** when some candidates are dismissed... the orchestrator hasn't called --complete-type yet for any type... so I can't rely on terminal_state... But wait: the subagent reports tell me their dismissed counts."

**根因（设计缺陷，非实现失误）**：
1. dismissed 候选**不落库** → DB 只有 `written_count`，无从区分"written=10/cand=15 是 5 条 dismissed（正常）"还是"5 条未分类（PARTIAL）"。
2. `terminal_state`/`ai_stage_status` 要等编排器收尾调 `--complete-type` 才翻转（日志:2889 的收尾循环），而 F5 要求编排器在**收尾之前**判定 PARTIAL——时序上拿不到判定依据。
3. 结果：编排器只能靠**子代理自报数交叉核对**（buffer-overflow: 10 confirmed + 5 dismissed = 15 ✓，日志:2193 一带）——而自报数本身不可靠（见 P7），等于双向都缺权威数据源。

**改进建议**（择一，按彻底程度排序）：
- **数据模型修复（推荐）**：让 dismissed 候选也落库（`status='dismissed'`，不进 SARIF/report.md，仅作审计维度）。DB 即可自证 `written + dismissed == candidate_count`，PARTIAL 判定完全自动化，同时消除 P7 的自报依赖。
- 最小改动：把 F5 的校验步骤移到 `--complete-type` 之后（`ai_stage_status='done'` 后 gap 即 dismissed），只修文档时序；但"complete 之前发现子代理漏写"的早期预警能力会丢失。
- 折中：F5 判定式改为 `written_count + subagent_reported_dismissed >= candidate_count`，自报数仅作辅助信号。

---

### P4【MEDIUM】两轴预算公式不计 auto-confirmed 复核负载

指令规定的批次预算公式 `types×6 + candidates×0.8 < 54`（日志:971）完全忽略 re-review 工作量。编排器两度注意到并只能口头带过：

- 日志:1003："The formula doesn't account for auto-confirmed re-review, but let me be careful..."
- 日志:1036："the turn formula doesn't account for re-review, but re-review of 42 entries may take several turns... Probably 3-5 turns per type... let me split"

实际负载：B4 携带 dangerous-function 42 条 + uninit 11 条 auto-confirmed 复核，B5 携带 unchecked-return 29 条（日志:1752/:1786 的任务书原文），都是重 re-review 批次。本次靠编排器的人工平衡（把 sizeof-misuse 并入 B4、拆 B5，日志:1067-1073）兜住了，但这是**模型即兴发挥，不是设计保证**。

**改进建议**：公式升级为三轴并写入指令：
`estimated_turns = types×6 + candidates×0.8 + auto_confirmed×0.3 < 54`
（re-review 单条成本低于候选研判——批量分页 + 无需写 findings）。用本会话校验：B4 = 3×6 + 4×0.8 + 53×0.3 ≈ 37.1 ✓；B5 = 4×6 + 4×0.8 + 35×0.3 ≈ 37.7 ✓——阈值不变、批次结构无需调整，公式却恢复预测力。

---

### P5【MEDIUM】文档与 agent 定义矛盾：子代理 Bash 权限

`command-instructions.md` 断言 OpenCode 子代理无 Bash、不能自己跑 `--complete-type`（515 行一带的表述："OpenCode-NGA, no Bash"）；但 `extension/opencode/agents/security-auditor.md` 的 permission 实际允许 `bash "secguard*": allow`。编排器自己发现了矛盾并即兴裁量（日志:1091-1095, :1230-1236）：

> "the subagents CAN run `secguard*` bash commands... The prompt guidance for OpenCode says subagents should use the MCP tool with finalize:false and NOT call --complete-type. But since they have bash allowed, they could do either. I'll instruct them to..."

附带子问题：`secguard_review` **不在** permission allow list 中（日志:1226-1228 编排器对此也拿不准），但实测子代理能调用（P1 的三处实证即来自子代理成功调用它）——权限模型语义不清（未列出 = 默认允许？）。

**影响**：指令与实际能力不符时，行为一致性取决于当次模型的裁量——同一套指令在不同模型/心情下可能产生不同的工具选择（B2 原始 worker 与重派 worker 的工具选择差异可能正源于此，见 B2 节）。

**改进建议**：
1. 修正 `command-instructions.md` 的 host 能力矩阵，如实描述 OpenCode 的 security-auditor 权限（有 `secguard*` Bash）。
2. 把 `secguard_review` 显式加入 allow list，消掉"未列出但可用"的灰区。

---

### P6【MEDIUM】F6 读源审计未执行 + 会话级可观测性缺口

**F6 被跳过（事实）**：指令要求"audit 前扫子代理 transcripts / `scan.log` 查 source-read + Evidence-open 条目，双向核对（confirmed 未读、dismissed 未读即弃）"（日志:489-497）。执行段中编排器从 DB 校验（日志:2390-2500）直接跳到 complete-type 循环 + audit（日志:2889），**未发生任何 transcript 扫描**——日志全文除指令段外再无 "transcript" 字样。

**更根本的缺口（设计层面）**：本会话日志只含编排器侧调用，子代理内部工具调用完全不可见。后果：
1. F6 在 OpenCode 上**当前根本不可执行**（编排器没有子代理 transcript 的访问路径）——跳过是环境约束下的必然，不是编排器偷懒。
2. 用户"每个并行任务都在读源码"的观察**无法从本工件验证或证伪**。
3. P1 类工具 bug 的实际影响面（多少子代理被灌、灌入后各自做了什么）无法追溯。

**改进建议**：
- 短期：F6 措辞改为条件性（"if subagent transcripts are accessible"），OpenCode 上降级为 DB+产物审计（本次实际行为），避免指令要求不可能的动作。
- 零基建增强：子代理返回消息模板强制附带 `source_reads: N, evidence_opens: M` 自报计数，编排器对超预算（>5）的类型在观察项表中标记。
- 中期：调研 OpenCode storage（session/message 落盘）的读取路径，让编排器可 grep 子代理 messages 做真实 F6；或在 `task_result` 中携带 per-subagent tool-usage summary。

---

### P7【MEDIUM】子代理自报数违反协议口径（两例实证）

协议定义 `written = total findings persisted`（agent-body.md）。两处违反：

| 子代理 | 自报 | DB 实际 | 错误方式 |
|---|---|---|---|
| B4 / dangerous-function | `written: 43, confirmed: 43`（日志:1768） | `written_count=1`（日志:2198） | 把 42 条 auto-confirmed 复核混入 written |
| B5 / unchecked-return | `written: 4, confirmed: 3, dismissed: 1`（日志:1821） | 3 written + 1 dismissed（日志:2426） | 把 dismissed 候选计入 written |

编排器被迫逐一纠偏并总结 "DB is authority"（日志:1885）。**这恰好印证了 F5 依赖 DB 的设计正确性——但 P3 又表明 DB 缺 dismissed 维度。两个数据源各缺一半，编排器只能在自报与 DB 之间来回缝补。**

**改进建议**：返回消息模板把口径拆细并显式命名：`written`（经 secguard_report 持久化的 confirmed 数）/ `re_reviewed`（review-json 覆盖的 auto-confirmed 数）/ `dismissed`（候选判 dismissed 数）。B4 的"43"正是 1 written + 42 re_reviewed 的口径混合，字段拆开后无处可混。根治方案见 P3 的 dismissed 落库。

---

### P8【LOW】编排器终报查询缺 `review_status` 过滤（181 vs 169）

编排器构建问题表时首次查询返回 181 行，与 audit 的 confirmed_total=169 差 12，自行定位根因（日志:5022-5034）：被 re-review 判 dismissed 的 12 条 auto-confirmed（memory-leak 2、resource-leak 3、unchecked-return 4、uninit 1、use-after-free 2）DB 行仍在（status='auto-confirmed' + review_status='dismissed'），查询须补 `AND (review_status IS NULL OR review_status != 'dismissed')`。

**改进建议**：指令中的 DB 速查段补一行"终报/问题表查询必须带 review_status 过滤"；或 CLI 提供封装好过滤的 `report --confirmed`（更符合"DB is authority、口径单点封装"的方向）。顺带：B2 的"12 条剔除"明细在最终观察项表已如实呈现（日志:7133），该环节无问题。

---

### B2 空回根因分析【高概率假设，未定论】

**现象**：第一波 6 任务中，B2 批次（path-traversal 7c/0a、race-condition 3c/0a、integer-overflow 2c/0a、signed-compare 1c/0a——4 类型全部 **0 auto-confirmed**，日志:1073/:1573）返回 `state="completed"` 且 `task_result` 完全为空（日志:1694-1698）；DB 显示 4 类型 `written_count=0, terminal_state=pending`（日志:2250）。

**编排器行为评价**：F1 重派机制**按设计生效**——单类型粒度重派 4 个子代理，全部成功（日志:2250 起）；重派 turn 耗时 509.4s（日志:2165），占 AI 研判总耗时的 **37%**。

**但两个遗留问题**：
1. **根因从未追查**：task_result 为空意味着无任何线索留下；编排器重派成功后即放下，未做任何归因动作。
2. **最终报告对用户不可见**：终报与观察项表（日志:6912-7144）**完全未提及** B2 空回与整波重派——用户无从知道 37% 的耗时是一次重试。异常被静默吸收。

**根因假设（按可能性排序，均未证实）**：
- **假设 1：P1 坏工具致上下文过载/异常终止**。B2 任务书指示 re-review 走 Bash（日志:1688 段 step 4 "via Bash (allowed)"），但**同模型的重派 worker 实测选择了 `secguard_review` MCP 工具**（日志:2283/:2317/:2384 三处实证）——原始 B2 worker 很可能同样弃 Bash 选 MCP 工具，被灌 135 条全量列表；其 4 个类型本应 0 条秒回。此假设与"P1 是已证实放大器"互洽，但原始 B2 内部无 trace，**不可证实**。
- **假设 2：宿主/免费端点侧故障**。`state="completed"` + 空结果更像宿主正常返回了空消息，而非超时/错误路径。

**验证路径**：修复 P1 后复测同一项目——若 B2 不再空回则假设 1 成立；配合 P6 的 tool-usage 记录后可直接定位。

---

## 3. 慢扫描归因（专节）

**结论先行：慢不在自动分析（0.793s），也不在"每任务读源码"（无证据支持），而在 AI 研判的两波同步派发（1307s / 1360s ≈ 96%），其中第二波（509s）整体是 B2 空回的重试，P1 坏工具是已证实的上下文洪泛源。**

分解：

| 项 | 数值 | 占 AI 耗时 | 性质 |
|---|---|---|---|
| 自动分析 | 0.793 s | — | 非瓶颈（日志:3385） |
| 第一波派发 turn（6 任务并行） | 797.6 s | 59% | 日志:1500；时长由最重任务（B4 42 条复核 / B5 29 条 / B1 15+5 候选）+ 模型推理延迟构成 |
| 第二波重派 turn（4 任务并行） | 509.4 s | 37% | 日志:2165；**整体是 B2 空回的代价**；B2 本是全场最轻批次（13 候选 0 复核） |
| 其余编排开销（DB 校验/complete-type/audit/终报） | ≈53 s | 4% | 含 169 行问题表的生成（日志:3302-3324 的取舍过程） |

**P1 对耗时的已证实贡献**：第二波 4 个 worker 中至少 3 个（path-traversal/race-condition/signed-compare）被坏工具灌入全量列表后被迫绕道直查 DB（日志:2283/:2317/:2384）——每个受影响子代理多处理了一大段无用上下文 + 一次额外工具往返。第一波是否同样受灌**无直接证据**（B1/B3/B4/B5 的内部调用不可见，见 P6），但重派 worker 的实测行为（弃 Bash 选 MCP 工具）使其具有合理可能性。

**"每个任务都在读源码"的证伪边界**：本工件**无法验证**该观察（子代理内部调用不入日志）。现有证据链：任务书明令 "Do NOT do per-candidate source reads"（日志:1688 段）；Evidence 文件内嵌 ±8 行上下文（产物已核验）；指令含 ≤5 read 预算；编排器侧无违规记录。**结论：现有证据不支持把慢归因于 per-candidate 读源；已证实的上下文压力源是 P1。**该观察的最终裁定需要 P6 的可观测性改进。

**修复后的预期（估算，非承诺）**：消除第二波（-509s）+ 子代理上下文瘦身（P1）→ AI 研判有望进入 <800s 区间；复测验证。

---

## 4. 改进建议汇总（按优先级）

| # | 建议 | 层 | 对应问题 |
|---|---|---|---|
| 1 | 修 `secguard_review.ts` List 路径参数拼接（数组插值） | `extension/opencode/tools/` | P1 |
| 2 | CLI 拒绝"疑似拼接参数"（前导空白 + 内含 ` --`）并报错 | `sgre/internal/cli/report.go` | P1 防御 |
| 3 | `report` 无 flag 不再全量兜底，打印 usage 退出非零 | `sgre/internal/cli/report.go` | P2 |
| 4 | dismissed 候选落库（status='dismissed'，不进 SARIF），F5 判定全面自动化 | `sgre/`（写路径 + 查询） | P3 根治 / P7 根治 |
| 5 | 批次预算公式加第三轴 `auto_confirmed×0.3` | `extension/shared/command-instructions.md` | P4 |
| 6 | 修正 host 能力矩阵；`secguard_review` 显式入 allow list | `extension/shared/` + `extension/opencode/agents/` | P5 |
| 7 | F6 改条件性执行；子代理自报 `source_reads/evidence_opens`；调研 transcript 读取 | `extension/shared/command-instructions.md` | P6 |
| 8 | 返回消息模板字段拆细（written / re_reviewed / dismissed） | `extension/shared/agent-body.md` | P7 |
| 9 | DB 速查段补 review_status 过滤提示，或加 `report --confirmed` 封装 | 指令 / `sgre/internal/cli/` | P8 |
| 10 | 空回/重派事件必须进最终报告观察项（异常对用户可见） | `extension/shared/command-instructions.md` | B2 遗留 |

修复顺序建议：1+2+3 一个提交（同一根因链，含回归测试）；4 独立提交（数据模型变更，需同步 report/audit/SARIF 过滤逻辑）；5-10 均为指令/文档层，可合并一批。

## 5. 修复后复测验证清单

1. 同项目同模型重跑 `/secguard`：B2 型空回应不再出现（验证 B2 假设 1）。
2. 任意子代理调用 `secguard_review list_auto_confirmed`：传 `type` 后只返回本类型条目；B2 类 0-auto 类型应秒回空列表。
3. 手工构造带前导空格的参数调 CLI：应得到明确报错而非全量输出。
4. 全程只有一波派发（无重派 turn）；AI 研判耗时显著下降并记录对比值。
5. 观察项表包含任何重试/异常事件（若发生）。