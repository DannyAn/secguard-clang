# 扫描会话问题分析与扫描性能改进建议 — round2

> 分析对象：`examples/c-vuln-benchmark` 的一次真实全量扫描会话
> 扫描 ID：`sc_2026-11-01_132321_606fef`（secguard-clang v0.11.9，OpenCode 宿主）
> 前置：`样例项目扫描问题与性能提升改进建议-round1.md`（扫描 `sc_2026-11-01_125551_a885a5`）
> 本文所有数字均取自本次会话的 `secguard_scan` / `secguard_status` / `report --audit` /
> `secguard_metrics` / `sgre.db` / 扫描目录产物；估算量明确标注「估算」。

---

## 0. 结论摘要（TL;DR）

| # | 问题 | 本轮证据 | 影响 | 建议 | 预期收益 |
|---|------|----------|------|------|----------|
| **P0-1** | `remaining` 语义未修：dismissed 仍不落库，`candidate_count − written_count` 把「已驳回」算成「未处理」 | 全部类型 `terminal_state=done` 后，仍有 **9 个类型 remaining 非零、合计 54**（= 全部 dismissed 数） | 断点恢复、进度显示、人工对账全部失真；等于 round1 P0-1 原样复现 | 落 `candidate_verdicts`（含 dismissed）或让 `report --write-json` 接收 dismissed 数组 | 进度/恢复一条命令可判 |
| **P0-2** | 同一物理量三处口径仍不一致（类型归属键不同） | divide-by-zero auto：scan **2** / status **3** / audit **0**；integer-overflow auto：**3** / **5** / **5** | 汇总数字不可程序化校验，仍需人工对账 | 统一以 `rule_id→VulnTypeSpec` 单键派生；`status` 做薄封装 | 消除三口径漂移 |
| **P0-3** | `written_count` 语义不统一（同一字段在不同类型算不同东西） | divide-by-zero cand2/written4/auto3；injection cand1/written1/auto4；uninit cand9/written7/auto4 | 无法用 `written == candidate` 判断完成 | schema 文档写明定义 + 回归测试 | 可判定完成态 |
| **P1-4** | 25 个 `_index.md` 图例的占位符 `<value>` **未渲染** | `grep -l "<value>" */_index.md` = **25/25** | 子代理拿到的 hint 图例是模板原文，hint 词表等于缺失 | 图例从 `hint_tokens.go` 渲染实际取值，并加渲染测试 | hint 可用、少开 Evidence |
| **P1-5** | use-after-free 自动确认把「指针变量赋值/返回」当成「使用」 | 本会话 5 条 UAF auto 中 1 条误报（`p5_null_flow.c:48-50`，5.5 已驳回），另 1 条同为弱「使用」（`p30:19` `return p`） | 机器判定 FP 率偏高，交付物需人工复核 | 自动确认要求真实解引用/间接访问；指针重新赋值视为 kill | 减少 UAF 类 FP |
| **P1-6** | CWE-732 发现被归入 path-traversal 章节且摘要文案与其自身证据矛盾 | `report.md:296` 摘要写「attacker-controlled path … ../」，而证据是 `path@literal` + `mode@0666`；`result.sarif:1797/1829` ruleId=`CWE-732` | 交付物文案误导（不是路径穿越而是任意用户可写） | 子类 CWE 单列 skill 行或按证据生成摘要 | 消除错误描述 |
| **P1-7** | `integer-overflow` 的「整函数 Evidence」假设仍不成立 | 3 个候选 Evidence 的 `## Code Context` 各 **11 行**（≤±8 窗口外扩），非整函数 | 我按 round1 文档的旧结论在派发提示里写了「整函数嵌入」，给子代理传了错误前提 | 按**实际字节数**定价；或在生成侧真正输出整函数并加断言 | 批次成本模型可信 |
| **P1-8** | 子代理自报 `evidence_opens` 超预算（14 > 12） | unchecked-return 回执 `evidence_opens: 14`；null-deref 恰好 12 | 证据打开预算约束失效（无硬门禁） | 在子代理侧把 12 做成硬门禁并上报 `budget_exceeded` | 成本可控 |
| **P1-9** | 派发批次未压到理论最小值 | 25 类型 / 200 候选，实际 **9** 批；理论下界 `ceil(23/4)+1(heavy 批)=7` | 多 2 次 spawn（约 10~20s） | 小类型按 4 个/批填满，heavy 批单独占 2 类型 | 少 2 次 spawn |
| **P2-10** | 空索引仍返回 `indexed: true` | 会话开始 `files_indexed: 0` 且 `indexed: true`（round1 P2-10 未修） | 编排器需额外判断 | 增加 `state: empty/stale/ready` | 少一次误判 |
| **P2-11** | `.tmp` 结算报告重复且命名混乱 | `status --reports` 报 **19** 份（实际 9 个批次）；同时有 `<id>-report.json` 与 `<id>-<type>-report.json`；还有 `batch-double-free-oob-double-free-report.json`（id 已含 type） | 吸收逻辑可能重复计分 | 一批只留 1 份汇总 + 每类型 1 份；文件名禁二次拼接 | 结算可幂等吸收 |
| **P2-12** | `ai-dismissed.json`（R1 人工复核台账）本轮**未生成** | 扫描目录中 `ai-dismissed.json` ABSENT | 54 条驳回只存在于子代理聊天消息，未外显给客户 | 编排器固定产出；或由 `candidate_verdicts` 自动生成 | 召回台账闭环 |
| **P2-13** | 无廉价的「按类型确认数」只读接口 | 我为拿到 per-type confirmed 又跑了一遍完整 `--audit`（192 个 findings 文件 + SARIF 642KB + xlsx 87KB 重渲染） | 纯读需求触发重渲染 | 新增 `report --stats`（只读）或让 `status --per-type` 带 confirmed/auto/dismissed | 省 1 次全量渲染 |

**总体判断：本轮相比 round1 明显变好（AI 229s vs 579s、spawn 9 vs 19、0 中断、0 重派），
但 round1 的三个 P0 一个都没修好；同时暴露出两个**全新的产品级缺陷**：
`_index.md` 图例占位符未渲染（25/25）与 UAF 自动确认把指针赋值当使用。
优化重心仍是「编排/恢复语义」，而不是索引或检测器（自动分析仅 1.3s）。**

---

## 1. 会话事实时间线

| 阶段 | 实际动作 | 观测（实测） |
|---|---|---|
| 0 | `secguard_status` | `indexed: true` 但 `files_indexed: 0`（空库，P2-10 复现） |
| 1 | `secguard_scan ./src` | 61 文件 / 419 函数 / 4924 行；689 seeds → 200 候选；`auto_confirmed_count=47`；`detector_errors`/`plan_errors` 均空 |
| 2 | 规模门（type_count=25 ≥4，candidates=200 ≤200） | 选 **PARALLEL**（规则强制，未走 SEQUENTIAL） |
| 3 | 同一回合派发 **9** 个 `task` | 9/9 同步返回；**0 中断、0 空回、0 failed_types、0 needs_context** |
| 4 | DB 复核 + `--complete-type` × 29（一条 shell 循环） | 与子代理自报**完全一致**，无 partial、无 missing |
| 5 | 基线 `report --audit` | 193 confirmed（47 机器 + 146 AI）/ 54 dismissed / 0 unclassified |
| 5.5 | 复核 47 条机器判定（只读 SQL + 定点读源） | **驳回 1 条**（`p5_null_flow.c:49` UAF 误报），保留 46 |
| 5.5b | `secguard_review` 批量写驳回 + **再次** `report --audit` | 192 confirmed（46 机器 + 146 AI）；SARIF 642KB；`findings/` 192 个文件 |
| 6 | 为渲染总览表**第三次**跑 `report --audit` 取 `audits` | 纯读需求触发全量重渲染（P2-13） |
| 7 | 写最终 Markdown 报告 | **漏做** R1 台账 `ai-dismissed.json`（P2-12） |

> 注：本轮没有触发 F11 超时、F9 句柄失效、F3a 补位任何一条恢复路径——这是首次
> 「一次派发即完成」的干净会话，即恢复语义的缺陷本轮**未被暴露**，属侥幸而非已修复。

---

## 2. 本轮度量

### 2.1 规模与产出（实测）

| 指标 | 值 |
|---|---|
| 文件 / 函数 / 行 | 61 / 419 / 4924 |
| 原始种子 → 收敛候选 | 689 → 200（29.0%） |
| 机器自动确认（落库前） | 47（23.5% 候选） |
| 5.5 复核结论 | 驳回 1、保留 46 |
| AI 确认 | 146（73.0% 候选） |
| 驳回（AI） | 54（27.0% 候选） |
| 确认合计 | **192**（46 机器 + 146 AI） |
| 严重度 | critical 29 / high 41 / medium 115 / low 7 |
| 未落库判定 | 0 |
| 产物 | `report.md` 39KB / `result.sarif` 642KB / `result.xlsx` 87KB / `findings/` 192 个 |

> 该样例仓是刻意构造的漏洞集，确认率高属预期。但**机器判定 47 → 1 条误报（2.1%）**
> 与「UAF 自动确认」同源，说明机器判定的证明前提仍需逐类校验，而不是数值抽样。

### 2.2 时间（`secguard_metrics` + 实测墙钟）

| 口径 | round2 | round1 | 变化 |
|---|---|---|---|
| 自动分析 | **1.321 s**（index 57ms / graph 287ms / detectors 611ms / plan 240ms / report 66ms） | 1.298 s | 持平 |
| AI 研判 | **229 s** | 579 s（含中断） | **−60%** |
| 端到端 | ≈ **248 s** | ≈ 581 s | −57% |
| spawn 数 | **9** | 19 | −53% |
| 中断/重派 | 0 / 0 | 有（10 批全断）+ 9 重派 | 消除 |

> AI/自动比仍约 **173 : 1**，优化重心不变。round1 预估「降到 420~480s」，本轮实际
> 229s，超额达成——但主要来自「零中断」而非编排算法改进（见 P1-9：批次仍多 2 个）。

### 2.3 派发效率

| 指标 | 值 |
|---|---|
| 派发提示词 | 9 次 × 约 1.2~1.5k 字符 ≈ **300~380 tokens/次**（估算，round1 为 1,100~1,500/次） |
| 提示词总量 | ≈ 3k tokens（估算；round1 ≈ 25k） |
| 单批最大类型数 | 4（`buffer-overflow`+`path-traversal`+`format-string`+`injection`） |
| 单批最大候选数 | 44（`dangerous-function` 39 + `crypto-misuse` 3 + `hardcoded-secret` 2） |
| 证据打开 | 多数 ≤8；`null-deref` = **12（顶格）**；`unchecked-return` = **14（超预算）** |
| `repo_greps` | 全部 0（合格） |
| 读源 | 各类型 ≤5（合格；`null-deref` 5、`dangerous-function` 5、`unchecked-return` 5） |

---

## 3. round1 遗留项核验（逐条对照，2026-11-01 复测）

| round1 项 | 状态 | 本轮证据 |
|---|---|---|
| P0-1 dismissed 不落库 / `remaining` 不可信 | ❌ **未修** | `terminal_state=done` 后 9 个类型 `remaining` 非零，合计 54（恰为 dismissed 数） |
| P0-2 settlement 只在结束时写 | ⚠️ **部分修复** | 已出现类型级文件（`batch-…-double-free-report.json` 等），`status --reports` valid=true；但**仍有批次级汇总重复**（19 份报告 / 9 批次），且无 `needs_context`/逐候选 dismissed 明细 |
| P0-3 三处口径不一致 | ❌ **未修** | divide-by-zero 2/3/0；integer-overflow 3/5/5 |
| P0-4 派发提示词冗余 | ✅ **已改**（编排侧） | 9 次派发合计 ≈3k tokens（估算），每次 ≤400 |
| P1-5 大 light + tiny 打包 | ✅ **已用** | `dangerous-function(39)` 与 `crypto(3)`/`hardcoded(2)` 合批 |
| P1-6 同步宿主小类型策略 | ✅ **已按打包执行** | 小类型全部并入 4 类型批，未做编排器直判 |
| P1-7 报告 Skill 表 CWE 错标 | ✅ **已修（总览表）** | `report.md:68` = `path-traversal | CWE-22`；但**子类行文案仍错**（见 P1-6） |
| P1-8 integer-overflow 整函数 Evidence | ❌ **未修** | 3 个候选的 Code Context 均 **11 行** |
| P1-9 divide-by-zero 图例与主流程冲突 | ❌ **未修** | `candidates/divide-by-zero/_index.md` 仍写「EVERY shape … requires the ±8-line Code Context」，与主流程「bare 可只读 Source」冲突 |
| P2-10 空索引返回 `indexed: true` | ❌ **未修** | 会话开始 `files_indexed: 0` + `indexed: true` |
| P2-11 ai_duration 混入宿主空闲 | ⚠️ **口径仍在**（本轮无中断，影响小） | 229s 为实测墙钟；仍无 `interrupt_ms` 拆分 |
| P2-12 整文件读取未标注 | ✅ 本轮未发生 | 各类型 source_reads ≤5 且为 offset/limit 定点读 |

> **结论：round1 的 12 项里，4 项已修、2 项部分、6 项未修；未修的 6 项中有 3 项是 P0。**

---

## 4. 本轮发现的问题（按优先级）

### P0-1　`remaining` 把「已驳回」算成「未处理」——恢复语义仍然不可判定

**现象（实测）**

全部 25 个有候选类型执行完 `--complete-type` 后，`ai_stage_status=done`、
`terminal_state=done`，但 `status --per-type` 仍报：

| 类型 | candidate | written | remaining |
|---|---|---|---|
| dangerous-function | 39 | 25 | **14** |
| unchecked-return | 27 | 10 | **17** |
| buffer-overflow | 16 | 9 | 7 |
| memory-leak | 22 | 17 | 5 |
| null-deref | 26 | 22 | 4 |
| path-traversal | 8 | 5 | 3 |
| uninit | 9 | 7 | 2 |
| integer-overflow | 3 | 2 | 1 |
| resource-leak | 16 | 15 | 1 |
| **合计** | | | **54** |

54 恰等于 `summary.dismissed_total`。也就是说：**`remaining` 不是「未处理」，而是
「未落库」**。一旦子代理在写完 confirmed、尚未执行 `--complete-type` 时被打断，
恢复方看到 `remaining > 0` 既可能是「还有候选没判」，也可能是「判完了但全是
dismissed」——与 round1 P0-1 描述完全一致，本轮**原样复现**。

**额外证据：`terminal_state` 也无法承担判定职责**

- 中断前快照：25 个类型**全部** `terminal_state=in-progress`，其中 **15** 个类型
  已 `written_count == candidate_count`（argument-type / crypto-misuse /
  data-representation / implicit-contract / out-of-bounds / race-condition /
  signed-compare / sizeof-misuse / stack-address-escape / switch-fallthrough /
  unbounded-length-copy / double-free / format-string / hardcoded-secret / injection）。
- `--complete-type` 全跑完后：25 个**全部** `done`。
- 说明 `terminal_state` 完全由 `ai_stage_status` 驱动，**与「候选是否判完」无关**；
  崩溃在 `complete-type` 之前时，它只会显示 `in-progress`，无法区分「正在跑」与「已跑完未标记」。

**建议**

1. 落 `candidate_verdicts(scan_id, vuln_type, candidate_no, file, line, function,
   variable, verdict, reason, subagent_id)`（同 round1 P0-1 的建表语句）；
2. `report --write-json` 接受 dismissed（或新增 `--write-dismissed-json`）；
3. `status --per-type` 的 `remaining` 改为 `candidate_count − classified_count`
   （classified 含 dismissed），并新增 `classified_count`；
4. `terminal_state` 增加 `classified`（候选判完、尚未 complete-type）这个中间态。

**收益**：断点恢复「一条命令」；进度条不再虚高 54 条。

---

### P0-2　三处 auto_confirmed 口径仍然不一致（类型归属键不同）

**实测数据**

| 类型 | `scan.auto_confirmed_by_type` | 运行中 `status.auto_confirmed` | 终报 `audit.auto_confirmed` |
|---|---|---|---|
| divide-by-zero | **2** | **3** | **0** |
| integer-overflow | **3** | **5** | **5** |
| 全部合计 | 47 | 50 | 46（5.5 驳回 1 条后） |

**已定位的根因（可验证）**

- `scan`/`status` 按**检测器/类型名**归属；`audit` 与 `findings.rule_id` 按 **CWE** 归属。
- 本会话中「divide-by-zero 检测器」的 2 条 auto 发现，其 `rule_id` 是 **CWE-190**
  （`INT_MIN / -1` 整数溢出），于是 audit 把它们归到 `integer-overflow`，
  `divide-by-zero` 的 auto 变成 0、`integer-overflow` 变成 5。
- 同类现象还有：`path-traversal` 检测器产出的 `CWE-732`（任意用户可写）、
  `integer-overflow` 检测器产出的 `CWE-758`（移位 UB）、`injection` 检测器的 `CWE-89`。

**建议**

- 单一归属键：`findings` 增加 `vuln_type` 列（写入时由 `planner.VulnTypeSpec` 决定），
  `audit`/`status`/`scan` 三处一律按该列聚合，`rule_id` 只用于 SARIF；
- 或（更小改动）在报告层用 `CWE → VulnTypeSpec` 反查，并对「检测器产出的子类 CWE」
  保持属主类型不变；
- 回归测试：无 AI 写入时 `scan.auto_confirmed_by_type == audit.auto_confirmed(by vuln_type)`，
  逐类型断言。

---

### P0-3　`written_count` 的定义在不同类型上不一致

**实测对照**

| 类型 | candidate | written_count | auto_confirmed | AI 实际写入 |
|---|---|---|---|---|
| divide-by-zero | 2 | **4** | 3 | 2 |
| injection | 1 | **1** | 4 | 1 |
| integer-overflow | 3 | **2** | 5 | 2 |
| uninit | 9 | **7** | 4 | 7 |

`uninit` 的 written 只算 AI 行（7），`divide-by-zero` 的 written 却算成「AI 2 + 同族
auto 2 = 4」，`injection` 只有 1（auto 4 完全不计）。同一字段三种算法，导致
「`written == candidate` 即完成」这条判定在图例上成立、在数据上不成立。

**建议**：schema 文档写死 `written_count` 的定义（建议 = AI 写入的 confirmed 行数，
auto 单独一列），并加跨类型回归测试；`remaining` 与它同源派生（见 P0-1）。

---

### P1-4　25 个 `_index.md` 的 hint 图例占位符 `<value>` 未渲染

**现象（实测）**

```
$ grep -l "<value>" candidates/*/_index.md | wc -l
25
```

样例（`candidates/divide-by-zero/_index.md:7-8`）：

```
> - `cat@<name>` — the detector's sub-category: <value>
> - `divisor@<shape>` — the divisor's shape: <value> (`bare` = ... )
```

`<value>` 是模板占位符，没有被实际取值替换。`integer-overflow` 的图例更进一步：
整段只列了 `cat@<name>`，**完全没有** `buf@` / `cap@` / `idx@` 的词条——而该类型的
候选恰恰全部依赖这三个 token。

**影响**

- 子代理读到的「图例」等于「hint 词表缺失」，只能凭 `Source` 猜；
- 直接推高 Evidence 打开量（本会话 `unchecked-return` 打开 14 次、`null-deref` 打满 12 次），
  与 round1 P1-9「图例与主流程冲突」是同一处生成逻辑的两个症状。

**建议**

- 图例在写盘时对 `hint_tokens.go` 的词表**求值渲染**（把 `<value>` 替换成真实取值与
  该类型的 token 全集），而不是拼模板；
- 加渲染守卫：`grep "<value>" candidates/*/_index.md` 非空即测试失败；
- 图例与主流程提示**同源生成**（round1 P1-9），避免「bare 要不要开 Evidence」再冲突。

---

### P1-5　use-after-free 自动确认把「指针赋值/返回」当成「使用」

**现象（实测，5.5 复核中确认）**

`src/p5_null_flow.c:44-50`：

```c
int fp_copy_nonnull(void) {
    Node *a = (Node *)malloc(sizeof(Node));
    Node *b = &g_fallback;
    free(a);          // :48
    a = b;            // :49  ← 被当作 "use@49"
    return a->value;  // :50
}
```

`:49` 是**写指针变量**，不是读被释放对象；`:50` 读的是 `b`。自动确认仍产出
「free@48 → use@49」的 CWE-416，本轮已在 5.5 驳回（1/47）。

**同类弱「使用」仍被保留**：`p30_cross_fn_return_double_free.c:18-19`
`free(p); return p;` —— `return p` 只是取指针值，并非解引用；真正的缺陷是调用方
`free(q)`（已在 `p30:24` 以 CWE-415 确认）。这条我本轮**保留了**，属于 5.5 的判定
边界未覆盖情形。

**建议**

- 自动确认的「use」只接受**间接访问**（`*p`、`p->f`、`p[i]`、作为实参传给可解引用
  callee），把 `p = …`（指针重赋值）视为 **kill**，把 `return p` 视为「悬空指针外泄」
  而非 UAF（可另立子类或并入 CWE-562/415 语义）；
- 5.5 检查清单补一条：「use 位置是否构成真实解引用、是否与其它类型发现重复」。

**收益**：本轮 5 条 UAF auto 中 1 条已证伪、1 条边界，FP 率约 20~40%，修完可清零。

---

### P1-6　CWE-732 发现被归入 path-traversal，且摘要与自身证据矛盾

**现象（实测）**

- `report.md:294` 章节标题：`## path-traversal (CWE-22)`；
- `report.md:296` 行内摘要：「filesystem call chmod receives a path that is not a
  fixed string literal — an attacker-controlled value could use ../ …」；
- 而该行的自动确认证据是 `path@literal` + `mode@0666`（`path` 是字面量 `/etc/app.conf`，
  **根本不存在路径穿越**，真实问题是「任意用户可写」）；
- `result.sarif:1797 / :1829` 的 `ruleId` 是 **CWE-732**。

即：章节=CWE-22、ruleId=CWE-732、摘要=路径穿越、证据=世界可写 + 字面量路径，四者互斥。

**建议**

- 属主类型与子类 CWE 分离：`CWE-732` 单列（`permission-setting` skill 行）或在该行
  显式标注「子类 CWE-732」并且**摘要按证据生成**；
- 摘要由 `auto_confirm_verdict_facts` 直接模板化，禁止跨类别套用同一句 path-traversal 文案；
- 加断言：`path@literal` 的行不得输出「attacker-controlled path」类摘要。

---

### P1-7　`integer-overflow` 的「整函数 Evidence」假设仍不成立（round1 P1-8 未修）

**实测**

```
candidates/integer-overflow/001_src_allocator_c_110.md   Code Context = 11 行
candidates/integer-overflow/002_src_p8_value_analysis_c_28.md   = 11 行
candidates/integer-overflow/003_src_p8_value_analysis_c_21.md   = 11 行
```

均为 ±8 窗口级别，**不是**整函数跨度。

**本轮后果（编排侧）**：我复用 round1 文档里的旧结论，在 integer-overflow 批次的
派发提示中写了「Evidence embeds the WHOLE function」，给子代理传了错误前提（该批次
恰好只有 3 个候选，被子代理用 3 次 Evidence 打开 + 0 次读源稳妥消化，未致损）。

**建议**：成本模型按 **Evidence 实际字节数**定价（`_index.md` 已有大小可测），
不再按类型名硬编码 heavy 假设；如需整函数证据，在生成侧实现并用单测断言跨度。

---

### P1-8　证据打开预算无硬门禁

`unchecked-return` 批自报 `evidence_opens: 14`（上限 12），`null-deref` 恰好 12。
说明 agent-body 的「12」是建议值而非强制值；超预算后子代理仍继续开文件，成本模型
（`N ≤ ⌊12 / r_type⌋`）失效。

**建议**：达到 12 次后强制转入「Source + Hint 结算 + 其余进 `needs_context`」，
并在结构化报告里输出 `budget_exceeded: true`，便于编排器下一轮调整 `r_type`。

---

### P1-9　批次仍多于理论最小值（9 vs 7）

25 个类型、`MAX_TYPES_PER_BATCH=4`，heavy（integer-overflow）须独占 2 类型批：

- 理论下界 = `1（heavy 批，2 类型）+ ceil(23/4) = 1 + 6 = 7`；
- 本轮实际 **9** 批：有 4 个批次只装了 2 个类型（integer+signed / null+uninit /
  memory+resource / double-free+out-of-bounds），本可两两合并。

**建议**：派发前显式跑一次装箱（按候选数降序 first-fit），目标 `≤ ceil(type/4)+1`；
本样例目标 ≤8，理想 7。

---

### P2-10　空索引仍返回 `indexed: true`

会话首帧 `{"indexed": true, "files_indexed": 0, "functions_indexed": 0}`（round1 P2-10 复现）。

**建议**：`state: empty | stale | ready`；`files_indexed == 0` 或源文件 mtime 晚于
`sgre.db` 时不得报 `ready`。

---

### P2-11　`.tmp` 结算报告重复、命名二次拼接

`status --reports` 报 **19** 份，而实际只有 9 个批次：

- 每个批次既写 `<id>-report.json`（汇总），又写 `<id>-<type>-report.json`（类型级）；
- 部分文件名出现类型二次拼接：`batch-double-free-oob-double-free-report.json`；
- 同目录还混放 findings 载荷 `<type>.json`（如 `null-deref.json` 15KB）。

**风险**：`--reports` 的「已覆盖类型」匹配若按文件名解析，会重复吸收或误判。

**建议**：一个批次只写 1 份汇总（`<id>-report.json`）+ 每类型 1 份
（`<id>-<type>.json`，文件名中的 `<type>` 去重）；findings 载荷移入 `.tmp/writes/`
子目录；`status --reports` 去重后计数。

---

### P2-12　`ai-dismissed.json`（人工复核台账）本轮未生成

扫描目录内 `ai-dismissed.json` **ABSENT**（round1 有 48 条台账）。本轮 54 条驳回只
存在于子代理最终消息里；`dismissed.json` 是**收敛期**丢弃清单（`total_dropped` +
`by_vuln_type`），不是 AI 驳回台账，两者名字近似、语义完全不同。

**建议**：编排器把「写 `ai-dismissed.json`」作为 finalize 的强制步骤（缺则任务未完成）；
长期由 P0-1 的 `candidate_verdicts` 自动生成；并把收敛期文件改名为
`convergence-dropped.json` 以免混淆。

---

### P2-13　缺少廉价的「按类型确认数」只读接口

为了在最终报告里给出 per-type confirmed/auto，我**第三次**执行了 `report --audit`
（该命令会重渲染 192 个 `findings/*.md` + 642KB SARIF + 87KB xlsx）。

**建议**：新增只读 `report --stats --format json`（复用 `audits` 的查询），或让
`status --per-type` 增加 `confirmed` / `auto_confirmed` / `dismissed` 三列。
编排侧同时改进：第一次 `--audit` 的响应体已含完整 `audits`，应就地解析缓存，而非再跑。

---

## 5. 编排器（AI 执行方）自身的过程问题

| # | 问题 | 现象 | 改进 |
|---|---|---|---|
| O-1 | **漏产出 `ai-dismissed.json`** | 会话结束时未创建该文件，违反 R1 台账要求 | finalize 前做产物 checklist（report/sarif/findings/ai-dismissed） |
| O-2 | **沿用旧文档的错误前提** | 按 round1 文档写「integer-overflow 整函数 Evidence」，未先验证（实际 11 行） | 派发前用 `wc -l` 抽查 1 个 Evidence 文件，而非信任历史结论 |
| O-3 | **重复全量 audit** | 3 次 `--audit`，其中 1 次纯为读取 per-type 统计 | 缓存首次 audit 的 `audits`；改用 `--stats`（待产品补） |
| O-4 | **批次未装箱到最优** | 9 批，理论 7 批 | 派发前跑一次 first-fit |
| O-5 | **5.5 边界未覆盖** | `p30:19 return p` 被保留为 UAF（无解引用） | 把「真实解引用」写进 5.5 检查清单，并在报告里单列「边界保留项」 |
| O-6 | **时间戳命令不适配 macOS** | `date +%s%3N` 输出 `17935106003N`（zsh/BSD date 不支持 `%3N`），回退到 `python3` | 直接统一用 `python3 -c` 计时，省一次失败往返 |

---

## 6. 改进优先级与落地顺序

| 顺序 | 事项 | 类型 | 实施面 | 验证方式 |
|---|---|---|---|---|
| 1 | `candidate_verdicts` + dismissed 落库 + `remaining` 语义 | 功能 | db / cli / report + agent-body | `done` 后 `remaining == 0`；中断注入后能精确报剩余 |
| 2 | 图例 `<value>` 渲染 + 与主流程同源 | 缺陷 | planner（`_index.md` 生成） | `grep "<value>" candidates/*/_index.md` 为空 |
| 3 | 统计口径统一（`vuln_type` 列） | 缺陷 | db / report / cli | 逐类型断言 scan == status == audit |
| 4 | UAF 自动确认「使用」定义收紧 | 准确性 | detectors（`lifetime`/UAF） | `fp_copy_nonnull`、`make_ptr` 不再产出 CWE-416 |
| 5 | CWE-732 子类归属 + 摘要按证据生成 | 缺陷 | report / planner | `path@literal` 行不出现「attacker-controlled」 |
| 6 | `written_count` 定义 + 回归测试 | 缺陷 | db / cli | 四种类型的计数可复现且文档一致 |
| 7 | `.tmp` 结算文件去重与命名规范 | 流程 | agent-body + `status --reports` | 报告数 == 批次数（+ 类型级） |
| 8 | `report --stats`（只读） | 体验 | cli | 一次调用拿到 per-type confirmed/auto/dismissed |
| 9 | 证据预算硬门禁 + `budget_exceeded` | 流程 | agent-body | 下轮 `evidence_opens ≤ 12` |
| 10 | `status` state 枚举 / 批次 first-fit 装箱 | 体验/性能 | cli / command-instructions | `state=ready` 才继续；spawn ≤ 8 |

---

## 7. 本轮做对、建议保留

1. **派发提示词瘦身到位**：每次 ≈300~380 tokens（估算），规则全部留在 agent-body/skill，
   只传类型、候选数、scan_id、scan_dir、绝对 db/tmp 路径。
2. **一次派发即完成**：9 批同一回合发出、同步收口，0 中断 / 0 空回 / 0 重派 / 0 `needs_context`。
3. **打包规则正确执行**：大 light 类型（39 候选）与 2 个 tiny 类型合批，heavy 类型单独成批。
4. **DB 为权威**：`--complete-type` 前先比对 `written_count` 与子代理自报，逐类型一致；
   子代理未自报 complete，`ai_stage_status` 只由编排器写，无竞态。
5. **5.5 真的抓到了 FP**：47 条机器判定里用 1 条定点读源证伪了 UAF，不是走过场。
6. **`repo_greps == 0`**：全部用 `secguard_def` / 内嵌 `## Callee Definition`，无全仓 grep。
7. **自动分析零故障**：`detector_errors` / `plan_errors` 均为空，1.3s 完成 689→200 收敛。

---

## 8. 下轮验证清单（round3）

- [ ] `done` 状态下 `status --per-type` 的 `remaining` 全部为 0（当前 9 个类型合计 54）
- [ ] `grep "<value>" candidates/*/_index.md` 输出为空（当前 25/25 命中）
- [ ] 同一类型在 `scan` / `status` / `audit` 的 `auto_confirmed` 三处相等
- [ ] `fp_copy_nonnull` / `make_ptr` 不再产生 CWE-416（UAF 严格解引用）
- [ ] `report.md` 中 `pm_permission.c:2` 的摘要不再写「attacker-controlled path」
- [ ] `integer-overflow` Evidence 实际跨度与成本模型一致（或模型改为按字节）
- [ ] `.tmp` 报告数 == 批次数 + 类型数，且无 `<type>-<type>` 二次拼接
- [ ] `ai-dismissed.json` 存在且条数 == `summary.dismissed_total`（当前 ABSENT vs 54）
- [ ] spawn 数 ≤ 8（当前 9，理论下界 7）
- [ ] `evidence_opens ≤ 12`（当前 `unchecked-return` 14）
- [ ] `secguard_status` 首次调用返回 `state: empty` 而非 `indexed: true`
- [ ] AI 耗时守住 ≤ 260s（本轮 229s，round1 579s）

---

### 附：本轮关键产物

| 产物 | 路径 / 值 |
|---|---|
| 扫描报告（192 条明细） | `.codeagent/secguard-clang/scans/sc_2026-11-01_132321_606fef/report.md`（39 KB） |
| SARIF | `.../result.sarif`（642 KB） |
| Excel | `.../result.xlsx`（87 KB） |
| 逐条确认文件 | `.../findings/`（192 个） |
| 收敛期丢弃清单 | `.../dismissed.json`（`total_dropped` + `by_vuln_type`） |
| AI 驳回台账 | **缺失**（应生成 `ai-dismissed.json`，54 条） |
| 数据库 | `.codeagent/secguard-clang/.sgre/sgre.db` |
| 结算报告 | `.sgre/.tmp/*-report.json`（19 份，实际 9 批次） |
