# 扫描会话问题分析与扫描性能改进建议 — round3

> 分析对象：`examples/c-vuln-benchmark` 的一次真实全量扫描会话
> 扫描 ID：`sc_2026-11-01_134321_e8d594`（secguard-clang，OpenCode 宿主）
> 前置：`扫描会话问题分析与扫描性能改进建议-round2.md`（扫描 `sc_2026-11-01_132321_606fef`）
> 本文数字取自本次会话的 `secguard_scan` / `secguard_status` / `report --audit` /
> `secguard_metrics` / `sgre.db` / 扫描目录产物；估算量明确标注「估算」。

---

## 0. 结论摘要（TL;DR）

| # | 问题 | 本轮证据 | 影响 | 建议 | 预期收益 |
|---|------|----------|------|------|----------|
| **P0-1** | **三处 `auto_confirmed` 口径仍不一致**（round2 P0-2 原样复现） | scan **46** / status **49** / audit **46→44**；divide-by-zero **2 / 3 / 0**，integer-overflow **3 / 5 / 5** | 汇总数字无法程序化校验，仍需人工对账 | `findings` 落 `vuln_type` 列，三处统一按该列聚合 | 消除三口径漂移 |
| **P0-2** | **子类 CWE 与证据语义错配，导致 5.5 误驳回真阳性（召回损失）** | `p9_secure_func.c:28` `strcpy_s(dst,4,"hello")`、`:60` `memcpy_s(dst,sizeof(dst),src,100)` 的 `cat@secure_constraint_violation` 被写成 `CWE-787`「越界写」，我按 CWE-787 前提驳回 **2 条** | 交付件少 2 条真问题；`_s` 误用类检出被自我抵消 | `_s` 约束违约单列子类（CWE-252/754），SARIF `ruleId` 与摘要按子类生成 | 召回 +2，语义自洽 |
| **P0-3** | `written_count` 定义仍不统一（round2 P0-3 未修） | divide-by-zero cand2/**written3**/auto3；buffer-overflow cand16/**written7**/auto7；double-free cand3/**written3**/auto3 | `written == candidate` 仍不能判定完成 | schema 写死定义（= AI confirmed 行数）并加回归 | 完成态可判定 |
| **P1-4** | 25 个 `_index.md` 图例 `<value>` **仍未渲染**（round2 P1-4 未修） | `grep -l "<value>" candidates/*/_index.md` = **25/25** | 子代理拿到模板原文，等于没有 hint 词表 | 写盘时对 `hint_tokens.go` 求值渲染 + 渲染守卫 | 少开 Evidence |
| **P1-5** | UAF 自动确认「使用」定义只修了一半 | `p30_cross_fn_return_double_free.c:19` `free(p); return p;` 仍产出 CWE-416（id=44，本轮保留） | `return` 取指针值不是解引用，FP 仍存在 | `return p` 归入「悬空指针外泄」而非 UAF | 清零该子类 FP |
| **P1-6** | CWE-732 仍被归入 path-traversal 章节，且 SARIF 文案带错类型名 | `report.md:290` 标题 `## path-traversal (CWE-22)` 下含 `pm_permission.c:2`；SARIF `ruleId=CWE-732` 但 message 以 **"path-traversal in pm01_chmod_literal"** 开头 | 章节/类型名与 ruleId 互斥（round2 已修正摘要正文，未修正归属） | 归属键与摘要同源；SARIF message 前缀取 `vuln_type` 而非属主 skill | 消除矛盾文案 |
| **P1-7** | `integer-overflow` 的「整函数 Evidence」假设仍不成立（round2 P1-7 未修） | 3 个候选 `## Code Context` 均 **11 行** | 批次成本模型按 heavy 计费，实际是轻量类型 | 成本按 Evidence 实际字节数定价 | 批次装箱更准 |
| **P1-8** | `ai-dismissed.json`（人工复核台账）**连续两轮未生成** | 扫描目录仅 `dismissed.json`（收敛期丢弃 422 条），无 `ai-dismissed.json`（本轮 AI 驳回 58 条） | 58 条驳回只存在于子代理聊天消息，客户不可见 | finalize 强制清单；长期由 `candidate_verdicts` 自动生成 | 召回台账闭环 |
| **P1-9** | 无廉价「按类型确认数」接口，重复全量 audit | 为读 `audits` 数组**第二次**执行 `report --audit`（重渲染 186 文件 + 612KB SARIF + 84KB xlsx） | 纯读需求触发全量重渲染 | 新增 `report --stats`；或 `status --per-type` 带 confirmed/auto/dismissed | 省 1 次渲染 |
| **P2-10** | 空索引仍返回 `indexed: true`（round2 P2-10 未修） | 首帧 `{"indexed": true, "files_indexed": 0, "functions_indexed": 0}` | 编排器需额外判断 | `state: empty/stale/ready` | 少一次误判 |
| **P2-11** | `.tmp` 结算报告多于批次，命名体系混用 | **9 份报告 / 7 批次**；同目录存在 `<subagent-id>-report.json`（`bof-rl-ic-sc-batch-report.json`）与 `<type>-sub-report.json`（`buffer-overflow-sub-report.json`）两套命名 | 吸收去重依赖文件名解析，易误判 | 一批一汇总 + 一类型一文件，命名规则唯一 | 幂等吸收 |
| **P2-12** | `report --list` 输出字段集不稳定 | 186 行中 **2 行缺 `variable` 字段**，导致 `KeyError` 往返一次 | 消费方必须 `.get()` 兜底 | 字段 schema 固定（缺失时给 `""`） | 免一次失败往返 |
| **P2-13** | `secguard_db` 结果在 ~8KB 截断；`scan_runs` 查询直接失败 | 46 行 auto 查询被截断，被迫改投影重查；`SELECT … FROM scan_runs` 返回 exit 1（表不存在/名称不同） | 多一次往返；错误无可读提示 | 提供聚合/分页；错误提示给出可用表名 | 省往返 |
| **P2-14** | `ai_duration_ms` 本轮为**取整估计**，非毫秒实测 | 会话实耗时 13:43:59 → 13:47:18 ≈ 199s，写入 205000 | 计时数据精度不足以做 A/B | 统一用 `python3` 纳秒计时（macOS `date` 不支持 `%3N`） | 计时可信 |

**总体判断：本轮是三轮里最干净的一轮——spawn 7（理论下界）、0 中断 / 0 重派、
0 空回 / 0 `needs_context`、evidence_opens 全部 ≤12、repo_greps 全 0、AI 205s。
round2 的 P0-1（dismissed 不落库 / `remaining` 失真）**确已修复**。
但三个"统计口径"类 P0（P0-1/P0-2/P0-3）仍然存在，并且本轮新增了一条
**由口径错配直接引发召回损失**的实证（P0-2）。优化重心依旧是
「类型归属与统计语义」，而不是索引或检测器（自动分析仅 1.3s）。**

---

## 1. 扫描会话事实时间线

| 阶段 | 实际动作 | 观测（实测） |
|---|---|---|
| 0 | `secguard_status` | `indexed: true` 但 `files_indexed: 0`（空库，P2-10 复现） |
| 0b | `find ./src` 规模探测 | 61 个 C 文件 / 276KB |
| 1 | `secguard_scan ./src` | 61 文件 / 419 函数 / 4924 行；688 seeds → 200 候选；`auto_confirmed_count=46`；`detector_errors`/`plan_errors` 均空 |
| 2 | 规模门（type_count=25 ≥4，candidates=200） | 选 **PARALLEL** |
| 3 | 同一回合派发 **7** 个 `task` | 7/7 同步返回；0 中断、0 空回、0 `failed_types`、0 `needs_context` |
| 4 | DB 复核 + `--complete-type` × 29（shell 循环） | 与子代理自报一致；`remaining` 全部为 **0**，`dismissed_count` 已填充 |
| 5 | 基线 `report --audit` | 186 confirmed（44 机器 + 142 AI）/ 58 dismissed / 0 unclassified |
| 5.5 | 复核 46 条机器判定（只读 SQL + 定点读源 4 处） | **驳回 2 条**（`p9_secure_func.c:28`、`:60`，见 P0-2），保留 44 |
| 5.5b | `secguard_review` 批量写驳回 + **第二次** `report --audit` | 186 confirmed（44 机器 + 142 AI）；SARIF 612KB；`findings/` 186 个 |
| 6 | 写最终 Markdown 报告 | **漏做** R1 台账 `ai-dismissed.json`（P1-8 复现） |

> 注：本轮同样没有触发 F11 超时、F9 句柄失效、F3a 补位——第二次「一次派发即完成」。
> 恢复语义的缺陷仍未被执行路径正向验证，属未暴露而非已修复。

---

## 2. 本轮度量

### 2.1 规模与产出（实测）

| 指标 | 值 |
|---|---|
| 文件 / 函数 / 行 | 61 / 419 / 4924 |
| 原始种子 → 收敛候选 | 688 → 200（70.9% 过滤率） |
| 机器自动确认（落库前） | 46 |
| 5.5 复核结论 | 驳回 2、保留 44 |
| AI 确认 | 142 |
| AI 驳回 | 58 |
| 确认合计 | **186**（44 机器 + 142 AI） |
| 严重度 | critical 32 / high 37 / medium 110 / low 7 |
| 未落库判定 | 0 |
| 产物 | `report.md` 35KB / `audit-report.md` 15KB / `result.sarif` 612KB / `result.xlsx` 84KB / `findings/` 186 个 |

### 2.2 时间（`secguard_metrics` + 实测墙钟）

| 口径 | round3 | round2 | 变化 |
|---|---|---|---|
| 自动分析 | **1.316 s**（index 59 / graph 300 / detectors 584 / plan 247 / report 68 ms） | 1.321 s | 持平 |
| AI 研判 | **205 s** | 229 s | **−10%** |
| 端到端 | ≈ **206 s** | ≈ 248 s | −17% |
| spawn 数 | **7**（= 理论下界） | 9 | **−22%** |
| 中断/重派 | 0 / 0 | 0 / 0 | 持平 |

> AI/自动比仍约 **156 : 1**。AI 耗时仍由「子代理上下文装载 + Evidence 打开」主导，
> 不是索引或检测器。

### 2.3 派发效率（实测 / 估算）

| 指标 | 值 |
|---|---|
| 派发提示词 | 7 次 × ≈350~420 tokens ≈ **2.6k tokens**（估算；round2 ≈3k） |
| 单批最大类型数 | 4 |
| 单批最大候选数 | **42**（dangerous-function 39 + sizeof-misuse 1 + hardcoded-secret 2） |
| 证据打开 | 最大 **12**（dangerous-function / null-deref / unchecked-return 顶格），其余 3~11 |
| 读源 | 各类型 ≤5（integer 0 / dangerous 1 / null 5 / memleak 1 / bof 5 / path 5） |
| `repo_greps` | 全部 **0** |
| 装箱结构 | heavy(integer 3 + oob 2)；dangerous(39)+sizeof(1)+secret(2)；null(26)+switch(3)+fmt(1)+divz(2)；unchecked(27)+argtype(2)+datarep(2)+ulc(1)；memleak(22)+double-free(3)+stack(3)+crypto(3)；bof(16)+resource(16)+implicit(4)+signed(1)；path(8)+uninit(9)+injection(1)+race(3) |

---

## 3. round2 遗留项核验（逐条对照，2026-11-01 复测）

| round2 项 | 状态 | 本轮证据 |
|---|---|---|
| P0-1 dismissed 不落库 / `remaining` 不可信 | ✅ **已修** | 29 个类型 `remaining` **全为 0**，`dismissed_count` 逐类型填充（合计 58 = `summary.dismissed_total`） |
| P0-2 三处 `auto_confirmed` 口径不一致 | ❌ **未修** | scan 46 / status 49 / audit 44；divz **2/3/0**、integer **3/5/5** |
| P0-3 `written_count` 定义不一致 | ❌ **未修** | divz cand2/written3/auto3；bof cand16/written7/auto7；double-free cand3/written3/auto3 |
| P1-4 `<value>` 图例占位符未渲染 | ❌ **未修** | `grep -l "<value>" candidates/*/_index.md` = **25/25** |
| P1-5 UAF「使用」定义过宽 | ⚠️ **部分修复** | `fp_copy_nonnull`（指针重赋值）已不再报；但 `make_ptr`（`free(p); return p;`）仍自动确认 |
| P1-6 CWE-732 归入 path-traversal、摘要矛盾 | ⚠️ **部分修复** | 摘要正文已按证据改为「world-writable」；但章节标题仍为 `## path-traversal (CWE-22)`，SARIF message 仍以 "path-traversal in …" 开头 |
| P1-7 integer-overflow 整函数 Evidence 假设 | ❌ **未修** | 3 个候选 Code Context 均 **11 行** |
| P1-8 证据打开预算无硬门禁 | ✅ **已达成** | 全部 ≤12（dangerous / null / unchecked 恰好 12） |
| P1-9 批次未装箱到理论最小值 | ✅ **已修** | **7 批 = 理论下界**（heavy 1 批 + ceil(23/4)=6） |
| P2-10 空索引返回 `indexed: true` | ❌ **未修** | 首帧 `files_indexed: 0` + `indexed: true` |
| P2-11 `.tmp` 结算文件重复/命名混乱 | ⚠️ **部分修复** | 无 `<type>-<type>` 二次拼接；但仍 9 份 / 7 批次，且 subagent-id 与 type 两套命名混用 |
| P2-12 `ai-dismissed.json` 未生成 | ❌ **未修** | 目录仅 `dismissed.json`（收敛期 422 条丢弃），无 AI 驳回台账（58 条） |
| P2-13 缺 `report --stats` 只读接口 | ❌ **未修** | 仍靠第二次 `report --audit` 取 `audits`（本轮 2 次，round2 3 次） |
| O-6 macOS 时间戳命令不适配 | ❌ **复现** | 再次使用 `date +%s000`，最终以 `stat` + `%H:%M:%S` 估算出 ≈199s |

> **结论：round2 的 14 项里，3 项已修、3 项部分、8 项未修；未修的 8 项中有 3 项是 P0。**

---

## 4. 本轮发现的问题（按优先级）

### P0-1　`auto_confirmed` 三处口径仍不一致（round2 P0-2 原样复现）

**实测**

| 类型 | `scan.auto_confirmed_by_type` | 运行中 `status.auto_confirmed` | 终报 `audit.auto_confirmed` |
|---|---|---|---|
| divide-by-zero | **2** | **3** | **0** |
| integer-overflow | **3** | **5** | **5** |
| 全部合计 | **46** | **49** | **44**（5.5 驳回 2 条前为 46） |

**根因（已在 round2 定位，本轮再次可验证）**

- `scan` / `status` 按**检测器名**归属；`audit` 与 `findings.rule_id` 按 **CWE** 归属。
- divide-by-zero 检测器产出的 2 条 auto 发现，其 `rule_id` 是 **CWE-190**（`INT_MIN / -1`），
  于是 audit 把两条归到 `integer-overflow`，`divide-by-zero` 的 auto 归零。
- `status` 又用了第三套映射（divz = 3），三处互不相等。
- 同类现象：`path-traversal` 检测器产出的 `CWE-732`、`integer-overflow` 检测器的
  `CWE-758`（移位 UB）、`injection` 检测器的 `CWE-89`。

**建议**

1. `findings` 增加 `vuln_type` 列（写入时由 `planner.VulnTypeSpec` 决定），
   `scan` / `status` / `audit` 一律按该列聚合，`rule_id` 只用于 SARIF 规则映射；
2. 回归测试：无 AI 写入时 `scan == status == audit`，逐类型断言；
3. 对「检测器产出的子类 CWE」保持属主类型不变（与 P0-2 同一改动）。

**收益**：汇总数字可程序化校验，去掉人工对账。

---

### P0-2　子类 CWE 与证据语义错配，导致 5.5 误驳回真阳性（召回损失，本轮新增实证）

**现象（实测，5.5 复核中确认）**

`src/p9_secure_func.c`：

```c
void tp_secure_constraint(void) {
    char dst[4];
    strcpy_s(dst, 4, "hello");      // :28  dmax=4 如实，源 6 字节 → 约束违约
}
errno_t tp_memcpy_s_count_overflow(char *restrict src) {
    char dst[8];
    return memcpy_s(dst, sizeof(dst), src, 100);  // :60  destsz=8 如实，count=100 → 约束违约
}
```

- 检测器给出的 hint 是 `cat@secure_constraint_violation` / `cat@secure_copy_overflow`，
  说明检测器**理解**了语义是「约束违约」；
- 但落库的 `rule_id` 是 **CWE-787**，`auto_confirm_evidence` 由模板生成
  「the access at line 28 **writes/reads past the end of** `dst`」——按 C 标准
  Annex K，这两处**不会发生任何拷贝**（`strcpy_s` 置 `dst[0]='\0'` 并返回 ERANGE，
  `memcpy_s` 置零并返回非零），因此该句是事实错误；
- 我在 5.5 按「CWE-787 的前提是否成立」判定，**驳回 2 条**——而这正是该样例仓
  标注的 `_s` 误用真阳性。

**影响**

- 交付件少 2 条真问题（本轮 186 vs 若保留则 188）；
- 更本质的是：**同一份自动确认证据，被错误 CWE 归类后，会让 5.5 的"按前提复核"
  自我抵消掉检出**。这不是 5.5 的错，是归属层的错。

**建议**

1. `_s` 约束违约单列子类（建议 CWE-252 / CWE-754 / CWE-20），不要复用 CWE-787 模板；
2. `auto_confirm_evidence` 的末句由 **类别 + 证据**共同模板化，
   禁止对 `cat@*_constraint*` 输出「past the end of」；
3. 5.5 检查清单增加一条：**先核对 `cat@` 与 `rule_id` 是否一致，不一致以证据为准且不驳回**；
4. 回归用例：`tp_secure_constraint` / `tp_memcpy_s_count_overflow` 必须保留为 finding。

---

### P0-3　`written_count` 的定义在不同类型上仍不一致（round2 P0-3 未修）

| 类型 | candidate | written_count | auto_confirmed | AI 实际写入 |
|---|---|---|---|---|
| divide-by-zero | 2 | **3** | 3 | 2 |
| buffer-overflow | 16 | **7** | 7 | 7 |
| double-free | 3 | **3** | 3 | 3 |
| uninit | 9 | **1** | 4 | 1 |
| path-traversal | 8 | **6** | 1 | 6 |

`divide-by-zero` 的 written 含 1 条 `rule_id=CWE-369` 的 auto 行；
`buffer-overflow` 的 written 只算 AI 行（auto 另计）；`uninit` 也只算 AI 行。
同一字段三种算法。

**建议**：schema 文档写死 `written_count := AI 写入的 confirmed 行数`，
auto 独立成列；`remaining := candidate_count − written_count − dismissed_count`，
并加跨类型回归测试。

---

### P1-4　25 个 `_index.md` 的 hint 图例占位符 `<value>` 未渲染（round2 P1-4 未修）

```
$ grep -l "<value>" candidates/*/_index.md | wc -l
25     # 25 个有候选的类型全部命中
```

样例（`candidates/divide-by-zero/_index.md:7`）：

```
> - `cat@<name>` — the detector's sub-category: <value>
```

`<value>` 是模板占位符，未求值替换；`integer-overflow` 的图例仍缺 `buf@/cap@/idx@`
词条，而该类型全部候选都依赖这三个 token。

**影响**：子代理拿到的「图例」等于「hint 词表缺失」，退化为按 `Source` 猜，
直接推高 Evidence 打开量（本轮 dangerous / null / unchecked 三类均打满 12）。

**建议**

- 写盘时对 `hint_tokens.go` 词表**求值渲染**，并输出该类型的 token 全集；
- 加渲染守卫：`grep "<value>" candidates/*/_index.md` 非空即测试失败；
- 图例与主流程提示同源生成（round1 P1-9 遗留冲突仍未修，见下）。

---

### P1-5　UAF 自动确认「使用」定义只修了一半（round2 P1-5 部分修复）

- 已修：`p5_null_flow.c` 的 `free(a); a = b; return a->value;` 不再产出 CWE-416
  （指针重赋值已视为 kill）；
- **仍存在**：`p30_cross_fn_return_double_free.c:18-19`

```c
free(p);
return p;          // :19 被当作 "use" → CWE-416（id=44）
```

`return p` 只读取指针值，不解引用被释放对象。真正的缺陷是调用方 `free(q)`
（已在 `p30:24` 以 CWE-415 确认），因此这条是**与 double-free 重复的弱「使用」**。

**建议**：自动确认的「use」只接受间接访问（`*p` / `p->f` / `p[i]` / 传给可解引用
callee）；`p = …` 视为 kill；`return p` 归入「悬空指针外泄」子类（CWE-562/415 语义），
不再计入 UAF。5.5 清单补一条「use 是否构成真实解引用、是否与其它类型重复」。

---

### P1-6　CWE-732 仍归入 path-traversal 章节，SARIF 文案带错类型名（部分修复）

**实测**

- `report.md:290` 章节标题：`## path-traversal (CWE-22)`；
- 该章节第 1 行（`report.md:296`）是 `pm01_chmod_literal` / `src/pm_permission.c:2`，
  其 `rule_id` 实为 **CWE-732**，证据为 `path@literal` + `mode@0666`；
- **摘要正文已修好**：「chmod/fchmod call chmod sets an other-writable mode (0o002) —
  a world-writable file/dir that any local user can modify」；
- **但 SARIF 未修**：`result.sarif` 中该 result 的 `ruleId` = `CWE-732`，
  message 却是 **"path-traversal in pm01_chmod_literal at src/pm_permission.c:2 — chmod …"**，
  即以属主类型名 `path-traversal` 作前缀。

**建议**

- SARIF message 的类型前缀取 `vuln_type` 或子类名，不取「属主 skill」；
- 若保留属主归属，至少在该行显式标注「子类 CWE-732」；
- 断言：`path@literal` 的行不得出现 `path-traversal` 前缀。

---

### P1-7　`integer-overflow` 的「整函数 Evidence」假设仍不成立（round2 P1-7 未修）

```
candidates/integer-overflow/001_src_allocator_c_110.md          Code Context = 11 行
candidates/integer-overflow/002_src_p8_value_analysis_c_28.md   = 11 行
candidates/integer-overflow/003_src_p8_value_analysis_c_21.md   = 11 行
```

均为 ±8 窗口级别。本轮我仍按文档把它当 heavy 类型，给了它独占的 2 类型批
（integer 3 + out-of-bounds 2 = 5 候选）。本轮 25 类型 / 上限 4 的下界是 7 批，
heavy 规则没有造成额外批次，但**成本模型与真实证据体积不符**，一旦类型数或候选数
变化就会误装箱（例如把 3 个候选的"heavy"独占一个 spawn）。

**建议**：装箱按 **Evidence 实际字节数**（scan 侧可测）定价，而非按类型名硬编码；
若确需整函数证据，在生成侧实现并用单测断言跨度。

---

### P1-8　`ai-dismissed.json` 连续两轮未生成（round2 P2-12 未修）

扫描目录仅：

- `dismissed.json` —— **收敛期**丢弃清单（`total_dropped: 422` + `by_vuln_type`）；
- **无** `ai-dismissed.json` —— 本轮 58 条 AI 驳回只存在于子代理最终消息。

两者名字近似、语义完全不同，客户侧极易误读。

**建议**：finalize 前做产物 checklist（`report.md` / `result.sarif` / `findings/` /
`ai-dismissed.json`），缺则任务未完成；长期由 `candidate_verdicts` 自动生成；
并把收敛期文件改名 `convergence-dropped.json`。

---

### P1-9　缺少廉价的「按类型确认数」只读接口

为在最终报告里给出 per-type confirmed/auto，第二次执行了 `report --audit`，
重渲染 186 个 `findings/*.md` + 612KB SARIF + 84KB xlsx。

**建议**：新增 `report --stats --format json`（只读，复用 `audits` 查询），
或让 `status --per-type` 增加 `confirmed` / `auto_confirmed` / `dismissed` 三列。
编排侧同时改进：**第一次 audit 的响应体已含完整 `audits`，应就地解析缓存**。

---

### P2-10　空索引仍返回 `indexed: true`

会话首帧 `{"indexed": true, "files_indexed": 0, "functions_indexed": 0}`（round1/round2 复现）。

**建议**：`state: empty | stale | ready`；`files_indexed == 0`
或源文件 mtime 晚于 `sgre.db` 时不得报 `ready`。

---

### P2-11　`.tmp` 结算报告多于批次，且两套命名混用

```
bof-rl-ic-sc-batch-report.json            ← subagent-id 命名
buffer-overflow-sub-report.json           ← 类型命名（同批的另一种写法）
integer-overflow-out-of-bounds-report.json
mem-leak-batch-report.json
null-deref-worker-report.json
resource-leak-sub-report.json
sa-dangerous-sizeof-secret-report.json
sub_pt_ui_inj_race-report.json
unchecked-return-argtype-datarep-ulc-report.json
```

**9 份 / 7 批次**；同一批次的 `buffer-overflow` 与 `resource-leak` 各自又写了一份
`*-sub-report.json`。round2 的 `<type>-<type>` 二次拼接已消失，但命名体系仍不唯一。

**建议**：一批只写 1 份 `<subagent_id>-report.json`；需要类型级时写
`<subagent_id>-<type>.json`；`status --reports` 按 `subagent_id` 去重后计数。

---

### P2-12　`report --list` 输出字段集不稳定

186 行中有 **2 行缺少 `variable` 字段**，直接导致我第一次统计脚本
`KeyError: 'variable'`，多花一次往返。

**建议**：`report --list` 固定字段 schema，缺失时输出 `""` 而非省略键。

---

### P2-13　`secguard_db` 结果截断与表名不可发现

- 46 行 auto 查询的 JSON 在 ~8KB 处被截断，被迫改成 `json_extract` 投影重查；
- `SELECT … FROM scan_runs …` 直接返回 `exit code 1`（该表不存在或名称不同），
  错误信息未给出可用表名。

**建议**：提供 `--limit/--offset` 或服务端聚合；`secguard_schema` 的报错里
附「可用表」列表；`scan_runs` 与 `scan_stats` 的命名统一。

---

### P2-14　`ai_duration_ms` 是取整估计，不是毫秒实测

本轮流程：`date +%s000`（BSD date 不支持 `%3N`，得到的是"秒+字面 000"）→
改用 `stat` + `date '+%H:%M:%S'` 得 ≈199s → 最终写入 `205000`。

**建议**：统一用 `python3 -c 'import time; print(int(time.time()*1000))'`；
持久化前把「实测/估算」标记进 `scan_runs`（如 `ai_duration_source: measured|estimated`）。

---

### P2-15　单批候选数 42 超出自适应上限 40（编排侧违规，未致损）

按 `r_type = 0.3`（无历史样本的默认值），`N_type = min(⌊12/0.3⌋=40, 上下文界)` = **40**。
我把 `dangerous-function(39) + sizeof-misuse(1) + hardcoded-secret(2)` 打成 **42 候选** 一批，
超出上限 2 条。实际执行 12 次 Evidence 打开、0 读源、12 驳回，未致损，但违反明文上限。

**建议**：把 tiny 打包的候选数也纳入 ceiling 校验（`batch_candidate_count ≤ N_type`），
超限时拆出最轻的 tiny 类型；或在规范里明确「打包 tiny 可豁免 ≤3 条/类型的溢出」。

---

## 5. 本轮扫描发现的问题（漏洞侧画像）

| 类别 | 确认 | 说明 |
|---|---:|---|
| dangerous-function | 27 | 主要是刻意样例中的 `gets/strcpy/sprintf/alloca/mktemp` 等禁用 API |
| null-deref | 23 | 多为外部 API 返回/框架供给字段未判空 |
| memory-leak / resource-leak | 17 / 16 | 错误返回路径未释放，fd/socket/lock/mmap 未闭环 |
| buffer-overflow / out-of-bounds | 12 / 3 | `_s` 容量说谎、off-by-one、未校验索引 |
| unchecked-return | 10 | `malloc`/`recv` 返回值未检查 |
| 其余 22 类 | 91 | 见 `report.md` |
| **合计** | **186** | critical 32 / high 37 / medium 110 / low 7 |

**质量观察**

- 5.5 驳回的 2 条是**归属错误**造成的假阴性（P0-2），不是检测器漏报；
- `p30:19 return p` 是与 double-free 重复的弱 UAF（P1-5），FP 率约 1/4；
- 本轮 AI 驳回 58 条，主要集中在 `unchecked-return`(17)、`dangerous-function`(12)、
  `buffer-overflow`(9)、`uninit`(8) —— 与「NULL 安全的 free 包装」「已有边界检查」
  「strdup 惯用法」等合理豁免一致。

---

## 6. 编排器（AI 执行方）自身的过程问题

| # | 问题 | 现象 | 改进 |
|---|---|---|---|
| O-1 | **漏产出 `ai-dismissed.json`** | finalize 后未创建，58 条驳回不可见 | finalize 前跑产物 checklist |
| O-2 | **重复全量 audit** | 2 次 `--audit`，第 2 次纯为读 `audits` | 缓存首次响应的 `audits`；等 `--stats` |
| O-3 | **批次候选数超上限** | 42 > N_type 40（P2-15） | 派发前断言 `batch_candidate_count ≤ N_type` |
| O-4 | **5.5 判定未先校验 cat 与 rule_id** | 按 CWE-787 前提驳回 `_s` 约束违约（P0-2） | 5.5 清单第一条：`cat@` 与 `rule_id` 冲突时以证据为准、不驳回 |
| O-5 | **未在派发前跑 `status --reports`（F11a）** | 本轮为新扫描、无影响，但流程缺失 | 派发前固定执行一次 |
| O-6 | **macOS 计时命令再次误用** | `date +%s000`（round2 O-6 复现），最终 `ai_duration_ms` 为估计值 | 统一 `python3` 计时 |
| O-7 | **沿用历史结论未先验证** | 仍把 integer-overflow 当 heavy（实际 11 行） | 派发前 `wc -l` 抽查 1 个 Evidence |
| O-8 | **最终报告用聚合表替代逐条表** | 186 条按 skill 聚合，未逐条列 `文件:行号` | 长报告改为「聚合 + 重点明细 + 指向 report.md」的显式声明 |

---

## 7. 改进优先级与落地顺序

| 顺序 | 事项 | 类型 | 实施面 | 验证方式 |
|---|---|---|---|---|
| 1 | `findings.vuln_type` 单一归属键（P0-1/P1-6） | 缺陷 | db / planner / report / cli | `scan == status == audit` 逐类型断言 |
| 2 | `_s` 约束违约子类化 + 证据模板不跨类复用（P0-2） | 召回 | detectors / evidence | `tp_secure_constraint`、`tp_memcpy_s_count_overflow` 保留为 finding |
| 3 | `written_count` 定义 + `remaining` 同源派生（P0-3） | 缺陷 | db / cli | 5 种类型计数可复现且文档一致 |
| 4 | `_index.md` 图例 `<value>` 求值渲染 + 守卫（P1-4） | 缺陷 | planner | `grep "<value>" candidates/*/_index.md` 为空 |
| 5 | UAF「use = 真实解引用」收紧（P1-5） | 准确性 | detectors | `make_ptr` 不再产出 CWE-416 |
| 6 | `ai-dismissed.json` 强制产出（P1-8） | 流程 | agent-body / finalize | 文件存在且条数 == `dismissed_total` |
| 7 | `report --stats` 只读接口（P1-9） | 体验 | cli | 一次调用拿到 per-type confirmed/auto/dismissed，不再重渲染 |
| 8 | `.tmp` 报告命名与去重（P2-11） | 流程 | agent-body / `status --reports` | 报告数 == 批次数（+ 类型级），命名唯一 |
| 9 | `status` state 枚举（P2-10） | 体验 | cli | 空库首次调用返回 `state: empty` |
| 10 | Evidence 成本按字节定价（P1-7） | 性能 | command-instructions | 装箱不再依赖类型名 heavy 假设 |
| 11 | `report --list` 字段 schema 固定（P2-12） | 体验 | cli | 每行键集完全一致 |
| 12 | 计时统一 + `ai_duration_source`（P2-14） | 数据质量 | cli / 编排 | `ai_duration_ms` 与墙钟误差 < 1% |

---

## 8. 本轮做对、建议保留

1. **一次派发即完成**：7 批同一回合发出、同步收口，0 中断 / 0 空回 / 0 重派 /
   0 `needs_context`。
2. **批次装箱达到理论下界**：25 类型 / 上限 4 / 1 个"heavy" → 7 批（round2 为 9）。
3. **证据预算受控**：全部 `evidence_opens ≤ 12`（round2 曾出现 14），
   `source_reads ≤ 5`，`repo_greps == 0`。
4. **dismissed 落库生效**：`remaining` 全 0、`dismissed_count` 逐类型可见，
   round1/round2 的 P0-1 闭环。
5. **DB 为权威**：`--complete-type` 前逐类型比对 `written_count` 与子代理自报；
   `ai_stage_status` 只由编排器写，无竞态。
6. **5.5 真的做了定点读源**：5 处只读（`p9_secure_func.c` 全文、`windows.c:40-69`、
   `memory_extra.c:1-35`、`p4_uninit.c:10-49`、`parser.c:80-93`），不是走过场。
7. **自动分析零故障**：`detector_errors` / `plan_errors` 均为空，1.316s 完成
   688→200 收敛。
8. **计时口径讲清楚**：最终报告区分「自动分析 / AI 研判 / 端到端」三档，
   不再用"流水线耗时"混淆。

---

## 9. 下轮验证清单（round4）

- [ ] 同一类型在 `scan` / `status` / `audit` 的 `auto_confirmed` 三处相等
      （当前 divz **2/3/0**、integer **3/5/5**）
- [ ] `tp_secure_constraint` / `tp_memcpy_s_count_overflow` 作为 finding 保留
      （当前被 5.5 驳回 2 条）
- [ ] `written_count` 在 divz / bof / double-free / uninit 四类上口径一致
      （当前 3 / 7 / 3 / 1）
- [ ] `grep "<value>" candidates/*/_index.md` 输出为空（当前 25/25 命中）
- [ ] `make_ptr` 不再产生 CWE-416（当前 id=44 仍保留）
- [ ] `report.md` / `result.sarif` 中 `pm_permission.c:2` 不再出现 `path-traversal` 类型前缀
      （当前 SARIF message 以 "path-traversal in …" 开头）
- [ ] `integer-overflow` Evidence 实际跨度与成本模型一致（当前 11 行 vs heavy 假设）
- [ ] `ai-dismissed.json` 存在且条数 == `summary.dismissed_total`（当前 ABSENT vs 58）
- [ ] `.tmp` 报告数 == 批次数 + 类型数，且命名唯一（当前 9 vs 7，两套命名）
- [ ] `report --list` 每行字段集一致（当前 2/186 缺 `variable`）
- [ ] `secguard_status` 首次调用返回 `state: empty`（当前 `indexed: true` + 0 文件）
- [ ] 单批 `batch_candidate_count ≤ N_type`（当前 42 > 40）
- [ ] spawn 数 ≤ 7（当前正好 7，保持）
- [ ] AI 耗时守住 ≤ 205s（本轮 205s，round2 229s，round1 579s）

---

### 附：本轮关键产物

| 产物 | 路径 / 值 |
|---|---|
| 扫描报告（186 条明细） | `.codeagent/secguard-clang/scans/sc_2026-11-01_134321_e8d594/report.md`（35 KB） |
| 审计报告 | `.../audit-report.md`（15 KB） |
| SARIF | `.../result.sarif`（612 KB） |
| Excel | `.../result.xlsx`（84 KB） |
| 逐条确认文件 | `.../findings/`（186 个） |
| 收敛期丢弃清单 | `.../dismissed.json`（`total_dropped: 422`） |
| AI 驳回台账 | **缺失**（应生成 `ai-dismissed.json`，58 条） |
| 数据库 | `.codeagent/secguard-clang/.sgre/sgre.db` |
| 结算报告 | `.sgre/.tmp/*-report.json`（9 份 / 7 批次） |
| 本轮三个时间口径 | 自动 1.316s / AI 205s / 端到端 ≈206s |
