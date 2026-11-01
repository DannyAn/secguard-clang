# Skills 设计全面审视与优化调研报告

> 日期：2026-11-01  
> 范围：`extension/shared/skills/**/SKILL.md`（29 个）、`SKILL_TEMPLATE.md`、`agent-body.md`、`command-instructions.md`、`hint_tokens.go` / `evidence_package.go`、相关 detector / planner registry、`examples/c-vuln-benchmark`。  
> 约束：**本报告只做调研，没有修改任何代码、技能或配置文件。** 所有结论都尽量落到具体文件与行号；无法从代码验证的，明确标注为“判断/建议”。

---

## 0. 结论摘要

**一句话判断：当前 skills 的主要问题不是“规则不够多”，而是“没有把 skill 当成一个可测量、可失败、可迭代的决策契约”。**

现状可以概括为三句话：

1. **少数 skill 已经是“专家决策卡”，多数还停留在“证据词典 + 规则表”。**
   29 个 skill 共 3291 行，平均约 113 行；`null-deref`（252 行）和 `memory-leak`（139 行）明显更成熟，而 `uninit`（83 行）、`use-after-free`（77 行）、`sizeof-misuse`（73 行）、`unbounded-length-copy`（105 行）等仍以“说明证据 + 一张表”为主。按本次统一 rubric 打分，平均约 **4.8/10**；A 级（7–8 分）只有 2 个，C 级（3–4 分）有 13 个。评分是评审判断，不是统计测量，但它反映了一个明显事实：**质量分布极不均匀**。

2. **当前没有 skill 级评测，因此“skills 还有多少提升空间”这个问题现在无法用数据回答。**
   `examples/c-vuln-benchmark` 有 263 个用例、29 个类型，`--coverage` 也显示每个类型都有 finding / no_finding 对照；但 CI 只跑 `secguard scan` + `report --audit`，**不运行 AI 分类**。CI 的 `result.sarif` 里只有 auto-confirmed，validator 又把“候选出现”就算作 detected（[validate-benchmark.py:229-241](../examples/c-vuln-benchmark/scripts/validate-benchmark.py#L229-L241)），所以 **AI/skill 的 precision 和 recall 都没有被测到**。这正是“改 skill 只能凭感觉”的根因。

3. **skills 同时存在“过度确认”和“过度驳回”两类错误，而且“未决 → dismissed”把后者隐藏了。**
   生产证据里既有 unchecked-return 25/25 全误报（[benchmark.md:561](../examples/c-vuln-benchmark/benchmark.md#L561)）、null-deref 6 项误报（[benchmark.md:596](../examples/c-vuln-benchmark/benchmark.md#L596)）、uninit auto-confirm 层 75% 误报（[command-instructions.md:811-812](../extension/shared/command-instructions.md#L811-L812)），也有“201-candidate zero-confirmed”的整类零确认（[null-deref/SKILL.md:85](../extension/shared/skills/null-deref/SKILL.md#L85)）和“基准 118/118 全绿但 5 条可证明漏报”（[benchmark.md:437](../examples/c-vuln-benchmark/benchmark.md#L437)）。**只盯 precision 会把 recall 越修越低；只盯 recall 会把误报重新放回来。**

### 最优先的 8 件事（P0）

| # | 动作 | 解决什么 | 预期影响 |
|---|------|----------|----------|
| 1 | 建 skill 级 golden set：用 263 个基准 + 生产抽样，给每个候选标注**预期 verdict**（confirm/dismiss/needs_review），跑真实 agent 而不是只跑 scan | 没有基线，无法判断改动好坏 | 让后续所有优化可度量；这是最高 ROI |
| 2 | 把 verdict 从二元改成 **confirmed / dismissed / needs_review**，并给 dismissed 加 reason class（`false-positive` / `safe-by-contract` / `unresolved-*`） | “不知道”被写成“安全”，召回被隐藏 | 让 recall 可见、可复核、可反馈 |
| 3 | 修 10 个会直接导致错判的领域/矛盾规则（见 §4.3–§4.5） | FP 与 FN 同时下降 | 预计能消掉一批生产误报和整类漏报 |
| 4 | 对每个 decisive hint 增加 **premise check**（前提校验），禁止“只凭 token 确认” | hint 前提错时 skill 会放大错误 | 减少 auto-confirm / 高置信误报 |
| 5 | hint 契约做成**双向**：code→registry→skill 全覆盖；注册所有 emitted token，删除 dead token | 模型看到无法解释的 token | 减少“看不懂 hint 就猜”的随机性 |
| 6 | 增加**跨类型路由**（route_to / observation），不要因为“不属于我这类”就 dismissed | 真实漏洞落在错误桶里被丢掉 | 直接补召回，尤其是 UAF/null、buffer/injection、implicit/OOB |
| 7 | 移除“按名字信任安全包装器”（SafeCopy/SafeQuery/LockGuard/`_s` 无条件安全），改为读 body/contract | 合成 demo 名字导致误杀 | 减少 precision 与 recall 双向误差 |
| 8 | 统一文档与落库行为：dismissed 是否持久化，`command-instructions`、`agent-body`、`report.go` 现在互相矛盾 | 台账缺失，无法复盘 | 让 dismissed 数据真正可用于学习 |

**边界说明：** 即使把 skills 全部重写，也不能突破 candidate 生成层的天花板；反过来，pipeline 再强，skill 把真实漏洞 dismissed 也会前功尽弃。本报告聚焦 skill 层，但会把 pipeline / orchestration 的耦合点明确标出来。

---

## 1. 调研范围与方法

### 1.1 实际读了什么

- 29 个 `extension/shared/skills/*/SKILL.md` 全文；
- `SKILL_TEMPLATE.md`、`agent-body.md`（726 行）、`command-instructions.md`（975 行）；
- `sgre/internal/planner/hint_tokens.go`、`evidence_package.go` 的 hint 生成逻辑；
- 相关 `registry_*.go`、`filter_*.go`、`evidence/*.go` 的关键分支；
- `examples/c-vuln-benchmark` 的 ground truth、validator、CI workflow、生产误报复盘章节；
- `release/check-extension-consistency.py` 的 skill 结构守卫；
- `secguard report --write-json` 对 dismissed 的实际落库逻辑。

### 1.2 方法

1. **结构盘点**：行数、章节、是否有 Hint Tokens / 代码示例 / Common False Positives / Detection Logic / Fix Suggestions。
2. **决策质量评审**：按同一 rubric 看“一个 LLM 是否能只靠这个 skill + 候选证据稳定地做出正确 verdict”，重点找：内部矛盾、C 语义错误、缺失的 FP/TP 模式、不可执行规则、未决处理。
3. **代码对照**：把 skill 里的 token、category、tier 与 registry / detector / hint 生成逐项对照，确认“skill 说的是不是代码真的会发”。
4. **评测对照**：确认 benchmark / CI 到底测了什么，dismissed 是否落库，最终报告的数字从哪里来。
5. **外部专家视角**：从静态分析、C 安全、LLM skill 设计三个方向补“还应该考虑什么”。

### 1.3 证据等级与限制

- **代码可验证**：token 是否注册、是否 emitted、filter 是否只处理 early-exit、registry tier 等，均已对照源码。
- **文本可验证**：skill 内部矛盾、规则表与 bullet 冲突、severity/status 混用，均可直接引用行号。
- **判断性**：某条规则“会不会导致误判”依赖具体代码形状；本报告给出的是高置信的典型形状，不是对所有代码的统计结论。
- **未做**：没有跑生产扫描、没有运行 AI 分类、没有改 skill 做 A/B。因此本报告不宣称“改完一定提升 X%”，只给出可验证的改进方向和度量方案。

---

## 2. 先校准：你说的“准确率”是哪一层？

“检出准确率偏低”可以指三种完全不同的问题。如果不拆开，优化会打错靶。

| 层 | 产出 | 指标 | 主要由谁决定 | 典型失败 |
|----|------|------|--------------|----------|
| L1 候选生成 | `security_events` → converged candidates | candidate recall / candidate precision | detectors + filters + planner | 真实漏洞没有候选；或候选爆炸 |
| L2 AI 分类 | confirmed / dismissed | **classification precision / recall** | **skills + hints + model + agent-body** | 把安全代码 confirm；把真实漏洞 dismiss |
| L3 落库与审计 | `findings` / `candidate_verdicts` / `result.sarif` | persistence completeness / audit integrity | CLI + agent-body + command-instructions | 判了但没写；写了但没统计；dismissed 丢失 |
| L4 呈现与严重度 | `report.md` / SARIF / `findings/` | severity accuracy / actionability | skills 的 severity matrix + 人工 | 真实漏洞标 LOW；误报标 HIGH |

### 2.1 现网证据同时指向两个方向

**偏“过度确认”（precision 问题）的证据：**

- `unchecked-return`：IDM 生产 AI 复核 **25/25 全误报**，根因包括“消费门槛错档、cast 别名守卫不可见、字段逃逸无建模”（[benchmark.md:561-575](../examples/c-vuln-benchmark/benchmark.md#L561-L575)）。
- `null-deref`：生产 AI 复核 **6 项误报**，根因是短路守卫、条件非空 getter、返回值可空性合成（[benchmark.md:596-626](../examples/c-vuln-benchmark/benchmark.md#L596-L626)）。
- `uninit`：生产实测 auto-confirm 层 **75% 误报**（宏 for-init、block-scope extern、out-param 填充）（[command-instructions.md:811-812](../extension/shared/command-instructions.md#L811-L812)）。

**偏“过度驳回”（recall 问题）的证据：**

- `null-deref` skill 自己记录了一个 **201-candidate zero-confirmed** 的整类零确认（[null-deref/SKILL.md:85](../extension/shared/skills/null-deref/SKILL.md#L85)）。
- benchmark 0.7.0 打磨时发现 **5 条逻辑上可证明会漏报**的形状，而当时 118 例全绿（[benchmark.md:437-455](../examples/c-vuln-benchmark/benchmark.md#L437-L455)）。
- 多个 skill 把“无法 settle”直接写进 dismissed 分支（见 §4.2），这类分支在统计上不会被算作 FN，只会被算作“已处理”。

**结论：** 现在不是“precision 或 recall 哪一个低”的问题，而是 **两者都可能低，且系统没有能力把它们分开度量**。任何只改一端的优化，都会把另一端推得更差。

### 2.2 当前 benchmark 到底测了什么

`validate-benchmark.py` 的 evaluate 逻辑说得很清楚：

- `finding` 用例：**任何 tier 的 candidate 出现就算 detected**，不要求 AI confirm；
- `no_finding` 用例：**CI 的 `result.sarif` 里只有 auto-confirmed，所以只测到 auto-confirm 的 FP**；AI confirm 的 FP 不在 CI 口径里；
- CI 只跑 `secguard scan` + `report --audit`，**没有 AI 分类步骤**（[pr-benchmark.yml:35-53](../.github/workflows/pr-benchmark.yml#L35-L53)）。

因此：

- 它测的是 **detector/filter 的 candidate 召回与 auto-confirm 精度**；
- 它**没有**测 skill 的分类 precision / recall；
- 它甚至会把“AI 把真实漏洞 dismiss 了”算作 detected（因为 candidate 存在），从而掩盖 skill 的召回问题。

这不是说 benchmark 没价值——它作为 pipeline 回归门禁是有价值的；但它**不能回答 skills 的问题**。这是本报告认为的第一大缺口。

---

## 3. 现状盘点：skills 到底做了什么

### 3.1 结构指标

| 指标 | 数值 | 说明 |
|------|------|------|
| skill 数 | 29 | 与 `secguard types` 对齐 |
| 总行数 | 3291 | 平均 113 行；最长 null-deref 252，最短 signed-compare 65 |
| 有 `### Hint Tokens` | 20 / 29 | 9 个没有；null-deref 用 tier 表替代，但不在标准小节 |
| 有代码示例 | **5 / 29** | memory-leak、resource-leak、out-of-bounds、path-traversal、data-representation |
| 有 `### Common False Positives` | 21 / 29 | 8 个没有：buffer-overflow、crypto-misuse、deadlock、hardcoded-secret、injection、integer-overflow、out-of-bounds、race-condition |
| 有 `### Detection Logic` | 17 / 29 | 12 个没有 |
| 有 `### Fix Suggestions` | 25 / 29 | 4 个没有：divide-by-zero、signed-compare、sizeof-misuse、unchecked-return |
| 写 `dismissed → low` | 28 / 29 | 但 19 个 skill 的 severity 表里又有 `HIGH/MEDIUM (dismissed)` 行 |
| `compatibility` 含 DSH | 24 / 29 | 5 个只写 `opencode`（invalid-free、stack-address-escape、switch-fallthrough、unbounded-length-copy、use-after-free） |

> 这些是结构指标，不代表内容质量；但它们说明一个事实：**模板并没有被真正执行到每个 skill**，而且 guard 只检查结构，不检查内容。

### 3.2 已经做得好的地方（不要推翻）

这套设计里有几件事是明显正确的，应该保留并强化：

1. **单一模板 + 结构守卫**：frontmatter name、H2 标题、`### Classification Rules` 表、`### Evidence closure` 都有机器检查（[check-extension-consistency.py:226-285](../release/check-extension-consistency.py#L226-L285)），避免了 v0.5.x 那种“skill 根本加载不了”的事故。
2. **Evidence closure**：明确要求先读 `## Callee Definition` / `## Macro Definition`，再用 `secguard def`，禁止全仓 grep（如 [null-deref/SKILL.md:43-52](../extension/shared/skills/null-deref/SKILL.md#L43-L52)）。这是对“agent 到处搜代码”的正确约束。
3. **Hint Token 词汇表**：把 pipeline 的机器事实压缩成可读 token（[hint_tokens.go:38-208](../sgre/internal/planner/hint_tokens.go#L38-L208)），并生成 `_index.md` 的 Hint 列，这是这套方案最有价值的抽象之一。
4. **按 tier 给动作，而不是按类型给口号**：`null-deref` 的 Nullable-Origin Tier 表、`memory-leak` 的 `leak@definite` / `leak@conditional` + `escape@` 决策，都是“证据 → 动作”的好例子。
5. **Group verdict / 跨函数模式复用**：对大批量 suspected 类型，这是控制 token 与墙钟的关键设计（[null-deref/SKILL.md:74-85](../extension/shared/skills/null-deref/SKILL.md#L74-L85)、[agent-body.md:274-291](../extension/shared/agent-body.md#L274-L291)）。
6. **Evidence-open / source-read 预算**：把“开证据文件”当成预算资源，而不是默认动作（[agent-body.md:71-83](../extension/shared/agent-body.md#L71-L83)），这对大类型是必要的。
7. **Macro / caller census 的显式处理**：`macro-context`、`callsites@`、`callers@` 这些 token 把跨文件事实变成 in-file 判断，减少 grep。
8. **Severity 与 status 的正交理念**：模板明确说两者独立（[SKILL_TEMPLATE.md:65-82](../extension/shared/skills/SKILL_TEMPLATE.md#L65-L82)），方向是对的（虽然执行有矛盾，见 §4.8）。
9. **单遍最终裁决 + 引用证据**：`dismissed` 必须引用具体证据，不允许“insufficient context”式 bail（[agent-body.md:591-598](../extension/shared/agent-body.md#L591-L598)），这是可审计性的基础。
10. **边界扫描 / 库场景的 fail-open**：对无 `main` 的 partial scan，指针参数按外部 ABI 处理（[agent-body.md:267-273](../extension/shared/agent-body.md#L267-L273)），这是对“库没有调用者”场景的正确认识。

### 3.3 分层评价

以下评分是同一 rubric 下的**评审判断**（10 = 接近专家决策卡；5 = 可用但依赖模型自由发挥；3 = 规则表与证据脱节），不是统计精度。

| 层级 | 分数 | Skill |
|------|------|-------|
| **A：接近决策卡** | 7–8 | null-deref、memory-leak |
| **B：可用，但有明显规则/一致性问题** | 5–6 | double-free、resource-leak、out-of-bounds、integer-overflow、injection、dangerous-function、hardcoded-secret、unchecked-return、race-condition、signal-handler、switch-fallthrough、signed-compare、argument-type、invalid-free |
| **C：需要重写或大修** | 3–4 | use-after-free、uninit、stack-address-escape、buffer-overflow、divide-by-zero、sizeof-misuse、unbounded-length-copy、format-string、path-traversal、crypto-misuse、data-representation、implicit-contract、deadlock |

**核心诊断：**

> 大多数 skill 在回答“这个候选携带了哪些证据”，而不是“面对这些证据，我下一步该问什么、问到什么程度可以停、什么情况下必须承认不知道”。

这导致三个后果：

- 规则是**平铺的**，没有优先级；当两条规则同时命中时，模型只能猜。
- 规则是**描述性的**，没有可证伪的前提；模型无法判断 token 是否可信。
- 规则是**封闭的**，没有“未决”出口；不知道就 dismissed，于是召回被系统性牺牲。

---

## 4. 最影响准确率的具体缺陷

> 这一节按“影响机制”分组，不按 skill 目录组织。每条都给出证据；`[P]` = 主要造成误报，`[R]` = 主要造成漏报，`[M]` = 主要让指标不可测。

### 4.1 [M] 没有 skill 级 ground truth，所有优化都是“信仰驱动”

**证据：**

- benchmark 的 validator 把 candidate 出现算 detected、只把 auto-confirmed 算 FP（[validate-benchmark.py:229-241](../examples/c-vuln-benchmark/scripts/validate-benchmark.py#L229-L241)）。
- CI 只跑 scan + audit，没有 AI 分类（[pr-benchmark.yml:35-53](../.github/workflows/pr-benchmark.yml#L35-L53)）。
- 文档写“25 个注册 skill / 202 用例”，实际 `--coverage` 输出是 **29 个类型 / 263 用例**；文档已经落后于代码。
- `agent-body.md` 要求 dismissed 也写入 `candidate_verdicts`（[agent-body.md:412-419](../extension/shared/agent-body.md#L412-L419)），`report.go` 也确实会写（[report.go:666-690](../sgre/internal/cli/report.go#L666-L690)），但 `command-instructions.md` 明确说“dismissed 不写、不统计”（[command-instructions.md:439](../extension/shared/command-instructions.md#L439)、[command-instructions.md:665-667](../extension/shared/command-instructions.md#L665-L667)、[command-instructions.md:688-691](../extension/shared/command-instructions.md#L688-L691)）。**结果很可能是：台账功能存在，但生产 dispatch 提示词不让子代理写，台账长期为空。**

**为什么这是第一问题：**

- 你无法比较“改前 vs 改后”；
- 你无法知道某个 skill 的 FP 率；
- 你无法从生产 dismiss 中挖 hard negative；
- 你只能凭“这次感觉好一点”来迭代。

**建议：**

1. 建立 `eval/skills/`：每个 type 至少 20 个用例（10 finding / 10 no_finding），带 `expected_verdict`、`expected_severity`、`hard_negative`、`source`、`rationale`。
2. 用真实 agent + 真实 skill 跑 `candidates/`，不要只跑 `scan`；测量 L2。
3. 先跑一次 baseline（当前 29 个 skill 的 precision/recall/needs_review），把它写进 CI 注释或 dashboard。
4. 把“benchmark 全绿”与“skill 准确率”分开汇报，禁止用前者证明后者。

---

### 4.2 [R] “未决 → dismissed”被制度化，召回被系统性牺牲

**证据（按严重度排序）：**

| Skill | 规则 | 问题 |
|-------|------|------|
| `uninit` | `Variable may be initialized on some paths but not all → dismissed`（[uninit/SKILL.md:58](../extension/shared/skills/uninit/SKILL.md#L58)） | 某些路径未初始化正是 CWE-457 的典型形态；dismiss 等于漏报 |
| `stack-address-escape` | `escape-kind@store into a global whose lifetime ≤ the local's, or into a static target → dismissed`（[stack-address-escape/SKILL.md:64](../extension/shared/skills/stack-address-escape/SKILL.md#L64)） | 把 `&local` 存进 global/static 后返回，是标准的悬垂指针；这里反而 dismiss |
| `hardcoded-secret` | 只匹配变量/字段名、低熵值 → dismissed（[hardcoded-secret/SKILL.md:62](../extension/shared/skills/hardcoded-secret/SKILL.md#L62)） | `password = "hunter2"` 是真实弱口令；名字匹配不是“安全”证据 |
| `path-traversal` | 参数没有可证明的 tainted caller、没有 census → dismissed（[path-traversal/SKILL.md:66](../extension/shared/skills/path-traversal/SKILL.md#L66)） | 库/partial scan 的导出函数，调用者在 scan 外；这正是信任边界，不能 dismiss |
| `crypto-misuse` | `reason@` token 单独出现 → 已由 Hint 决定，无需开证据（[crypto-misuse/SKILL.md:44-46](../extension/shared/skills/crypto-misuse/SKILL.md#L44-L46)） | 与 agent-body “弱 crypto 取决于用途，MD5-for-checksum dismiss”直接冲突（[agent-body.md:261](../extension/shared/agent-body.md#L261)） |
| `use-after-free` | 跨函数 free+use → dismissed（[use-after-free/SKILL.md:46](../extension/shared/skills/use-after-free/SKILL.md#L46)） | 与 double-free 的 global-slot 跨函数确认、pipeline 的跨函数分析能力不一致 |
| `memory-leak` | 释放/所有权无法在本函数内确定 → dismissed（[memory-leak/SKILL.md:85](../extension/shared/skills/memory-leak/SKILL.md#L85)） | 这里恰恰应该 needs_review；skill 自己也提供了 `needs_context` 出口（[memory-leak/SKILL.md:48](../extension/shared/skills/memory-leak/SKILL.md#L48)），但规则表没走 |
| `divide-by-zero` | divisor 来源无法 settle → dismissed（[divide-by-zero/SKILL.md:64](../extension/shared/skills/divide-by-zero/SKILL.md#L64)） | 与同文“要 judge callers”矛盾 |

**机制：** 这不是某一个 skill 的笔误，而是模板层面的设计：

- 模板的 Classification Rules 示例行就是 `| <needs-out-of-scope-facts shape> | **dismissed** |`（[SKILL_TEMPLATE.md:54](../extension/shared/skills/SKILL_TEMPLATE.md#L54)）；
- severity 示例又把 `unproved shape` 写成 `MEDIUM / LOW (dismissed)`（[SKILL_TEMPLATE.md:88](../extension/shared/skills/SKILL_TEMPLATE.md#L88)）；
- agent-body 又把 `dismissed` 定义为“false positive **OR** could not settle”（[agent-body.md:574-580](../extension/shared/agent-body.md#L574-L580)）。

这三处叠加，等于告诉模型：**不知道就写 dismissed，而且这样是合规的。** 统计上它不会进入 FP，也不会进入 FN，于是 recall 永远看起来“还行”。

**建议：**

- 在协议层增加 `needs_review`（不是 finding，不改变 confirmed 列表），并强制写 reason class；
- 把 `dismissed` 限定为“有具体反证”：guard、safe call、contract、lifetime、bounds、whitelist 等；
- 如果暂时不能改协议，至少在 `candidate_verdicts.reason` 里加结构化前缀（`unresolved:origin` / `unresolved:guard` / `unresolved:contract`），让统计能分开。

---

### 4.3 [P/R] 过度信任 hint：前提不成立时，skill 会放大错误

skills 大量使用“machine-proved → confirm，no read”的句式。这个设计在 hint 正确时很高效，但当前至少有三类前提缺陷。

#### 4.3.1 `data-representation`：唯一的 verdict token 实际不会出现

- skill 说 `cast@<type>` 是“the whole verdict basis”（[data-representation/SKILL.md:68-71](../extension/shared/skills/data-representation/SKILL.md#L68-L71)）。
- 但 detector 只写 `expected` / `actual`，不写 `cast`（[data_representation.go:141-142](../sgre/internal/evidence/data_representation.go#L141-L142)）。
- planner 把 `CastType` 从 `props.Cast` 取（[planner.go:568](../sgre/internal/planner/planner.go#L568)），因此 `CastType` 为空；`BuildVerdictFacts` 直接返回 nil（[registry_data_representation.go:28-35](../sgre/internal/planner/registry_data_representation.go#L28-L35)）。

**后果：** 每一行都没有 Hint；skill 却告诉模型“从 cast token 判断”。模型只能去读 Evidence/源码，或者凭 `Source` 猜。**这不是“模型能力问题”，是契约断了。**

**修法：** detector 增加 `cast` property（它已经有 `ci.castType`），或者在 `BuildVerdictFacts` 里用 `ActualType` 生成 `cast@`；同时让 skill 的 token 表与 emitter 对齐。

#### 4.3.2 `buffer-overflow`：`cap@` 是“元素数”，`idx@` 可能是“字节数”

- Hint 表把 `cap@N` 描述为“capacity in elements”，把 `idx@` 描述为“access index / copy size / declared size argument”（[buffer-overflow/SKILL.md:62-63](../extension/shared/skills/buffer-overflow/SKILL.md#L62-L63)）。
- 规则表却说“constant index >= array size → confirmed”（[buffer-overflow/SKILL.md:111](../extension/shared/skills/buffer-overflow/SKILL.md#L111)），并让模型直接比较 `idx@` 与 `cap@`。
- 对 `int arr[10]; memcpy(arr, src, 40)`，`cap@10`（元素）、`idx@40`（字节），直接比较会得出“越界”，但 40 字节正好是 10 个 int。

**后果：** 单位错误会制造 confirmed 误报；如果 detector 端也按同一比较发事件，则是 pipeline 误报被 skill 确认。

**修法：** 在 token 层显式带单位（`cap@10elem` / `idx@40B`），或在 skill 里强制“先换算成同一单位”；对 `memcpy` 类，比较 `idx_bytes` 与 `cap_elements * sizeof(elem)`。同时检查 `checkBoundedCopyOverflow` 的比较是否已经做了元素→字节换算（[buffer_overflow.go:388-400](../sgre/internal/evidence/buffer_overflow.go#L388-L400)）。

#### 4.3.3 `cap@` 缺失时仍声称“detector 已证明越界”

- `buildBufferVerdictFacts` 只要 `idx` 是常量，就写“the detector already proved it reaches past cap@, machine-proved out-of-bounds”，即使 `c.Size == 0`、根本没有 `cap@`（[registry.go:445-453](../sgre/internal/planner/registry.go#L445-L453)）。
- skill 的规则表又要求“constant index >= array size → confirmed”。

**后果：** 没有容量证据的常量下标也会被当成“已证明”。这是“hint 说 proven，skill 就 confirm”的典型放大链。

**修法：** 没有 `cap@` 时，token 应降级为“unproven”，skill 对应行改为“needs element-size / cap; if absent → needs_review”。

#### 4.3.4 `sizeof-misuse`：registry 说 suspected，skill 说 machine-confirmed

- registry 两个 category 都是 `suspected`，注释明确说“redis scan dismissed 11/11 auto-confirms”（[registry_sizeof_misuse.go:20-23](../sgre/internal/planner/registry_sizeof_misuse.go#L20-L23)）。
- skill 却写 `sizeof_pointer` 是 `confirmed`（[sizeof-misuse/SKILL.md:34](../extension/shared/skills/sizeof-misuse/SKILL.md#L34)、[sizeof-misuse/SKILL.md:54](../extension/shared/skills/sizeof-misuse/SKILL.md#L54)）。

**后果：** 模型会把这类型当成“机器已证”，不再判断“到底想分配元素还是指针数组”。

**修法：** 与 registry 对齐，两个 category 都按“judge intent from use of the allocated object”处理；只有在能看到 `p[i]` 被当对象使用、且分配大小确实少了一个元素宽度时才 confirm。

#### 4.3.5 `implicit-contract`：filter 只认 early-exit guard，skill 却说“no dominating guard”是 proven

- `filter_contract_gap.go` 只接受 `if (...) return;` 形态的 early-exit guard（[filter_contract_gap.go:128-138](../sgre/internal/planner/filter_contract_gap.go#L128-L138)）。
- 因此 `if (obj->p != NULL) { use(obj->p); }` 这种 if-body 守卫不会被 drop，candidate 仍然到达 AI。
- skill 却说“no dominating null guard”是事实（[implicit-contract/SKILL.md:28-30](../extension/shared/skills/implicit-contract/SKILL.md#L28-L30)），且分类表没有“deref 就在测试它的 if 里”这一行（[implicit-contract/SKILL.md:80-87](../extension/shared/skills/implicit-contract/SKILL.md#L80-L87)）。

**后果：** 这是最典型、最高频的 FP 形状之一。

**修法：** skill 增加一行“deref inside the same if-body / && chain as the null test → false-positive”；filter 端扩展 guard dominance 到 if-body（这是 pipeline 修复，但 skill 必须能识别这种已存在但未建模的 guard）。

#### 4.3.6 `unchecked-return`：`contract@known` 到底是“决定性”还是“suspected”？

- skill 说 `contract@known` → **suspected**，还要判断失败是否可观察（[unchecked-return/SKILL.md:33](../extension/shared/skills/unchecked-return/SKILL.md#L33)）。
- agent-body 把 `contract@known` 列入“Machine-proved facts → decisive, no read”（[agent-body.md:206](../extension/shared/agent-body.md#L206)）。
- hint_tokens 的说明是“an unchecked return is a genuine CWE-252 defect”（[hint_tokens.go:55](../sgre/internal/planner/hint_tokens.go#L55)）。

**后果：** 同一个 token，三份文档三种强度；模型会按最省力的“decisive”执行，直接 confirm，这正是 25/25 误报的土壤。

**修法：** 选一个权威定义。建议：`contract@known` 只证明“返回值未被检查”，不证明“失败可观察”；verdict 必须结合调用点上下文，skill 应把“unchecked is proved / observability is not”写清楚，并删除 agent-body 的“decisive”归类。

---

### 4.4 [P] 会直接制造 confirmed 误报的领域错误

这些不是“措辞问题”，是 C 语义/安全语义错误。由于 skill 会让模型 confirm，它们会直接进入 `findings/`。

| # | Skill | 错误 | 为什么错 | 证据 |
|---|-------|------|----------|------|
| 1 | `signal-handler` | 把 `strlen/strcpy/strncpy/strcat/strncat/strcmp/strncmp/strchr/strstr` 列为“非 async-signal-safe”，并说“unsafe list 是 POSIX 列表的反集” | 这些函数在 POSIX.1-2008 TC2 起就是 async-signal-safe（见 [signal-safety(7)](https://man7.org/linux/man-pages/man7/signal-safety.7.html)）。detector 的 `asyncSignalUnsafe` 确实把它们标为 unsafe（[signal_handler.go:43-47](../sgre/internal/evidence/signal_handler.go#L43-L47)），而 registry 又是 `confirmed`，于是直接产出 confirmed FP | [signal-handler/SKILL.md:53-56](../extension/shared/skills/signal-handler/SKILL.md#L53-L56) |
| 2 | `format-string` | `snprintf(buf, sizeof(buf), fmt, ...)` → false-positive（“bounded with sizeof”） | `sizeof` 只约束输出长度，不约束 format 本身；非字面量 format 仍然可以有 `%s`/`%n` 任意读/写。detector 也没有“含 sizeof 就跳过”的逻辑（[format_string.go:52-70](../sgre/internal/evidence/format_string.go#L52-L70)） | [format-string/SKILL.md:61](../extension/shared/skills/format-string/SKILL.md#L61)、[format-string/SKILL.md:38](../extension/shared/skills/format-string/SKILL.md#L38) |
| 3 | `signed-compare` | `u <= -1` 总是 false、`u > -1` 总是 true | 对 rank ≥ int 的 unsigned（`unsigned`/`size_t`），`-1` 会转换为 `UINT_MAX`/`SIZE_MAX`：`u <= -1` 恒真，`u > -1` 恒假。skill 的方向写反了；只有窄 unsigned（`unsigned char/short` 提升为 int）才符合它写的方向 | [signed-compare/SKILL.md:17-18](../extension/shared/skills/signed-compare/SKILL.md#L17-L18) |
| 4 | `buffer-overflow` | 顶部 category 说明写 `format_overflow_var` / `secure_constraint_violation` 是 dismissed，规则表又写 confirmed | 同一文件内三处不一致；registry 里 `secure_constraint_violation` 是 `suspected` + CWE-754（[registry_buffer_overflow.go:26-32](../sgre/internal/planner/registry_buffer_overflow.go#L26-L32)），既不是 dismissed 也不是 CWE-787 | [buffer-overflow/SKILL.md:32](../extension/shared/skills/buffer-overflow/SKILL.md#L32)、[buffer-overflow/SKILL.md:37](../extension/shared/skills/buffer-overflow/SKILL.md#L37)、[buffer-overflow/SKILL.md:117](../extension/shared/skills/buffer-overflow/SKILL.md#L117)、[buffer-overflow/SKILL.md:127](../extension/shared/skills/buffer-overflow/SKILL.md#L127) |
| 5 | `argument-type` | 7 条规则里 4 条是 detector 根本不会发的（void*/byte/same-size/aggregate）；剩下的 live 行全部写 confirmed | detector 在发事件前已经过滤了这些（[argument_type.go:125](../sgre/internal/evidence/argument_type.go#L125)、[argument_type.go:310](../sgre/internal/evidence/argument_type.go#L310)、[argument_type.go:314](../sgre/internal/evidence/argument_type.go#L314)），且 registry 的 DefaultSuspicion 是 suspected（[registry_argument_type.go:11](../sgre/internal/planner/registry_argument_type.go#L11)）。skill 的“flagship dismissal”永远不会出现，live 行则变成橡皮图章 | [argument-type/SKILL.md:72-78](../extension/shared/skills/argument-type/SKILL.md#L72-L78) |
| 6 | `race-condition` | “Shared variable accessed by only one thread function → false-positive” | 同一个 thread function 可以被 `pthread_create` 启动两次；detector 的 gate 是 `instances < 2`（[race_condition.go:465](../sgre/internal/evidence/race_condition.go#L465)），一个函数启动两次正是经典 race | [race-condition/SKILL.md:70](../extension/shared/skills/race-condition/SKILL.md#L70) |
| 7 | `deadlock` | `pthread_mutex_timedlock` 参与的锁序环 → dismissed（“timeout allows recovery”） | detector 明确说“It is still an acquisition — the inversion is real”，只是把 emission 保持为 suspected（[deadlock.go:63-67](../sgre/internal/evidence/deadlock.go#L63-L67)）。timeout 只能降级影响，不能否认 inversion | [deadlock/SKILL.md:59](../extension/shared/skills/deadlock/SKILL.md#L59) |
| 8 | `switch-fallthrough` | “a `fall through` comment or an int switch without default → false-positive（detector never emits it）” | comment 匹配是前缀锚定的（`HasPrefix(t, m+" ")` / `m+":"`），`/* deliberately fall through to default */` 不会被豁免，仍会 emit（[switch_flow.go:199-207](../sgre/internal/evidence/switch_flow.go#L199-L207)）；`__attribute__((fallthrough))` / `[[fallthrough]]` 不是注释，也照样 emit | [switch-fallthrough/SKILL.md:66](../extension/shared/skills/switch-fallthrough/SKILL.md#L66) |

**处理原则：** 这类错误不要“在 skill 里加一句解释”就完事；要么修 skill 规则，要么修 detector 的清单/过滤，两者必须一致。特别是 `signal-handler` 和 `format-string`，它们会直接产生 confirmed 误报，优先级最高。

---

### 4.5 [R] 会直接造成漏报的领域错误

| # | Skill | 错误 | 为什么错 | 证据 |
|---|-------|------|----------|------|
| 1 | `uninit` | 条件初始化 → dismissed | 未初始化路径就是 CWE-457；正确动作是“若未初始化路径能到达 read → confirmed；否则 dismissed” | [uninit/SKILL.md:58](../extension/shared/skills/uninit/SKILL.md#L58) |
| 2 | `stack-address-escape` | store 到 global/static → dismissed | `static`/global 的生命周期比 frame 长，但存进去的是 `&local`，返回后仍是悬垂指针；`*p = local`（拷贝值）才是安全形态 | [stack-address-escape/SKILL.md:64](../extension/shared/skills/stack-address-escape/SKILL.md#L64) |
| 3 | `hardcoded-secret` | 仅名字匹配、低熵 → dismissed | 真实弱口令往往低熵；名字匹配只能算“线索”，不能算“安全反证” | [hardcoded-secret/SKILL.md:62](../extension/shared/skills/hardcoded-secret/SKILL.md#L62) |
| 4 | `path-traversal` | 没有 in-tree tainted caller / 没有 census → dismissed | 库/partial scan 的导出函数，调用者在 scan 外；agent-body 要求从签名判断参数是否是 public entry-point（[agent-body.md:223-226](../extension/shared/agent-body.md#L223-L226)），边界扫描还要按外部 ABI 处理（[agent-body.md:267-273](../extension/shared/agent-body.md#L267-L273)），而不是默认安全 | [path-traversal/SKILL.md:66](../extension/shared/skills/path-traversal/SKILL.md#L66) |
| 5 | `crypto-misuse` | `reason@` 单独出现就“settled”，无需上下文 | 与 agent-body 的“weak crypto is context-dependent”直接冲突；MD5-for-checksum 不是缺陷 | [crypto-misuse/SKILL.md:44-46](../extension/shared/skills/crypto-misuse/SKILL.md#L44-L46)、[agent-body.md:261](../extension/shared/agent-body.md#L261) |
| 6 | `integer-overflow` | `Arithmetic on int (signed) feeding malloc → dismissed` | signed overflow 是 UB；更常见的是负的 int 被 widen 成 size_t 后进入 malloc（CWE-195）。整类 dismiss 会漏掉最常见的真实 bug | [integer-overflow/SKILL.md:132](../extension/shared/skills/integer-overflow/SKILL.md#L132) |
| 7 | `use-after-free` | 跨函数 free+use → dismissed | 与 double-free 的 global-slot 跨函数确认、pipeline 的跨函数分析方向不一致；即使当前 detector 不常发，也不该在 skill 层写成“永远 dismiss” | [use-after-free/SKILL.md:46](../extension/shared/skills/use-after-free/SKILL.md#L46) |
| 8 | `memory-leak` | 本函数无法确定 owner → dismissed | 应该 needs_review；skill 自己都有 `needs_context` 出口 | [memory-leak/SKILL.md:85](../extension/shared/skills/memory-leak/SKILL.md#L85) |

**共同点：** 这些规则都在“证据不足”时选择了“安全”，而不是“未决”。它们不是精度优化，而是把不确定性藏起来。

---

### 4.6 [P/R] 跨类型盲区：真实漏洞落在错误的桶里，然后被 dismiss

当前架构是“按 type 分派、按 type 持久化”，每个 subagent 只写自己 type 的 findings。skill 又经常在“这不是本类型”时直接 false-positive/dismissed，而没有路由机制。

典型例子：

| 场景 | 一个 skill 的裁决 | 另一个 skill 的裁决 | 后果 |
|------|------------------|--------------------|------|
| `free(ptr); ptr = NULL; ptr->field` | UAF: “crash, not UAF (NULL deref instead)” → dismissed（[use-after-free/SKILL.md:57](../extension/shared/skills/use-after-free/SKILL.md#L57)） | null-deref 可能根本没有在同一行发出 candidate | 真实 NULL deref 被丢掉 |
| `sprintf(dst, ..., system_cmd)` | buffer-overflow: “false-positive for buffer-overflow (injection is the root cause)” → dismissed（[buffer-overflow/SKILL.md:119](../extension/shared/skills/buffer-overflow/SKILL.md#L119)） | injection 不一定会从同一行发出 candidate | 真实注入被丢掉 |
| `for (i=0; i<obj->n; i++) use(obj->p[i])` | implicit-contract: “empty state handled” → dismissed（[implicit-contract/SKILL.md:84](../extension/shared/skills/implicit-contract/SKILL.md#L84)） | out-of-bounds: `idx-src@` 无 bounds check → confirmed（[out-of-bounds/SKILL.md:116](../extension/shared/skills/out-of-bounds/SKILL.md#L116)） | 同一形状，两个相反结论 |
| `p = obj->P; p->x` | implicit-contract: CWE-20 candidate | null-deref: CWE-476 candidate（`null@opaque-origin`） | 可能重复报告，也可能只报一个 |
| `system()` / `execve()` with tainted path | injection: CWE-78 | injection 自己的 “safe alternative” 表又说 execve 安全（[injection/SKILL.md:57](../extension/shared/skills/injection/SKILL.md#L57)） | 同一调用，取决于读哪一行 |

**建议：**

- 在 verdict JSON 增加 `route_to` / `route_evidence`（可选），当模型判断“这是另一类缺陷”时记录，而不是 dismiss；
- orchestrator 收集 `route_to`，在全部 type 跑完后做一次跨类型 triage；
- 至少不要用 `false-positive` 表达“属于别的类型”；用 `dismissed + reason: cross-type`，保留线索。

---

### 4.7 [P/R] 按名字信任“安全包装器”，而且是 demo 名字

- `agent-body.md` 直接写“Safe wrappers (SafeCopy, SafeQuery, ResourceHandle, LockGuard) → false-positive”（[agent-body.md:262](../extension/shared/agent-body.md#L262)）。
- `injection` skill 有一整张 P1 表：`SafeQuery_exec`、`SafeExecArg`、`validate_exec_arg`、`sanitize_argv`、`strip_crlf` 等（[injection/SKILL.md:64-77](../extension/shared/skills/injection/SKILL.md#L64-L77)），并规定“SafeExecArg wrapper used → false-positive”。
- 这些名字来自 benchmark 的 demo（`apikb.go:48-49`），不是通用项目约定；`filter_extended.go` 甚至匹配“包含该名字的函数”，一个叫 `SafeQuery_exec` 的容器函数会把它内部的所有调用都豁免。
- `apikb.go` 还把 `_s` 系列当作无条件安全，这与 agent-body 自己说的“function is safe ≠ this call is safe”矛盾（[agent-body.md:260](../extension/shared/agent-body.md#L260)）。

**后果：**

- 真实项目里只要有一个名字像“safe”的 wrapper，就可能被错误豁免（漏报）；
- 反过来，如果 wrapper 名字不“safe”，即使它真的做了检查，也可能被 confirm（误报）。

**修法：** 删除按名字的 blanket exemption。统一规则：

> 只有当 `## Callee Definition` 里的 body 证明了检查（或 `[contracts]` 声明了契约）时，才豁免；名字只用于“值得优先看”，不能用于 verdict。

---

### 4.8 [P/R] skill 内部自相矛盾（同一文件，两套裁决）

这类矛盾比“规则不够细”更危险，因为模型会按先读到的内容执行。

| Skill | 矛盾 | 证据 |
|-------|------|------|
| `buffer-overflow` | 顶部说 `format_overflow_var` dismissed / `secure_constraint_violation` dismissed；表里说 confirmed | [SKILL.md:32](../extension/shared/skills/buffer-overflow/SKILL.md#L32) vs [117](../extension/shared/skills/buffer-overflow/SKILL.md#L117)；[37](../extension/shared/skills/buffer-overflow/SKILL.md#L37) vs [127](../extension/shared/skills/buffer-overflow/SKILL.md#L127) |
| `crypto-misuse` | `reason@` 单独出现就 settled；表里又说 MD5/SHA1 必须“for security purposes”才 confirmed | [44-46](../extension/shared/skills/crypto-misuse/SKILL.md#L44-L46) vs [75](../extension/shared/skills/crypto-misuse/SKILL.md#L75) |
| `unchecked-return` | `contract@known` 是 suspected；agent-body 说是 decisive；hint_tokens 说是 genuine defect | [33](../extension/shared/skills/unchecked-return/SKILL.md#L33)、[agent-body.md:206](../extension/shared/agent-body.md#L206)、[hint_tokens.go:55](../sgre/internal/planner/hint_tokens.go#L55) |
| `hardcoded-secret` | 说“judge each one”，分类表又说 name-only 直接 dismissed | [24](../extension/shared/skills/hardcoded-secret/SKILL.md#L24)、[31](../extension/shared/skills/hardcoded-secret/SKILL.md#L31) vs [62](../extension/shared/skills/hardcoded-secret/SKILL.md#L62) |
| `use-after-free` | “free + use same function → confirmed”，但 `free; p=NULL; p->field` 又说不是 UAF | [43](../extension/shared/skills/use-after-free/SKILL.md#L43) vs [57](../extension/shared/skills/use-after-free/SKILL.md#L57) |
| `memory-leak` | 全文 `dismissed → low`，severity 表又写 `MEDIUM (dismissed)` | [132](../extension/shared/skills/memory-leak/SKILL.md#L132) vs [139](../extension/shared/skills/memory-leak/SKILL.md#L139) |
| `dangerous-function` | “any category → suspected”，下一行 “UNBOUNDED → confirmed”，后文又说 pipeline emits every non-exempt call as suspected | [65-66](../extension/shared/skills/dangerous-function/SKILL.md#L65-L66) vs [105](../extension/shared/skills/dangerous-function/SKILL.md#L105) |
| `stack-address-escape` | async-arg “不 copy → confirmed”，但 “join 了 → dismissed”，没有 detach/join 判别 | [63](../extension/shared/skills/stack-address-escape/SKILL.md#L63) vs [65](../extension/shared/skills/stack-address-escape/SKILL.md#L65) |
| `sizeof-misuse` | 证据模式说 `sizeof_pointer_ambig` 是 suspected → AI decides；分类表直接 dismissed | [35](../extension/shared/skills/sizeof-misuse/SKILL.md#L35) vs [54](../extension/shared/skills/sizeof-misuse/SKILL.md#L54) |

**修法：** 每个 skill 只保留**一处** verdict 定义（Classification Rules 表），其他位置只做“证据说明”，不再写 verdict；或者把顶部 bullet 改成“category → tier”清单，明确“tier 不是 verdict”。

---

### 4.9 [P/R] Hint 词汇契约是单向的，模型会看到“无法解释的 token”

`TestExtensionDocsHintTokensRegistered` 只检查“文档里出现的 token 是否在 registry 注册”（doc→registry），不检查“代码发出的 token 是否在 registry / skill 里被解释”（[zz_hint_protocol_guard_test.go:26-95](../sgre/internal/planner/zz_hint_protocol_guard_test.go#L26-L95)）。这造成几类真实缺口：

| 缺口 | 例子 | 影响 |
|------|------|------|
| emitted but unregistered | `sign@`（[registry_signed_compare.go:43](../sgre/internal/planner/registry_signed_compare.go#L43)）、`policy@`（[registry_dangerous_function.go:44](../sgre/internal/planner/registry_dangerous_function.go#L44)）、`free-mismatch@` / `transfer-cond@` / `free-on-borrow@`（[evidence_package.go:426](../sgre/internal/planner/evidence_package.go#L426)、[431](../sgre/internal/planner/evidence_package.go#L431)、[437](../sgre/internal/planner/evidence_package.go#L437)） | `_index.md` 的 Hint 列出现无图例 token；模型只能猜 |
| registered but not emitted | `use@`（[hint_tokens.go:128](../sgre/internal/planner/hint_tokens.go#L128)），`check@` 在前，compound token 的 prefix match 先命中 `check@` | 描述永远不渲染；死词汇 |
| documented but not emitted | `data-representation` 的 `cast@`（skill 说它是 basis，detector 不写 `cast`）；`null-deref` 的 `retnull-cond@`（skill 说“Hint carries”，实际只是 VerdictFact，[registry_null_deref.go:166](../sgre/internal/planner/registry_null_deref.go#L166)） | 模型按一个不存在的 token 做判断 |
| 同一个 key 两种语义 | deadlock 发 `lock@A-B`（[registry_deadlock.go:34](../sgre/internal/planner/registry_deadlock.go#L34)），registry 的 `lock@` 描述的却是 race 的 critical-section span（[hint_tokens.go:126](../sgre/internal/planner/hint_tokens.go#L126)） | `_index.md` 图例把锁名当行号解释 |
| emitted but missing from skill | `locks@` / `reverse@`（deadlock）、race 的 7 个 token、UAF 的 `free@/may-free/cond@`、`second-callee@`、`lhs-influenced`、`self-guard@`、`field@`、`src-cap@` | skill 没有解释，模型只能回退到 agent-body 的全局列表 |
| 9 个 skill 没有 `### Hint Tokens` | dangerous-function、deadlock、injection、integer-overflow、null-deref、race-condition、signed-compare、unchecked-return、use-after-free | 与模板/ADDING_A_VULN_TYPE 的硬规则不一致 |

**修法：**

1. 做**双向**测试：`code emits → registry`、`registry → 至少一个 protocol doc / 对应 skill`、`skill token → 该 type 会 emit`。
2. 让 `TestBuildHintPartsTokensRegistered` 覆盖所有 type，特别是 memory-leak / resource-leak（目前 14 个 fixture 里没有 leak 类型，正是未注册 token 的藏身处）。
3. 把 VerdictFacts token 也纳入 registry 检查（`policy@`、`sign@`、`retnull-cond@` 都从这里漏掉）。
4. 修 token 正则：`[a-z0-9-]*` 匹配不了 `case_end@`、`shift_count@`、`alloc_size@`，这些 token 实际上绕过了协议守卫。

---

### 4.10 [M] dismissed 台账“存在但没被写”，导致无法学习

- `report.go` 会为 dismissed 写 `candidate_verdicts`，并同步候选文件（[report.go:666-690](../sgre/internal/cli/report.go#L666-L690)）。
- `agent-body.md` 也要求 dismissed 行必须写进同一个数组（[agent-body.md:412-419](../extension/shared/agent-body.md#L412-L419)）。
- 但 `command-instructions.md` 说“Dismissed candidates are not written in any batch”（[command-instructions.md:439](../extension/shared/command-instructions.md#L439)），“Dismissed count is not persisted”（[command-instructions.md:665-667](../extension/shared/command-instructions.md#L665-L667)），“dismissed candidates are not persisted”（[command-instructions.md:688-691](../extension/shared/command-instructions.md#L688-L691)）。
- 实际 dispatch 提示词也按后者写：“Only CONFIRMED findings are written; dismissed are not persisted”（见生产 session 的 subagent prompt，[session-ses_e6ad-20261101-round1.md:1549](../examples/c-vuln-benchmark/session-ses_e6ad-20261101-round1.md#L1549)）。

**后果：**

- 如果子代理按 dispatch prompt 执行，`candidate_verdicts` 基本为空；
- 你无法知道某个 type 的 dismiss 率、dismiss 理由分布、哪些是 unresolved；
- “改 skill 后误报减少”无法从数据上验证，只能看最终 confirmed 数量（而 confirmed 数量又受 candidate 数量影响）。

**修法：** 先做产品决策——dismissed 到底要不要持久化。如果要（推荐），把 `command-instructions.md` 和 dispatch prompt 统一到 `agent-body.md` 的行为；如果不要，就删除 `candidate_verdicts` 的承诺和 `report.go` 的写入，避免“看起来有台账，实际没有”。

> **施工决策（2026-11-01 维护者确认）：** dismissed **不落盘是主动取舍**——现网这块最耗时。因此本轮**不反向引入 dismissed 持久化**，也不引入 `needs_review` 三态（它同样会带来落盘开销）。准确率提升改由“修错判规则 + hint 契约收口 + skill 决策质量”实现；dismissed 不落盘的口径以 `command-instructions.md` 为权威，`agent-body.md` 的“dismissed 必须同批写”表述按此对齐。

---

### 4.11 [P/R] Skill 教学法问题：抽象规则多，可执行示例少

- **24/29 没有代码示例**；只有 memory-leak、resource-leak、out-of-bounds、path-traversal、data-representation 有代码块。
- 21/29 有 Common False Positives，但很多只有 3–4 条抽象 bullet；真正能教会模型“这个形状为什么安全”的 hard negative 很少。
- 规则表经常要求“judge intent”“judge the business contract”“judge whether the next case is an independent semantic action”——这些不是可执行判据，而是把判断重新丢回给模型。
- 长表格（buffer-overflow 52 行、injection 51 行、dangerous-function 46 行）在没有优先级的情况下，模型容易“读到最后一条就按最后一条”。
- 大量重复：Evidence closure 段落 29 次逐字重复，severity 模板 29 次重复；任何修正都要改 29 处，且容易漂移。

**这不是“文风问题”。** 对 LLM 分类器来说：

- 一条具体的 `code → why safe` 示例，通常比 5 条抽象规则更能约束判断；
- 一个有序的 decision procedure，通常比一张 30 行表更稳定；
- 一个“stop rule”（什么情况下必须停、必须承认不知道），比“尽量判断”更能保护召回。

---

### 4.12 [P/R] C 领域覆盖缺口：专家会补，但当前 skill 没提

以下是“即使规则表全对，也会因为没考虑这些维度而错”的缺口。它们不一定都要写进每个 skill，但应该有共享 reference 或按 type 补充。

**对象生命周期 / 所有权**

- `realloc` 失败导致旧块泄漏（`p = realloc(p, n); if (!p) return;`）；`realloc` 后旧别名失效。
- `free(NULL)`、`free` 内部指针、`free` 非堆对象、pool/arena 分配器（free 是 no-op）。
- `longjmp` 跳过 cleanup；`__attribute__((cleanup))` 的析构执行两次；`atexit` 生命周期。
- 结构体字段别名（`q = p->f; free(p->f); q->x`）、container_of、flexible array member。

**整数 / 对象表示**

- 整数提升与 usual arithmetic conversions（`unsigned short a,b; a*b` 在 int 里算，可能 signed overflow）。
- signed overflow 是 UB；`INT_MIN / -1` 是 UB（x86 上 SIGFPE），不是“溢出为 INT_MIN”。
- `size_t` 下溢、负数转 `size_t`、`calloc(n, m)` 的乘法、`n * sizeof(T)` 的乘法、`alloca`。
- 有效类型 / strict aliasing / `memcpy` 重叠 / 对齐 / padding / bitfield / `-fshort-enums` / ILP32 vs LP64。

**字符串 / 格式化**

- `strncpy` 不保证 NUL 终止；`strncat` 的 size 语义；`snprintf` 返回值截断；`%n` 写原语；width/precision DoS；`%s` 的 precision。
- `syslog`/`err`/`warn` 的 format 语义；`errx/warnx` 不格式化。
- gettext / `.mo` / config 提供的 format string（真实世界最常见的来源之一）。

**并发 / 信号**

- C11 `_Atomic` / `atomic_*` / memory order；`volatile` 不是同步。
- happens-before：join、condvar、barrier、once；不是“没有 mutex 就 race”。
- 锁身份 vs 锁名字（两个 mutex 实例同名）；trylock/recursive/timedlock 的语义；死锁需要“两个顺序都可并发到达”。
- `sigaction` 注册（当前 detector 只看 `signal()`）；`errno` save/restore；`SA_RESTART`；handler 可重入；transitive unsafe call。

**路径 / 信任边界**

- `openat` + `O_NOFOLLOW` + dirfd anchoring；`realpath` 对不存在文件失败；symlink TOCTOU；`rename`/`unlink`/`chmod` 的路径语义。
- Windows `\`、drive-relative、UNC；zip-slip / tar extraction；setuid / privilege boundary。
- `argv` / `getenv` / config / network / file 的信任等级；库导出 API 的“外部调用者”假设。

**编译 / 工程上下文**

- `#ifdef` / `#if 0` / 平台分支 / 未编译代码；test / example / vendor / generated code 的 scope policy。
- `__attribute__((nonnull))`、`_Nonnull`、SAL、`warn_unused_result`、`noreturn`、`fallthrough`、`cleanup`、`malloc` 等注解。
- 编译选项：`-fshort-enums`、packing、endianness、ABI、32/64 位；`compile_commands.json` 已有，但 skill 没有消费。

这些缺口不是“再加 100 条规则”能解决的；更适合做成一个**共享的 C 语义 / 范围 / 信任边界 reference**，由各 skill 在需要时引用，而不是每个 skill 复制一份。

---

## 5. 领域专家会额外做什么

这一节回答“除了你和当前 AI Agent 一起设计的这套方案，还有什么是没考虑到的”。分成四类专家。

### 5.1 静态分析专家：先把“测什么”定义清楚

1. **分开 candidate recall 与 classification precision。**
   候选生成和 AI 分类是两个模型；用一个“准确率”会把两者混在一起。专家会分别建 confusion matrix，分别设目标。
2. **为每个规则建 per-rule 指标，而不是一个总数。**
   `null-deref` 的 precision 和 `hardcoded-secret` 的 precision 不可比；一个总数会让高 volume 类型淹没低 volume 类型。
3. **定义 proof class / refutation class。**
   confirm 必须落到“哪类证明”（must-dataflow、constant bound、literal、type-inherent、contract）；dismiss 必须落到“哪类反证”（guard、safe call、lifetime、bounds、whitelist、ownership）。没有 class 的 verdict 不可审计。
4. **建立 hard-negative corpus（误报动物园）。**
   每个生产 dismiss 都应该被归类、脱敏、变成 skill 的一条规则或一个 eval case。当前 skill 的 Common False Positives 太短，正是因为缺这个闭环。
5. **做 mutation / differential testing。**
   对同一段代码加一个 guard、改一个类型、换一个宏，verdict 应该可预测地变化；这能测出“规则是否真的在起作用”。
6. **用 adjudication 处理标签噪声。**
   安全漏洞的 ground truth 本身有争议；需要双人标注 + 第三人裁决，记录分歧，而不是把一个人的判断当金标准。
7. **区分“真阳性”与“可执行问题”。**
   一个真实但不可达、已在 dead code、只在 test 里的缺陷，是否要报，是产品策略；skill 要有 scope policy，而不是让模型每次自由裁量。
8. **把 suppression / baseline / annotation 纳入设计。**
   不是所有 TP 都值得报；项目可能有 `// secguard:ignore`、`__attribute__((nonnull))`、SAL、contract 配置。skill 应该知道这些“合法豁免”，而不是把它们当 FP 或 FN。
9. **关注 witness / 可解释性。**
   一个好的 finding 不只是 verdict，还要有“source → sink → missing guard”的 witness；这也是 path-sensitive 分析的核心输出。
10. **接受“不知道”。**
    静态分析专家不会把“分析不出来”叫“安全”；他们会输出 unknown / needs-review。当前协议缺少这个状态。

### 5.2 C 安全专家：把“语言语义”写进判据

1. **对象生命周期与别名**：UAF/double-free/leak 的核心不是“有没有 free”，而是“这个指针是否还指向活对象、所有权在谁手里、别名是否还有效”。
2. **整数语义**：promotion/conversion/UB/宽度；很多“看起来有 guard”的代码，在转换后已经失效。
3. **字符串与格式化**：NUL 终止、截断、返回值、`%n`、width；`snprintf` 不是万能安全。
4. **并发内存模型**：happens-before、atomics、memory order；`volatile` 不是锁；没有 mutex 不等于 race。
5. **信号安全**：POSIX async-signal-safe 列表、`errno`、`sigaction`、handler 可重入；不要把“不在列表里”当成“一定不安全”，也不要把列表里的函数当成不安全。
6. **信任边界**：argv/getenv/config/network/file 的等级；库导出 API 的外部调用者；setuid/privilege drop；TOCTOU 的 namespace 重解析。
7. **注解与契约**：`nonnull`、`_Nonnull`、SAL、`warn_unused_result`、`cleanup`、`noreturn`、`fallthrough`；这些是最便宜、最可靠的证据。
8. **编译上下文**：`#ifdef`、`-fshort-enums`、packing、ABI、32/64、endianness；同一行代码在不同构建下可能是不同漏洞。
9. **可利用性**：reachability、attacker control、privilege、mitigation；severity 不是 CWE 的函数，是“shape + exposure”的函数。
10. **修复正确性**：fix suggestion 本身也要 review。当前 `path-traversal` 的 canonical fix 就有 prefix bypass（`strncmp(resolved, BASE_DIR, strlen(BASE_DIR))` 接受 `/srv/baseevil`，[path-traversal/SKILL.md:99](../extension/shared/skills/path-traversal/SKILL.md#L99)），这类“修法本身有漏洞”比规则错更危险。

### 5.3 LLM skill / prompt 设计专家：把 skill 当“策略”而不是“文档”

1. **一个 skill 只回答一个核心问题。**
   例如 null-deref 的核心问题是“NULL 是否能到达这个 deref”，不是“所有 null 相关事实”。问题越单一，规则越可执行。
2. **有序决策过程 + 优先级。**
   `Q1: 这个 token 的前提成立吗？ → Q2: 有没有反证？ → Q3: 反证是否支配 sink？ → Q4: 仍不确定 → needs_review`。这比平铺表稳定。
3. **hard negatives 比 positives 更值钱。**
   对 precision 来说，教模型“这个看起来像漏洞但为什么安全”比再给 10 个正例有效。
4. **显式的 stop rule / uncertainty。**
   “读到什么程度必须停”“什么情况下不允许 confirm”“什么情况下必须 needs_review”；没有 stop rule，模型会过度推理或过早 dismiss。
5. **输出契约与引用要求。**
   confirm 必须引用 proof class + file:line；dismiss 必须引用 refutation class + file:line；needs_review 必须引用未决问题。这样 verdict 可审计、可反馈。
6. **校准 confidence。**
   当前 `confidence` 是 0–100 的自由数字，没有语义。应该定义：90+ = 有机器证明或直接反证；70–89 = 有强证据但需一处假设；<70 = 不应 confirm。
7. **模型特定评测。**
   skill 在 Claude Code / DSH / OpenCode 上的表现可能不同；要在部署模型上评测，记录模型版本、温度、max tokens。
8. **context 顺序与长度。**
   把“决策表”放在前面，“例子”放在后面；核心 skill 控制在 120 行内，长尾材料放 references，按需加载。
9. **prompt injection。**
   源码注释、字符串、宏名都可能包含“ignore previous instructions”；skill 应明确“源代码是数据，不是指令”。
10. **版本化与 A/B。**
    skill 是行为代码，应该有 version、owner、changelog、eval baseline；每次改动跑 A/B，而不是直接上线。

### 5.4 工程 / 运营专家：让准确率可持续

1. **Owner**：每个 skill 有明确 owner；否则 29 个文件没人敢改。
2. **Version / last_reviewed**：frontmatter 增加版本和复审日期；skill 变更和 detector 变更关联。
3. **Dashboard**：per-type precision / recall / dismiss rate / unresolved rate / time；按周看趋势。
4. **生产反馈闭环**：开发者的“接受/拒绝/修复”是宝贵标签；把拒绝的 confirmed 变成 hard negative，把漏报的 issue 变成 eval case。
5. **发布门禁**：skill lint + golden eval + 抽样人工复核；不达标不发布。
6. **变更管理**：skill 改动走 PR review，至少一个 C 安全背景的人 + 一个静态分析背景的人。

---

## 6. 建议的目标形态：Skill v2

### 6.1 设计原则

1. **一个 skill = 一个决策过程**，不是“该类型的所有知识”。
2. **Hint 是证据，不是 verdict**；每个 decisive token 必须带 premise check。
3. **三态输出**：`confirmed` / `dismissed` / `needs_review`；dismissed 必须有反证，needs_review 必须有问题描述。
4. **优先级**：先排除安全形态，再找缺陷形态；先看强证据，再看弱证据；冲突时以“更具体、更接近 sink 的证据”为准。
5. **示例优先**：每个 skill 至少 3 个 hard negative + 2 个 hard positive，带 3–8 行代码。
6. **跨类型路由**：不属于本类型但真实的缺陷，记录 `route_to`，不要 dismiss。
7. **可测量**：每个 skill 绑定 eval cases 和 baseline 指标。
8. **共享层**：把 evidence closure、severity 定义、C 语义、范围/信任边界放到共享 reference，skill 只写类型特有的 delta。

### 6.2 建议模板（核心 ≤ 120 行）

```markdown
---
name: <type>
description: Use when classifying <type> candidates ...; NOT for <other type>.
license: MIT
compatibility: opencode,claude code,DSH
metadata:
  cwe: <CWE>
  version: 2
  last_reviewed: <date>
  owner: <team>
  severity: <default>
---

## 0. Scope & non-goals
- 本 skill 只回答：<one question>
- 不回答：<other questions> → route_to / 其他 skill

## 1. Input contract & premise checks
| Hint | 它证明什么 | 前提 | 前提不成立时 |
|------|------------|------|--------------|
| `null@cfg-proof` | NULL 到达 deref | 无 macro 赋值 | 读 `## Macro Definition`，降级 |
| ... | ... | ... | ... |

## 2. Decision procedure（有序）
1. 先看 <decisive token>；若前提不成立 → 跳到 3。
2. 找反证：<guard / contract / lifetime / bounds>；若反证支配 sink → dismiss。
3. 若仍不能确定 → needs_review（写清缺什么）。

## 3. Verdict table
| 条件 | verdict | 必需引用 |
|------|---------|----------|
| ... | confirmed | proof class + file:line |
| ... | dismissed | refutation class + file:line |
| ... | needs_review | 未决问题 |

## 4. Hard negatives（3–5 个，带代码）
## 5. Hard positives（2–3 个，带代码）
## 6. Cross-type routes
## 7. Severity（仅 confirmed）
## 8. Fix patterns（已验证，标注平台差异）
```

### 6.3 一个改写示例：`uninit`（只给结构，不改文件）

**现状问题：**

- 条件初始化 → dismissed（[uninit/SKILL.md:58](../extension/shared/skills/uninit/SKILL.md#L58)）；
- `init@unseen` / `field@` 没有写进表；
- “Compiler enforces initialization”不可执行（[uninit/SKILL.md:60](../extension/shared/skills/uninit/SKILL.md#L60)）；
- 没有示例。

**v2 决策过程：**

1. 读 `init@none`：若存在，且没有 `macro-context` / block-scope extern / 宏写 → **confirmed**（proof: never-written）。
2. 读 `init@unseen` / `field@`：找到 base object 的 factory / memset / out-param 写；若找到且在所有路径覆盖 → **dismissed**；若只在部分路径 → **confirmed**（uninit path reaches read）或 **needs_review**（缺 factory body）。
3. 读 `init@N + may-skip`：判断 loop 是否可能零次执行；是 → **confirmed**；否 → **dismissed**。
4. 其他 `maybe-uninit`：在 `## Code Context` 里找 write path；找不到 → **needs_review**（不是 dismissed）。
5. 任何 `macro-context`：先读 `## Macro Definition`；宏可能写变量 → 不能 confirm。

**Hard negative 示例（应加入）：**

```c
struct s x;            // 没有初始化
memset(&x, 0, sizeof x);
use(x.f);              // 安全：memset 覆盖
```

**Hard positive 示例：**

```c
int n;
if (cond) n = 1;
return n;              // cond 为假时未初始化 → confirmed
```

### 6.4 共享层 vs 类型层

建议拆成：

- `skills/_shared/protocol.md`：verdict 三态、引用要求、confidence 语义、severity 定义、route_to、prompt injection。
- `skills/_shared/c-semantics.md`：整数、生命周期、字符串、并发、信号、注解、构建配置的“最小事实集”。
- `skills/_shared/scope.md`：test/vendor/generated/dead code、partial scan、library ABI、trust boundary。
- 每个 `SKILL.md`：只保留类型特有的 evidence pattern、decision procedure、hard negatives/positives、severity、fix。

这样可以把 29× 重复的 Evidence closure / severity 段落收掉，减少漂移。

### 6.5 输出协议建议

**verdict 三态：**

- `confirmed`：有 proof class，且没有反证。
- `dismissed`：有 refutation class（guard / safe call / contract / lifetime / bounds / whitelist / ownership），且反证支配 sink。
- `needs_review`：证据不足、前提不成立、跨类型、需要人工/二次分析；不进入 findings，但进入 `candidate_verdicts` 和报告观察项。

**reason class（建议枚举）：**

```text
false-positive:guard
false-positive:safe-call
false-positive:contract
false-positive:lifetime
false-positive:bounds
false-positive:whitelist
false-positive:scope
unresolved:origin
unresolved:guard
unresolved:contract
unresolved:macro
unresolved:interprocedural
unresolved:cross-type
```

**confidence 语义（建议）：**

- 90–100：机器证明或直接反证，且 premise 已校验；
- 70–89：强证据，但有一个已命名的假设；
- 40–69：启发式，不应 confirm；
- 0–39：猜测，只能 needs_review。

### 6.6 跨类型路由

在 verdict JSON 增加：

```json
{"status":"needs_review","route_to":"null-deref","route_evidence":"free(p); p=NULL; p->x at file:line"}
```

orchestrator 在全部 type 跑完后：

1. 收集 `route_to`；
2. 按目标 type 重新分派（只对 `needs_review`，不改 confirmed）；
3. 若目标 type 已有同位置 finding，去重；
4. 在报告中记录“cross-type routed”数量。

这样既不强行把缺陷塞进错误类型，也不丢失。

---

## 7. 评测与度量方案

### 7.1 指标定义

| 指标 | 定义 | 用途 |
|------|------|------|
| `candidate_recall` | 有 candidate 的真实缺陷 / 全部真实缺陷 | 评 detector/filter |
| `confirmed_precision` | confirmed 中真实缺陷 / 全部 confirmed | 评 skill + hint |
| `classification_recall` | confirmed 的真实缺陷 / 全部应报真实缺陷 | 评 skill + hint |
| `dismiss_precision` | dismissed 中确实安全 / 全部 dismissed | 评“驳回是否正确” |
| `needs_review_rate` | needs_review / 全部候选 | 评“不确定性” |
| `cross_type_leak_rate` | 被错误 dismiss 的跨类型真实缺陷 / 全部真实缺陷 | 评路由 |
| `citation_rate` | 带 file:line + class 的 verdict / 全部 verdict | 评可审计性 |
| `severity_agreement` | 与人工裁决 severity 一致 / 全部 confirmed | 评 severity |

### 7.2 数据集

1. **benchmark 263 例**：作为基础集，补充每个候选的 `expected_verdict`（当前只有 finding/no_finding，不等于 AI verdict）。
2. **生产抽样**：每类 50–100 个 confirmed + 50–100 个 dismissed，人工裁决；按类型/严重度分层。
3. **hard negatives**：从生产 dismiss 中提炼，每条带“为什么安全”的代码/契约。
4. **adversarial positives**：真实漏洞的变体（加一个不完整 guard、换一个宏、改一个类型），测试规则是否真的在判断。
5. **premise-violation cases**：专门测试 hint 前提不成立时，skill 是否会错误 confirm。

### 7.3 实验协议

- **blind**：执行 agent 不读 expected；裁决者读。
- **同模型同版本**：记录模型、温度（建议 0）、max tokens、skill 版本。
- **3 次重复**：报告均值 + 方差；小样本用 Wilson 区间。
- **分层报告**：per-type、per-tier（auto-confirm / suspected / possible）、per-source（benchmark / production / adversarial）。
- **A/B**：同一批 case，旧 skill vs 新 skill；只看同一模型、同一 prompt 结构。
- **人工复核**：对 `needs_review` 和随机 confirmed/dismissed 抽样，计算 inter-rater agreement。

### 7.4 CI 门禁

1. **Skill lint**：
   - frontmatter name/cwe/version/owner；
   - 必须有 Hint Tokens、Decision procedure、≥3 hard negatives、≥2 hard positives；
   - token 必须双向对齐（code→registry→skill）；
   - 禁止 synthetic wrapper 名字（SafeCopy/SafeQuery/...）；
   - 禁止 `suspected`/`possible` 作为最终 verdict；
   - 禁止 severity 表出现 `(dismissed)`。
2. **Golden eval**：
   - `confirmed_precision` 不低于 baseline；
   - `classification_recall` 不低于 baseline；
   - `needs_review_rate` 不超过阈值；
   - 任何 per-type 回退超过 X% 失败。
3. **Prompt regression**：固定 20 个“陷阱 case”，任何 skill 改动都必须通过。

### 7.5 生产反馈闭环

- 每周抽样 dismissed / needs_review，人工裁决；
- 把错误 verdict 归类到 reason class；
- 每类错误转化为：skill 规则 / hard negative / detector 修复 / 评测 case；
- 每月看 per-type 趋势，而不是只看总数。

### 7.6 建议目标（需与业务基线校准）

这些是建议值，不是现状：

- `confirmed_precision` ≥ 90%（高 volume 类型 ≥ 85%）；
- `classification_recall` ≥ 75%（关键类型 ≥ 80%）；
- `needs_review_rate` ≤ 10%；
- auto-confirm precision ≥ 95%；
- `cross_type_leak_rate` < 3%；
- `citation_rate` ≥ 95%。

**注意：** precision/recall 是权衡；不要在没有业务输入的情况下单独追求一个。对“可自动提单”的场景，precision 优先；对“人工复核队列”，recall 优先。

---

## 8. 路线图

### P0（1–2 周，先让系统可测、少犯错）

| 动作 | 具体内容 | 影响 |
|------|----------|------|
| P0-1 | 建 skill 级 golden set（263 + 生产抽样），跑 baseline | 让后续可度量 |
| P0-2 | 增加 `needs_review` + reason class（先落 `candidate_verdicts`，不改 findings 协议也可） | 让 recall 可见 |
| P0-3 | 修 §4.4 / §4.5 的 10 个错判规则 | 直接降 FP/FN |
| P0-4 | 给 decisive hint 加 premise check；禁止“token 单独 confirm” | 降低 hint 前提错误的放大 |
| P0-5 | hint 双向契约 + 注册所有 emitted token + 修 `sign@`/`lock@`/leak token | 减少“看不懂 token” |
| P0-6 | 移除按名字信任 wrapper；要求 body/contract | 降 FP/FN |
| P0-7 | 统一 dismissed 持久化行为（文档 + dispatch prompt） | 让台账可用 |
| P0-8 | 把 `path-traversal` 的 fix 改成 `openat`/`O_NOFOLLOW` + 边界检查，修 `strncmp` prefix bug | 修法本身不能有漏洞 |

### P1（3–6 周，重写高影响 skill）

优先重写（按 volume × 当前问题）：

1. `null-deref`（长，但有价值；修 L70、caller-null、group 前提）
2. `uninit`（条件初始化、init@unseen/field@、示例）
3. `use-after-free`（hint 表、alias/realloc、跨函数）
4. `buffer-overflow`（cap 单位、顶部 bullet vs 表、src-cap）
5. `format-string`（删 sizeof 误判、local buffer、`%n`）
6. `path-traversal`（no-census、census 语义、fix）
7. `unchecked-return`（contract@known 三处统一、setuid 返回值）
8. `memory-leak`（unknown owner → needs_review、realloc failure）
9. `crypto-misuse`（context、bytes/bits）
10. `signal-handler`（AS-safe list、sigaction、errno）

同时：

- 加 `_shared/c-semantics.md` / `_shared/scope.md` / `_shared/protocol.md`；
- 把 29× 重复的 Evidence closure / severity 收进共享层；
- 加 cross-type routing；
- 清理 severity/status 混用。

### P2（一个季度，持续提升）

- 每类建立 50+ 生产 case 的 gold set；
- 主动学习：从 dismissed / needs_review 中挖 hard negative；
- 按模型/平台做 A/B；
- 加注解/契约支持（`nonnull`、`_Nonnull`、SAL、`cleanup`、`warn_unused_result`）；
- 加 build config / `#ifdef` / platform 维度；
- 加 C11 atomics / happens-before / lock identity；
- 加 interprocedural UAF / double-free / leak；
- 做 per-skill dashboard 和发布门禁。

### 不要做的事

- 不要用“再加更多规则”解决规则冲突；先删/合并。
- 不要为了降误报把更多东西 auto-confirm 或直接 disable 类型；那只是把 FP 变成 FN。
- 不要把 severity 当成 verdict；dismissed 不需要 severity。
- 不要用“benchmark 全绿”证明 skill 准确率；它测的不是这个。
- 不要按 wrapper 名字豁免；读 body/contract。
- 不要让“unknown”写成“dismissed”；那会让系统永远学不到 recall。

---

## 9. 验收清单（每个 skill 改完后逐项过）

- [ ] frontmatter `name` == 目录名；`cwe` 与 registry 一致；有 `version` / `owner` / `last_reviewed`。
- [ ] `## Scope & non-goals`：只回答一个问题；明确不回答什么、route 到哪里。
- [ ] `### Hint Tokens`：覆盖该 type 实际 emitted 的**全部** token；每个 decisive token 有 premise + 前提不成立时的动作。
- [ ] 有序 decision procedure：先反证、再确证、最后 needs_review；有 stop rule。
- [ ] Verdict table 使用 `confirmed` / `dismissed` / `needs_review`；不出现 `suspected` / `possible` / `false-positive` 作为最终状态。
- [ ] 每个 dismissed 行都有 refutation class；每个 confirmed 行都有 proof class。
- [ ] ≥3 hard negatives（带 3–8 行代码 + 为什么安全）。
- [ ] ≥2 hard positives（带代码 + 为什么是缺陷）。
- [ ] `## Cross-type routes`：列出常见误桶和 route_to。
- [ ] Severity 只用于 confirmed；删除 `(dismissed)` 行。
- [ ] Fix 已验证：Linux/Windows 可用；不引用不存在的 `_s` 变体；路径修复无 prefix/symlink bypass。
- [ ] 不按名字信任 wrapper；不出现 SafeCopy/SafeQuery/LockGuard 等 demo 名字作为豁免依据。
- [ ] 与 agent-body / SKILL_TEMPLATE 无矛盾；token 与 hint_tokens 双向对齐。
- [ ] 绑定 eval cases（每个 ≥20，含 hard negatives）；baseline 已记录。
- [ ] 核心 ≤120 行；长尾材料放 references。

---

## 附录 A：29 个 skill 的结构与评分

> 评分是同一 rubric 下的评审判断（10 = 接近专家决策卡），不是统计精度。`Hint` = 有 `### Hint Tokens`；`例` = 有代码块；`FP` = 有 `### Common False Positives`。

| Skill | 行数 | Hint | 例 | FP | 评分 | 主要问题（简） |
|-------|-----:|:----:|:--:|:--:|-----:|----------------|
| null-deref | 252 | – | – | Y | 7 | L70 external-return 过度 dismiss；缺 caller-null；表里用 suspected |
| memory-leak | 139 | Y | Y | Y | 8 | unknown owner → dismissed；realloc failure 无行 |
| double-free | 96 | Y | – | Y | 6 | Hint 说可判、表里又说 reassignment 可能；second-callee 缺失 |
| resource-leak | 125 | Y | Y | Y | 6 | process-exit 误判；fd/lock 资源模型混用 |
| out-of-bounds | 143 | Y | Y | – | 6 | 一半规则是 auto-confirmed 不可达；struct-hack/one-past-end 缺失 |
| integer-overflow | 162 | – | – | – | 5 | signed int 整类 dismissed；guard@none 与“找 guard”矛盾 |
| injection | 157 | – | – | – | 6 | 缺 taint@none/sanitizer；demo wrapper 名字；execve 两义 |
| dangerous-function | 164 | – | – | Y | 6 | 禁 snprintf；suspected/confirmed 冲突；`_s` 不可移植 |
| hardcoded-secret | 87 | Y | – | – | 5 | name-only dismiss；masked value 无法判 |
| unchecked-return | 78 | – | – | Y | 6 | contract@known 三处冲突；自取消行 |
| race-condition | 91 | – | – | – | 5 | 单 thread function dismiss；无 atomics/happens-before |
| signal-handler | 77 | Y | – | Y | 5 | AS-safe 列表错误，confirmed FP |
| switch-fallthrough | 107 | Y | – | Y | 5 | comment “never emits” 不成立；只判 intent |
| signed-compare | 65 | – | – | Y | 5 | 负数比较方向写反；scope 只有 unsigned-vs-0 |
| argument-type | 106 | Y | – | Y | 5 | 4/7 规则不可达；live 行全 confirmed |
| invalid-free | 106 | Y | – | Y | 5 | 全部 confirm；allocator family 缺失 |
| buffer-overflow | 162 | Y | – | – | 4 | 顶部 bullet vs 表；cap 单位；src-cap 缺失 |
| divide-by-zero | 96 | Y | – | Y | 4 | INT_MIN 文案错；unsettled→dismissed |
| sizeof-misuse | 73 | Y | – | Y | 3 | registry suspected vs skill confirmed；sizeof(type) 误判 |
| unbounded-length-copy | 105 | Y | – | Y | 3 | clamp 语义矛盾；signed carrier；compat 元数据 |
| format-string | 85 | Y | – | Y | 4 | snprintf+sizeof 被当安全；local buffer dismiss |
| path-traversal | 114 | Y | Y | Y | 5 | no-census dismiss；realpath prefix bug |
| crypto-misuse | 107 | Y | – | – | 3 | reason@ 单独 settle；bytes/bits |
| data-representation | 133 | Y | Y | Y | 3 | cast@ 实际不 emit；只比 depth |
| implicit-contract | 117 | Y | – | Y | 4 | if-body guard 未建模；self-guard 未写 |
| deadlock | 83 | – | – | – | 4 | timedlock dismiss；name-based graph；无并发前提 |
| use-after-free | 77 | – | – | Y | 3 | 无 hint 表；跨函数 dismiss；无 alias/realloc |
| uninit | 83 | Y | – | Y | 3 | 条件初始化 dismiss；init@unseen/field@ 未写 |
| stack-address-escape | 109 | Y | – | Y | 4 | static/global store dismiss；async join 矛盾 |

---

## 附录 B：跨 skill 矛盾矩阵

| 形状 | Skill A 的裁决 | Skill B 的裁决 | 建议 |
|------|----------------|----------------|------|
| 跨函数 free → use | UAF: dismissed（[46](../extension/shared/skills/use-after-free/SKILL.md#L46)） | double-free: 跨函数 global-slot 可 confirmed（[58](../extension/shared/skills/double-free/SKILL.md#L58)） | 统一为“有 callee body/所有权证据则可判；否则 needs_review” |
| `&local` 存进 global/static | memory-leak: 不把它当 leak（不是堆泄漏，本身没错） | stack-address-escape: dismissed（[64](../extension/shared/skills/stack-address-escape/SKILL.md#L64)） | memory-leak 不报是对的，但必须 route 到 stack-address-escape；现在两边都没有把悬垂指针报出来 |
| `snprintf` | dangerous-function: banned（[40](../extension/shared/skills/dangerous-function/SKILL.md#L40)） | format-string: safe when literal（[61](../extension/shared/skills/format-string/SKILL.md#L61)） | 明确“policy vs vulnerability”两层；不要互相否定 |
| `count-field` 保护的 `p[i]` | implicit-contract: empty state handled → dismissed（[84](../extension/shared/skills/implicit-contract/SKILL.md#L84)） | out-of-bounds: `idx-src@` 无 check → confirmed（[116](../extension/shared/skills/out-of-bounds/SKILL.md#L116)） | 先判断 count 是否 gate 这个 buffer；再判断 index 是否可越界 |
| `contract@known` | unchecked-return: suspected（[33](../extension/shared/skills/unchecked-return/SKILL.md#L33)） | agent-body: decisive（[206](../extension/shared/agent-body.md#L206)） | 统一为“unchecked proved, observability judged” |
| 弱 crypto | crypto-misuse: reason@ 单独 settle（[44-46](../extension/shared/skills/crypto-misuse/SKILL.md#L44-L46)） | agent-body: context-dependent（[261](../extension/shared/agent-body.md#L261)） | 以 agent-body 为准；skill 加 use-context |
| 参数来源未知 | path-traversal: dismissed（[66](../extension/shared/skills/path-traversal/SKILL.md#L66)） | agent-body: judge from signature（[225-226](../extension/shared/agent-body.md#L225-L226)） | 库/partial scan 按外部 ABI 处理；不要默认安全 |
| `dismissed` 的 severity | 28 个 skill: `dismissed → low` | 19 个 skill 的 severity 表: `HIGH/MEDIUM (dismissed)` | severity 只用于 confirmed；dismissed 无 severity |

---

## 附录 C：关键证据索引

**Skill 内容**

- [buffer-overflow/SKILL.md:32](../extension/shared/skills/buffer-overflow/SKILL.md#L32)、[37](../extension/shared/skills/buffer-overflow/SKILL.md#L37)、[117](../extension/shared/skills/buffer-overflow/SKILL.md#L117)、[127](../extension/shared/skills/buffer-overflow/SKILL.md#L127)
- [uninit/SKILL.md:58](../extension/shared/skills/uninit/SKILL.md#L58)
- [stack-address-escape/SKILL.md:64](../extension/shared/skills/stack-address-escape/SKILL.md#L64)
- [signed-compare/SKILL.md:17-18](../extension/shared/skills/signed-compare/SKILL.md#L17-L18)
- [signal-handler/SKILL.md:53-56](../extension/shared/skills/signal-handler/SKILL.md#L53-L56)
- [format-string/SKILL.md:38](../extension/shared/skills/format-string/SKILL.md#L38)、[61](../extension/shared/skills/format-string/SKILL.md#L61)
- [path-traversal/SKILL.md:66](../extension/shared/skills/path-traversal/SKILL.md#L66)、[99](../extension/shared/skills/path-traversal/SKILL.md#L99)
- [hardcoded-secret/SKILL.md:62](../extension/shared/skills/hardcoded-secret/SKILL.md#L62)
- [crypto-misuse/SKILL.md:44-46](../extension/shared/skills/crypto-misuse/SKILL.md#L44-L46)
- [unchecked-return/SKILL.md:33](../extension/shared/skills/unchecked-return/SKILL.md#L33)
- [data-representation/SKILL.md:68](../extension/shared/skills/data-representation/SKILL.md#L68)
- [implicit-contract/SKILL.md:50](../extension/shared/skills/implicit-contract/SKILL.md#L50)、[80-87](../extension/shared/skills/implicit-contract/SKILL.md#L80-L87)
- [race-condition/SKILL.md:70](../extension/shared/skills/race-condition/SKILL.md#L70)
- [deadlock/SKILL.md:59](../extension/shared/skills/deadlock/SKILL.md#L59)
- [switch-fallthrough/SKILL.md:66](../extension/shared/skills/switch-fallthrough/SKILL.md#L66)
- [integer-overflow/SKILL.md:132](../extension/shared/skills/integer-overflow/SKILL.md#L132)
- [use-after-free/SKILL.md:46](../extension/shared/skills/use-after-free/SKILL.md#L46)
- [memory-leak/SKILL.md:85](../extension/shared/skills/memory-leak/SKILL.md#L85)

**协议 / 模板**

- [SKILL_TEMPLATE.md:54](../extension/shared/skills/SKILL_TEMPLATE.md#L54)、[80-82](../extension/shared/skills/SKILL_TEMPLATE.md#L80-L82)、[88](../extension/shared/skills/SKILL_TEMPLATE.md#L88)
- [agent-body.md:206](../extension/shared/agent-body.md#L206)、[260-266](../extension/shared/agent-body.md#L260-L266)、[412-419](../extension/shared/agent-body.md#L412-L419)、[574-580](../extension/shared/agent-body.md#L574-L580)、[591-598](../extension/shared/agent-body.md#L591-L598)
- [command-instructions.md:439](../extension/shared/command-instructions.md#L439)、[665-667](../extension/shared/command-instructions.md#L665-L667)、[688-691](../extension/shared/command-instructions.md#L688-L691)、[811-812](../extension/shared/command-instructions.md#L811-L812)
- [report.go:666-690](../sgre/internal/cli/report.go#L666-L690)

**Hint / 代码**

- [hint_tokens.go:45](../sgre/internal/planner/hint_tokens.go#L45)、[55](../sgre/internal/planner/hint_tokens.go#L55)、[84](../sgre/internal/planner/hint_tokens.go#L84)、[118](../sgre/internal/planner/hint_tokens.go#L118)、[126](../sgre/internal/planner/hint_tokens.go#L126)、[205-207](../sgre/internal/planner/hint_tokens.go#L205-L207)
- [evidence_package.go:426](../sgre/internal/planner/evidence_package.go#L426)、[431](../sgre/internal/planner/evidence_package.go#L431)、[437](../sgre/internal/planner/evidence_package.go#L437)、[508-510](../sgre/internal/planner/evidence_package.go#L508-L510)、[621-622](../sgre/internal/planner/evidence_package.go#L621-L622)
- [registry.go:445-453](../sgre/internal/planner/registry.go#L445-L453)
- [registry_buffer_overflow.go:26-32](../sgre/internal/planner/registry_buffer_overflow.go#L26-L32)
- [registry_sizeof_misuse.go:20-23](../sgre/internal/planner/registry_sizeof_misuse.go#L20-L23)
- [registry_data_representation.go:28-35](../sgre/internal/planner/registry_data_representation.go#L28-L35)
- [filter_contract_gap.go:128-138](../sgre/internal/planner/filter_contract_gap.go#L128-L138)
- [data_representation.go:141-142](../sgre/internal/evidence/data_representation.go#L141-L142)
- [signal_handler.go:43-47](../sgre/internal/evidence/signal_handler.go#L43-L47)
- [registry_deadlock.go:34](../sgre/internal/planner/registry_deadlock.go#L34)
- [registry_signed_compare.go:43](../sgre/internal/planner/registry_signed_compare.go#L43)
- [deadlock.go:63-67](../sgre/internal/evidence/deadlock.go#L63-L67)
- [race_condition.go:465](../sgre/internal/evidence/race_condition.go#L465)
- [format_string.go:52-70](../sgre/internal/evidence/format_string.go#L52-L70)
- [switch_flow.go:199-207](../sgre/internal/evidence/switch_flow.go#L199-L207)
- [apikb.go:48-49](../sgre/internal/apikb/apikb.go#L48-L49)
- [zz_hint_protocol_guard_test.go:26-95](../sgre/internal/planner/zz_hint_protocol_guard_test.go#L26-L95)

**评测**

- [validate-benchmark.py:229-241](../examples/c-vuln-benchmark/scripts/validate-benchmark.py#L229-L241)
- [pr-benchmark.yml:35-53](../.github/workflows/pr-benchmark.yml#L35-L53)
- [benchmark.md:302](../examples/c-vuln-benchmark/benchmark.md#L302)、[437](../examples/c-vuln-benchmark/benchmark.md#L437)、[561](../examples/c-vuln-benchmark/benchmark.md#L561)、[596](../examples/c-vuln-benchmark/benchmark.md#L596)

---

## 附录 D：方法与限制

- **没有修改代码**：本报告的所有建议都是“下一步可以做什么”，不是已实施变更。
- **没有跑 AI 分类**：因此不提供“改后 precision 提升 X%”的承诺；提供的是可验证的度量方案。
- **评分的局限**：评分是同一 rubric 下的主观判断，用于排序和定位，不用于对外宣称准确率。
- **代码对照的局限**：detector 的分支很多，本报告只对照了与 skill 规则直接相关的路径；具体误报率仍需实测。
- **文档时效**：`benchmark.md` 仍写 202 用例 / 25 类型，实际脚本输出 263 / 29；`command-instructions.md` 与 `report.go` 对 dismissed 持久化的描述不一致。这两处本身就是需要修的“文档漂移”。

---

> **最后一句：** 这套 skills 的基础并不差——evidence closure、hint token、group verdict、severity matrix 都是正确的方向。真正的提升空间在于：**把“证据说明”升级为“可证伪的决策过程”，把“未决”从 dismissed 里救出来，把“准确率”从感觉变成可重复的测量。** 这三件事做完，再谈“加多少规则”才有意义。
