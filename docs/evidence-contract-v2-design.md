# Evidence Contract v2 — candidates 证据链路与 Hint 体系重构设计

> 状态：设计稿（2026-10-17），待用户确认后分批落地。
> 前序：round2 证据契约审计（docs/round2-evidence-contract-audit.md）、round2/round3 扫描会话自检
> （docs/第二轮样例项目扫描会话自检报告与改建建议.md）、round3 机器 FP 修复（684863a/b602785/0704443）。

---

## 1. 问题定义（现状缺陷全景）

AI 研判的消费链是三级漏斗（command-instructions.md）：

```
Level 1  _index.md 的 Source + Hint 列直接定夺     （预算模型假设大多数在此解决）
Level 2  打开 candidates/<type>/NNN_*.md          （Code Context ±8 / 整函数 / Callee 嵌入）
Level 3  ≤5 次 source read（硬预算，per type）
```

预算模型 `PER_CANDIDATE_TURNS = 0.8`（约 20% 的候选需要开文件）建立在
"Hint 足够定夺多数候选"的假设上。**该假设对一半类型不成立**，导致 Level 2/3
触发率远超设计值——这正是 round2 观察到的"四类反复读源码"和用户对研判质量
不信任的机制根源：AI 的最终判定依赖自己临时读到的 ±8 行窗口，而不是管线
已经证明的事实，同一候选不同轮次结论漂移、ground truth TP 被误驳回
（round3：p13:170 被 AI 驳回）。

### 缺陷清单（按层次）

| # | 缺陷 | 实证 | 层次 |
|---|------|------|------|
| D1 | **Hint 不进 candidate 单文件**——复核/深判时唯一入口是单文件，但初判依据（Hint）在那里不可见 | 001_src_p2_raii_memory_c_46.md 无任何 Hint | 渲染 |
| D2 | **Hint 语义贫瘠且类型间极不均**——race/deadlock/unchecked-return 有丰富 token；BO/OOB/leak 零类型专属 token；null-deref 的 `maybe-null` 不区分"CFG 证明"与"external fail-open 假设" | buildHint switch（evidence_package.go:159-281）只覆盖 8 类 | 语义 |
| D3 | **语义图产物在渲染层断链**——detector 已算出的决定性事实（区间、别名、TOCTOU 对、props 富化字段）到 Hint/Evidence 为止丢失 | round2 审计：race TOCTOU 全断链、crypto reason 断链、LHSInfluenced 断链、BO props 全弃 | 语义 |
| D4 | **token 词汇表散落 6 处无单一源**——buildHint（Go）、markdown.go 两处硬编码图例、SKILL.md、command-instructions.md 三段、agent-body.md；每新增一个 token 需人工同步 6 处 | `check@<fn>→use@<fn>` 在 4 个文件重复出现 | 架构 |
| D5 | **re-review 材料比初判还贫瘠**——auto-confirmed 复核只拿 `snippet + context` 一行 JSON，无 Hint、无 fragments、无 Code Context 窗口、无 callee 嵌入 | agent-body.md:342-348；round3 AI 驳回 27/38、含误杀 TP | 渲染 |
| D6 | **词汇表协议无机器守护**——TestVulnTypeSkillConsistency 只守护类型名三处一致，不守护 SKILL 引用的 token/fragment 与 buildHint 实际产出的词汇表一致 | SKILL.md 列举的 fragment Type 与 registry 实际产出靠人肉对齐 | 架构 |

D4+D6 是"想到哪改到哪"的机制根源：改动成本高且无守护，所以每类都停在
"detector 算了、渲染没接"的半成品状态。**本设计优先修 D4/D6（架构），
再按契约矩阵逐类型修 D1/D2/D3/D5（语义）。**

## 2. 设计目标与原则

- **G1 单一事实源**：Hint token 词汇表、每类型证据契约只在一处定义（Go），
  文档图例与协议文档由生成或 CI 守护。
- **G2 三级漏斗经济学**：Level 1 命中率是第一指标。Hint 变强 → Level 2/3
  触发率下降 → 每 candidate 实际 token 成本下降；candidate 文件可变大但必须
  预算化（冲击的是 100-candidate context 天花板）。
- **G3 蒸馏而非搬运**：semantic graph 在 Go 侧完成查询，AI 只看查询结果
  （"callee 会返回 NULL 吗"的答案 + 出处行号），**绝不嵌入 raw CFG / DFG /
  调用点全列表**——图的原始形式对 LLM 是纯噪声。
- **G4 体积预算硬上限**：candidate 单文件目标 ≤ 90 行（现状中位数 ~50），
  Verdict Facts 节常规 ≤ 15 行，嵌入代码段 ≤ 40 行（复用 maxCalleeDefLines
  先例），Code Context 维持既有 maxContextLines 机制。
- **G5 协议只增不破**：新增 token 不改变既有 token 语义；SKILL/instructions
  的旧引用在新词汇表下仍然成立。
- **G6 25 类型一次盘点、契约显式化**：每个类型的"研判需要哪些决定性事实、
  每条事实从哪个分析产物来、渲染到哪个通道"写进类型注册，成为
  ADDING_A_VULN_TYPE.md 清单的一部分。

## 3. 架构设计

### 3.1 核心新增：每类型 Verdict Facts 契约（Go 单一源）

`VulnTypeSpec` 新增声明式契约字段：

```go
// FactSpec declares ONE decisive fact for a vuln type's verdict: the question
// the AI needs answered, where the pipeline computes it, and how it renders.
type FactSpec struct {
    Token    string            // hint token, e.g. "null@external-unknown"
    Question string            // "does the callee ever return NULL?"
    Source   string            // "Candidate.Origin + CallerNullDetail / retNullable set"
    Render   FactRender        // HintOnly | FactLine | FactWithEmbed
    Order    int               // render order (most decisive first)
}
```

三个渲染档位：

| 档位 | 形态 | 预算 |
|------|------|------|
| `HintOnly` | 只进 _index.md Hint 列（token） | 计入 120 字符 |
| `FactLine` | Hint token + candidate 文件一行事实（key: value，含出处行号） | 1 行 |
| `FactWithEmbed` | 同上 + 可选小代码段（如 callee body） | ≤40 行嵌入 |

**单一渲染入口**：`newEvidenceItem` 按契约同时产出三面——
1. `_index.md` Hint 列（紧凑 token 序列，Order 决定排序，最决定性的靠前）
2. candidate 文件新增 `## Verdict Facts` 节（结构化 key-value + 嵌入段）
3. re-review JSON 的 facts 字段（见 3.4）

### 3.2 通道设计（回答"Hint 还要不要 / 单文件加什么"）

**_index.md Hint 列：保留**。它是 Level 1 的全部输入，已被预算模型和
divide-by-zero `divisor@bare`（从行直接定夺）验证价值。重新定位：Hint 不再
试图装下证据，而是**分诊信号**——告诉 AI 这条候选的 null 来源档位 / 契约
状态 / 竞态对，以及"Level 1 能不能定、要不要开文件"。120 字符预算不变，
`api@` 前置策略不变。

**candidate 单文件：新增 `## Verdict Facts` 节 + `## Pipeline Tokens` 行**：

```markdown
## Verdict Facts

- null@caller-arg: parameter `t` — caller `nd3_dispatch(t)` passes it unproven non-null (src/p5_null_flow.c:119)
- callee@p5_null_flow.c:112: the origin allocator is in-scan; its body is embedded below
- guard@none: no same-function NULL check dominates the deref at line 121
```

- `Pipeline Tokens` 一行 = 该候选的完整 Hint 序列（修 D1：复核时初判依据可见）。
- Verdict Facts 与 Hint token 一一对应（同一契约驱动），每行含出处 `file:line`
  ——AI 可选择 targeted read，而非窗口盲读。
- 嵌入段（FactWithEmbed）复用 Callee Definition 模式：先例已验证
  "跨文件 callee 变成 in-file 判断"能省 source read。

**不嵌入 raw CFG/DFG/Call Sites**（G3 论证）：
- 上下文经济学：100-candidate range 是硬天花板（split threshold），Level 2
  触发率 ~20%；文件膨胀直接击穿天花板。raw 图的每行对 LLM 的边际信息量
  远低于一行蒸馏事实。
- LLM 信噪比：LLM 需要的是"问答式事实 + 出处"，不是图遍历；图遍历
  （free→use 可达、retNullable 传播、guard 支配）是 Go 侧查询。
- 已验证替代模式：Callee Definition 嵌入（unchecked-return）+ source→sink
  span 窗口扩宽（E-06，窗口自动覆盖 SourceLines 全部决定性行）——
  Verdict Facts 是这两个先例的系统化推广。Call Sites 只给**摘要计数**
  （先例：DivisorCallers "3 direct call sites, 2 pass non-zero constants"），
  不给全列表。

### 3.3 token 词汇表单一源 + CI 守护（修 D4/D6）

- Go 侧新增 `hintTokens` 注册表：`token → (语义说明, 消费规则)`，
  FactSpec.Token 必须在注册表中声明。
- `_index.md` 头部图例**由注册表生成**（markdown.go 渲染时遍历注册表拼
  图例文案，删除两处硬编码）。
- `release/check-extension-consistency.py` 扩展两条守护：
  1. command-instructions.md / agent-body.md 中出现的所有 `` `token@…` ``
     形式 token ⊆ 注册表；
  2. 每个 SKILL.md 引用的 token/fragment Type ⊆ 该类型 FactSpec + 实际
     BuildEvidence 产出集合（新增 Go 测试同权守护，CI 失败即阻断）。
- SKILL.md 瘦身：不复制全局词汇表，只写本类型专属 token 的消费规则
  （与 Evidence Pattern 对应），全局图例引用 _index.md 头部。

### 3.4 re-review 材料升级（修 D5）

`--list-auto-confirmed` 返回的每条 finding 增加：
- `facts []string`：该 finding 的 Verdict Facts 行（与 candidate 同一契约、
  同一渲染管线——auto-confirmed 在 scan 阶段已算出全部事实，只是丢弃了）；
- `context_window`：±8 行窗口文本（复用 readCodeContext）。

这是 round3 教训的直接修复：复核 AI 拿到与初判同源的事实包，
"getter 误判为 allocation"类误报在复核时一眼可辨，无需再花 read 预算。
分页机制（--limit）不变，单页体积因 facts 增加约 3-5 行/条，
按 50 条/页仍远小于一页 candidate 文件。

### 3.5 25 类型事实契约矩阵（核心交付）

> 依据：Candidate 现有字段、62 种 fragment 清单、round2 审计断链清单、
> 各子链路检视记忆。Batch 0 实施时逐类型核对现状并修订此矩阵（盘点本身
> 是 Batch 0 的验收物）。`▲` = round2 审计已实证断链，`◆` = 现状已有 token
> 只需接渲染，`●` = 需 detector/planner 补装载。

| 类型 | 决定性事实（token → 来源） | 现状 |
|------|---------------------------|------|
| null-deref | `null@malloc-fail\|cfg-proof`（Origin+CFG）/ `null@caller-arg`（CallerNullDetail）/ `null@external-unknown`（fail-open 档，明确"这是假设非证据"）/ `callee@file:line`（IsCallResultDeref+retNullable / allocator）/ `guard@none\|weak`（guardModel） | ● maybe-null 不分档 |
| uninit | `tier@certain\|maybe`◆ + `origin@stack\|heap\|struct`（Fix C 引入）/ `decl@N`◆ / `write@never\|partial` | ◆/● |
| unchecked-return | `contract@known\|unknown`◆ + `callee@file:line`◆ + `consumed@return-check\|dead-store`（Fix A/B） | ◆ 标杆，补 consumed@ |
| use-after-free | `free@N`◆ + `alias@q\|r`（findAliases 集合）/ `use-form@field\|subscript\|return\|assign`（UF-05 补全后） | ◆/● |
| double-free | `free@N,M`◆ + `may-free`◆ + `cond@first-release`（条件释放 helper 名） | ◆/● |
| buffer-overflow | `buf@name` + `cap@N`（Array/Size 字段已在）/ `idx@expr`◆ + `size-unit@byte\|elem`（BO-13）/ `bound-check@unrelated\|covers`（BO-04） | ● 零 token（dfaafab props 全弃=▲） |
| out-of-bounds | `buf@name` + `idx@expr`◆ + `idx-form@const\|var\|param` + `cap@N` | ● 同上 |
| divide-by-zero | `divisor@shape`◆ + `range@interval`（DivisorInterval，仅含 0 时）/ `callers@summary`（DivisorCallers）◆ | ◆ range@ 未进 Hint |
| integer-overflow | `lhs@/rhs@/rhs-influenced/sink@/guard@none`◆（unsigned_sub）——扩展至其余 category + `width@type-width`（IO 检视遗留） | ◆ 单 category |
| memory-leak | `alloc@N`（DeclLine）+ `escape@global\|param\|return\|none`（escape-transfer）/ `raii@paired`（RAII 配对）/ `cond-release@helper` / `alias@`（ML-02） | ● 零 token |
| resource-leak | `acquire@N` + `escape@` / `raii@` / `writeback@out-param` | ● 零 token |
| race-condition | `threads@/write@/mutex@/lock@`◆ + `check@fn→use@fn`+`arg@`▲断链（detector 已发 props 未装载） + `synchronizes@api`（atomic/rwlock 豁免证据） | ▲/◆ |
| deadlock | `locks@A\|B`◆ + `reverse@fn`◆ | ◆ 完整 |
| injection | `src@N`◆ + `sink@api`◆ + `sanitizer@none\|found`（入口净化调用证据） | ◆/● |
| format-string | `fmt-arg@expr`◆（FormatArg）+ `literal@yes\|no` + `tainted`◆ | ◆/● |
| path-traversal | `path-arg@expr`◆ + `canonicalized@realpath\|none` + `checked@` | ◆/● |
| crypto-misuse | `algo@name` + `key-size@N`◆ + `reason@`▲断链（unchecked-key 类别） | ▲/◆ |
| hardcoded-secret | `value-shape@prefix+len`（MASKED 渲染先例）+ `var-tier@credential\|placeholder\|test` | ● |
| signal-handler | `async-unsafe@api`（async-signal-unsafe 调用名） | ● |
| dangerous-function | `api@`◆ + `banned-reason@` + `safe-variant@name\|none`（dangerous→safe 变体对照） | ◆/● |
| signed-compare | `operands@signed/unsigned` + `promoted@type` + `sink@use-of-result` | ● |
| sizeof-misuse | `subject@type\|expr` + `unit@byte\|elem`（BO-13 同源）+ `context@alloc\|copy\|arith` | ● |
| data-representation | `cast@from→to`◆（CastType）+ `width-loss@bits` | ◆/● |
| argument-type | `expected@/actual@/cast@`◆（三字段已有） | ◆ 只差渲染 |
| implicit-contract | `subject@`◆ + `count-field@`◆ + `evidence-kind@self\|caller`◆ | ◆ 多数已有 |

共性规则：所有类型保留公共 token（`api@`/`cat@`/`src@N`/`weak-guard`/
`macro-context`/`tainted`）。矩阵中 `●` 项的实施顺序见 §5。

## 4. 与既有机制的关系

| 机制 | 关系 |
|------|------|
| Evidence fragments（62 种） | Verdict Facts 是 fragments 的**上游结构化层**：token 行先给机器可扫的事实，fragments 保留自然语言叙事（复核需要解释性）。渲染顺序：Verdict Facts → Evidence |
| Code Context 窗口策略 | 不变。E-06 source→sink span 自动覆盖 FactSpec 声明的 SourceLines |
| SKILL.md 协议 | Evidence Pattern 节保留；新增 Verdict Facts 的消费说明引用全局图例（3.3 守护一致性） |
| ADDING_A_VULN_TYPE.md 6 步清单 | 第 3 步（注册类型）扩展为"填 FactSpec 契约"；SKILL_TEMPLATE.md 同步加 Facts 节模板 |
| Fix A/B/C（round3） | 契约化后这类修复变成"补一个 FactSpec 条目 + 装载"，不会忘渲染 |
| null-deref 三态建模（记忆：方案已定待实施） | `null@` 档位 token 即三态建模的渲染面，二者合并实施 |

## 5. 实施计划（分批，每批可独立验收+commit）

| 批次 | 内容 | 验收 |
|------|------|------|
| **B0 架构层** | FactSpec 类型 + newEvidenceItem 三面渲染 + hintTokens 注册表（先收录现状全部 token）+ _index.md 图例改生成 + 一致性守护（Go 测试 + check-extension-consistency.py）+ candidate 文件加 `## Pipeline Tokens` 行与 `## Verdict Facts` 节（B0 只渲染既有事实，**所有类型行为等价**）+ 逐类型契约盘点修订 §3.5 矩阵 | 全量测试绿；benchmark A/B：auto-confirm 集合与 candidate 文件 diff 仅限新增小节 |
| **B1 null-deref 试点** | `null@` 三档 + `callee@` 嵌入（allocator/call-result）+ `guard@` 档位；同步 SKILL.md、agent-body、instructions 的 null-deref 段；**合并实施三态建模方案**；re-review facts/context_window 升级（修 D5，全类型受益） | null-deref 单测 + benchmark A/B 零回归 + round3 误驳回样本（p13:170）人工重判验证 |
| **B2 实证断链** | race TOCTOU（▲）+ crypto reason（▲）+ LHSInfluenced（▲）+ BO/OOB token（●，dfaafab props 接渲染） | round2 审计断链清单全闭 |
| **B3 leak 双类型** | memory-leak / resource-leak 契约（escape@/raii@/cond-release@/writeback@） | 生产误报根因（memory-leak-analysis.json：21 FP）可由 facts 直接解释 |
| **B4 剩余类型铺开** | §3.5 矩阵 `●` 项按类型逐个 commit（每类型：FactSpec + 装载 + SKILL 同步 + 单测 + A/B） | 25 类型契约全覆盖，守护测试全绿 |
| **B5 文档与流程** | ADDING_A_VULN_TYPE.md / SKILL_TEMPLATE.md 更新；instructions/agent-body 的 Hint 词汇段落改为引用生成图例 | check-extension-consistency.py 全绿 |

每批固定流程：单测 → 全量 → benchmark A/B（干净目录，见记忆
sgre_ab_validation_suppression_index）→ 会话级验证（Level 2/3 触发率对比：
evidence_opens / source_reads 自报计数）→ commit。

## 6. 风险与对策

| 风险 | 对策 |
|------|------|
| candidate 文件膨胀击穿 100-candidate 天花板 | G4 硬预算（Facts ≤15 行 / 嵌入 ≤40 行）；B0 加渲染器行数统计测试；嵌入段仅 FactWithEmbed 档且每文件 ≤1 段 |
| token 120 字符截断吃掉关键信息 | Order 排序（最决定性在前）+ `api@` 前置既有策略；截断行为不变 |
| SKILL/instructions 大面积重写引入协议回归 | B0 的图例生成 + CI 守护先行；SKILL 改动按类型分批（B1 只动 null-deref） |
| re-review 单页体积上升 | facts 控制在 3-5 行/条；--limit 分页不变 |
| 与 v0.9.5 迭代流程冲突（用户在现网冒烟） | 本工程只动 sgre 渲染/装载层与 extension 协议文档，不动检测语义（B1 三态档除外，其本身是已定方案）；每批独立可发布 |

## 7. 对"生产结果可信度"的回应（用户核心疑虑）

现状 AI 能扫出问题靠的是 Level 3 兜底（AI 自己读码），这是**不稳定的
质量来源**：round3 中同一批候选被 AI 驳回 27/38，其中混有 ground truth TP。
本方案把质量来源从"AI 临时读码"换成"管线证明的事实包"：
- Hint 分诊准确 → AI 不再对贫瘠信息过度自信/过度怀疑；
- Verdict Facts 带出处行号 → AI 的确认/驳回理由可追溯、可复核；
- re-review 同源材料 → 机器 FP 在复核阶段即可辨识（round3 类误报的
  结构性出口）。

验收的最终指标不是扫描数量，而是：**AI 研判 reasoning 中引用 facts 的
比率、Level 2/3 触发率下降、benchmark 上 FP 率与 FN 率同步收敛**。