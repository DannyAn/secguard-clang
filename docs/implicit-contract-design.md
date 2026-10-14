# implicit-contract 隐式契约缺失检测 — 设计方案（定稿）

> 状态：评审通过，进入实施。本文是《ChatGPT给的函数校验落地指导方案.md》阶段 0 调研结论 +
> 阶段 1 最小落地设计。**决策已收敛：单类型 CWE-20 + 可扩展 category 框架，阶段 1 只做
> `ptr_guard`，不做独立 count_guard。**

## 0. 一句话结论

本案例（`import_dn_group_tree_refresh`）不是 null-deref 能证明的空指针缺陷，而是「函数入口
缺少对输入对象关联状态（指针字段）的校验」的隐式契约缺失。落地 = **新增 `implicit-contract`
能力（CWE-20，全部 `suspected` 交 AI）**，用「证据门」把触发面压到极小，绝不 machine-confirm。

## 1. 调研结论（为什么当前没发现，根因定位）

1. `tree = (T*)(resp->group_data)` —— `resp->group_data` 是**结构体字段读**，当前没有任何
   检测器把「字段值」当作空源；`tree` 没有空源 → `tree->x` / `tree[i]` 被「no null source
   reaches」丢弃。
2. `resp` 参数即使有 `caller_null` 源，未证明的非空参数会被 `onlyUnprovenCallerNullSources`
   丢弃。
3. 修复补丁 `if (tree == NULL || resp->group_num == 0) return 0;` 证明 `group_data` 可空、
   `group_num` 可零——这是**业务契约**，代码静态证明不了 `p = NULL`。

## 2. 目标与边界

### 2.1 目标（阶段 1）

新增内部能力 `implicit-contract`，检测：**函数入口对「结构体指针参数的可空指针字段」缺校验、
而后续确有解引用**的高置信度候选。唯一 category：`ptr_guard`。

计数/长度字段（`group_num` 之类）**不作为独立告警**，只作为触发上下文：它证明 `obj->data`
是「被计数的集合」、指针确实要被解引用/遍历，从而把「字段读 + 解引用」这个弱信号升级为
「计数集合的指针缺判空」这个强信号。

### 2.2 非目标（阶段 1）

- 不做「所有指针参数必须判空」「所有计数器必须非零」。
- **不做独立 `count_guard`**（「缺 `count!=0` 判断」）：`count==0` 是否非法是纯业务语义，
  静态证明不了，做进去必然误报爆炸（指导方案 §1.2/§2.2/§7.3）。
- 不覆盖 `ptr_length`（指针—长度/容量）、`state_operation`（状态字段—操作）、返回值未验证。
- 不新增平行 null-deref、不复制 detector 框架、不改 findings schema、不自动建议 return 值/日志。

## 3. 核心设计：触发条件 + 证据门 + 误报控制

### 3.1 触发条件（`ptr_guard`，全部满足才 seed）

对每个函数 `f`、每个「结构体指针参数 `obj`」（`T *` 形参且被 `->` 访问）：

1. **指针字段被解引用**：`obj->P`（或 `p = obj->P` / cast 派生的局部 `p`）在 `f` 内被解引用
   （`->` / `*` / `[]`）。
2. **缺守卫**：入口到 use site 的路径上，无支配性 `obj->P == NULL` / `p == NULL` 早退守卫。
   复用 `guard_model.go` + `filter_nullable_source.go` 的 CFG guard 模型（`ContractGapFilter`）。
3. **证据门（必须命中至少一条）** —— §3.2。
4. **（可选）计数/长度门控，仅作增强证据**：若存在 `obj` 的另一个字段 `obj->N`，其**用法**是
   循环边界 / 下标上界 / 与 0 比较 / size 实参，则把 `count` 记进候选证据，证明这是「被计数的
   集合、指针确实要被解引用」。**它不 gate 检测**——`tree == NULL`（纯指针判空）独立于任何
   计数关系，`count==0` 是业务语义，不与内存安全的指针判空绑定。

### 3.2 证据门（误报控制核心：无证据就不产候选）

只有**代码本身把该字段当作「可空」**时，才报告缺校验（三选一，已全部实现）：

- **E-b（自证）**：`f` 自己在**某条路径**上判过 `obj->P == NULL` / `p == NULL`，
  但未覆盖本 use site 的那条路径（部分守卫）。
- **E-a（同类契约）**：参数声明类型文本相同的**兄弟函数**对同名字段判空——按形参类型锚定，
  不跨 struct 裸名匹配。这是生产用例 `import_dn_group_tree_refresh`（函数自身无判空）被拦住的
  关键证据。
- **E-c（调用方证据 + 抑制）**：某调用方在调用 `f` 前对 `obj->P`（或其派生）判空。
  - 存在这样的调用方 → 证据成立（调用边界上该字段可空）；
  - **所有**调用方都判空（且 `f` 自己没判）→ **抑制**（调用方已完成校验，指导方案 §7.1）。

> 关键推论：若全代码库从无任何人判空 `group_data`，则**不报**——符合指导方案 §5「仅保留有
> 证据的候选或不报」与 §8.4「业务语义证据不足时不升级」。证据门是特性，不是缺陷。

### 3.3 误报控制七道防线

| # | 防线 | 机制 |
|---|---|---|
| 1 | 窄触发 | 「字段被解引用」+「缺守卫」+「证据门」三合一（计数/长度仅作可选增强证据，不 gate） |
| 2 | 证据门 | 无 E-b/E-c 证据 → 不产候选 |
| 3 | 不 machine-confirm | `DefaultSuspicion="suspected"`，无 confirmed 路径 |
| 4 | 守卫支配 → 机器 drop | `ContractGapFilter` 用 CFG `ReachesAvoiding` 丢弃被守卫支配的 use site |
| 5 | 精确指出失败模式 | 候选逐 use site 记录 use_line、missing 条件、证据来源；不笼统「缺校验」 |
| 6 | 与 null-deref 去重关联 | 字段被函数自身写 → 跳过（归 null-deref），避免双告警（§7.10） |
| 7 | 可关停 + 可观测 | `[disabled_types]` 关停；summary 暴露 Seed/Final/Dedup 与 drop 原因 |

## 4. 架构落地

### 4.1 关键决策（已定）

- **单类型** `implicit-contract`，canonical CWE-20（Improper Input Validation），domain=`contract`。
- **可扩展框架 = category 机制**（复用 `injection` 的 `CategoryCWEs` 先例）：阶段 1 注册
  `ptr_guard`；阶段 2 直接加 `ptr_length`/`state_operation` 等 category，不动 registry/schema。
- **不拆分多个 CWE 类型**：CWE-20 / CWE-754 / CWE-476 是这个家族的自然候选，但 CWE-754
  （异常状态未检查）与 CWE-20 高度重叠，CWE-476 的可证明部分已被 null-deref 覆盖——再造类型
  只会重复 machinery 并造成 `TypeForCWE` 撞车。
- **`ptr_guard` 确认后本质是 CWE-476 等价**：skill 里写明，但 finding 的 rule_id 保持 CWE-20，
  避免与 null-deref 的 CWE-476 在 `TypeForCWE` 撞车。
- **全部 suspected，不 auto-confirm**：因此**不**在 `zz_ai_judgment_boundary_test.go` 的
  confirmed 黄金清单登记（它是「故意留 suspected」类型，与 argument-type / data-representation 同类）。

### 4.2 修改/新增文件清单

| # | 文件 | 变更 | 必要性 |
|---|---|---|---|
| 1 | `sgre/internal/db/schema.go` | `event_type` CHECK 枚举加 `CONTRACT_GAP` | 缺枚举 InsertEvent 静默失败 |
| 2 | `sgre/internal/evidence/contract_gap.go` | **新增** detector：窄触发 + 证据门，emit `CONTRACT_GAP` | 能力本体 |
| 3 | `sgre/internal/evidence/registry.go` | `RegisterDetector(NewContractGapDetector)` | 注册 detector |
| 4 | `sgre/internal/planner/registry.go` | `RegisterVulnType("implicit-contract", CWE-20, Categories=[ptr_guard], ...)` | 类型注册 |
| 5 | `sgre/internal/planner/filter_contract_gap.go` | **新增** filter：CFG guard 复核 + E-c 全调用方校验抑制 + null-deref 关联去重；不 promote | 收敛/抑制 |
| 6 | `sgre/internal/planner/planner.go` | `getFilters` 加 `case "implicit-contract"` | 接 filter 链 |
| 7 | `sgre/internal/skills/vuln_type_skill.go` | `allSkillSpecs` 加 `implicit-contract` | 四列表同步 |
| 8 | `extension/shared/skills/implicit-contract/SKILL.md` | **新增** skill（copy 模板） | AI 研判规则 |
| 9 | 测试 + fixtures | `contract_gap_test.go`、`filter_contract_gap_test.go`、`zz_contract_gap_*.go`、`sgre/testdata/tc_contract_gap_*.c` | 正反例/回归 |
| 10 | `docs/implicit-contract-design.md` | 本设计文档 | 评审/归档 |

### 4.3 候选证据（不新增 findings schema 字段）

指导方案 §6 的字段（subject / required_condition / use_site / path_evidence /
contract_evidence / counter_evidence / limitations / recommendation）全部通过
`EvidenceFragment` 渲染（现有机制）。`Candidate` 加少量承载字段（`Missing`、`EvidenceKind`、
`Subject`、`CountField`、`UseLine`），照现有 `FieldPath`/`Origin` 先例。

## 5. 测试计划

### 5.1 正例（产 `suspected` 候选）

1. `obj->data` 被解引用、`obj->count` 做循环边界，无守卫，且**函数自身在另一路径判过空**（E-b）。
2. 同上无守卫，且**某调用方在调用前判过空**（E-c）。
3. 守卫只覆盖部分路径，另一条可达路径仍解引用（部分守卫）。

### 5.2 反例（必须不报）

1. 所有使用点前已有有效判空 + 早退（完整守卫）。
2. **所有**调用方都已校验，函数内部不再判（E-c 全校验 → 抑制）。
3. 指针字段被读但**从不被解引用**（只传参/比较）。
4. 只有命名相似但用法上无指针-计数关联。
5. **全代码库无人判空该字段**（无证据门命中）→ 不报。

### 5.3 案例专属 fixture（指导方案 §8.3 变体）

以 `import_dn_group_tree_refresh` 结构为蓝本，覆盖 `group_data==NULL`、`group_num==0`、
`group_data==NULL && group_num>0`、`group_data!=NULL && group_num==0`、调用方已校验、
仅一个分支有检查、后续有无真实解引用。每个 fixture 显式声明契约与后续操作，预期结果按声明设定。

### 5.4 验收门槛（指导方案 §8.4）

正例被识别或给出「证据不足/需复核」，不靠函数名/变量名/代码文本匹配；反例不因缺显式判空误报；
null-deref 无回归；schema/状态/输出协议兼容；每条候选指出 use site、path evidence、
contract evidence；以精确率/误报/漏报/单候选模型调用成本为指标。

## 6. 性能与成本

- 检测器走 `forEachFile`（每文件一次 parse + 一次树遍历），与现有 detector 同量级。
- E-c 复用 `call_sites.go` / `caller_null.go` 的调用点解析模式，一次预处理、按需查询，无 N+1。
- 证据门收窄，预计候选量远小于 null-deref；summary 可审计 Seed→Final 收敛率。
- AI 侧：候选全部 suspected，Hint 预计算 `missing@ptr-null` + `evidence@self/caller`，让 AI
  尽量只读 _index 行即可 dismiss。

## 7. 风险与备选

| 风险 | 缓解 / 备选 |
|---|---|
| CWE-20 偏宽 | 备选：`ptr_guard` 用 `CategoryCWEs` 映射 CWE-476（但会与 null-deref 在 `TypeForCWE` 撞车，已否决） |
| 证据门太严 → 漏报 | 已用 E-a（同类契约）+ E-c（调用方）提召回；无证据仍不报（符合指导方案 §5） |
| 字段名误配（跨 struct 同名字段） | 计数角色按「用法」判定；E-a 按形参声明类型文本锚定；不用裸字段名语义 |
| 宏 / 自定义校验函数不可见 | 复用 `macro-context`，宏上下文候选绝不 machine-confirm；记录 limitations |
| 性能 | 检测器两遍扫描 + 一次调用点索引，与现有同量级；证据门天然减量 |

## 8. 分阶段实施（当前状态）

- **阶段 1（已完成）**：`ptr_guard`，证据门 **E-b + E-a + E-c** 全实现，全 suspected，
  正反例测试 + 生产用例 `import_dn_group_tree_refresh` 配对 fixture + 变体，null-deref 无回归。
- **阶段 2（验证后）**：`ptr_length`（指针—长度/容量）、`state_operation`、返回值未验证；
  按真实误报/漏报调优。

## 9. 评审决策记录

1. CWE：**CWE-20 单类型 + category 扩展框架**（不拆多类型，不映射 CWE-476）。
2. 范围：阶段 1 只做 `ptr_guard`；**不做独立 count_guard**（业务语义不可静态证明，风险过高）。
3. 证据门：E-b + E-c，宁漏勿误。
