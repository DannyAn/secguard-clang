# 跨skills 参考方案 → 本仓库（secguard-clang）适配评估

> 评估对象：`docs/跨skills架构调整参考方案.md`（下称「参考方案」）
> 评估结论：**不需要架构重构**。本仓库已经站在参考方案要迁移到的「站点级」终点上；
> 值得做的是**少量增量增强**（补 2–3 条站点级规则 + 可选的「自适应 cap / 分层回填」），
> 而非照搬参考方案的任务模型 / 证据预取 / worker 集成。

---

## 1. 结论先行（TL;DR）

参考方案要解决的核心问题是：**把「函数级」的候选任务模型 + 函数级 auto_fp 规则，迁移成「站点级」**。
它假设的痛点——task 是函数批、规则作用在函数上、worker 每次重取函数事实——在**当前 Go 仓库里不存在**：

- 本仓库的收敛管线**从 seed 到 filter 到 dedup 全程都是站点级**：
  一个 `Candidate` = 一条 `security_events` 记录 = 一个站点（`planner.go:168-230` 的
  `seedCandidatesByType`，`filter.go:64-82` 的 `Candidate{Line, LocationID, DerefEventID}`）。
- 参考方案「Change 1: 修 null_guard 的 scope_start/scope_end」**本仓库早已完成**：
  `null_guard.go:85-101` 已经输出 `scope_start` / `scope_end`。
- 参考方案「Change 4: 证据预取」**已由 `PlanResult`/`EvidenceItem` + agent 侧「只在报出的
  file:line 读源码」等价满足**，不存在 worker 重复取事实的浪费。

因此「架构重构」这整件事的收益为负——那是把一个已经站在终点上的系统，照着另一条路线的施工图
再走一遍。真正值得投入的是**三条增量**（见 §5），合计约 2–4 人日，不是重构。

---

## 落地记录（2026-08-14）

按 §5/§7 三条增量逐条核对后的实际进展与勘误：

| 增量 | 结论 | 落地结果 |
|---|---|---|
| **A.1** `sizeof_pseudo_deref` | 值得补 | ✅ **已落地**（tag + filter，见下） |
| **A.2** `deref_implies_nonnull` | 值得补 | ⛔ **不落地**：`ConvergeByVariable=true` 已把同变量多次解引用 dedup 成一个候选，无可抑制对象；且「首解引用被 guard、次解引用未 guard」时抑制次解引用会**吞真漏洞**（误伤） |
| **B** memory-leak `perfect_cleanup` | 值得补 | ✅ **已实现，无需改动**：`memory_leak.go` 的 `hasLeakingPath` 已做「逐 return 路径释放」的路径敏感分析，`tc06_memleak_error_path` 已覆盖。§增量 B 原判断「ReleaseFilter 任意释放即丢弃」**不成立** |
| **C** 自适应 cap | 暂缓 | ⏸ 维持暂缓，等 A/B 真实数据 |

### A.1 落地方式（tag + filter，避免跨类型干扰）

`DEREFERENCE` 事件还被 `interprocedural` 消费，故**不在 detector 里抑制**，而是：
1. `dereference.go` 在 `insertDerefEvent` 对 `sizeof`/`alignof` 内的解引用打 `is_type_expr=true` 标记；
2. 新增 `TypeExprFilter`（name=`sizeof_pseudo_deref`），挂在 null-deref 链**最前**，读标记丢弃；丢弃进 `Dismissed` 账本，可审计。

**关键事实**：`sizeof(*p)` 的 `*p` 在 tree-sitter-c 里被解析成指针类型（`abstract_pointer_declarator`），
从不产生 `unary_expression`，故**从不是 FP**；真正误报的是 `sizeof(p->field)` 与 `sizeof(p[0])`，均已被兜住。

### 顺带修复：uninit 同源 sizeof 误报

补 benchmark 锚点时暴露 `detectHeapUninit` 对 `sizeof(node->field)` 同样误发 `VALUE_USE`（当作读未初始化
堆内存），与 null-deref 同源的「sizeof 未求值上下文」缺陷。已在 unary / pointer / field 三个解引用循环加
`isInsideTypeExpr` 守卫，与新 null-deref 规则对称。

### 验证

- `go test ./...` 全绿（含 tc01 真解引用、tc04 跨函数、tc05/tc06 memory-leak、tc11–tc17 uninit）；
- `c-vuln-benchmark` 扩到 **35 例**（新增 ND-01，CWE-476 sizeof FP 抑制），`validate-benchmark.py` 35/35：
  precision 100% / recall 100%。

---

## 2. 参考方案的本质（它到底在解决什么）

参考方案是给**另一个项目**（Python 版 sgre，30 个 skill，IDM 生产数据 4,410 函数）写的。
它的四个根因：

1. **规则引擎缺口**：22/30 skill 的 auto_fp 规则 ≤1 条，SQL 过滤是唯一筛子且太宽。
2. **验证单元错配**：task = 函数批，但原子问题是「*这个* deref 安全吗」这种站点级问题。
3. **证据冗余**：worker 对每个站点都重取整份函数事实；同函数站点共享 70–90% 证据。
4. **scope 分析失效**：`null_guards.scope_start/scope_end` 恒为 NULL，guard 覆盖分析被禁用。

它开出的药方：**站点级任务模型**（task = `(function_id, site_ids[])` + 预取证据包）、
**站点级规则引擎**（AUTO_FALSE_POSITIVE / PROVEN_SAFE / LOW_RISK / NEEDS_AI 四分类）、
**站点级分层回填**（按 TP 率 gate 是否继续审低优先站点）。

**关键判断**：这四条根因里，本仓库只有「规则引擎还有补强空间」这一条部分成立；
其余三条在本仓库的架构下根本不成立（见 §3 逐条对照）。

---

## 3. 逐条对照：参考方案 8 项改动 vs 本仓库现状

| 参考方案改动 | 本仓库现状 | 判定 |
|---|---|---|
| **Change 1** 修 `null_guard` scope_start/end | `null_guard.go:85-101` / `152-152` 已输出 scope_start/scope_end；`GuardFilter`（`filter_guard.go`）已按行区间做覆盖判断 | ✅ 已实现，跳过 |
| **Change 2** `sizeof_pseudo_deref` 站点规则 | `dereference.go:74-87` 的 `detectExplicitDeref` 对 `*` 开头的 `unary_expression` 一律发 DEREFERENCE，**未排除 sizeof/alignof 内的类型表达式** | ⚠️ 缺失，值得补 |
| **Change 3** 扩展 task schema 为站点级 | 本仓库无 task 概念；`Candidate` 本身就是站点级（`filter.go:64-82`） | ❌ 不适用（已站点级） |
| **Change 4** `SkillEvidenceSpec` + 证据预取 | 已有 `PlanResult`/`EvidenceItem`（`evidence_package.go`）带 `Target{file,function,line,variable}` + 证据片段；agent 只在报出位置读源码（`agent-body.md` §6「limit ≤10 files」） | ✅ 已等价满足，跳过 |
| **Change 5** 站点级规则引擎 | filter 已站点级：`GuardFilter`≈guard_covers、`NullableSourceFilter`≈nullable_source、`LifetimeFilter`≈路径可达、`SafeFunctionFilter`、`CallReachFilter`、`ReleaseFilter` | ⚠️ 部分已实现，缺几条高价值规则 |
| **Change 6** 其余 skill 站点规则 | 本仓库 15 类型，多数靠 detector 级抑制（如 buffer-overflow 的 `hasPrecedingBoundsCheck`）+ `SafeFunctionFilter` 已覆盖 | ⚠️ 低 ROI，多数不适用 |
| **Change 7** 站点级 tier + 回填 gate | **本仓库没有 tier/backfill**（grep 无 tier/backfill/priority）；当前是「rank 后硬截断在 30」（`planner.go:146-153`） | ⚠️ 结构性缺口，最有价值的增量 |
| **Change 8** Worker 集成 | 平台不同（本仓库 agent 走 `secguard_scan/plan` → report.md 表 → `secguard_report`），无 Dispatcher/Worker | ❌ 不适用 |

**结论**：8 项里 3 项已实现、3 项不适用，真正有落地价值的是 **Change 2、Change 5 的一部分、Change 7**。

---

## 4. 本仓库与参考方案的关键差异（为什么不能照搬）

1. **收敛方向相反**。参考方案是把「函数级 → 站点级」；本仓库从设计上就是站点级，且进一步用
   `dedup` 把同根因的多站点收敛成一个 finding（`planner.go:232-262`）：
   - `ConvergeByVariable`（null-deref）：`(file, function, variable)` → 一个可空变量的多次解引用算一个缺陷；
   - 自定义 `ConvergeKey`（injection/crypto/integer-overflow）：把同根因的多事件（如 `srand`+`rand`）合并。
   这正是参考方案「site-batched task」想达到的「同函数站点共享推理」效果，而且更彻底——直接合并成一个候选。

2. **证据形态不同**。参考方案的证据包是「共享函数事实 + 站点事实」两大层；本仓库的 `EvidenceItem`
   是「精简证据片段 + 让 agent 按需读源码」。后者更省 token（agent 只在报出位置读源码，而非预取整函数），
   且源码是唯一 ground truth，没有「证据过期」问题（参考方案 §10.2 自己都要用 content_hash 兜底）。

3. **吞吐优化走的是另一条路**。本仓库的吞吐瓶颈（613s，其中 AI 分类 ~400s 串行）已经由
   `docs/parallelization-design.md` 用「detector 波次并行 + 14 类型 agent 扇出」解决；
   参考方案解决的是「精度 / 候选爆炸」，不是墙钟。两者正交、可叠加。

---

## 5. 值得借鉴的三条增量（按 ROI 排序）

### 增量 A：补齐 2 条 null-deref 站点级规则（低投入 / 高回报）

本仓库 null-deref 的 FP 压力真实存在（近期 round5 实测 85 候选 / 79 dismissed，命中率 ~7%，
与参考方案 IDM 数据 96.3% FP 同量级）。补两条精确、保守的规则能直接砍掉大头：

| 规则 | 分类 | 逻辑 | 改法 |
|---|---|---|---|
| `sizeof_pseudo_deref` | AUTO_FP | `sizeof(*p)` / `sizeof(p->x)` 是类型表达式，非运行时解引用 | `dereference.go` 的 `detectExplicitDeref`/`detectMemberAccess` 判断节点是否在 `sizeof`/`alignof`/`_Alignof` 内，是则不发 DEREFERENCE 事件（或在 properties 打 `is_type_expr=true`，由 filter 丢弃） |
| `deref_implies_nonnull` | PROVEN_SAFE | 同一变量在更早行已被解引用 → 该解引用前变量必非空 | 新增一个 filter（或并入现有链），读该函数内同一变量的历史 DEREFERENCE 事件，行号 `< 当前行` 则标记 `PROVEN_SAFE` 丢弃 |

两者都是**保守**的（只在不歧义时判定），可在 `c-vuln-benchmark` 上回归验证不吞真漏洞
（参考方案 §10.1 的安全校验思路直接适用）。

### 增量 B：memory-leak 用「每路径释放」替换「任意释放」（中投入 / 中回报）

> ⚠️ **勘误（2026-08-14）**：下述「ReleaseFilter 是任意释放即丢弃」的判断**不成立**，本增量**无需落地**。
> 复查 `memory_leak.go` 后确认：detector 已用 `hasLeakingPath`（`graph.BuildCFG` + `FindInnermostScope` +
> `CanReach`）做「逐 return 路径都有释放」的路径敏感分析，`ReleaseFilter` 消费的是 detector 已按路径 gate 过的
> `MEMORY_RELEASE` 事件；`tc06_memleak_error_path` 已覆盖「成功路径释放 / 错误路径漏」场景。详见 §落地记录。

当前 `ReleaseFilter`（`filter_extended.go:46-82`）的语义是「该函数里**任意一行**释放了该变量 → 丢弃」，
这是**过激进**的：`if (a) free(p); ...; return p;`（只有一条路径释放）会被误判为无 leak。
参考方案的 `perfect_cleanup` / `goto_cleanup` 是「**每条** return 路径都释放才算 PROVEN_SAFE」。
把 `ReleaseFilter` 从「存在释放」升级为「逐 return 路径都有释放」（复用 `graph.BuildCFG` 的
作用域树 + `HasExit` 做路径枚举），能把 memory-leak 的漏报风险从「粗粒度一刀切」降到「精确」。

> 注：这是「提升召回」的改动，与增量 A（提升精度）方向相反，需分开验证，别一起上。

### 增量 C：自适应 cap / 分层回填（高投入 / 结构性收益，可选）

当前 `planner.go:146-153` 是「rank 后硬截断在 `MaxCandidates=30`」，超出的候选**被静默丢弃**
（虽有 `Dismissed` 账本，但不会送审）。参考方案 Change 7 的分层回填把它变成「自适应」：

- **P1（core）**：rank 前 30 送审；
- agent 分类后算 TP 率，**≥ 阈值则回填下一层**（P2/P3 按 TP 率 gate，参考方案 §6.4 的 20% / 5% 门限）；
- 好处：候选少时一个不多审、候选多且真命中多时不漏审；坏处：需要 planner 支持「按优先级分页产候选」、
  agent 侧多一轮 `secguard_plan`+分类的循环、`scan_stats` 记分层指标。

这是唯一「结构性」改动，但它解决的是「固定 cap 的召回损失」，不是吞吐也不是精度，收益要
看目标代码库的候选量级（候选常年 <30 的类型，此改动零收益）。**建议先做 A、B，用真实 FP/召回
数据决定是否值得投入 C**。

---

## 6. 不建议照搬的部分（及原因）

| 参考方案项 | 不建议原因 |
|---|---|
| 站点级 task schema（Change 3） | 本仓库 `Candidate` 已是站点级，无 task 抽象可迁移 |
| `SkillEvidenceSpec` / 证据预取（Change 4） | `EvidenceItem` + agent 按需读源码已等价且更省 token，还无证据过期问题 |
| Worker / Dispatcher 集成（Change 8） | 平台不同 |
| 30 个 skill 的站点规则表（§4.3 整表） | 本仓库只有 15 类型，且多数类型靠 detector 级抑制 + `SafeFunctionFilter` 已覆盖，逐条照搬 ROI 为负 |
| scope 覆盖「精确化」（`scope_guard_covers` 区分 terminating/scope） | `null_guard.go` 已区分 `NULL_CHECK` 与 `EARLY_RETURN`，`GuardFilter` 已按行区间判断，再细分收益边际 |

---

## 7. 投入产出与推荐节奏

| 阶段 | 内容 | 改动面 | 预估 | 前置 |
|---|---|---|---|---|
| **Step 1** | 增量 A：`sizeof_pseudo_deref` + `deref_implies_nonnull` | `evidence/dereference.go` + 1 个 filter | 0.5–1 人日 | 无 |
| **Step 2** | 增量 B：memory-leak「每路径释放」 | `planner/filter_extended.go` + 复用 `graph/cfg.go` | 1–1.5 人日 | Step 1 后（避免两类改动互相污染回归） |
| **Step 3（可选）** | 增量 C：自适应 cap / 分层回填 | `planner` + `scan_stats` + agent 侧循环 | 2–3 人日 | 用 Step 1/2 后的真实候选量级 + TP 率数据决策 |

**推荐结论**：**只做 Step 1 + Step 2**（合计 ≤2.5 人日），它们是「补几条站点级规则」的增量，
不是重构，且每一项都能用 `c-vuln-benchmark`（现 35 例 ground truth）做**不吞真漏洞**的回归验证。
Step 3 是唯一够得上「架构调整」的改动，建议**暂缓**，等 Step 1/2 数据出来再决定。

> 📌 **进展（2026-08-14）**：Step 1 的 `sizeof_pseudo_deref` 已落地，`deref_implies_nonnull` 评估后
> 不落地；Step 2 复查后确认已实现。详见 §落地记录。

### 一句话判断

> 参考方案是一份「函数级 → 站点级」的迁移施工图；本仓库**从第一天就是站点级**，已经站在那条路
> 的终点。所以「按参考方案做架构重构」不值得——那是倒退着重建已经存在的东西。值得做的只是
> **把参考方案里那几条精确的站点级规则（A、B）移植进来**，作为对现有 filter 链的补强。

---

## 附：与 `docs/parallelization-design.md` 的关系

- **参考方案（跨skills）** 优化的是**精度 / 候选收敛**（少送审、少 token、少 FP）。
- **parallelization-design.md** 优化的是**吞吐 / 墙钟**（detector 并行 + 14 类型 agent 扇出，613s→~150s）。
- 两者**正交且可叠加**：先做 parallelization 的 Layer 1（Go 侧并行，低风险、纯提速），
  再补本评估的增量 A/B（精度），二者不冲突、不互相阻塞。若要排优先级，**吞吐的收益（4 倍）远大于
  精度增量（FP 率从 ~93% 降到 ~85% 量级）**，建议 parallelization Layer 1 优先。
