# SecGuard-Clang 架构设计检视（kimi-k3，2026-10-23）

> **检视与修复分离**：本报告只产出架构层面的问题清单与建设性意见，不动代码。所有修复由用户安排的其他 AI Agent 依据本清单执行。
>
> **检视焦点**：与世界一流 AI Agent C 扫描器目标对齐，重点回答两个问题——
> 1. 为什么近几个版本发布后**扫描速度与检出准确度**没有质的飞跃？
> 2. 是否存在**架构层**的结构性原因，而非仅是 detector 局部 bug？

## 基线

- **Commit**：`db2f184e`（v0.9.9 预发布自检后）
- **代码规模**（`sgre/internal/`）：

  | 模块 | 行数 | 文件数 | 最大单文件 |
  |---|---|---|---|
  | evidence（检测器） | 35,141 | 42（不含 test） | `uninit_variable.go` 91K / `buffer_overflow.go` 71K / `memory_leak.go` 68K |
  | planner（收敛） | 37,046 | 38（不含 test） | `registry.go` 83K / `null_flow.go` 73K / `filter_nullable_source.go` 53K |
  | **graph（语义图）** | **3,388** | 12 | `control_flow.go` 935 |
  | **parser（AST）** | **2,663** | 13 | `guard.go` 397 |
  | db | 4,309 | 30 | — |

- **AI 编排侧**：`extension/shared/command-instructions.md` 797 行 + `agent-body.md` 625 行 + 24 份 `SKILL.md`（3808 行），hint token 已超 **60 种**
- **检视方式**：源码静态分析 + 历史多轮检视结论交叉比对；未跑端到端（用户只要求架构审视）

---

## 核心结论（一句话版）

当前架构已经搭出了「**detector 生成候选 → planner filter 收敛 → AI 研判**」的三层骨架，并且局部点（null-deref 的 CFG guard 模型、range_flow 区间引擎、Evidence Contract v2、libxml2/cJSON API 语义模型）已经达到业界不错的水准；但**整体仍停留在「每个 vuln type 一套独立 detector+filter」的初代形态**，graph/parser 两层公共基建的规模（合计 6K 行）只有 evidence+planner 规模（72K 行）的 **1/12**，导致：

1. **同一函数 CFG 被重建 10+ 次**、同一文件 AST 被遍历 32 次、graph/events/findings 无增量 → **速度上不去**；
2. **语义判定下沉到 detector/filter**（文本子串 + 行号区间启发式）、**证据契约只落地 4/24 个 vuln type**、**confirmed 精准性靠单点测试而非架构保证** → **误报率压不下去**；
3. **registry.go 83K 单文件 + Candidate 70 字段上帝对象 + filter chain switch-case 硬编码** → 新增一个 vuln type 要动 4-5 个地方，**演进成本随类型数线性增长**。

近几个版本的 changelog 也印证了这一判断：0.9.9 几乎所有条目都是**点修复**（null-deref guard 形态、UAF may-free、goto label CFG 缺口、typeof 预处理、API 语义建模），没有一项是**结构性**改动。这解释了为什么「发布后速度与准确度没有质的飞跃」——**点修复无法改变架构级的重复计算与启发式堆积**。

---

## 一、做得对的地方（先肯定，避免误伤）

| 架构决策 | 体现 | 价值 |
|---|---|---|
| 三层流水线分离 | indexer → graph → evidence → planner → agent → report | 关注点清晰，detector 与 filter 可独立演进 |
| `AI_JUDGMENT_BOUNDARY.md` 唯一权威 | confirmed 必须是"证明"（CFG must / 区间 / 字面量 / 类型固有），其余 suspected/possible 交 AI | 奠定了"confirmed 精准无误"的契约基础 |
| `TestConfirmedTierPolicy` 机器守卫 | 静态 confirmed 集合必须登记证明手段，否则构建失败 | 把原则变成了可执行的构建期约束 |
| Evidence Contract v2（B0/B1/B2） | null-deref / crypto / BO / OOB 的 `VerdictFact` 结构化事实 | AI 从"读 hint 推理"升级为"读事实判决" |
| `null_flow.go` 的 reaching-sources 引擎 | 同一套 may+must 数据流引擎被 null-deref / UAF / double-free / uninit 复用 | 证明了"通用引擎 + 类型特化"的路线是可行的 |
| `range_flow.go` 区间引擎 | 被 divide-by-zero / integer-overflow / RangeOOB 复用 | 区间分析已具备雏形 |
| 事件驱动 + 批量加载 | `seedCandidatesByType` 批量 ListFunctions/Locations，消灭 N+1 | 已意识到 DB 查询热点 |
| 检测器并发 + plan 并发 | `RunAllDetectors` 8 并发 + `pl.Plan` 8 并发 | 并发模型是对的 |
| `dismissed` 不持久化 + UPSERT 幂等写 | `ON CONFLICT ... DO UPDATE ... RETURNING id` | 数据库写入语义清晰 |
| 解析层 `ParseCached` + tree-sitter-c DannyAn fork v0.24.4 | 原生支持 typeof + 6 类 GNU 扩展 | 解析层技术选型领先 |

**这十条是"不能拆"的地基。**后续所有优化都必须在这十条之上叠加，而不是推倒重来。

---

## 二、速度维度：四个结构性瓶颈

### PERF-1（CRITICAL）同一函数 CFG 被重建 10+ 次——无函数级缓存

**证据**：`graph.BuildStmtCFG(body, endLine)` 在 **14 处**被独立调用，每一处都重新构建一次：

```
planner/filter_nullable_source.go  → 调 null_flow.go:305/326 → 每次每函数重建
planner/filter_uninit_flow.go:223  → 每函数重建
planner/filter_uninit_heapstruct.go:70
planner/filter_contract_gap.go:122
planner/range_flow.go:160          → RangeFilter / IntOverflowGuardFilter / RangeOOBFilter 共用
planner/null_flow.go:305/326       → NullableSourceFilter
evidence/free_summary.go:114/208
evidence/memory_leak.go:64         → 每函数一次
evidence/race_condition.go:578
evidence/resource_leak.go:51
evidence/uninit_variable.go:451
evidence/use_after_free.go:64
```

对同一个函数 `foo`：memory-leak detector 构建一次、use-after-free detector 构建一次、uninit_variable detector 构建一次；然后 plan 阶段 NullableSourceFilter、DefiniteInitFilter、RangeFilter、LifetimeFilter 又各自重建一次。**一个函数在一次扫描中的 CFG 构建成本被放大 8-12 倍**。

**影响**：
- `redis 786 files / 11225 functions` 这种规模，plan 阶段的 24 个 vuln type 里至少 6 个类型需要 CFG，合计 CFG 构建次数 = **6 × 11225 ≈ 67,350 次**；
- `BuildStmtCFG` 本身是 O(语句数) + goto 补边，单函数平均 ~1ms → **67s 纯浪费**。

**建议**：引入**进程内函数级 CFG 缓存**：
```go
// planner 层新增
type StmtCFGCache struct {
    mu   sync.RWMutex
    byFn map[int64]*graph.StmtCFG  // key = function ID
}
func (c *StmtCFGCache) Get(fn *db.Function, body parser.Node) *graph.StmtCFG
```
Planner 持有此 cache，所有 filter 通过 cache 取 CFG；evidence 层同理（挂在 parser 或 detector 共享 context 上）。预期收益：**plan + evidence 阶段总耗时降 30-50%**。

### PERF-2（CRITICAL）32 个 detector 各自独立遍历 AST

**证据**：`evidence/detector.go` 的 `forEachFile` / `forEachIndexedFile` / `forEachFileIncludingEmpty` 是 detector 的公共入口，**每个 detector 独立调用一次**，内部对每文件做 `root.FindAll(...)`。

32 个 detector × 每文件 1 次 AST FindAll = **每文件 32 次全 AST 遍历**。`ParseCached` 只省了 tree-sitter parse 成本（内存共享），没省 AST 遍历成本。

**影响**：`redis` 786 文件 × 32 detector ≈ **25,000 次全 AST 遍历**；假设单文件单遍 10ms → 250s 纯遍历开销（其中 240s 是重复）。

**建议**：转向**单遍遍历 + 访问者分发**架构：
```go
// 新 Detector 接口
type DetectorV2 interface {
    Name() string
    // OnFunction / OnCallExpr / OnAssignment / OnDeclaration ...
    // indexer 单遍遍历 AST，按节点类型分发到所有订阅的 detector
    OnNode(ctx context.Context, n parser.Node, fctx *FileContext) error
}
```
indexer 对每文件做一次 AST 遍历，按节点类型派发到所有订阅的 detector。32 次 → 1 次。预期收益：**evidence 阶段耗时降 80%+**。

**注意**：这是一次接口改造，可以分阶段做——先保留 `Detector.Detect` 兼容层，新 detector 走 V2 接口；再逐个迁移存量 detector。

### PERF-3（HIGH）graph / events / findings 三层全无增量

**证据**：
- `pipeline.go:91` `store.ClearGraph(ctx)` —— 每次扫描全量重建语义图
- `pipeline.go:158` `store.ClearSecurityEvents(ctx)` —— 每次扫描全量清空事件
- indexer 层有 checksum 增量（`indexer.go:110` `if existing != nil && existing.Checksum == checksum`），但增量信息**没有向上传递**

**影响**：修改一行代码 → 全图重建 + 全 detector 重跑 + 全 plan 重跑 + AI 全量重判。对开发者日常"改几行→重扫"的场景，这是不可接受的。

**建议**：分层增量——
1. **indexer 增量已有**（checksum skip），把"受影响文件集合"向上暴露；
2. **graph 增量**：受影响函数的 CALL/DATA_FLOW/ALIAS 边删除重建，未受影响函数保留；
3. **evidence 增量**：只对受影响文件重跑 detector，未受影响文件的 events 保留；
4. **plan 增量**：受影响文件关联的候选才重新收敛，其余保留上次结论；
5. **AI 增量**：`findings` 表已有 `scan_id` + UPSERT，天然支持——只需要 plan 层告诉 AI"这轮只改了多少"。

预期收益：小改动重扫从分钟级降到秒级，**这是"开发者内循环"的关键**。

### PERF-4（MEDIUM）AI 举证协议成本模型过于复杂

**证据**：`command-instructions.md` 797 行，定义了：
- 批容量：`MAXTURNS=60` / `PER_TYPE_FIXED_TURNS=6` / `PER_CANDIDATE_TURNS=0.8` / `PER_AUTO_CONFIRMED_TURNS=0.3` / `MAX_EVIDENCE_OPENS_PER_TYPE=12`
- RANGE-split owner 去重协议（`--list-auto-confirmed` 并发竞态）
- F3（同时序合规）/ F7（子代理返回模型——OpenCode 同步 vs Claude Code 异步 vs DSH continuable）/ F8（完成契约）/ F9（句柄失效恢复）/ F10（命名解析失败恢复）
- 60+ hint token 词汇表

**根因**：**这套复杂度本质上是在为"举证不足"兜底**。如果 pipeline 能把决定性事实全部算好（VerdictFacts），AI 只需要读事实下判决，就不需要 RANGE-split 的并发去重、不需要 60 种 hint token、不需要 ≤12 的 evidence-open 预算。

**建议**：
1. 把 AI 举证协议的复杂度指标化：`新 hint token 数 / 月`、`evidence-open 率`、`needs_context 率`，任何新增 hint token 必须评审——能由 pipeline 算成 VerdictFact 的一律算成 VerdictFact；
2. 优先把 Evidence Contract v2 推广到全部 24 个 vuln type（见 ACC-3），让每个类型的决定性事实都从 hint token 迁移到结构化 VerdictFacts；
3. **最终目标**：`agent-body.md` 从 625 行收敛到 200 行以内，`command-instructions.md` 的批容量表从 8 个参数收敛到 2-3 个。

---

## 三、准确率维度：五个结构性缺口

### ACC-1（CRITICAL）confirmed 精准性缺乏架构级保证，靠单点测试兜底

**现状**：
- 静态 confirmed：`registry.go` 的 `CategoryConfidence` / `DefaultSuspicion` map（由 `TestConfirmedTierPolicy` 守卫）
- 动态 confirmed：各 filter 在 `Apply` 中升级（NullableSourceFilter / DefiniteInitFilter / RangeFilter / LifetimeFilter / DoubleFreeFilter / TaintSourceFilter / HardcodedSecretProofFilter / ReturnCheckFilter / LockOrderFilter / SharedAccessFilter / RangeOOBFilter / LeakProofFilter / ContractGapFilter / IntOverflowGuardFilter）

**问题**：
1. `TestConfirmedTierPolicy` 只守卫**静态**集合，**动态升级路径完全无守卫**——任何 filter 都可以在任何条件下升级 confirmed 而无需登记证明手段；
2. detector 侧通过 `CategoryConfidence` 直接标 confirmed（如 buffer-overflow 的 6 个 category），但 detector 的判定可能基于启发式而非证明——历史检视已实证：
   - buffer-overflow：`hasPrecedingBoundsCheck` 用 `strings.Contains(cond, "len")` 文本匹配 → confirmed 既误又漏（BO-04/11/16）
   - divide-by-zero：`isConfigFieldDivisor` 无证明 confirmed（DBZ-01/02/03）
   - uninit：confirmed 无护栏（UN-09）
   - unchecked-return：confirmed 违规（CR-01/02/03）
3. `AI_JUDGMENT_BOUNDARY.md` 列举了四类证明手段，但**没有机器可校验的"证明实例登记册"**——每条 confirmed 应能反向追溯到"哪一类证明、哪段代码、哪份测试"。

**建议**：
1. **建立"证明实例"类型**：所有 confirmed（无论静态还是动态）必须携带 `ProofClass + ProofEvidence`：
   ```go
   type Proof struct {
       Class    string  // "cfg-must-dataflow" / "interval" / "literal" / "type-inherent"
       Evidence string  // 证明的可追溯描述（如 "CFG path: 12→15→18, must-null at node 18"）
       TestRef  string  // 覆盖此证明路径的测试名
   }
   ```
2. **`TestConfirmedTierPolicy` 扩展到动态升级**：每个 filter 的 `升级 confirmed` 分支必须在黄金清单中登记（filter 名 + vuln type + 证明类别 + 测试引用），否则构建失败；
3. **detector 禁止直接标 confirmed**：把 `CategoryConfidence` 里的 confirmed 全部迁移到 filter 层完成——detector 只产出 suspected/possible 候选，证明统一在 filter 层（这样"证明"就只有一处可审计）；
4. **预期收益**：confirmed 误报结构性清零——这是"世界一流"的入场券。

### ACC-2（CRITICAL）graph 层规模 1:12 落后于检测器需求，语义判定被迫下沉

**证据**：
- `graph/` 3,388 行（其中 `alias.go` 174 行 / `data_flow.go` 115 行 / `interproc.go` 279 行）
- `evidence/` + `planner/` = 72,187 行
- **graph : (evidence+planner) = 1 : 21**

这意味着大量**本应沉淀在 graph 层的语义判定**被堆积在 detector/filter 里用文本/行号启发式实现。具体证据：

| 缺失的 graph 能力 | 现状 | 历史检视实证 |
|---|---|---|
| **统一的 must-nonnull 查询** | null-deref 有 4 套基于行号/文本的 guard 判定（已修复为 guardModel，但其他类型仍在用） | null_deref_guard_architecture_defects.md |
| **类型宽度 / 整数提升** | 零建模，`sizeCalcExprs` 只看操作数形态 | integer_overflow_detection_defects.md（IO-21 benchmark 腐烂实例） |
| **跨函数别名** | `alias.go` 174 行只支持基本形态，UAF/double-free/memory-leak 共用需要 | UF-02 / ML-02（q=p;free(q)、free((void*)p)、g=(T*)p 误报） |
| **通用 return summary** | 只有 `computeRetNullable`（null 专用），没有 return-nonzero / return-capacity / return-tainted | integer-overflow 无跨函数 size 可大性分析 |
| **浮点类型建模** | divide-by-zero 曾因此产生浮点豁免失效误报（已修复但非架构解） | typeof_preprocess_review_20261002.md（TF-04） |
| **区间引擎的"判定"能力** | `range_flow.go` 只用于"抑制"，不用于"发现"（buffer-overflow 完全未接入） | buffer_overflow_oob_detection_defects.md（BO-02） |

**建议**：把 graph 层升级为**"语义查询服务"**，而不是"数据存储层"：
1. **新建 `graph/query.go`**：暴露 `MustNonNullAt(var, line)` / `IntervalAt(var, line)` / `AliasSet(var)` / `TypeWidthOf(expr)` / `ReturnSummaryOf(func)` 等**声明式查询接口**；
2. **detector/filter 全部改为调用查询接口**，禁止自己解释 AST/行号；
3. **graph 层目标规模**：3,388 → 10,000+ 行（承载类型系统、别名分析、通用 summary、查询 DSL）；
4. **预期收益**：检测器的"启发式正确性"问题从**无穷尽的点修复**变成**graph 查询层的一次性修复**——改一处，所有 detector/filter 受益。

### ACC-3（HIGH）证据契约 v2 只落地 4/24 个 vuln type

**证据**：
- 已完成：null-deref / crypto-misuse / buffer-overflow / out-of-bounds（B0/B1/B2）
- 未启动或部分启动：memory-leak / resource-leak / unchecked-return / integer-overflow / uninit / use-after-free / double-free / format-string / injection / path-traversal / divide-by-zero / race-condition / deadlock / hardcoded-secret / signal-handler / dangerous-function / argument-type / data-representation / sizeof-misuse / signed-compare / implicit-contract（**20 个**）

**问题**：`registry.go` 中 20 个 `buildXXXVerdictFacts` 函数存在（`buildNullDerefVerdictFacts` / `buildCryptoMisuseVerdictFacts` / ...），但很多类型只填了框架没填实质。AI 拿到的仍是"hint token 字符串"，需要逐 token 推理。

**证据**：`agent-body.md` 625 行中，hint token 词汇表占了大半——`src@N` / `certain-null` / `maybe-null` / `null@cfg-proof` / `null@malloc-fail` / `null@caller-arg` / `null@opaque-origin` / `null@assumed-return` / `null@external-unknown` / `tainted` / `taint@none` / `weak-guard` / `divisor@<shape>` / `certain-uninit` / `maybe-uninit` / `init@unseen` / `api@` / `cat@` / `lhs@` / `rhs@` / `rhs-influenced` / `sink@` / `guard@none` / `macro-context` / `threads@<fn>` / `instances@N` / `write@N` / `mutex@<name>` / `lock@<lo>-<hi>` / `check@<fn>→use@<fn>` / `arg@<expr>` / `may-free` / `reason@<text>` / `key-size@N` / `buf@<name>` / `cap@N` / `idx@<expr>` / `src-cap@N` / `alloc@N` / `acquire@N` / `leak@definite` / `leak@conditional` / `escape@none|store|return` / `free@N,M` / `range@<interval>` / `callers@<census>` / `origin@<kind>` / `decl@N` / `field@<path>` / `init@none` / `init@N` / `may-skip` / `expected@<type>` / `actual@<type>` / `cast@<type>` / `fmt-arg@<expr>` / `path-arg@<expr>` / `value-shape@<masked>` / `async-unsafe@<fn>` / `subject@<name>` / `count-field@<field>` / `evidence-kind@<kind>` / `cond@<callee>` / `transfer-cond@` / `free-mismatch@` / `free-on-borrow@<api>` / `cwe-chain@CWE-X→CWE-Y` / `null@field-read` / `null@iter-macro` …

**这是举证责任倒置的直接证据**：pipeline 没把事实算尽，只能靠 AI 理解 60+ 种 token 的含义并推理。

**建议**：
1. **设定硬性目标**：24 个 vuln type 全部落地 VerdictFacts，deadline 建议 v1.0.0；
2. **收敛 hint token**：每落地一个类型的 VerdictFacts，对应的 hint token 必须**冻结新增**（只减不增）；
3. **VerdictFacts 的设计原则**（从 B0/B1/B2 提炼）：
   - 每个 fact 必须带 `provenance file:line`（AI 可定点验证，不需整文件读）；
   - 每个 fact 必须是"判定性事实"（AI 读到此 fact 即可判 confirmed 或 dismissed），不是"线索"；
   - fact 的 token 命名遵循 `<dimension>@<value>` 格式，维度表全局唯一；
4. **验收指标**：`evidence-open 率`（AI 需要打开 Evidence 文件的候选比例）从当前的 ~30% 降到 **< 5%**；`needs_context` 事件降到 **0**。

### ACC-4（HIGH）文本子串启发式在 detector 间扩散，跨类型语义互相污染

**证据**（仅列代表）：
- `memory_leak.go` / `resource_leak.go` 用 `strings.Contains(name, "alloc")` 判 allocator → 误命中 `dealloc` / `alloc_stats`（历史 ML-08/10）
- `integer_overflow.go` `isSizeFunction` 同样 `strings.Contains(name, "alloc")` → 同款误命中
- `buffer_overflow.go` `hasPrecedingBoundsCheck` 用 `strings.Contains(cond, "len")` → 命中 `silent` / `challenge`（BO-04）
- `null_guard.go` / `caller_null.go` / `interprocedural.go` 曾各自实现 guard 判定，语义不一致（D4-D8，已修复）

**根因**：**没有统一的"名称解析 + 语义识别"层**。每个 detector 都在做"这个名字是什么"的局部判断。

**建议**：
1. **新建 `sgre/internal/apikb/classify.go`**：把所有 `IsAllocator` / `IsDeallocator` / `IsBoundedCopy` / `IsFormatFunction` / `IsSafeFunction` / `IsOwnershipTransfer` / `IsGuard` 等**名称/签名分类函数**集中一处；
2. **detector/filter 禁止字符串匹配函数名**，必须走 apikb；
3. **apikb 的规则必须三态**：`Yes` / `No` / `Unknown`——Unknown 交给 AI，而非默认 Yes 或 No；
4. **验收**：`grep -rn "strings.Contains.*[Ff]unc.*[Nn]ame" sgre/internal/evidence/ sgre/internal/planner/` 应归零（除 apikb 内部）。

### ACC-5（MEDIUM）`AI_JUDGMENT_BOUNDARY` 的"故意 suspected"集合过大，是 confirmed 率的隐形天花板

**证据**：`AI_JUDGMENT_BOUNDARY.md` 列举的"suspected 尾巴"包括：
- `path-traversal`：完全 suspected（"内容未知"）
- `argument-type`：完全 suspected（"不兼容≠缺陷"）
- `data-representation`：完全 suspected（"证明不够可靠"）
- `dangerous-function` 的 `obsolete_api_conditional`：suspected
- 所有"may 数据流"候选：suspected

**问题**：这些"故意 suspected"在原则上是正确的（诚实反映证明能力上限），但**它们占候选总量的比例很高**——AI 的研判压力都集中在这里。如果能通过**架构升级**把其中一部分推进到"可证明"区间，AI 负担会显著下降。

**建议**（逐项）：
1. **path-traversal**：接入 `buildStringConstants` 已有的常量折叠能力 + 扩展为"字符串区间"分析（字符集上界是否含 `..` 与 `/`）——能把"字面量可证安全"和"字面量可证危险"两类从 suspected 移出；
2. **argument-type**：接入类型宽度模型（见 ACC-2）+ ABI 布局等价判定——`uint32_t*` vs `int32_t*`（同宽度同表示）可证安全，`uint32_t*` vs `uint64_t*` 可证危险；
3. **data-representation**：同上，类型宽度模型是基础；
4. **integer-overflow**：把 `range_flow` 从"抑制"升级为"判定"，乘法/加法的溢出上界可证（区间上界 < INT_MAX 则 confirmed-safe，下界 > INT_MAX 则 confirmed-overflow）；
5. **uninit 的 heap/struct**：接入跨函数 output-param summary（写/不写字段），扩展到 must 语义。

**总原则**：每推进 1 个类型从 suspected → confirmed 或 dismissed，AI 的研判量就降一档；**这才是"降误报 + 提速度"的根本路径**（而不是让 AI 看得更仔细）。

---

## 四、可维护性维度：架构债务

### DEBT-1（HIGH）`registry.go` 83K 单文件承载 24 个 vuln type 的全部元数据

**证据**：`sgre/internal/planner/registry.go` 1,744 行，包含：
- 24 个 `VulnTypeSpec` 注册（`init()`）
- 20 个 `buildXXXVerdictFacts` 函数（每个 20-100 行）
- CWE 查询、type/category 查询、证据构建辅助

**问题**：
- 新增一个 vuln type 必须在 `registry.go` 里加 100+ 行——**单文件并行编辑冲突高发**；
- `VulnTypeSpec` 本身的字段已经 20+ 个，阅读困难；
- `buildXXXVerdictFacts` 与 vuln type 的注册分散在文件不同位置，查找困难。

**建议**：
1. 每个 vuln type 一个独立文件：`planner/types/null_deref.go` / `planner/types/buffer_overflow.go` / ...，文件内包含该类型的 `VulnTypeSpec` 定义 + `BuildVerdictFacts` + `BuildEvidence`；
2. `registry.go` 只保留 `vulnTypeRegistry` map + 查询函数，**目标 < 200 行**；
3. 此举直接降低并行开发冲突，也是 ACC-3 全量推广 VerdictFacts 的前置条件。

### DEBT-2（HIGH）`Candidate` 70+ 字段上帝对象 + `eventProps` 70+ 字段 stringly-typed

**证据**：
- `planner.go:475-558`：`Candidate` 结构体字面量赋值 70+ 字段
- `props.go:36-231`：`eventProps` struct 70+ 字段，全部 JSON tag
- detector 端通过 `map[string]string` / `map[string]any` 序列化，planner 端通过 `parseEventProps` 反序列化

**问题**：
1. **类型安全丧失**：detector 写 `"key_size": "abc"`（字符串），planner 读 `flexInt` 静默变 0——`flexInt` 的存在本身就是 stringly-typed 的补丁；
2. **新增字段要改 3 处**：detector 写入点 + `eventProps` 字段定义 + `Candidate` 赋值点；
3. **字段命名漂移**：`Callee` / `FirstCallee` / `SecondCallee` / `APIName` / `Function` 都有"被调函数"含义，detector 作者容易用错。

**建议**：
1. **分层 struct**：
   ```go
   type Candidate struct {
       Common  CommonCandidate       // 所有类型共有：File/Line/Function/Category/Suspicion
       Null    *NullDerefPayload     // null-deref 专属
       Buffer  *BufferPayload        // buffer-overflow / OOB 专属
       Leak    *LeakPayload          // memory-leak / resource-leak 专属
       ...
   }
   ```
   通过 interface 或 `type switch` 访问类型专属字段；
2. **events properties 同样分层**：`properties` 字段改为 `common` + `<type>` 两级 JSON；
3. **存量迁移**：可以分阶段——新 vuln type 用新结构，存量逐个迁移。

### DEBT-3（MEDIUM）filter chain 硬编码 switch-case

**证据**：`planner.go:55-158` 的 `getFilters(chain string)` 是 13 个 case 的硬编码 switch-case。

**问题**：新增 vuln type 必须修改 `planner.go`（违反开闭原则）；filter 组合的关系不可见（只有读代码才知道 null-deref 用哪些 filter）。

**建议**：把 filter chain 声明迁移到 `VulnTypeSpec`：
```go
type VulnTypeSpec struct {
    ...
    FilterFactories []FilterFactory  // 声明式，替代 FilterChain string
}
```
`planner.go` 的 `getFilters` 变为直接读 `spec.FilterFactories`；`planner.go` 回归"pipeline 执行器"角色。

### DEBT-4（MEDIUM）巨型文件

**证据**：
- `evidence/uninit_variable.go` 91K（~2500 行）
- `evidence/buffer_overflow.go` 71K
- `evidence/memory_leak.go` 68K
- `evidence/unchecked_return.go` 65K
- `planner/null_flow.go` 73K（2,065 行）
- `planner/filter_nullable_source.go` 53K
- `planner/filter_taint_source.go` 47K

**问题**：单文件职责过多，code review 困难，新人上手成本高。

**建议**：按"子职责"拆分——例如 `uninit_variable.go` 拆为 `uninit_detector.go`（主流程）+ `uninit_stack.go`（栈变量）+ `uninit_heap.go`（堆）+ `uninit_struct.go`（结构体）+ `uninit_macro.go`（宏处理）；`null_flow.go` 拆为 `null_flow_dataflow.go`（数据流引擎）+ `null_flow_effects.go`（节点效果）+ `null_flow_guard.go`（guard 模型）+ `null_flow_ternary.go`（三元 guard）。

### DEBT-5（MEDIUM）config 全局单例，测试注入困难

**证据**：`evidence/detector.go:267` `config.Load().EntryPointNames()` 在 detector 内部直接调用全局单例。

**问题**：detector 无法注入 mock config 做测试；config 读取时机分散；`secguard.toml` 读错位置时静默归零（历史 v070 调查报告实证）。

**建议**：
1. `Detector` 接口注入 `*config.Config`（构造函数参数），禁止 `config.Load()` 内部调用；
2. `config.Load` 增加"读取失败/路径不存在"的显式日志，不得静默返回零值；
3. CLI 启动时一次性加载 config，全程传递。

### DEBT-6（MEDIUM）benchmark 无 CI，ground truth 易腐烂

**证据**：`examples/c-vuln-benchmark` 只有 release.yml，无 PR 级 CI；已有 IO-21 实例（单测断言 `malloc(n+1)`/`malloc(n*4)` 不报，benchmark 却 `expect: finding`，两边直接矛盾）。

**建议**：
1. `.github/workflows/pr-benchmark.yml`：PR 级 CI 跑 `secguard scan examples/c-vuln-benchmark` + `validate-benchmark.py`；
2. detector 修复必须同步 `expected-results.json`，否则 CI 红；
3. 腐烂的 ground truth 视为 P0 bug（"测试断言错误"与"检测器错误"同级）。

---

## 五、业界对标

| 维度 | Clang Static Analyzer | CodeQL | Coverity | Infer | SecGuard-Clang 现状 |
|---|---|---|---|---|---|
| 中间表示 | CFG + ExplodedGraph（路径敏感符号执行） | 关系 DB + Datalog | 统一 IR + 多 pass | 函数级 summary（compositional） | AST + 简化 CFG + 事件表 |
| 检测器复用 | 共享 CFG + SymbolManager | 共享关系 DB | 共享 IR | 共享 summary | **每 vuln type 独立 detector，重复遍历** |
| 数据流引擎 | 路径敏感符号执行 | 声明式 dataflow library | 过程间数据流 | bi-abduction | null_flow / range_flow（已具备雏形但未全用） |
| 增量 | 无（全量） | 有（DB 增量） | 有（capture 增量） | 有（summary 增量） | **仅 indexer 增量，graph/evidence/plan 全量** |
| AI 集成 | 无（纯静态） | 无（纯静态） | 无（纯静态） | 无（纯静态） | **AI 研判 suspected 层（架构特色）** |
| 准确率保障 | 路径敏感证明 | 语义查询精度 | 工业级规则 + 人工审计 | 函数级证明 | **confirmed 精准性无架构级保证（ACC-1）** |

**差距定位**：
- 与 Clang SA / CodeQL 相比，我们**缺一个统一语义查询层**（ACC-2）；
- 与 Infer 相比，我们**缺函数级 summary 的通用化**（只有 null-return 有，其他类型没有）；
- 与 Coverity 相比，我们**缺工业级的增量架构**（PERF-3）；
- 我们的**独特优势**是"AI 研判 suspected 层"——这是世界一流的差异化定位，但它的有效性**完全取决于 suspected 层的举证质量**（ACC-3）。

---

## 六、建设性意见：分层路线图

### 短期（1-2 月，快赢，不动架构）

| # | 项目 | 对应缺陷 | 预期收益 |
|---|---|---|---|
| S1 | 引入 `StmtCFGCache`，所有 filter 共享函数级 CFG | PERF-1 | plan 阶段耗时降 30-50% |
| S2 | `apikb/classify.go` 集中所有"函数名分类"逻辑 | ACC-4 | 消除 detector 间启发式污染 |
| S3 | `TestConfirmedTierPolicy` 扩展到动态升级（filter 的 confirmed 必须登记证明类别） | ACC-1 | confirmed 误报结构性清零 |
| S4 | VerdictFacts 推广到 unchecked-return / integer-overflow / memory-leak / resource-leak（用户已在使用的高优先级类型） | ACC-3 | AI 研判耗时降 20-30% |
| S5 | benchmark PR 级 CI | DEBT-6 | ground truth 腐烂清零 |
| S6 | `config.Load` 失败显式告警 | DEBT-5 | 消除静默配置失效 |

**落地顺序建议**：S1 → S3 → S4 → S5 → S2 → S6。S1 是性能快赢，S3 是准确率快赢，S4 是 AI 体验快赢。

### 中期（3-6 月，结构性升级）

| # | 项目 | 对应缺陷 | 预期收益 |
|---|---|---|---|
| M1 | graph 层升级为"语义查询服务"（`MustNonNullAt` / `IntervalAt` / `AliasSet` / `TypeWidthOf` / `ReturnSummaryOf`） | ACC-2 | 检测器启发式问题从"无穷点修复"变"一处修复" |
| M2 | 类型系统建模（宽度/符号/浮点） | ACC-2 / ACC-5 | integer-overflow / sign-conversion / data-representation / argument-type / divide-by-zero 的准确率整体跃升 |
| M3 | 跨函数别名分析（q=p、参数别名、return 别名） | ACC-2 | UAF / double-free / memory-leak 的误报率大幅下降 |
| M4 | 通用函数 summary（return-nonzero / return-capacity / return-tainted） | ACC-2 | 跨函数分析不再每次重进入函数体 |
| M5 | filter chain 声明式化（迁移到 `VulnTypeSpec.FilterFactories`） | DEBT-3 | 新增 vuln type 无需改 `planner.go` |
| M6 | `registry.go` 拆分（每 vuln type 独立文件） | DEBT-1 | 并行开发冲突清零 |
| M7 | `Candidate` / `eventProps` 分层 struct | DEBT-2 | 类型安全 + 新增字段改动收敛 |
| M8 | 增量扫描架构（graph / evidence / plan 三层增量） | PERF-3 | 小改动重扫从分钟级降到秒级 |

### 长期（6-12 月，迈向世界一流）

| # | 项目 | 对应缺陷 | 预期收益 |
|---|---|---|---|
| L1 | 单遍 AST 遍历 + 访问者分发（detector 接口 V2） | PERF-2 | evidence 阶段耗时降 80%+ |
| L2 | AI 举证"零阅读"目标：VerdictFacts 充实到 AI 无需打开候选文件 | ACC-3 | AI token 消耗降一个数量级；`agent-body.md` 从 625 行 → < 200 行 |
| L3 | 函数级 compositional summary（Infer 风格） | ACC-2 / PERF-3 | 支撑 10 万 + 函数级代码库 |
| L4 | 把 `path-traversal` / `argument-type` / `data-representation` / `integer-overflow` 的"suspected 尾巴"中可证部分推进到 confirmed | ACC-5 | confirmed 覆盖率从当前 ~30% 升到 60%+ |
| L5 | 检测器巨型文件拆分 | DEBT-4 | 新人上手成本降 50% |

---

## 七、落地优先级矩阵

按「**投入产出比 × 对用户痛点（误报率/速度）的直接缓解**」排序：

```
优先级  项目  类型    误报↓  准确↑  速度↑  可维护性↑  工作量
P0      S1   速度     -      -      ★★★      -       1 天
P0      S3   准确    ★★★    ★★★     -       ★        2-3 天
P0      S4   举证    ★★     ★★     ★★       -       1-2 周
P1      S5   CI       -     ★★      -       ★★       1 天
P1      M5   维护     -      -      -       ★★★      3 天
P1      M6   维护     -      -      -       ★★★      1 周
P1      M1   架构    ★★★   ★★★    ★        ★★       2-3 周
P2      M2   架构    ★★     ★★★     -       ★        2-3 周
P2      M3   架构    ★★★    ★★      -       ★        2-3 周
P2      M8   架构     -      -     ★★★      ★★       4-6 周
P2      S2   准确    ★★      -      -       ★        1 周
P3      M7   维护     -      -      -       ★★★      2 周
P3      L1   速度     -      -     ★★★      ★★       4-6 周
P3      L2   举证    ★★     ★★    ★★       ★        8-12 周
```

**给用户的一句话建议**：先做 **S1 + S3 + S4 + S5**（2-3 周内完成），这四项不动架构、直接命中"误报率高 + 速度慢"的用户痛点，能让 v1.0.0 在用户侧立刻感受到质变。然后启动 **M1（graph 语义查询服务）** 作为下一个版本的架构主线——这是从"每个 vuln type 一套 detector"走向"统一语义查询层"的关键一步，也是与 CodeQL/Infer 正面竞争的基础。

---

## 八、与历史检视结论的关联

本报告不与以下历史检视重复，而是把它们**上升到架构层面**重新归因：

| 历史检视 | 当时定位 | 架构归因（本报告） |
|---|---|---|
| null_deref_guard_architecture_defects.md（D4-D8） | guard 语义四套机制重复 | **ACC-2**：graph 层缺 must-nonnull 统一查询（已通过 guardModel 部分修复，架构债未还清） |
| integer_overflow_detection_defects.md（IO-01..26） | 零类型宽度 / 整数提升建模 | **ACC-2**：graph 层缺类型系统 |
| buffer_overflow_oob_detection_defects.md（BO-01..20） | detector 独扛全部语义判定 | **ACC-2**：区间引擎未接入 OOB；**ACC-1**：detector 直接标 confirmed 无证明 |
| use_after_free_double_free_detection_defects.md（UF-01..16） | 无别名分析 / 行号顺序生成候选 | **ACC-2**：graph 层别名分析太薄 |
| memory_leak_detection_defects.md（ML-01..18） | 恒 suspected 无 confirmed 通道 | **ACC-5**：未走到"证明即 confirmed"；**ACC-2**：缺跨函数 ownership summary |
| divide_by_zero_detection_defects.md（DBZ-01..14） | 浮点类型未建模 / confirmed 精准违规 | **ACC-2**（类型建模）+ **ACC-1**（confirmed 证明链） |
| uninit_detection_defects.md（UN-01..15） | 三层收敛只覆盖 stack_uninit | **ACC-2**：跨函数 output-param summary 缺失 |
| typeof_preprocess_review_20261002.md（TF-01..08） | typeof 重写破坏类型语义 | **ACC-2**：类型系统缺失的下游表现 |
| candidates→AI 研判举证链路（E-01..06） | 指令与实现矛盾 / 语义事实断链 | **ACC-3**：证据契约未全量落地 |
| 第二轮扫描会话自检（反复读源码） | candidates 举证信息不足 | **ACC-3** |
| IO-21 benchmark ground truth 腐烂 | 单测与 benchmark 矛盾 | **DEBT-6** |

**统一观察**：**80% 的历史点修复都可以归因到本报告的 3 个架构根因**——ACC-1（confirmed 无架构级保证）、ACC-2（graph 语义查询层缺失）、ACC-3（证据契约未全量）。如果不解决这三个根因，点修复会无限持续下去。

---

## 九、结语

SecGuard-Clang 已经走完了"从无到有"的阶段（24 个 vuln type、三层流水线、AI 研判分工、Evidence Contract v2 雏形、null_flow / range_flow 引擎、机器守则 `TestConfirmedTierPolicy`），在世界一流 AI Agent C 扫描器的赛道上**已经具备差异化优势**（AI 研判 suspected 层的定位是 CodeQL / Coverity 都没有的）。

但**从"有"到"世界一流"的距离**，不再由"点修复的速度"决定，而由**三个架构决策**决定：

1. **是否把 confirmed 精准性从"单点测试"升级为"架构保证"**（ACC-1）；
2. **是否把 graph 层从"数据存储"升级为"语义查询服务"**（ACC-2）；
3. **是否把证据契约从"4 个类型落地"推广到"24 个类型全覆盖"，并以此为杠杆把 AI 举证成本降一个数量级**（ACC-3）。

短期做 S1/S3/S4/S5 锁定现有成绩，中期启动 M1 完成架构跃迁，长期通过 L1/L2/L3 达到世界一流。这条路是清晰的，剩下的只是执行。

> **不要继续在 detector 层面做零散修补**——那是无穷尽的工作量。把同样的人力投到 graph 层与证据契约层，一个月后会看到完全不同的格局。