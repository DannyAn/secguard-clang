# 四类跨过程程序语义 Gap：实际实施计划

> 对应 Issue #228。
> 配套分析：[four-semantic-gaps-analysis.md](four-semantic-gaps-analysis.md)；评审处理记录：[four-semantic-gaps-review-decisions.md](four-semantic-gaps-review-decisions.md)。
> 本文是 **Phase 0 交付物**：给出可评审的分阶段施工方案、文件级改动面、测试矩阵、证据完整性、验收门槛与度量方法。
> **本 PR 不包含生产代码改动**；实施按本文分阶段、分 PR 进行，每阶段完成后单独评审。
>
> **修订记录**：v2（2026-11-05）按 PR #229 评审 P0-1..P0-5 / P1-1..P1-3 修订；删除代码行数目标，增加 Evidence Completeness、unsupported/degradation、性能测量方法与 Return Contract/Layout provenance 要求。

- 基线：`main@7176ab2`（v0.12.2 + PR #227），2026-11-05。
- 前置验证：`go build -buildvcs=false ./...` 通过；`TestFeedbackWatchCapabilityMatrix` 通过。
- 施工顺序：**1038 → 1029 → 1031 → 1140 → 统一回归**（依赖关系见分析文档 §0.3）。
- **当前门禁（评审决定）**：本轮只修订文档；下一步只启动 **Phase 1（1038）**，Phase 1 通过独立评审后才启动 Phase 2，禁止同时施工四类 Gap。

---

## 1. 目标与非目标

### 1.1 目标

让 secguard-clang 获得四类**可复用**的跨过程程序理解能力：

1. 参数与对象容量的跨过程关联（1029）；
2. C/C++ 类型布局与对象边界（1038）；
3. 全局变量写入值的跨过程传播（1031）；
4. 输出参数的跨过程初始化覆盖（1140）。

### 1.2 非目标

- 不为四个样例写硬编码特判；
- 不新增漏洞类型 / 不新增 skill（四类复用现有 `out-of-bounds`、`buffer-overflow`、`null-deref`、`uninit`）；
- 不降低现有 `confirmed` 门槛来“通过测试”；
- 不删除/跳过/弱化原有回归测试；
- MVP 不新增 SQLite 表、不新增 `security_events` 事件类型、不新增 `graph_edges` 边类型；
- 不引入未测量的全局缓存；不跨扫描缓存新事实；
- **不以代码行数作为完成标准**；
- **本轮不修改生产代码、不启动 Phase 1 施工**（评审要求）；
- **不把 heuristic、默认 ABI 假设或不完整跨过程信息升级为 Confirmed**；
- **不把“计划支持”表述成“已经支持”**。

---

## 2. 交付拆分与评审检查点

| 阶段 | 交付 | 主要事实 | 最小必要范围（非行数目标） | 合入前关键条件 |
|---|---|---|---|---|
| Phase 0（本 PR） | 分析文档 + 实施计划 + 评审决策记录 | 无 | 文档修订；无生产代码 | 评审通过后才进入 Phase 1 |
| Phase 1 | 1038 Type Layout 基础层 | TypeLayout（TU/Config、provenance/confidence） | 布局算法 + per-TU 配置 + 检测集成 + 正反测试 | layout 来源可信；未知/assumed 不升级；证据完整性 |
| Phase 2 | 1029 调用点容量 + 关联 + guard | CallSiteBinding、BufferLengthAssoc、GuardWitness | 对象/容量绑定 + 完整 Guard Witness + 稳定性 | 对象/容量/index/guard 完整证据链；`must` 才 dismiss |
| Phase 3 | 1031 全局写入来源摘要 + null 集成 | GlobalWriteIndex（may-only） | writer/source/覆盖/未知源 + consumer 证据 | 不把 may-write 当 consumer 当前状态；不承诺 confirmed |
| Phase 4 | 1140 输出参数 | ReturnContract + 逐路径/字段级覆盖 | 返回契约 + 字段覆盖 + caller 消费 | 返回语义可信、路径/字段匹配；must-only |
| Phase 5 | 统一回归 + 性能 + 最终报告 | 无新事实 | 回归/基准/度量 | 证据完整性、TP/FP/FN、性能方法 |

每个 Phase 的 PR 必须包含以下内容（评审 P1-1）：

- 最小必要实现范围（不以代码行数为目标）；
- 事实模型与现有设施（repofacts / function_summary / CFG / callsite / AliasGraph）的复用说明；
- 必须通过的正反测试（含反例）；
- Evidence Completeness（分析 §3.4）；
- Precision/Recall 变化（基准不足时明确说明）；
- 扫描耗时、RSS 和必要的 Token 成本（无采集写“未测量”）；
- 本 Phase 明确不解决的问题（unsupported cases + 降级行为）。

每个 Phase 一个独立 PR，分支从最新 `main` 切出，PR 描述包含：

- 本阶段解决到什么程度；
- 新增/扩展的事实及证据链示例；
- 新增/修改的 category 与 tier 依据；
- 测试清单与实际运行结果；
- 性能对照（本阶段增量）；
- 明确未解决项（Remaining Gap）。

Phase 1-4 的 PR 不合并到同一个 PR；Phase 5 可以在最后一个功能 PR 内完成，也可以单独出 PR，由评审决定。

两个 Phase 允许按前置重构再拆：

- Phase 1a（宽度表/typedef 收敛，行为保持） + Phase 1b（Type Layout + 1038 检测）；
- Phase 4a（`buildFuncSummaries` scan-scoped 缓存，行为保持） + Phase 4b（per-return 覆盖 + 调用者消费）。

拆分的目的是让“纯重构”和“行为变更”分开评审；如果评审认为改动面可控，也可以合并。

---

## 3. 通用工程约束

### 3.1 事实生产时机

**检测器并发执行**（`evidence.RunAllDetectorsWithSkip`，`cli/pipeline.go:291`）。因此：

- Type Layout、CallSiteBinding、GlobalWriteIndex 统一在**检测器之前**构建；Type Layout 挂在一次 `repofacts.Build` 上，检测器/过滤器通过 ctx 共享；
- 构建位置：`cli/pipeline.go` 的 `ClearSecurityEvents` 之后、`RunAllDetectorsWithSkip` 之前，与 `AliasGraph` 相邻（`cli/pipeline.go:266`）；
- ctx 注入（`WithTypeLayout` / `WithCallSiteBinding` / `WithGlobalWriteIndex`），检测器与 planner filter 共享同一实例；
- 每次 scan 重建，不跨扫描缓存；
- pre-detector 阶段内部顺序：**per-TU `compile_commands` 配置** → `repofacts`（含按 TU/Config 隔离的 Type Layout）→ `CallSiteBinding`（消费 layout 的元素大小）→ `GlobalWriteIndex`（可复用 file_scope / AliasGraph）；
- Type Layout 的 key 必须包含 `TU`/`Config`；不能把同名类型在全局合并；
- 不在 `buildFuncSummaries`（被 3 个检测器各调用一次）里追加跨检测器事实；1140 的摘要扩展在 Phase 4 先把 `buildFuncSummaries` 缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 结果）。

### 3.2 持久化与失效

| 事实 | MVP 落点 | 失效方式 |
|---|---|---|
| Type Layout | `repofacts.Facts` 的内存扩展，按 `(TU, Config, Type)` 索引 | 每次 scan 重建；不落库 |
| CallSiteBinding | 扫描期 `CallSiteBindingIndex` | 每次 scan 重建；不落库 |
| GlobalWriteIndex | 扫描期内存索引 | 每次 scan 重建；不落库 |
| OutputParamSummary | `function_summary.summary_json`（扩展现有 key：`return_contract` / `outparam_return_coverage`） | function 变更时 indexer 删除 function，FK 级联删除 summary |
| GuardWitness | 不落库，filter 现算 | 无状态 |

如果评审要求持久化 Type Layout / GlobalWrite，必须先定义：

- 新表或 `summary_json` key 的 schema 迁移（additive migration）；
- 清空/重建语义（与 `ClearGraph` / `ClearSecurityEvents` 同级）；
- 旧数据兼容与回滚方案；
- 增量扫描的失效测试。

### 3.3 确认边界

- 只有满足 `AI_JUDGMENT_BOUNDARY.md` 的证明手段才允许 `confirmed`；
- 新增 `confirmed` category 必须同时更新：
  - `planner/registry_*.go` 的 `CategoryConfidence`；
  - `planner/zz_ai_judgment_boundary_test.go` 的 golden 清单；
  - `AI_JUDGMENT_BOUNDARY.md` 的证明类别；
  - 如果是 filter 内升级，还必须实现 `ProofRegistrar` 并登记到 `TestDynamicConfirmedUpgradesRegistered`；
- 所有新增事实在 `unknown` / `assumed` 时 fail-open：不确认，必要时 `suspected`；
- **must vs may**：`confirmed` 必须是 must 证明；may 证据只能 `suspected`/`AI_REQUIRED`；
- **Layout**：`assumed_default_abi` / `unknown` 禁止 confirmed；只有 `compiler_proven` / `derived_from_complete_config` 且证据完整才可讨论 confirmed（Phase 1 默认只 suspected，除非评审批准 proof class）；
- **Guard**：只有 `proof_status=must` 的结构化 Guard Witness 才能 dismiss；CFG 支配不是充分条件；
- **Global Write**：may-write 不得当作 Consumer 当前状态；Phase 3 不承诺 confirmed；
- **Output Param**：Return Contract 未知时不得 confirmed；写入覆盖必须到字段/子对象；
- **Evidence Completeness**：每个 Phase 的验收必须引用分析文档 §3.4 的证据表；证据不完整不得 confirmed；
- 任何“为了通过测试”而降低门槛的改动，必须在评审中拒绝。

### 3.4 Evidence Completeness 与 AI 消费

统一证据表在分析文档 §3.4。本计划要求每个 Phase 的验收表引用该表，并至少检查：

| Gap | 合入前必须能展示的证据 |
|---|---|
| 1029 | 访问位置、调用点、实际对象绑定、字节容量来源、元素大小/容量、index 表达式、Guard 谓词/分支/稳定性/alias/副作用 |
| 1038 | 分配大小、目标类型、TU/Config、layout provenance/confidence、字段偏移/大小、访问起止、整数计算可信度 |
| 1031 | 所有已知 writer、NULL 来源、调用上下文/顺序、覆盖、未知 writer/escape/并发、Consumer 读取位置 |
| 1140 | 每条 return path、Return Contract 来源、参数/字段/子对象覆盖、caller 分支、分支与契约对应、实际消费字段 |

新增候选还必须能回答：

- 漏洞位置（file:line + function）；
- 相关函数源码（`## Callee Definition` 已有）；
- 参数绑定关系（caller arg → callee param）；
- 调用点上下文（call site file:line + 容量来源）；
- 关键数据流（buffer → length → index）；
- CFG 分支条件 / guard witness；
- 不确定性来源（未知 ABI/配置 / 未知容量 / 未解析调用点 / 多 writer / 并发 / 未知返回契约）。

落点：

- `planner/registry_*.go` 的 `BuildEvidence`；
- `planner/hint_tokens.go` 新增 token（必须登记）；
- `planner/evidence_package.go` 的新 section（如有）；
- `extension/shared/agent-body.md` 的研判纪律（仅当新增 token/section 影响 AI 判断时）。

**provenance 规则**：每项关键事实必须标注来源（source / compile-config / repofacts / cfg / contract / heuristic）；heuristic 与 compiler-proven fact 不能混写；不能仅凭函数名、变量名、注释或模式相似度升级 Confirmed。

### 3.5 去重与体量

- 1029：同一 `(callee, access line, capacity)` 一个候选；多个调用点作为 `Clustered Sites` / `callers@` evidence；
- 1031：同一 `(consumer function, global)` 一个候选；writers 列表作为 evidence；
- 1140：同一 `(caller function, variable/outparam)` 一个候选；多个 callee/path 折叠；
- 复用 `ShapeKey` / `clusterShapeCandidates` 的既有折叠机制，不新增一套 dedup；
- 每阶段在 benchmark 上统计候选增量；如果某类型候选 > 基线 +20%，先做体量分析，再决定是否收窄播种条件。

### 3.6 性能测量与预算（评审 P1-2）

性能门槛是初始预算，不是牺牲准确率的理由。测量必须满足：

1. 同一机器、同一代码数据集、同一编译参数和扫描参数；
2. 基线与新版本采用相同运行环境；
3. 至少多次运行，报告中位数，必要时报告 P90；
4. 区分冷启动、热缓存和增量扫描；
5. 同时报告 wall time、peak RSS、扫描文件数/函数数和事实数量；
6. 如果 Token 成本没有可靠采集，明确写“未测量”，不要估算或声称无影响。

暂定预算（评审可调整）：

- 单阶段新增扫描时间 ≤ +10%（相对同 corpus 的基线）；
- 峰值 RSS ≤ +50 MB（或 ≤ +5%，以较大者为准）；
- 新增全树遍历必须复用已有 parse / RepoIndex / cfgCache，不能每个候选重新读文件；
- 超过预算的阶段必须给出 profile 与优化方案，或拆分/回退；**不能为满足预算而降低检测准确率**。

---

## 4. Phase 1：CWD-SUB-1038 Type Layout（基础层）

### 4.1 前置重构（必须先做）

1. **收敛宽度表**：把 `evidence/typedefs.widthOf`（LP64 位宽）与 `graph/types_width.lp64Widths`（第二张表）收敛到单一共享实现；
   - 推荐新包 `internal/typeinfo`（或 `repofacts` 子文件）；
   - `typedefs.widthOf` / `graph.TypeByName` 改为委托；
   - 行为保持：现有单测必须全绿，不改变既有位宽结果。
2. **typedef 解析共享**：把 `evidence/typedefs` 的传递解析抽出为共享 API，避免 layout 再写一套。
3. **逐 TU 编译配置**：扩展 `build/compile_commands.go`，从每个 entry 提取 `File / Directory / Arguments`，以及 `target`、`-m32/-m64`、`-fpack-struct[=N]`、`-fshort-enums`、`-D` 等，形成 `TUConfig`/`ConfigKey`。当前“全局 union -D/-I”不足以支撑 layout。
4. **缺失配置的降级**：没有某文件 entry 或关键 pack/alignment 信息 → `assumed_default_abi`/`unknown`；不能拿另一 TU 的配置套用，也不能凭默认 LP64 产出 ABI-proven。

### 4.2 事实模型

```go
type LayoutKey struct {
    TU     string // 编译单元 / 编译配置 id
    Config string // target + pack/alignment/short-enums/macro 摘要
    Type   string // struct tag / typedef alias
}

type TypeLayout struct {
    Key        LayoutKey
    Name       string
    Size       int
    Align      int
    Kind       string // primitive | struct | union | array | pointer
    Fields     []FieldLayout
    Provenance string // compiler_proven | derived_from_complete_config | assumed_default_abi | unknown
    Source     string
    Unknown    string
}

type FieldLayout struct {
    Name       string
    Offset     int
    Size       int
    Align      int
    ArrayCount int
    BitWidth   int
    IsPointer  bool
}
```

### 4.3 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/typeinfo/*.go`（新） | ABI 表、typedef 解析、布局算法（含 pack/align 规则）、provenance、纯函数单测 |
| `sgre/internal/build/compile_commands.go` | 增加 per-TU entry / target / pack / short-enums / defines；不破坏现有 `-D/-I` 消费方 |
| `sgre/internal/repofacts/repofacts.go` | `Facts` 增加按 `LayoutKey` 索引的 `layouts`；`LayoutOf(key)` 查询；`WithFacts`/`FactsFromCtx` |
| `sgre/internal/repofacts/helpers.go` | 字段类型拼写、嵌套/匿名/数组/位域/条件编译识别 |
| `sgre/internal/evidence/typedefs.go` | `widthOf` 委托共享实现 |
| `sgre/internal/graph/types_width.go` | `TypeByName` 委托共享实现（或保留薄封装） |
| `sgre/internal/cli/pipeline.go` | 检测器前：加载 per-TU 配置 → 构建 `repofacts`（含 layout）→ `WithFacts(ctx)` 注入；buffer/nullable 改为优先用 ctx 实例 |

### 4.4 检测器集成

- 新增 `detectCastObjectOOB`（在 `buffer_overflow.go` 内，复用 `bufCtx`，不新建 Detector）：
  - 识别 `p = (T *)malloc(n)` / `p = (T *)raw`；
  - 通过 `AliasGraph` 追到分配基址；
  - 对 `p->field` / `p[i].field` 计算 `offset + size`；
  - 与 `alloc_size` 比较（无符号、溢出安全）；
  - 产出**独立的** `layout_oob_read` / `layout_oob_write`，**不复用** `heap_oob_read/write`；
  - `Provenance=assumed_default_abi`/`unknown` → 只 `suspected`；`compiler_proven`/`derived_from_complete_config` 且证据完整 → 才考虑 confirmed（默认 Phase 1 只 suspected，除非评审批准 type-layout proof class）。

**明确不做 / 降级**：

- 指针已偏移的复杂形态（除常量偏移）→ suspected 或不报；
- 位域 / flexible array / `#pragma pack` 未解析 → unknown；
- 跨 TU 同名类型冲突 → 各自独立或 unknown，不合并；
- 条件编译不能按当前 TU 宏配置求值 → unknown；
- 分配大小未知 / 非常量 / 不可区间证明 → 不 confirmed。

### 4.5 测试矩阵

**纯函数单测（typeinfo）**

- 基本类型（char/short/int/long/long long/float/double/pointer）；
- typedef 链；
- struct 自然对齐、尾部 padding；
- union；
- 嵌套 struct / 匿名 struct / 匿名 union；
- 数组字段；
- packed / aligned（`__attribute__`、`#pragma pack(push,N)`、`-fpack-struct`）；
- `-fshort-enums` / enum 宽度；
- bitfield / flexible array → unknown；
- ILP32 / LP64 / LLP64（必须带完整 config）的 `long` / pointer / struct 偏移差异；
- 缺失 target/pack 信息 → `assumed_default_abi`/`unknown`，不猜；
- 未知类型 → unknown，不猜。

**TU/配置测试**

- 同一源码在 `-fpack-struct` / `#pragma pack` / `aligned` 下得到不同布局，或明确 unknown；
- 同一类型在不同 TU/宏配置下不合并；
- 同名类型冲突 → unknown；
- 没有 compile entry 的文件 → assumed/unknown；
- 条件编译字段差异 → 按 TU 宏配置求值或 unknown。

**集成测试**

- `malloc(8)` + `struct LargeRecord *` + `record->value` → suspected（或 confirmed，取决于评审）；
- `malloc(sizeof(*record))` + `record->value` → 不报；
- `calloc(n, sizeof(*record))` → 正确容量；
- 字段部分越界（`offset < size`、`offset + fieldSize > size`）；
- 嵌套字段 / union / packed / typedef；
- 第三方头文件类型（worktree header）；
- 未知类型布局 / assumed ABI → 不 confirmed；
- `TestDeclarationFactInvariance` 增加 layout 的 inline / header-split 孪生体；
- Evidence Completeness：每个 confirmed 候选都能展示分析文档 §3.4 的证据表。

### 4.6 Unsupported cases 与降级（评审 P1-3）

| 场景 | 降级行为 |
|---|---|
| 无 `compile_commands.json` / 无该 TU entry | `assumed_default_abi`；suspected，不 confirmed |
| pack/alignment/short-enums 未解析 | `unknown`；不猜偏移 |
| 条件编译无法按当前 TU 求值 | `unknown`；不猜字段 |
| 同名类型跨 TU 冲突 | 各自独立；冲突时 unknown |
| bitfield / flexible array / 复杂扩展 | `unknown` |
| 第三方头文件不在 worktree | `unknown` |
| 指针偏移/union 别名/realloc 等复杂分配 | suspected 或不报 |
| 字段只部分可解析 | 整个 layout unknown，禁止部分偏移 |

### 4.7 退出标准

- 所有新增单测/集成/TU 配置测试通过；
- `go build -buildvcs=false ./...`、`go test -buildvcs=false ./...`、nosqlite 子集全绿；
- 原有 `feedback_watch` 安全对照不误报；`c-vuln-benchmark` 的既有 out-of-bounds/buffer-overflow finding 不丢；
- Evidence Completeness：每个 confirmed 候选可复核；assumed/unknown 不 confirmed；
- 性能按 §3.6 方法测量并报告；
- 文档：`AI_JUDGMENT_BOUNDARY.md`（仅当新增 confirmed proof class 并获批准）；`hint_tokens.go` token 登记；
- **Phase 1 独立 PR、独立评审；通过后才允许启动 Phase 2**。

---

## 5. Phase 2：CWD-SUB-1029 调用点容量绑定

### 5.1 前置

Phase 1 的 Type Layout 可用（元素大小 / 字节↔元素换算）。

### 5.2 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/graph/interproc.go` | identifier 实参的 props 增加 `arg_kind / arg_text / line`；不把所有实参塞进图边（避免 taint fixpoint 边膨胀） |
| `sgre/internal/graph/callsite_binding.go`（新） | 调用点容量索引：记录**所有**位置实参，`(call file,line,callee,param) → arg text/kind/capacity/provenance`；identifier 实参可引用现有 PARAM_BINDING |
| `sgre/internal/cli/pipeline.go` | pre-detector 构建/注入 `CallSiteBindingIndex` |
| `sgre/internal/evidence/buffer_overflow.go` | 新增 `detectParamIndexAccess`：形参索引 + 容量事实播种 |
| `sgre/internal/evidence/buffer_unchecked_index.go` | 泛化 `hasIndexBoundsGuard`：符号上界 + 支配 + 重赋值检查（或把 guard 逻辑移到 filter） |
| `sgre/internal/planner/filter_param_capacity.go`（新） | `ParamCapacityGuardFilter`：dismiss / 升级 / evidence |
| `sgre/internal/planner/filter_chain.go` | 把 filter 加入 `chainBufferOverflow` |
| `sgre/internal/planner/registry_buffer_overflow.go` / `registry_out_of_bounds.go` | 新 category + confidence |
| `sgre/internal/planner/evidence_package.go` / `hint_tokens.go` | call-site / capacity / guard evidence |
| `sgre/internal/planner/zz_ai_judgment_boundary_test.go` | 如新增 confirmed category，登记 |

### 5.3 关键实现规则

1. **关联只接受显式证据**：同一调用点 `length == sizeof(数组实参)`（或同一对象容量宏/元素个数）；`sizeof(*p)` 只是元素大小，不能当容量；变量名、参数顺序、类型相似不算。
2. **单位归一**：容量同时记录字节数与元素数（由 `elemSize` 换算）；`elemSize` 来自 Type Layout；`index * elemSize` 做溢出检查；不能整除 → suspected。
3. **多调用点**：每个调用点保留容量上下文；候选按 `(callee, access line, capacity)` 去重；不同容量不合并。
4. **Guard Witness 必须完整**（评审 P0-2）：不能只检查“出现过 `index < length`”或“CFG 支配”。必须同时满足：
   - **控制流**：guard 支配访问，且访问在正确分支方向；
   - **谓词语义**：比较表达式确实约束本次访问的 `index`（同一值，含 cast 后同一值）；
   - **对象/容量关联**：guard 上界与本次访问的 buffer/object 容量关联；不能是另一个对象的 length；
   - **稳定性**：guard→access 之间 `index`、`buffer`、`length` 未被重赋值；
   - **alias/副作用**：无别名写入、未知函数调用副作用、指针偏移改变；
   - **整数语义**：`<` vs `<=`、有符号负数、转换/提升、`index * elemSize` 溢出；
   - **路径形状**：`&&`、`||`、early return、循环、多分支中正确识别保护路径。

   Guard Witness 必须输出结构化字段：`guard_location/access_location/guard_predicate/branch_polarity/index_binding/buffer_object_binding/capacity_binding/index_stable/buffer_stable/length_stable/alias_stability/call_side_effect_status/proof_status`。**只有 `proof_status=must` 才能 dismiss；`may`/`unknown` 必须保留 suspected/AI_REQUIRED。**
5. **反例必须进测试**（评审给出）：
   ```c
   if (index < length) { buffer = another_buffer; buffer[index] = 0; }
   if (index < length) { length = 1; buffer[index] = 0; }
   if (index < other_buffer_length) { buffer[index] = 0; }
   ```
   另加 index/buffer/length 各自重赋值、alias 写入、中间函数调用副作用、负索引、`<`/`<=`、`&&`/`||`、early return、循环、多分支。
6. **间接调用**：未解析的函数指针调用 → 不建立绑定；不猜。
7. **fail-open**：容量/元素大小/ABI/alias/副作用任一 unknown → 不确认；必要时 suspected。
8. **confirmed 门槛**：常量索引 × 元素大小 ≥ 容量，且对象/容量/layout 证据完整、无有效守卫，才考虑升级；Guard `must` 的访问必须 dismiss。

### 5.4 测试矩阵

Issue §2.3 的 10 类 + 评审新增：

- 固定数组 + `sizeof` + 常量越界 → confirmed（评审批准后）；
- `malloc` + 已知容量 + 常量越界 → confirmed；
- 形参 + 调用点容量 + 常量越界 → confirmed；
- 形参 + `length` 容量 + `must` guard → 不报；
- 形参 + `length` 容量 + 无 guard → suspected；
- **guard 后 buffer 被替换**（另一个 buffer）→ 不 dismiss；
- **guard 后 length 被重赋值** → 不 dismiss；
- **guard 检查 `other_buffer_length`** → 不建立关联；
- guard 后 index 重赋值 → 不保护；
- alias 写入 / 中间函数调用副作用 → 守卫失效或 suspected；
- 有符号负索引 → 识别；
- `<` vs `<=`、`&&`/`||`、early return、循环、多分支 → 正确判定保护路径；
- `length` 不是容量 → 不关联；
- 多调用点容量不同 → 保留上下文；
- 多层调用 → 正确传播（至少 2 层）；
- 间接调用/未解析 → 不绑定；
- `int` 数组 + 字节 `sizeof` → 正确换算（不把 16 字节当 16 个 int）；
- `sizeof(*p)` + typedef → 通过 Type Layout 求元素大小；
- Evidence Completeness：每个 confirmed/dismiss 都能展示对象/容量/index/guard 完整证据。

### 5.5 Unsupported cases 与降级

| 场景 | 降级行为 |
|---|---|
| 无调用点容量证据 | 不播种或 suspected |
| `length` 与 buffer 容量关联不成立 | 不 dismiss，不 confirmed |
| Guard `may`/`unknown` | suspected/AI，不得 dismiss |
| index/buffer/length 重赋值或 alias/副作用未知 | suspected/AI，不得 dismiss |
| 未解析的函数指针/间接调用 | 不绑定，不 confirmed |
| 元素大小/ABI/布局 unknown | suspected，不 confirmed |
| 多调用点容量冲突 | 保留各自上下文；不能合并成全局常量 |
| 负索引/有符号溢出无法证明 | suspected |

### 5.6 退出标准

- 新测试全绿；原 `TestFeedbackWatchCapabilityMatrix` 仍绿；
- `feedback_watch` 的 1029 正例开始报告（suspected 或 confirmed），安全对照不报；
- benchmark 中 `out-of-bounds` / `buffer-overflow` 的既有 finding 不丢、no_finding 不新增误报；
- 候选增量 ≤ +20%（或给出体量分析）；
- Evidence Completeness 达标；性能按 §3.6 测量。

---

## 6. Phase 3：CWD-SUB-1031 全局写入值摘要

### 6.1 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/graph/global_write.go`（新） | 单次遍历，收集 `GlobalWriteFact`；复用 `file_scope_variables` / `GLOBAL_ACCESS` / AliasGraph |
| `sgre/internal/cli/pipeline.go` | pre-detector 构建/注入 `GlobalWriteIndex` |
| `sgre/internal/evidence/null_source.go` | 新增 `detectGlobalWriteNull`：为解引用全局的函数发射 `NULL_VALUE`，`origin=global_write` |
| `sgre/internal/planner/null_analysis.go` | `nullSource` 增加 global_write 字段（writer/source/condition/callers/unknown）；`definite=false`，`ProofStatus=may` |
| `sgre/internal/planner/filter_nullable_source.go` | `global_write` 作为 may 来源处理（不 definite、不升级 confirmed）；tier 逻辑 |
| `sgre/internal/planner/registry_null_deref.go` | evidence：writers / source / condition / 覆盖 / 未知外部 writer |
| `sgre/internal/planner/hint_tokens.go` | `glb-wr@` / `global-writer@` / `no-writer@` 等 token 登记 |

### 6.2 关键实现规则

1. **Global Write Summary 是来源摘要，不是 Consumer 状态**（评审 P0-3）：必须区分“writer 存在 / 路径可能写 NULL / 实际调用执行 / Consumer 当前值”四层；不得把 may-write 直接播种成 Consumer CFG Entry 的确定 NULL。
2. **只允许 may**：`global_write` 来源的 `ProofStatus=may`；`nullSource.definite=false`；不得仅凭 writer 摘要把候选升级为 confirmed。
3. **不把一次 NULL 写入传播为永久 NULL**：每个 writer 保留 `PathCondition` 与 `WriterDefinite`（后者只表示 writer 函数内 every-path，不是 consumer 状态）。
4. **static vs extern**：`static` 全局按 `(File, Name)` 区分；`extern` 按程序级 `Name` 汇总；同名 static/extern 混用 → unknown。
5. **多 writer / 覆盖**：evidence 必须列出所有 writer；存在 non-null writer、覆盖写入、未知 writer → 不确认，标“可能来源”。
6. **并发/逃逸/间接写**：线程入口写入、volatile/atomic、`&g` 逃逸、`memcpy(&g,...)`、函数指针/外部 writer → writer 集合不完整，unknown/suspected。
7. **confirmed**：Phase 3 **不承诺**任何 `global_write` confirmed。若未来实现调用上下文/顺序证明，必须同时满足评审 P0-3 的 5 条（来源确定、调用顺序可证、无覆盖、无未知外部 writer/逃逸/并发、可达且无有效 guard），并单独评审。
8. **不改变**现有 `detectStaticNullGlobals` 的 static-only 通道；新通道是增量。

### 6.3 测试矩阵

Issue §4.4 的 12 类 + 评审新增：

- 单 writer NULL → suspected，evidence 标“可能来源”；
- 单 writer 非 NULL → 不报；
- 两个 writer 分别 NULL / 非 NULL → suspected，evidence 列两者；
- 先写 NULL 后被覆盖 → 不确认；
- 条件写入（路径相关）→ suspected，condition evidence；
- writer 从未被调用 → 不能证明 Consumer 当前 NULL；
- 多层调用 → 正确传播来源，不直接升级；
- 跨文件 extern → 正确汇总；
- 同名 static 两个文件 → 不合并；
- 静态初始化 → 现有 `global_null` 通道；
- 多调用点 → 保留调用点上下文；
- 未知 writer（`&g` 逃逸 / `memcpy(&g,...)` / 外部函数）→ suspected/unknown；
- 函数指针/间接调用可能写全局 → writer 集合不完整；
- 多线程/volatile/atomic → 不确认；
- 赋值后 NULL 检查保护 → 不报；
- 任何场景不得把 may-write 直接断言为 Consumer 当前 NULL。

### 6.4 Unsupported cases 与降级

| 场景 | 降级行为 |
|---|---|
| writer 集合不完整（外部/函数指针/escape） | unknown/suspected，不 confirmed |
| 调用顺序不可证明 | suspected，不 confirmed |
| 中间覆盖/多 writer | suspected，列覆盖链 |
| 并发/volatile/atomic | suspected/AI，不 confirmed |
| 同名 static/extern 混淆 | unknown |
| 全局地址逃逸 | unknown |
| 只能证明“可能写 NULL” | suspected，标“可能来源” |

### 6.5 退出标准

- 新测试全绿；`TestFeedbackWatchCapabilityMatrix` 中 1031 的 static 正例仍报，安全对照不报；
- `feedback_watch` 的 1031 参数→全局正例开始报告（suspected）；
- 不产生新的 global 相关误报（benchmark no_finding）；
- Evidence Completeness：每个候选能解释 NULL 来源及到消费点的状态链路；
- 不新增 `global_write` confirmed；
- 性能按 §3.6 测量。

---

## 7. Phase 4：CWD-SUB-1140 输出参数成功/失败覆盖

### 7.1 前置（重要）

- `buildFuncSummaries` 当前被 `double_free` / `use_after_free` / `uninit` 各调用一次；Phase 4 先把它缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 结果），再扩展摘要；
- 确认评审对 §7.4 的测试策略决定。

### 7.2 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/evidence/free_summary.go` | `FuncSummary` 增加 `ReturnContract` + `ParamReturnCoverage`（每参数每 return 的 `ReturnClass/WriteLines/WholeParam/Fields/Covered`）；CFG per-return + 字段级覆盖；持久化 `return_contract` / `outparam_return_coverage`（merge，不覆盖其他 key） |
| `sgre/internal/evidence/uninit_variable.go` | 消费 Return Contract + per-return/字段覆盖：success/error 分支判定；未检查返回值按评审决定；字段不匹配不得 dismiss |
| `sgre/internal/planner/filter_uninit_flow.go` | `hasOutputParamWrite` 优先查摘要并做字段级比较；未知外部函数仍 fail-open |
| `sgre/internal/planner/registry_uninit.go` | evidence + KnownLimitations 更新 |
| `sgre/internal/planner/hint_tokens.go` | `outparam@success` / `outparam@error` / `return-contract@` / `outparam-field@` 登记 |
| `sgre/internal/planner/zz_uninit_output_param_test.go` | 按评审决定更新 `TestUninit_OutputParamUnguarded`（见 §7.5） |

### 7.3 关键实现规则

1. **Return Contract，不硬编码 0/nonzero**（评审 P0-4）：成功/失败集合来自项目显式约定、可信 API contract 或局部可证明语义；无法确定 → `Source=unknown`、`Confidence=unknown`。
2. **unknown 不得 confirmed/dismiss**：`ReturnContract.Confidence=unknown` 时，“调用者检查了返回值”不等于“检查了成功”；不得把任何分支当作 success/error。
3. **per-return 覆盖**：`!ReachesAvoiding(Entry, writeNodes, returnNode)` 证明写入支配该 return；记录每条 return 的 `ReturnClass`、覆盖字段、`Covered`。
4. **字段/子对象覆盖**（评审 P0-4）：`out->status` 不代表整个 `Result` 已初始化；`*out = ...` / `memset(out,...)` 才是整体；调用者读取的字段必须出现在 `Fields[].Covered`（或 `WholeParam=true`）才可 dismiss。
5. **调用者成功分支**：只有 Return Contract 证明该分支是 success，且 success 的每条 return path 都覆盖实际消费字段/整体 → 不报。
6. **调用者错误分支**：只有 Return Contract 证明该分支是 error，且该 return path 未覆盖实际消费字段/整体 → 可 confirmed（must-uninit on that path）。
7. **未检查返回值**：只能 `suspected`/`AI_REQUIRED`（may 证据），evidence 写明 callee 未覆盖路径、调用者未检查；不得 confirmed。
8. **未知外部函数**：仍 fail-open（视为写入），不产生新误报。
9. **不改变** `ParamWrites` / `ParamConditionalWrites` 的现有语义；只增加 per-return/字段级精度。

### 7.4 测试矩阵

Issue §5.5 的 15 类 + 评审新增：

- 0 成功（`return 0`）+ 非 0 失败；
- 非 0 成功（如 `return 1` 表示成功）；
- 多个成功码 / 多个失败码；
- 负数错误码 / 枚举返回值；
- 返回约定未知；
- 所有路径初始化 → 不报；
- 条件初始化但所有 success 路径写入 → 不报；
- success 路径存在未写入分支 → suspected/confirmed；
- 调用者不读取 → 不报；
- 调用者检查返回值后读取 → 按 Return Contract + 覆盖判定；
- 调用者不检查返回值 → suspected（不得 confirmed）；
- 调用者传入已初始化变量 → 不报；
- 字段级：callee 只写 `out->status`，caller 读 `out->data` → 不得 dismiss；
- 通过 helper 初始化 → 沿用 forwarded-write（every-path 视为整体，conditional 不视为覆盖）；
- 提前 return / 多层调用 / 指针别名 / 循环内初始化；
- 原 `TestUninit_OutputParamUnguarded` 回归；
- Evidence Completeness：每个 confirmed/dismiss 都能展示 return path + 合约 + 覆盖字段 + caller 分支。

### 7.5 `TestUninit_OutputParamUnguarded` 处理

Issue 要求保留该测试，并明确区分：

- 它锁定的是“不产生 Confirmed”，还是“不产生任何候选”？

现状：断言 `candidateForFunc != nil` 失败，即“不产生任何候选”。

方案（需评审批准）：

- 改为断言“不产生 `confirmed`；允许 `suspected`，且必须带 outparam/return-contract evidence”；
- 新增一个测试锁定 `suspected` 的 evidence 内容；
- 保留原测试名与原始缺陷语义（不能简单改期望值掩盖问题）；
- 在 PR 描述中解释为什么这是**增加证据化降级**，不是放宽确认门槛。

如果评审选择“保持完全静默”，则 Phase 4 只能覆盖 success/error/字段不匹配场景，未检查返回值场景列为 Remaining Gap。

### 7.6 Unsupported cases 与降级

| 场景 | 降级行为 |
|---|---|
| Return Contract 未知 | 不 dismiss、不 confirmed；suspected/AI |
| 返回值是结构体/errno/复杂状态 | unknown；不猜 success/error |
| 输出参数只写部分字段 | 按字段级覆盖；未覆盖字段不得 dismiss |
| 通过未知 helper/宏/函数指针写入 | 覆盖不完整 → suspected/AI，不 confirmed |
| 循环内条件写入 | conditional；不能证明至少执行一次 → 不覆盖 |
| Caller 分支与合约不对应 | 不 dismiss、不 confirmed |
| 间接/别名写入 | 覆盖不完整 → suspected |

### 7.7 退出标准

- 新测试全绿；原 uninit 回归测试（含 `TestUninit_OutputParamGuardNearErrorBranch`、`TestUninit_ConditionalWriteGuard`、`TestUninit_AlwaysWriteParamNotUninit`）全绿；
- `feedback_watch` 的 1140 正例保持报告，安全对照不报；
- Return Contract/字段级覆盖测试通过；unknown 合约不 confirmed；
- 候选增量与 AI 体量有测量；如果 suspected 增量过大，收窄播种或加配置开关（不引入未测量缓存）；
- Evidence Completeness 达标；性能按 §3.6 测量。

---

## 8. Phase 5：统一回归与性能

### 8.1 测试矩阵（全部必须执行）

| 类别 | 命令 / 范围 |
|---|---|
| 新增四类单测 | 各 Phase 的 `go test` |
| 相关 Detector 单测 | `go test ./internal/evidence/` |
| 相关 Planner 单测 | `go test ./internal/planner/` |
| 完整项目测试 | `cd sgre && go test -buildvcs=false ./...` |
| nosqlite 子集 | `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` |
| 原有漏洞回归 | `examples/c-vuln-benchmark` + `validate-benchmark.py` |
| 原有误报回归 | benchmark 的 `no_finding` 集 |
| 全仓库扫描 | 见 §8.2 corpus |
| 增量扫描 | 全扫 → 修改 1 文件 → 重扫，检查变更文件重建、未变更文件跳过 |
| 内存/时间 | `/usr/bin/time -l`（macOS）或 `time -v`（Linux）+ `secguard metrics` |
| 候选/verdict 统计 | `candidates.sarif`（管线候选）+ `result.sarif`（AI verdict，若 AI 阶段可用） |
| 准确性 | TP / FP / FN；基准不足时明确说明，不用“测试通过率”替代 precision/recall |
| 证据完整性抽查 | 对每个 confirmed/dismiss 抽样复核证据链（分析 §3.4 表） |
| 降级行为 | 未知/配置不完整/跨过程信息不足时，验证按设计降级而非猜测 |
| 多次运行 | 同机同数据集至少 3 次；报告中位数，必要时 P90 |

### 8.2 基准 corpus

1. `sgre/testdata/feedback_watch`（四类能力夹具，候选级）；
2. `examples/c-vuln-benchmark/src`（39 文件 / 227 用例，precision/recall）；
3. 生成的大规模 C corpus：`go run testdata/perf/gen_codebase.go <dir> 100 50`（规模/内存基线）；
4. 既有的生产 C dogfood 仓库（如果在本机可用）；如果不可用，在最终报告中明确记录“未跑生产仓库”，不能假装跑过。

### 8.3 基线采集（Phase 0 之后、Phase 1 之前）

在 **未改代码** 的基线 commit 上采集（同一机器、同一数据集、同一编译/扫描参数）：

```bash
cd sgre
go build -buildvcs=false -o ../bin/secguard ./cmd/secguard

# 1) 能力夹具（候选级，至少 3 次）
../bin/secguard scan ../sgre/testdata/feedback_watch --db /tmp/sgbase-fw.db

# 2) benchmark（verdict 级；需要 AI 阶段）
../bin/secguard scan ../examples/c-vuln-benchmark/src --db /tmp/sgbase-bench.db
python3 ../examples/c-vuln-benchmark/scripts/validate-benchmark.py --json

# 3) 规模/性能（冷启动 + 热缓存，至少 3 次）
go run testdata/perf/gen_codebase.go /tmp/sgperf 100 50
/usr/bin/time -l ../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-perf.db

# 4) 增量（全扫 → 修改 1 文件 → 重扫）
../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-inc.db
touch /tmp/sgperf/<one>.c
../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-inc.db
```

记录：

- `scan_runs` 的 `duration_ms / index_ms / graph_ms / detectors_ms / plan_ms / report_ms`；
- `files_indexed / functions_indexed / seed_count / final_count / report_bytes / evidence_bytes`；
- 峰值 RSS；
- 每类型的 `scan_stats.seed_count / final_count`；
- 每类 Gap 的事实数量（layout 数、CallSiteBinding 数、GlobalWriteFact 数、ReturnCoverage 数）；
- 候选级 confirmed/suspected/possible 数量；
- verdict 级 confirmed/suspected/dismissed、TP/FP/FN、precision/recall；
- 冷启动 / 热缓存 / 增量三类数据；每类至少 3 次，报告中位数与 P90；
- AI token 消耗：**当前二进制没有 token 计量字段**，Phase 5 需要：
  - 从 AI host/orchestrator 的 settlement/usage 记录读取；或
  - 在最终报告中明确“未测量”及原因，不能编造数字。

### 8.4 回归对照表（最终报告必须包含）

| 指标 | 基线 | Phase 1 | Phase 2 | Phase 3 | Phase 4 | 变化 |
|---|---|---|---|---|---|---|
| wall time（median/P90，冷/热/增量） | | | | | | |
| detectors_ms | | | | | | |
| plan_ms | | | | | | |
| 峰值 RSS | | | | | | |
| confirmed 数 | | | | | | |
| suspected 数 | | | | | | |
| possible 数 | | | | | | |
| TP / FP / FN | | | | | | |
| benchmark precision | | | | | | |
| benchmark recall | | | | | | |
| no_finding 新误报 | | | | | | |
| feedback_watch 正例 | | | | | | |
| 证据完整性抽查 | | | | | | |
| layout provenance 分布 | | | | | | |
| 降级行为验证 | | | | | | |
| 增量扫描正确性 | | | | | | |
| AI token（或“未测量”） | | | | | | |

### 8.5 验收标准（对齐 Issue §9）

| 验收项 | 标准 |
|---|---|
| 四个 Gap | 每项独立测试覆盖 |
| 真实漏洞场景 | 按证据充分程度进入 confirmed 或 suspected |
| 合法代码场景 | 不产生无依据的 confirmed |
| 原有测试 | 全部保持通过 |
| 第三方类型 | 无法解析时保守降级 |
| 跨过程分析 | 多层调用可处理 |
| 事实追踪 | 可定位原始源码证据 |
| 增量扫描 | 相关事实失效后正确重建 |
| Finding 去重 | 不产生无意义重复 |
| 性能 | 有前后对照数据（同机/同数据集/多次/中位数/P90/冷热增量） |
| 能力支持矩阵 | 更新并附在最终报告 |
| Evidence Completeness | 每个 confirmed/dismiss 可复核分析 §3.4 证据表 |
| Unsupported/降级 | 每个 Phase 的 unsupported cases 有测试或明确说明 |
| ABI/layout provenance | `compiler_proven`/`derived`/`assumed`/`unknown` 分布可审计 |
| Return Contract | 成功/失败/未知集合与来源可审计 |
| Guard Witness | `must`/`may`/`unknown` 与 dismiss 对应正确 |
| Phase 门禁 | 当前只允许 Phase 1；Phase 1 通过后才启动 Phase 2 |

---

## 9. 最终报告模板（回答 Issue §11）

```markdown
## 四个 Gap 的解决程度
| Gap | 现状 | Confirmed 形态 | Suspected 形态 | 仍不支持 |

## 已支持 / 部分支持 / 未支持 / 未验证
| 能力 | 分类 | 证据 | 未验证原因 |
|---|---|---|---|

## 更新后的能力支持矩阵
| 能力 | 当前 | 完成后 | 证据/测试 | 备注 |
|---|---|---|---|---|

## Evidence Completeness 抽查
| 结论 | 证据链 | 是否完整 | 缺失项 |
|---|---|---|---|

## 新增了多少事实类型
| 事实 | 落点 | 消费者 | 是否持久化 |

## 是否产生新误报
- benchmark no_finding 变化：
- feedback_watch 安全对照：
- 新误报样例与原因：

## 是否影响原有召回
- 原有 finding 是否丢失：
- 各类型 confirmed/suspected 变化：
- precision/recall 变化：

## 全仓库扫描增加了多少时间和内存
- 基线 / 最终：duration、detectors_ms、plan_ms、峰值 RSS
- corpus 与命令

## 增量扫描是否正确
- 变更文件重建：
- 未变更文件跳过：
- 事实失效/重建：

## Layout provenance / Return Contract / Guard Witness / Global Write
- Layout：`compiler_proven` / `derived_from_complete_config` / `assumed_default_abi` / `unknown` 分布
- Return Contract：成功/失败/未知集合与来源
- Guard Witness：`must` / `may` / `unknown` 分布，dismiss 是否只来自 `must`
- Global Write：writer 数、覆盖/未知 writer/escape/并发，是否有 confirmed（预期无）

## 还有哪些跨过程分析盲区
- 位域/柔性数组/packed：
- 未知 ABI/编译配置：
- 函数指针/间接调用：
- 多线程全局状态：
- 未知外部 writer：
- 未知 Return Contract：
- 字段级覆盖不完整：
- 其他 Remaining Gap

## 未解决问题
- 设计未决：
- 实现未完成：
- 需要评审批准：

## AI Token 消耗
- 测量方式或“未测量”说明

## 性能测量方法
- 机器/数据集/编译参数/扫描参数：
- 冷/热/增量：
- 运行次数、median/P90：
- wall time / peak RSS / 文件数/函数数/事实数：
```

---

## 10. 风险与回滚

| 风险 | 触发条件 | 回滚/缓解 |
|---|---|---|
| Type Layout 误报 | assumed ABI / packed / union 别名 | 只 suspected；unknown 不出；回滚到 suspected-only |
| 1029 体量爆炸 | 普通 `buf[i]` 形参被播种 | 收窄为“有容量事实 + 常量索引/关联”；必要时配置开关 |
| 1031 状态污染误报 | 多 writer / 外部写 / 并发 | 默认 suspected；Phase 3 不承诺 confirmed；保留 writer/覆盖/未知源证据 |
| 1140 写回惯用法误报 | 大量 `fn(&x)` 无返回值检查 | 先做体量评估；Return Contract + 字段级覆盖；必要时保持静默 + Remaining Gap |
| 性能超预算 | 新全树遍历 | 复用 parse/RepoIndex/ctx 注入；profile；拆分或回退 |
| 测试守卫失败 | 新增 confirmed 未登记 | 先登记 `TestConfirmedTierPolicy` / `TestDynamicConfirmedUpgradesRegistered` |
| schema 迁移失败 | 新增枚举/表 | MVP 不新增；如必须，走 additive migration + 回滚脚本 |
| Target triple 被当成完整 ABI | layout 误判 | 按 TU/Config + provenance/confidence；assumed/unknown 不 confirmed |
| Guard 支配被当成谓词保护 | 错误 dismiss | 结构化 Guard Witness；只有 `must` 才 dismiss |
| may-write 被当成 Consumer 状态 | 错误 confirmed | may-only；Phase 3 不承诺 confirmed |
| 0/nonzero 返回约定 | 错误 success/error | Return Contract Evidence；unknown 不 confirmed |
| 字段级写入被当成整体 | 错误 dismiss | `WholeParam`/`Fields` 区分；caller 消费字段必须匹配 |
| heuristic 冒充 compiler-proven | 证据链不可审计 | provenance 标注；unknown/assumed 降级 |

---

## 11. 评审决策清单（详细处理见 review-decisions 文档）

评审已确认：

- 使用独立 layout 越界语义，不复用 `heap_oob_*`；
- `confirmed` 必须 must；may 证据只能 suspected/AI_REQUIRED；
- `assumed_default_abi` / `unknown` 不得 confirmed；
- Phase 3 不把 may-write 当 Consumer 当前状态；
- 1140 不硬编码 0/nonzero，必须 Return Contract；
- 当前只启动 Phase 1（1038），通过独立评审后才启动 Phase 2。

仍需确认/待定：

1. Phase 1 是否立即新增 `layout_oob_*` confirmed proof class；默认不新增，只 suspected。
2. `TestUninit_OutputParamUnguarded` 是否改为“不 confirmed、允许 suspected”，还是保持完全静默。
3. 1029 调用点常量越界是否沿用“常量边界 + 已知容量”的确认语义（前提：Guard Witness 完整）。
4. Type Layout 算法放 `internal/typeinfo` + census 扩展 `repofacts`，还是全部塞进 `repofacts`。
5. 无 `compile_commands.json` 时只出 suspected，还是直接不报。
6. 宽度表收敛是否在 Phase 1 前置。
7. MVP 是否接受“不新增表/枚举”的持久化策略。
8. 性能预算（+10% / +50MB）是否接受为初始预算。

---

## 12. 完成定义（Definition of Done）

一个 Phase 完成，必须同时满足：

- [ ] 代码实现 + 新增测试；
- [ ] `go build -buildvcs=false ./...` 通过；
- [ ] `go test -buildvcs=false ./...` 通过；
- [ ] `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 通过；
- [ ] 原有回归测试未被删除/跳过/弱化；
- [ ] 新事实有 provenance / 置信度 / 调用上下文 / 失效说明；
- [ ] 新增 confirmed 已登记证明类别（如适用）；
- [ ] evidence 能被 AI 消费（token 已登记）；
- [ ] Evidence Completeness 达标（分析文档 §3.4）；
- [ ] Unsupported cases 与降级行为有测试或明确说明；
- [ ] TP/FP/FN 与 precision/recall 有报告（基准不足时明确说明）；
- [ ] 性能按 §3.6 方法测量（同机/同数据集/多次/median/P90/冷热增量）；
- [ ] 候选体量与 AI 体量有测量；token 无采集则写“未测量”；
- [ ] PR 描述包含改动、测试、证据完整性、风险、Unsupported、Remaining Gap；
- [ ] 不以代码行数作为完成标准；
- [ ] 本轮只修订文档、不改生产代码；Phase 1 通过独立评审后才启动 Phase 2；
- [ ] 人工评审通过后由人合并（不启用 auto-merge）。
