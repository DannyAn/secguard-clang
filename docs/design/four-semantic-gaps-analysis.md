# 四类跨过程程序语义 Gap：Phase 0 调研分析

> 对应 Issue #228（CWD-SUB-1029 / 1038 / 1031 / 1140）。
> 本文是 **Phase 0 调研输出**，只描述现状、可复用设施、事实模型与最小实施边界，**不包含生产代码改动**。
> 配套文档：[four-semantic-gaps-implementation-plan.md](four-semantic-gaps-implementation-plan.md)、[four-semantic-gaps-review-decisions.md](four-semantic-gaps-review-decisions.md)。
>
> **修订记录**：v2（2026-11-05）按 PR #229 评审意见 P0-1..P0-5 / P1-1..P1-3 修订。逐项处理结果、未解决问题与对后续 Phase 的影响见 review-decisions 文档。

- 调研基线：`main@7176ab2`（v0.12.2 + PR #227），2026-11-05。
- 已执行验证：
  - `cd sgre && go build -buildvcs=false ./...` 通过；
  - `go test -buildvcs=false -run TestFeedbackWatchCapabilityMatrix ./internal/planner/` 通过（0.87s）。
- 结论以代码阅读 + 现有测试夹具 + 基线测试为准，不引用 `docs/` 下的历史评审结论。

---

## 0. 结论摘要

### 0.1 四类 Gap 的真实现状

| Gap | 外部能力名 | 现状 | 当前负责链路 | 真正缺的那一层 |
|---|---|---|---|---|
| CWD-SUB-1029 | 参数指针调用点容量绑定 | **不支持**（普通形参索引形态） | `evidence/buffer_overflow.go`：`detectArrayOOB` / `checkArrayOOB` / `detectUncheckedIndex` | 调用点容量事实 + buffer↔length 关联 + 符号化 guard witness |
| CWD-SUB-1038 | 类型大小与字段偏移 | **不支持** | 无；`repofacts` 只有字段形态（array count / pointer），没有 size/offset | Type Layout 事实层（size / align / offset），且必须按 TU/编译配置隔离并标注 provenance/confidence |
| CWD-SUB-1031 | 全局变量写入值的跨过程传播 | **部分支持**（仅“static 且从未被重写”的 NULL） | `evidence/null_source.go`：`detectStaticNullGlobals`；`planner/filter_nullable_source.go` | 全局写入值摘要（writer → source kind）+ 消费函数的状态不确定性 |
| CWD-SUB-1140 | 输出参数初始化覆盖 | **部分支持**（已有 `ParamWrites` / `ParamConditionalWrites`） | `evidence/free_summary.go` + `evidence/uninit_variable.go` + `planner/filter_uninit_flow.go` | 成功/失败返回路径与写入覆盖的关联；调用者未检查返回值时的证据化降级 |

### 0.2 四个系统性结论（比四个单点更重要）

1. **多数缺口不是“能力不存在”，而是“事实已产生、消费链路没接上”。**
   - `PARAM_BINDING` 已在图里，但只绑定裸标识符实参、不携带实参类型/容量，buffer 检测器也从不读它；
   - 输出参数写入覆盖已由 `FuncSummary.ParamWrites/ParamConditionalWrites` 用 CFG must-reach 证明并持久化，但调用者侧对“未检查返回值的条件写入”采取了刻意的 fail-open；
   - `static` 全局指针“只可能是 NULL”已能确认，但参数→全局→解引用的写入来源没有摘要。
2. **需要新增的事实是 3 个家族，而不是 4 套系统**：Type Layout、调用点绑定/容量、全局写入摘要；输出参数摘要是在现有 `function_summary` 上扩展，guard witness 是过滤器中按 CFG 现算的派生事实。MVP **不新增 SQLite 表、不新增 `security_events` 事件类型、不新增 `graph_edges` 边类型**。
3. **两个原策略问题已在评审中形成明确约束**：
   - **1038 使用独立的 layout 越界语义**（不把 layout 证据冒充现有 `heap_oob_*`）；只有布局来源/适用范围可信时才允许升级，`assumed`/`unknown` 不得 `confirmed`；
   - **1140 保持 must 语义**：只有“在读取路径上可证明未初始化”才 `confirmed`；“存在失败路径 + 调用者未检查返回值”属于 may 证据，只能 `suspected`/`AI_REQUIRED`。
4. **四个必须写进事实与证据链的语义边界**（评审 P0 的核心）：
   - **Layout 是 TU/编译配置相关事实**：target triple 只是输入之一，`-fpack-struct` / `-fshort-enums` / `#pragma pack` / attributes / 条件编译 / typedef / 匿名/嵌套/位域/柔性数组都会改变布局；同名类型跨 TU/宏配置不得无条件合并。
   - **Guard Witness 不是“支配 + 出现过谓词”**：还必须证明谓词约束了本次 index、guard 上界与本次 buffer/object 容量关联、index/buffer/length 在 guard 到访问之间稳定、alias/调用副作用不失效、比较符/有符号性/短路路径正确。
   - **Global Write Summary 是“来源摘要”，不是 Consumer 入口状态**：一次 may-write NULL 不得直接播种 Consumer 入口的确定 NULL；必须有调用上下文、调用顺序、覆盖、未知 writer/escape/并发分析。
   - **1140 不能硬编码“0 成功、非 0 失败”**：必须引入 Return Contract Evidence（成功/失败/未知返回集合、合约来源、逐 return path 覆盖、caller 分支对应），并把写入覆盖细化到参数/字段/子对象。

### 0.3 推荐施工顺序

按依赖关系，**不是**按 Issue 编号：

```
Phase 1  CWD-SUB-1038  Type Layout（基础事实层，先做纯函数单测）
Phase 2  CWD-SUB-1029  调用点容量绑定 + Buffer-Length 关联 + Guard Witness
Phase 3  CWD-SUB-1031  全局写入值摘要 + Nullability 集成
Phase 4  CWD-SUB-1140  输出参数成功/失败路径覆盖 + 调用者消费
Phase 5  统一回归、全仓库基准、性能与最终报告
```

理由：1029 的索引容量单位（字节 vs 元素）依赖 1038 的 `sizeof`/元素大小；1031 的“参数→全局”写入来源可以直接复用现有的 `ParamWrites` 覆盖基础设施（1140 的 Phase 4 只是把它扩展到成功/失败返回路径）；1140 最容易引入误报，放最后。

---

## 1. 调研基线与可复现证据

### 1.1 现有能力矩阵（已在基线复测）

`sgre/testdata/feedback_watch/README.md` 记录了 Issue #226 的外部缺陷夹具与实测结果。基线复测 `TestFeedbackWatchCapabilityMatrix` 通过，说明以下矩阵仍然成立：

| 场景 | 夹具 | 基线行为 |
|---|---|---|
| 1029 普通形参索引 | `CWD-SUB-1029-pointer-offset/01_external_offset_oob.c` | 0 候选（`read_byte` / `buffer[external_offset]`） |
| 1029 错误长度检查 | `03_wrong_length_check.c` | 0 候选 |
| 1029 无符号下溢 | `04_unsigned_underflow.c` | 0 候选 |
| 1029 正确守卫对照 | `02_validated_offset.c` | 0 候选（安全） |
| 1031 static 恒 NULL | `CWD-SUB-1031-global-null-deref/01_global_pointer_deref.c` | 1 候选，`global-null`，suspected |
| 1031 参数→全局→解引用 | `03_interprocedural_global_deref.c` | 0 候选 |
| 1031 守卫/并发对照 | `02` / `04` | 0 候选（安全） |
| 1038 分配不足的强制转换 | `CWD-SUB-1038-invalid-pointer-cast/01_cast_insufficient_size.c` | 0 候选 |
| 1038 错误的目标大小检查 | `03_wrong_target_size_check.c` | 0 候选 |
| 1038 元素数/字节数混淆 | `04_element_count_byte_size_confusion.c` | 0 候选 |
| 1038 正确分配对照 | `02_cast_sufficient_size.c` | 0 候选（安全） |
| 1140 标量/指针/字段/switch join | `01` / `02` / `03` / `05` | 均能报告（部分 auto-confirmed） |
| 1140 输出参数契约 | `07_outparam_contract.c` | 0 候选 |
| 1140 已初始化对照 | `04` / `06` | 0 候选（安全） |

> 注意：矩阵是**候选级**（AI 研判之前）的结果；`suspected` 候选不等于漏洞结论。

### 1.2 当前测试约束（实现时不能悄悄放宽）

- `TestFeedbackWatchCapabilityMatrix` 只锁定“安全对照不误报”，**刻意不锁定** 1029/1038 的漏报，允许未来检测器开始报告而无需改测试。
- `TestUninit_OutputParamUnguarded`（`planner/zz_uninit_output_param_test.go`）锁定“未检查返回值的条件写入不报候选”，这是 1140 的核心冲突点，详见 §7.5。
- `TestConfirmedTierPolicy`（`planner/zz_ai_judgment_boundary_test.go`）锁定静态 `confirmed` 集合；任何新增 auto-confirm category 必须登记。
- `TestDynamicConfirmedUpgradesRegistered` 锁定“filter 内升级 confirmed”的已审阅清单；新增升级 filter 必须实现 `ProofRegistrar` 并登记。
- `TestDeclarationFactInvariance`（`planner/zz_declaration_invariance_test.go`）保证 inline fixture 与 header-split 孪生体产生相同候选；Type Layout 必须纳入该测试。
- 本任务不新增漏洞类型、不新增 skill，因此 `TestVulnTypeSkillConsistency` 不应被触发；四类 Gap 全部复用现有 `out-of-bounds` / `buffer-overflow` / `null-deref` / `uninit`。

---

## 2. 现有可复用设施盘点

### 2.1 Repository / Declaration Facts

`internal/repofacts` 是树级声明事实的唯一来源：

- `Facts` 持有 `Macros map[string]int`、按 struct tag/typedef 别名的字段表、按字段名的歧义回退表、全局数组表；
- `Build` 两遍扫描 indexed files + worktree headers（`repofacts.go:57`）；
- `FieldFact` 目前只有 `Name / Type / Pointer / Array / Count / Symbol`（`repofacts.go:27`），**没有 size / align / offset**；
- `FieldByTag` / `FieldByName` / `GlobalArray` 是精确查询，歧义即“未知”（`repofacts.go:340-377`）。

可复用点：跨文件 header、宏容量、typedef 别名、歧义即未知的保守策略，正好是 Type Layout 需要的输入层。**Type Layout 应作为 `repofacts` 的扩展，而不是新起一套 census。**

### 2.2 全局变量与图

- `file_scope_variables` 表已存在并由 indexer 填充：`name / type / storage_class / declaration_line / is_pointer`（`db/schema.go:65`，`indexer/indexer.go:260`）；
- 文件变更时按 file 级联删除（`indexer/indexer.go:180`），增量重建语义正确；
- `GLOBAL_ACCESS` 边已由 `graph/shared_access.go` 持久化，但只有 function → global 的 `read / write / read_write` 聚合，**没有写入值来源**；
- `AliasGraph` 每次扫描构建并注入 ctx（`cli/pipeline.go:266`），已覆盖全局别名（`g = p` 时 `FunctionID=0`），可作为 1031 “全局指针别名”的现成设施。

### 2.3 调用点与参数绑定

- `PARAM_BINDING` 由 `graph/interproc.go` 持久化；边是 `variable_ref(actual) → parameter(callee)`，props 只有 `callee / index / param`；
- **只绑定 `arg.Kind() == "identifier"` 的实参**（`interproc.go:142`）。`sizeof(buffer)`、`&x`、cast、常量、调用结果都不绑定；
- 不携带实参文本、不携带容量、不携带调用点上下文；
- `planner/call_sites.go` 的 `callSiteResolver` 已经会遍历全仓库收集 `(callee → 每个调用点的实参文本)`，但它只服务于 divide-by-zero 的参数零传播，且是 filter 内临时构建。

可复用点：`PARAM_BINDING` 的边语义、`callSiteResolver` 的调用点普查、`InterprocBuilder` 的两遍跨文件解析。

### 2.4 CFG / 支配 / 流分析

- `graph.StmtCFG`（`graph/control_flow.go:45`）提供 `Entry / Exit / Nodes`、`NodeAt`、`Reaches`、`ReachesAvoiding`、`TrueSuccs / FalseSuccs`；
- **没有显式 dominator API**，但 guard 支配可以用 `!ReachesAvoiding(Entry, guardNodes, accessNode)` 表达（“去掉 guard 节点后能否从入口到 access”）；
- `planner/null_flow.go` 的 `flowAnalyzer` 是 may 到达源引擎；`runMustDataflow` 是 must 引擎；
- `evidence/cfg_cache_ctx.go` 的 `buildStmtCFGFromCtx` 让检测器也能共享同一份 per-scan CFG；
- `planner/filter_uninit_flow.go` 的 `DefiniteInitFilter` 已用 CFG must 证明“读取前没有写入”。

### 2.5 Nullability / 输出参数 / 全局 NULL

- `planner/null_analysis.go:87` 的 `buildNullModel` 从 `NULL_VALUE` 事件构建 `(function, variable)` 级来源；
- `filter_nullable_source.go` 把 `caller_null` / `opaque_param` / `global_null` 来源**种在 CFG entry**（`filter_nullable_source.go:546`）；
- `detectStaticNullGlobals` 只处理文件级 `static` 指针且只赋值 NULL/从未重写的形态（`null_source.go:104`）；
- `free_summary.go` 计算 `FuncSummary.ParamWrites` / `ParamConditionalWrites`（every/some），用 `ReachesAvoiding(Entry, writeNodes, Exit)` 证明 every-path，并持久化到 `function_summary.summary_json` 的 `outparam_writes` / `outparam_conditional_writes`；
- `uninit_variable.go` 消费该摘要：`ParamWrites` → 初始化；`ParamConditionalWrites` + 调用者错误守卫 → 守卫之后才算初始化；**无守卫 → 直接信任**（`uninit_variable.go:454-490`，注释明确写了这是 deliberate false-negative）；
- `bounded_return.go` 已经把“返回值的容量参数索引”持久化为 `bounded_return_cap_arg`，是“per-function 参数契约存进 `summary_json`”的现成先例。

### 2.6 类型宽度与编译配置

- `evidence/typedefs.go` 有 typedef 传递解析 + `widthOf`（LP64 位宽，`typedefs.go:310`）；
- `graph/types_width.go` 有另一张 `lp64Widths`（bit）+ `TypeByName`；
- **这是两张并行的宽度表**，再加 1038 会产生第三张——必须在 Phase 1 收敛成一张；
- `build/compile_commands.go` 只解析 `-D` / `-I`，**不解析 `-m32` / `-m64` / `--target=`**；当前 ABI 是硬编码 LP64。

### 2.7 证据与 AI 边界

- `planner/evidence_package.go` 已能把 callee body 嵌入 `## Callee Definition`，候选文件还承载 `## Macro Definition`、`## Clustered Sites`；
- `planner/hint_tokens.go` 是 token 注册表；新增 token 必须登记，否则文档/校验漂移；
- `AI_JUDGMENT_BOUNDARY.md` 定义四类证明手段；`zz_ai_judgment_boundary_test.go` 是机器守卫。

---

## 3. 统一事实模型：扩展，而不是再造

### 3.1 事实分层与归属

| Issue 建议的事实 | 本方案的落点 | 是否新增持久化 | 生产者 | 主要消费者（≥2） |
|---|---|---|---|---|
| `PARAM_BINDING` | **扩展现有边**：保留 identifier 绑定语义，props 增加 `arg_kind / arg_text / line`；非 identifier 实参（`sizeof` / `&` / cast / 常量）进入 `CallSiteBinding`，避免图边膨胀 | 否（边已存在） | `graph/interproc.go` + `graph/callsite_binding.go` | 1029；1031（参数→全局写入）；1140（`&out` 绑定） |
| `BUFFER_CAPACITY` | **调用点内存事实** `CallSiteBinding`，按 `(call file,line,callee,param)` 索引 | 否（每扫描重建） | 新 `graph/callsite_binding.go`（或扩展 `callSiteResolver`） | 1029；1038（分配容量与字段尺寸比较）；1140（`&out` 对象大小） |
| `BUFFER_LENGTH_ASSOCIATION` | **派生事实**：同一调用点上 `length == sizeof(数组实参)`（或同一对象的容量宏/元素个数）才建立 buffer↔length 关联 | 否（由调用点事实推导） | 1029 检测器/过滤器 | 1029；1038（数组字段容量） |
| `GUARD_WITNESS` | **不落库**：由过滤器按完整证据字段（谓词/分支极性/index 绑定/对象/容量/稳定性/alias/副作用/proof_status）现算；CFG 支配只是必要条件 | 否 | 新 `ParamCapacityGuardFilter` | 1029；1038（字段访问守卫）；1140（返回值守卫） |
| `TYPE_SIZE / TYPE_ALIGNMENT / FIELD_OFFSET / FIELD_SIZE` | **扩展 `repofacts`**：新增按 **TU/编译配置** 隔离的 `TypeLayout` 视图（含 layout provenance / confidence） | 否（`repofacts` 每次扫描重建） | `repofacts`（同一遍 parse）+ 每 TU 编译配置 | 1038；1029（元素大小/字节↔元素换算）；sizeof-misuse / memcpy 长度校验（既有能力） |
| `GLOBAL_WRITE_SUMMARY` | **pre-detector 内存事实** `GlobalWriteIndex`（ctx 注入）：只记录“writer → source kind / path / call context”，是来源摘要，**不是 Consumer 入口状态**；如需跨阶段复用再合并进 `summary_json.global_writes` | 否（MVP；`function_summary` 仅在确有跨阶段需求时使用） | 新 `graph/global_write.go` + `cli/pipeline.go` 的 pre-detector 阶段 | 1031；1038/1029（全局对象容量，可选） |
| `OUTPUT_PARAM_SUMMARY` | **扩展现有 `FuncSummary`**：增加 Return Contract Evidence（成功/失败/未知返回集合、合约来源）+ 逐 return path、参数/字段/子对象的写入覆盖 | 是（同一 `summary_json`） | `free_summary.go` | 1140；1031（参数写入覆盖→全局写入来源） |

**MVP 不新增 SQLite 表、不新增 `security_events` 事件类型、不新增 `graph_edges` 边类型。** 理由：

- `graph_edges.edge_type` 和 `security_events.event_type` 都带 CHECK 枚举（`db/schema.go:116`、`db/schema.go:131`），新增枚举值需要 schema 迁移，且迁移后旧数据库的兼容成本高；
- 语义图与事件表**每次扫描都清空重建**（`cli/pipeline.go:119` 清 graph，`:242` 清 events），把“调用点相关事实”持久化没有跨扫描收益，反而增加失效风险；
- `function_summary` 随 `functions` 级联删除（indexer 变更文件时删 function），增量失效语义已经正确。

### 3.2 事实的 provenance / 可信度 / 调用上下文 / 失效

所有新事实必须携带同一组元数据（对齐 Issue §6）：

```go
// 示意，不落生产代码
type FactMeta struct {
    File       string // 事实来源文件
    Line       int    // 事实来源行
    Function   string // 来源函数（可空）
    Symbol     string // 相关符号
    Evidence   string // "local-array-decl" / "sizeof-arg" / "malloc-arg" / "macro-cap" / ...
    Provenance string // "source" | "compile-config" | "repofacts" | "cfg" | "contract" | "heuristic"
    // Layout 专用：来源/适用范围/可信度
    TU              string // 编译单元/配置 key；空表示不适用
    Config          string // target + pack/alignment/short-enums/macro 配置摘要
    LayoutConfidence string // "compiler_proven" | "derived_from_complete_config" | "assumed_default_abi" | "unknown"
    // 跨过程状态专用
    ProofStatus string // "must" | "may" | "unknown"
    CallSite    string // 仅调用点事实：file:line + callee
}
```

约束：

- **调用点事实不得提升为全局事实**。`f(buf, 16)` 的容量只属于该调用点；同名的另一个调用点容量不同时必须保留两个上下文，不能合并成一个常量。
- **Layout 是 TU/编译配置相关事实**。`TU`/`Config` 必须进入 layout 的 key；同名类型跨 TU/宏配置不得无条件合并。target triple 只是输入之一，不能单独证明布局。
- **Layout confidence 四档**（评审 P0-1）：
  - `compiler_proven`：来自与目标编译配置匹配的权威布局信息（如未来的 Clang Record Layout Dump）；
  - `derived_from_complete_config`：输入配置完整（target + pack/alignment/short-enums/宏），按受约束 ABI 规则推导；
  - `assumed_default_abi`：基于默认 ABI 假设（例如无 `compile_commands.json`）；只能 suspected，禁止 confirmed；
  - `unknown`：关键信息缺失或无法建模；只能 suspected/AI_REQUIRED 或不报。
- **Global write 是来源摘要**：`ProofStatus` 在 Consumer 侧只能是 `may`/`unknown`，不得仅凭 writer 摘要把 Consumer 入口状态标成确定 NULL；必须结合调用上下文、调用顺序、覆盖和未知写入源。
- **Guard witness 是结构化证据**：`ProofStatus=must` 才可 dismiss；`may`/`unknown` 不得当作有效保护。
- 所有 `unknown` 走 fail-open：不确认，必要时降级为 `suspected`，绝不能把“未知”解释成“安全”。
- **证据来源不能混用**：heuristic 与 compiler-proven/config-derived fact 必须在 finding 中分别标注；不能把 heuristic 描述成已证明。

### 3.3 事实生产时机：pre-detector 共享阶段

检测器是**并发**执行的（`evidence.RunAllDetectorsWithSkip`，`cli/pipeline.go:291`），所以任何“检测器 A 产出、检测器 B 消费”的新事实都是不确定的。四类 Gap 中：

- Type Layout、CallSiteBinding、GlobalWriteIndex 都是**多消费者、跨检测器**的事实，必须在检测器之前构建；
- 构建位置：`cli/pipeline.go` 已有的“图构建完成、`ClearSecurityEvents` 之后、RunAllDetectors 之前”区间，与 `AliasGraph` 相邻（`cli/pipeline.go:266`）；
- 通过 ctx 注入（`graph.WithXxxIndex` 模式），检测器与 planner filter 都读同一份实例；
- 单次构建、单次 parse，避免 `repofacts.Build` 当前被 buffer 检测器与 nullable filter 各建一次（`buffer_overflow.go:33`、`filter_nullable_source.go:1222`）的重复成本；
- 不跨扫描缓存；每次 scan 重建，天然满足失效要求。

### 3.4 Evidence Completeness（证据完整性）与 provenance

这是评审 P0-5 的统一要求：不能只验证“是否命中样例/是否输出 finding”，还必须验证 detector 最终拿到的证据**足以支持该结论**。

| Gap | Confirmed 结论必须具备的证据 |
|---|---|
| 1029 参数 buffer 容量 | 访问位置；调用点；实际对象绑定（哪个 actual → 哪个 formal）；字节容量来源；元素大小/元素容量；index 表达式；guard 谓词及分支方向；guard 到访问之间的 index/buffer/length 稳定性与 alias/call-side-effect 证据 |
| 1038 struct layout | 分配大小；目标类型；TU/编译配置；ABI/layout 来源与置信度；字段偏移/字段大小；访问起止范围；整数计算可信度 |
| 1031 global NULL | 所有已知 writer；NULL 来源；调用上下文/调用顺序；覆盖情况；未知 writer/外部写入/escape/并发风险；Consumer 实际读取位置 |
| 1140 output parameter | 每条 return path；返回码语义来源（Return Contract）；参数/字段/子对象级写入覆盖；caller 分支条件；分支与成功契约的对应关系；实际消费字段和位置 |

规则：

- 证据不完整时，**可以保留候选并交给 AI**（`suspected` / `AI_REQUIRED`），但不能仅凭函数名、变量名、注释或模式相似度升级为 `confirmed`。
- finding 必须保留 **evidence provenance**：每项关键事实来自源码 / 编译配置 / Repository Facts / CFG 推导 / 项目 contract / heuristic。不要把 heuristic 与 compiler-proven fact 混在一起。
- 每个 Phase 的验收表必须引用本表；实现计划中给出对应测试与验收方式。

---

## 4. CWD-SUB-1029：函数参数指针的调用点容量绑定

### 4.1 当前代码路径（为什么漏）

`read_byte(data, sizeof(data), offset)` 的候选链路：

1. `BufferOverflowDetector.Detect`（`buffer_overflow.go:28`）构建 per-file `bufCtx`；
2. `detectArrayOOB`（`buffer_overflow.go:932`）遍历 `subscript_expression`，对 `buffer[external_offset]` 调 `checkArrayOOB`；
3. `checkArrayOOB`（`buffer_overflow.go:981`）：
   - `findArraySize(bc, f, "buffer", line)` 返回 0：`buffer` 是形参，本文件没有它的数组声明；`bc.facts.GlobalArray("buffer")` 也不命中；
   - `heapAllocationSize(bc, f, "buffer")` 只查**当前函数内**的 `init/assign`，形参没有 malloc 赋值，失败；
   - 因 `arrSize == 0`，常量索引分支只在 `heapAllocationSize` 成功时才比较，直接跳过；
4. `detectUncheckedIndex`（`buffer_unchecked_index.go:51`）只接受 `memberSubscriptBase`（`x->arr[idx]` 形态）且 `index` 来自结构体字段；`buffer[offset]` 的 base 不是结构体成员数组，直接跳过；
5. `PARAM_BINDING` 确实存在：`buffer` 绑定到形参 `buffer`，`offset` 绑定到 `external_offset`；但 `sizeof(data)` 不是 identifier，**不绑定**，而且 buffer 检测器从不查询这些边。

因此：**不是“不知道 buffer 是参数”，而是“没有把调用点的容量事实接进边界证明，且没有建立 buffer 与 length 的关联”。**

### 4.2 可复用设施

- `PARAM_BINDING` 边与 `InterprocBuilder` 的两遍跨文件解析；
- `findArraySize` 的局部/全局数组容量解析、`repofacts.GlobalArray`；
- `heapAllocationSize` 的分配容量表达式解析（需要泛化到“调用者函数内”）；
- `callSiteResolver` 已有全仓库调用点实参文本普查；
- `StmtCFG` + `ReachesAvoiding` 做 guard 支配；
- `hasIndexBoundsGuard`（`buffer_unchecked_index.go:317`）的两种惯用形态（早退守卫 / 正向守卫）；
- `caller_null` 的“开放链”fixpoint 思路（参数→参数转发）。

### 4.3 需要补的事实与能力

**A. 调用点绑定（扩展现有 `PARAM_BINDING` + 新 `CallSiteBinding`）**

- `PARAM_BINDING` 继续只承载 identifier 实参（taint / null / ownership 的既有语义不能变），props 增加 `arg_kind / arg_text / line`；
- `CallSiteBinding` 记录**所有**位置实参，包括非 identifier 形态：
  - `identifier`：`buffer`、`offset`；
  - `sizeof_expression`：`sizeof(data)` → 容量；
  - `pointer_expression` / `&x`：地址传递；
  - `cast_expression`：`(char *)buf`；
  - `number_literal` / 宏：常量容量；
  - `call_expression`：`malloc(n)` 结果。
- `CallSiteBinding` 字段至少包含：`callee / index / param / arg_kind / arg_text / line / capacity / provenance`。
- 不能确定调用目标（函数指针未解析、同名 static 多定义、外部函数）时**不伪造绑定**，该调用点标记 `unknown`。

**B. 调用点容量事实 `CallSiteBinding`**

对每个绑定，尝试解析实参对象容量：

| 实参形态 | 容量来源 | 示例 |
|---|---|---|
| `arr`（局部数组） | 数组声明 `count`（元素数） | `char data[16]` → 16 字节（char） |
| `sizeof(arr)` | `count * sizeof(elem)`（字节） | `sizeof(data)` → 16 |
| 全局数组 | `repofacts.GlobalArray` | `extern char g_buf[256]` |
| 结构体数组成员 | `repofacts.FieldByTag` + 基址偏移（需 Type Layout） | `s->arr` |
| `malloc(n)` / `calloc(n,m)` | 常量折叠后的字节容量 | `malloc(8)` |
| 未知/变量 | 不产生容量事实 | `malloc(len)` → unknown |

**关键单位问题**：C 的 `buffer[index]` 索引单位是元素，`sizeof(数组实参)` 的单位是字节（对指针形参 `sizeof(ptr)` 只是指针宽度，不是容量）。关联必须带 `elemSize`：

```
byte_capacity = sizeof(actual)
elem_capacity = byte_capacity / elemSize(pointee_type)   // 必须能整除
guard: index < elem_capacity
```

`elemSize` 来自 Type Layout（1038）。注意 `sizeof(*buffer)` 只是元素大小，绝不能当作容量。元素大小为未知或不能整除 → 该调用点只能 `suspected`。

**C. Buffer-Length 关联（per call site）**

只有明确证据才建立 `length` 是 `buffer` 的容量：

1. 同一调用点 `f(arr, sizeof(arr), ...)`，且**实际实参 `arr` 是数组**（不是指针）、形参 0 是 buffer、形参 1 是 length；若实际实参是指针，`sizeof(ptr)` 只是指针宽度，不能当容量；
2. 同一调用点 `f(buffer, CAP)`，其中 `CAP` 是该对象声明的容量宏；或 `f(buffer, count)`，其中 `count` 是同一对象声明的元素个数（不是 `sizeof(*buffer)`——那是**元素大小**，不是容量）；
3. 同一调用点 `f(struct.field, sizeof(struct.field))`；
4. 函数内部存在把 `length` 直接作为 `buffer` 边界使用的既有契约（例如 `memcpy(dst, src, length)` 的 dst 是 buffer）——这属于“函数内部关系”，只能作为辅助证据，不能单独确定。

**明确不建立关联**：变量名相似（`len` / `buffer_len`）、参数顺序、类型相同。Issue 明确禁止，且这是 1029 误报的主要来源。

**D. Guard Witness（结构化证据，不是布尔）**

评审 P0-2 明确：`ReachesAvoiding` / 支配关系只能证明控制流可达性，**不能替代谓词语义、对象/容量关联和变量稳定性**。当前 `hasIndexBoundsGuard` 只支持常量/宏上界，且是行序 + `bodyExits` 的启发式，不足以承担 1029 的 dismiss。

Guard Witness 必须同时回答：

1. **控制流**：guard 节点是否支配访问点？访问是否处于正确的分支方向？
2. **谓词语义**：比较表达式是否确实约束了本次访问使用的 `index`（同一个值，含 cast 后同一值）？
3. **对象/容量关联**：guard 上界（如 `length`）是否与本次访问的 `buffer`/object 存在可证明的容量关联？不能是“另一个 buffer 的 length”。
4. **稳定性**：guard 到访问之间，`index`、`buffer`、`length` 是否被重新赋值，或经 alias/pointer side effect 改变？
5. **副作用**：是否存在别名写入、函数调用副作用、指针偏移变化或未知外部调用，使此前的检查失效？
6. **整数语义**：`<` 与 `<=`、有符号负数、整数转换/提升、`index * elemSize` 溢出是否正确处理？
7. **路径形状**：`&&`、`||`、early return、循环、多分支路径中，真正保护访问的路径是否被正确识别？

建议把 Guard Witness 拆成明确字段（不是单一布尔）：

| 字段 | 含义 |
|---|---|
| `guard_location` / `access_location` | guard 与访问的 file:line / CFG 节点 |
| `guard_predicate` | 规范化后的比较表达式 |
| `branch_polarity` | 访问落在真/假分支，或早退后的存活分支 |
| `index_binding` | guard 中的 index 与访问中的 index 是同一值 |
| `buffer_object_binding` | 访问的 buffer/object 就是 guard 所约束的对象 |
| `capacity_binding` | guard 上界与 buffer 容量的关联（调用点证据） |
| `index_stable` / `buffer_stable` / `length_stable` | guard→access 之间未被重赋值 |
| `alias_stability` | 无 alias/指针 side effect 改变对象或长度 |
| `call_side_effect_status` | 中间调用是否有未知写入/副作用 |
| `proof_status` | `must` / `may` / `unknown` |

只有 `proof_status=must` 才能 dismiss；`may`/`unknown` 必须保留 `suspected`/`AI_REQUIRED`。

**必须击穿的反例**（评审给出，测试必须覆盖）：

```c
/* 1. buffer 在 guard 后被替换：检查的是旧 buffer 的 length */
if (index < length) {
    buffer = another_buffer;
    buffer[index] = 0;
}

/* 2. length 在 guard 后变化：检查已失效 */
if (index < length) {
    length = 1;
    buffer[index] = 0;
}

/* 3. 检查的是另一个对象的 length */
if (index < other_buffer_length) {
    buffer[index] = 0;
}
```

此外还要覆盖：`index` 重赋值、`buffer` 重赋值、`length` 重赋值、alias 写入、函数调用副作用、负索引、`<` vs `<=`、`&&`/`||` 短路、early return、循环内访问、多分支。

### 4.4 最小可行实施范围（MVP）

1. **扩展 `PARAM_BINDING` 的 props**（identifier 实参），不把所有实参塞进图边，避免 taint fixpoint 的边膨胀；非 identifier 实参由 `CallSiteBinding` 承载；
2. **新增 per-scan `CallSiteBinding` 索引**（内存，ctx 注入），容量解析复用 `findArraySize` / `GlobalArray` / `heapAllocationSize` 的规则；
3. **新增 `detectParamIndexAccess`**（在 `buffer_overflow.go` 内，不新建 Detector）：只对“buffer 是形参、索引是形参/局部、且至少一个调用点有容量事实”的访问播种；
   - 常量索引 + 容量已知 → `param_oob_read/write`，`suspected` 起步，由过滤器决定是否升级；
   - 变量索引 + 存在 buffer-length 关联 → `param_index_unchecked_read/write`，`suspected`；
4. **新增 `ParamCapacityGuardFilter`**（加入 `chainBufferOverflow`）：
   - 只有满足 §4.3D 全部条件且 `proof_status=must` 的守卫才 dismiss（写入 `Dismissed` ledger）；
   - 常量索引 × 元素大小 ≥ 容量，且对象/容量/layout 证据完整、无有效守卫 → 才考虑升级 `confirmed`（需评审批准独立 proof class，见 §10）；
   - 守卫为 `may`/`unknown`、对象/容量关联不成立、index/buffer/length 不稳定、alias/调用副作用未知 → 保持 `suspected`，evidence 写清容量来源、关联依据、守卫缺失/失效原因；
5. **去重**：同一 `(callee, access line, capacity)` 只出一个候选，多个调用点作为 `callers@` / `Clustered Sites` evidence，不重复 finding；
6. **不改变** `detectUncheckedIndex` 现有的结构体字段索引通道。

### 4.5 确认/降级边界

| 场景 | 目标 tier | 依据 |
|---|---|---|
| 常量索引 + 调用点容量已知 + 无守卫 | `confirmed`（待评审批准 proof class） | 区间/常量 + 对象边界 |
| 变量索引 + 有 buffer-length 关联 + 无守卫 | `suspected` | 关联是证据，索引范围未知 |
| 变量索引 + guard `must`（支配 + 正确分支 + index/buffer/length 稳定 + 对象/容量关联 + 无 alias/副作用） | dismiss | 完整 Guard Witness |
| 守卫为 `may`/`unknown`，或 index/buffer/length 重赋值、alias 修改、调用副作用未知 | `suspected`，不得 dismiss | 证据不足 |
| 守卫上界是另一个长度（`packet_len` / `other_buffer_length`） | 不 dismiss；容量若可从常量索引证明则 confirmed，否则 suspected | 不误关联 |
| 容量未知 / 元素大小未知 / layout `assumed`/`unknown` | `suspected` 或不出 | fail-open |
| 多调用点容量不同 | 取能证明越界的最小容量；保留调用点上下文 | 不合并成全局常量 |

### 4.6 风险

- **体量风险**：普通 `buf[i]` 形参代码极多；必须要求“至少一个调用点容量事实 + 常量索引或 buffer-length 关联”，否则会淹没 AI。
- **误关联风险**：`length` 不一定是容量；只接受 §4.3C 的显式证据。
- **多调用点语义**：一个调用点越界不代表所有调用点越界；evidence 必须写清是哪个调用点。
- **跨文件**：`PARAM_BINDING` 已支持跨文件，但调用点容量解析需要读取调用者所在文件；`CallSiteBinding` 必须按 caller file 解析，不能只用被调用者文件。
- **函数指针/间接调用**：现有 `FuncPtrWriteBuilder` 能解析一部分 slot；未解析的必须标 unknown，不能猜。

### 4.7 测试映射

新增：

| 测试 | 预期 |
|---|---|
| 固定数组 + `sizeof` 容量 + 常量越界索引 | `confirmed`（评审批准后） |
| `malloc` + 已知容量 + 常量越界索引 | `confirmed` |
| 函数参数 + 调用点已知容量 + 常量越界索引 | `confirmed` |
| 函数参数 + `length` 为容量 + 有效 `index < length` 守卫 | 无候选 |
| 函数参数 + `length` 为容量 + 无守卫 | `suspected` |
| `length` 实际不是 buffer 容量 | 不建立关联 |
| 多个调用点容量不同 | 保留调用点上下文，不合并 |
| 多层函数调用 | 正确传播（至少 2 层） |
| 守卫后 `index` 被重赋值 | 不认为受保护 |
| 守卫后 `buffer` 被替换（另一个 buffer） | 不认为受保护 |
| 守卫后 `length` 被重赋值 | 不认为受保护 |
| 守卫检查另一个对象的 `other_buffer_length` | 不建立容量关联 |
| alias 写入 / 中间函数调用副作用 | 守卫失效或降级 suspected |
| 有符号负索引 | 识别负索引风险 |
| `<` vs `<=`、`&&`/`||`、early return、循环、多分支 | 正确判定保护路径 |

夹具：`sgre/testdata/feedback_watch/CWD-SUB-1029-pointer-offset/*` + 新增 `sgre/testdata/param_capacity/`（或直接放 `feedback_watch` 子目录）。

---

## 5. CWD-SUB-1038：C/C++ 类型大小与结构体字段偏移模型

### 5.1 当前代码路径（为什么漏）

`read_record`：

1. `malloc(8)` 产生 `MEMORY_ALLOC` 事件，但 `raw` 的容量只以**表达式文本**存在（`heapAllocationSize` 返回 `"8"`），没有对象类型/字节容量事实；
2. `record = (struct LargeRecord *)raw` 是 cast，`AliasGraph` 能记录 alias，但没有“目标类型布局”；
3. `record->value` 是 `field_expression`，`detectArrayOOB` 只处理 `subscript_expression` 和 `*(p+i)`，不处理字段访问；
4. `detectUncheckedIndex` 只处理 `memberSubscriptBase`（成员数组下标），不处理字段访问；
5. `repofacts.FieldFact` 只有 name/type/pointer/array count，没有 `Offset / Size`；`typeKeys` 能取 tag/typedef 别名，`fieldFacts` 记录字段形态但不计算布局（`repofacts/helpers.go:46`）；
6. `sizeof(struct T)` 没有被求值；`sizeofTypeName` 只提取类型名用于精确 fit 匹配（`buffer_overflow.go:1702`）。

**同一个缺陷的 `memcpy` 形态**（`memcpy(raw, &tmp, 24)` 到 `malloc(8)`）由 `bounded_copy_overflow` 检测——这证明缺口是“类型/偏移知识”，不是“缓冲区访问通道”。

### 5.2 可复用设施

- `repofacts` 的跨文件 header census、typedef 别名、宏容量、歧义即未知；
- `AliasGraph` 的 cast alias / 全局 alias；
- `AliasGraph` 与 `cfgCache` 的 per-scan ctx 注入模式；
- `heapAllocationSize` / `constantAllocationSize` 的分配容量解析；
- `bounded_copy_overflow` 的“copy size vs capacity”证据与 category（可参照，不重复实现）；
- `evidence/typedefs.go` 的 typedef 传递解析 + `widthOf`（需要先收敛重复宽度表）。

### 5.3 需要补的事实：Type Layout（TU/编译配置相关）

**评审 P0-1 的结论：target triple 不是完整 ABI 证明，Type Layout 必须按 Translation Unit / 编译配置隔离。**

同一份源码在不同 `-fpack-struct` / `-fshort-enums` / `#pragma pack` / attributes / 条件编译宏下可以有不同布局；同名类型在不同 TU 采用不同宏配置时也不能无条件合并。

**事实模型（示意）**

```go
type LayoutKey struct {
    TU     string // 编译单元 / 编译配置 id
    Config string // target + pack/alignment/short-enums/macro 配置摘要
    Type   string // struct tag / typedef alias
}

type TypeLayout struct {
    Key        LayoutKey
    Name       string
    Size       int    // bytes
    Align      int    // bytes
    Kind       string // "primitive" | "struct" | "union" | "array" | "pointer"
    Fields     []FieldLayout
    Provenance string // "compiler_proven" | "derived_from_complete_config" | "assumed_default_abi" | "unknown"
    Source     string // "clang-record-layout" | "compile_commands" | "repofacts" | "default-abi"
    Unknown    string // 非空表示不可用原因
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

**Layout provenance / confidence（评审要求）**

| 档位 | 含义 | 是否可用于 `confirmed` |
|---|---|---|
| `compiler_proven` | 由与目标编译配置匹配的权威布局信息直接提供（未来可选数据源：Clang AST Record Layout Dump；本轮不要求引入 Clang 依赖） | 是（需同时满足其他证据完整性） |
| `derived_from_complete_config` | 输入配置完整（target + pack/alignment/short-enums + 宏配置），按受约束 ABI 规则推导 | 是（需证据完整） |
| `assumed_default_abi` | 基于默认 ABI 假设（例如没有 `compile_commands.json`，或缺少 pack/alignment 信息） | **否**，只能 suspected |
| `unknown` | 关键信息缺失、跨 TU 冲突或无法建模 | **否**，不报或 suspected/AI_REQUIRED |

**TU/编译配置维度**

- `LayoutKey` 必须包含 `TU`/`Config`；同名类型在不同 TU/宏配置下是不同布局，不能合并。
- 同一 `(TU, Config, Type)` 下出现冲突定义（不同字段/大小）→ `unknown`，不猜。
- `compile_commands.json` 当前只做全局 union `-D/-I`（`build/compile_commands.go`）；layout 需要**逐 entry** 的 `File / Directory / Arguments`，并从中提取 `target`、`-fpack-struct`、`-fshort-enums`、`-D` 等，形成 `ConfigKey`。
- 没有某文件的 compile entry → 该 TU 为 `assumed_default_abi` 或 `unknown`；不能拿另一个 TU 的配置套用。

**布局算法**

1. 基本类型：用**一张** ABI 表（LP64 / ILP32 / LLP64），输入来自当前 TU 的 target/ABI 选项；不用宿主机 `sizeof`；
2. typedef：传递解析到基本类型/复合类型；
3. struct：按声明顺序，`offset = alignUp(offset, fieldAlign)`，`structAlign = max(fieldAlign)`，`size = alignUp(offset, structAlign)`；应用当前 TU 的 pack/align 规则；
4. union：`size = max(fieldSize)`，`align = max(fieldAlign)`；
5. 数组：`size = count * elemSize`，`align = elemAlign`；
6. 嵌套 struct/union：递归；匿名 struct/union 按 C11 规则展平到父偏移；
7. 指针：按当前 ABI 宽度（LP64/LLP64 = 8，ILP32 = 4）；
8. enum：按当前 TU 的 `-fshort-enums`/target 规则；无法确定 → unknown；
9. `-fpack-struct`、`#pragma pack`（含 push/pop 作用域）、`__attribute__((packed))`、`__attribute__((aligned(N)))`：能解析且配置完整则应用；任一未知 → 受影响类型 `unknown`；
10. 条件编译（`#if`/`#ifdef`）导致字段差异：按当前 TU 的宏配置求值；宏配置未知或冲突 → `unknown`；MVP 不允许“忽略条件、取一支”；
11. 位域 / 柔性数组 / 复杂编译器扩展：**MVP 直接 unknown**，不猜偏移；
12. 任何字段类型/布局因子无法解析 → 整个 struct `unknown`，禁止输出部分偏移。

**ABI 来源**

- `compile_commands.json` 逐 TU 解析：`-m32` → ILP32；`-m64` / `--target=x86_64-*` → LP64；`--target=*-windows-*` → LLP64；`-target <triple>` 同样处理；
- `-fpack-struct`、`-fshort-enums`、`-fpack-struct=N`、对齐相关 flags 进入 `ConfigKey`；
- 多个 TU 的 target/pack/宏冲突 → 各自独立 layout；同名类型不合并；无法确定时 `unknown`；
- 没有 `compile_commands.json` → `assumed_default_abi`，`Provenance=assumed_default_abi`；**禁止**仅凭默认 LP64 产生 `ABI-proven`/`confirmed`；
- **禁止**用分析机 `unsafe.Sizeof` / `sizeof(void*)` 代替目标 ABI。

**落点**

- 布局算法放 `internal/typeinfo`（纯函数 + 单测）；`repofacts` 负责 census 与按 `LayoutKey` 持有 layout；
- 如果为了包依赖方向需要拆分，`repofacts` 与 `evidence` 必须共用同一个 layout 实例，不能各建一套；
- 收敛重复宽度表：`evidence/typedefs.widthOf` 与 `graph/types_width.lp64Widths` 合并到共享包，二者改为委托。这是 Phase 1 的**前置重构**，否则 1038 会产生第三张表；
- `compile_commands` 扩展为 per-TU 配置；如果短时间无法完成，所有 layout 一律 `assumed_default_abi` 或 `unknown`，只能 suspected。

### 5.4 OOB 集成

**访问范围公式**

```
access_start = object_base_offset + field.Offset
access_end   = access_start + field.Size
OOB if access_start < 0 || access_end > allocated_object_size
```

必须区分：

- `malloc(sizeof(*p))` → `allocated_object_size >= access_end`，合法；
- `malloc(8)` + `p->value` at offset 16 → 越界；
- 字段部分落在边界外（`offset < size` 但 `offset + fieldSize > size`）→ 越界；
- `calloc(n, sizeof(T))` → `n * sizeof(T)`，乘法溢出检查；
- 指针已偏移（`p = raw + k`）→ `object_base_offset` 需要加上偏移；MVP 只支持基址未偏移或常量偏移；
- 嵌套字段 / 数组字段索引 → 递归累加 offset；MVP 只支持一级字段 + 常量数组索引；
- 布局 `Provenance` 为 `assumed_default_abi` 或 `unknown` → 不出 `confirmed`；
- 分配大小未知 / 不是常量或区间可证明 → 不出 `confirmed`。

**category 与 proof class（评审已决定）**

使用独立的 `layout_oob_read` / `layout_oob_write`，**不复用** `heap_oob_read/write`：

- 现有 `heap_oob_*` 的 confirmed 证明是“常量/区间索引超出已知分配大小”；
- 字段偏移证明是“类型布局 + TU/编译配置”，属于新的 proof class；
- 复用会把不完整的 layout 证据冒充成现有 heap proof，违反 `AI_JUDGMENT_BOUNDARY.md` 与评审决定。

如果 Phase 1 评审不批准新增 confirmed proof class，则 `layout_oob_*` 只出 `suspected`，并在 Remaining Gap 中记录。

**判定边界**

| 场景 | 目标 tier | 条件 |
|---|---|---|
| `compiler_proven` 或 `derived_from_complete_config` + 字段/分配/整数证据完整 + 无有效守卫 | `confirmed`（仅当 Phase 1 评审批准独立 layout proof class） | 证据完整性表 §3.4 |
| `assumed_default_abi` / `unknown` / 跨 TU 冲突 / pack/align 未解析 / bitfield/flexible array | `suspected` 或不出 | 不得 confirmed |
| 字段部分越界/部分布局未知 | `suspected`/`AI_REQUIRED` | 不猜偏移 |
| 分配大小未知/非常量/不可区间证明 | 不出 confirmed | fail-open |
| `malloc(sizeof(*p))`、`calloc(n,sizeof(T))` 等合法对照 | dismiss | 范围覆盖 |

### 5.5 最小可行实施范围（MVP）

1. 收敛宽度表 + typedef 解析（前置重构，纯行为保持，补单测）；
2. `compile_commands` 扩展为 per-TU 配置（File/Directory/Args/Target/Pack/ShortEnums/Defines），形成 `ConfigKey`；
3. `repofacts` 增加按 `LayoutKey` 隔离的 Type Layout（基本类型、typedef、struct、union、数组、指针、嵌套 struct；packed/aligned 逐步支持；bitfield/flexible array/条件编译 unknown）；
4. 新增 `detectCastObjectOOB`（或在 `buffer_overflow.go` 内扩展）：
   - 识别 `cast_expression` 到 struct 指针 + 该指针的字段访问；
   - 通过 `AliasGraph` 追到分配基址；
   - 比较 `offset + size` 与分配字节容量；
   - 产出 `layout_oob_read/write`（MVP suspected；confirmed 需评审批准新的 type-layout proof class）；
5. AI evidence：`## Type Layout` 段（TU/Config、provenance/confidence、字段偏移/大小、来源）、分配容量、字段访问表达式；
6. 测试：Issue §3.5 的 12 类 + TU/编译配置差异 + inline/header-split invariance。

### 5.6 风险

- **ABI/配置不确定性**：target triple 不够；`-fpack-struct`、`#pragma pack`、attributes、条件编译都会改变偏移。MVP 必须把 `Provenance`/`Config` 写进 evidence；`assumed` 不做 confirmed。
- **跨 TU 冲突**：同名类型在不同 TU/宏配置下不同；不得合并；冲突 → unknown。
- **类型系统复杂度**：typedef 链、匿名 struct、嵌套、位域、flexible array、`__attribute__`、`#pragma pack`。MVP 明确 unknown，不追求全覆盖。
- **第三方头文件**：`repofacts` 已扫描 worktree headers，但第三方 include 路径可能不在 worktree 内；未知 → unknown。
- **性能**：布局计算与 TU/config 解析需要缓存；不要为每个访问重新计算整个 layout。
- **误报**：`malloc(sizeof(*p))`、`calloc`、`realloc`、指针偏移、union 别名、条件编译都可能让朴素比较误报；所有安全对照必须先过。

### 5.7 测试映射

Issue §3.5 的 12 类 + 评审新增：

- 基本类型/typedef/struct/union/数组/指针/嵌套/匿名；
- 不同 pack/alignment 配置（`-fpack-struct`、`#pragma pack(push,N)`、`__attribute__((packed))`、`aligned`）下同一 fixture 得到不同布局，或明确 unknown；
- 不同 TU/宏配置下同名类型不合并；
- 缺失编译参数 → `assumed_default_abi`/`unknown`，不 confirmed；
- `-fshort-enums` / enum 宽度；
- 位域 / flexible array → unknown；
- `malloc(sizeof(struct T))` / `calloc(n, sizeof(struct T))` 合法；
- 字段偏移越界 / 部分越界；
- 不同 ABI（`-m32` vs `-m64`）下同一 fixture 的不同偏移（需完整配置）；
- 未知类型布局 → 不 confirmed；
- inline vs header-split 布局一致（`TestDeclarationFactInvariance`）。

---

## 6. CWD-SUB-1031：全局变量写入值的跨过程传播

### 6.1 当前代码路径（为什么漏）

`03_interprocedural_global_deref.c`：

1. `static struct Session *g_session;` 是 static 零初始化；
2. `detectStaticNullGlobals`（`null_source.go:104`）检查 `staticGlobalNeverReassigned`：`initialize_session` 里有 `g_session = session`，非 NULL 赋值 → 返回 false → **不播种**；
3. `null_source` 不建模“参数写入全局”，`dereference` 产出 `DEREFERENCE` 事件但 `filter_nullable_source` 的 `nullModel` 里没有 `g_session` 的 NULL 来源 → 候选被 drop；
4. `GLOBAL_ACCESS` 边存在（`initialize_session` → `g_session` write；`consume_session` → `g_session` read），但边不携带 **写入值来源**；
5. `caller_null` 只处理“参数是否可为 NULL”，不处理“参数被写进全局，之后在另一个函数被读”。

### 6.2 可复用设施

- `file_scope_variables`（name/type/storage/decl line/is_pointer）；
- `GLOBAL_ACCESS` 边的 function→global 读写关系；
- `AliasGraph` 的全局别名（`g = p`）；
- `caller_null` 的 open-chain fixpoint（参数可空性传播）；
- `filter_nullable_source` 的 entry-seeded 来源机制（`global_null` 已走这条路）；
- `FuncSummary` 的 outparam write 覆盖（参数是否被写穿，可复用为“参数→全局”的写入来源置信度）；
- `ThreadFunctions` / race 检测的线程入口信息（用于并发写入的降级）。

### 6.3 需要补的事实：Global Write Summary（来源摘要，不是状态）

评审 P0-3 明确：

> “某个函数可能把 NULL 写入全局变量”不等于“另一个函数执行到解引用位置时，该全局变量必然为 NULL”。

必须区分四个层级：

1. 某函数存在 NULL 写入（writer/source 事实）；
2. 某函数在特定路径上可能写入 NULL（path / condition）；
3. 某次调用实际执行了该写入（call context / call order）；
4. 写入之后没有覆盖，Consumer 执行时该值仍为 NULL（state at consumer）。

`GlobalWriteSummary` 只负责第 1-2 层；第 3-4 层由消费侧结合调用点、可达性、调用顺序、覆盖和未知写入源另行证明。

**事实模型（示意）**

```go
type GlobalIdentity struct {
    Name         string
    StorageClass string // "static" | "extern"
    File         string // static 全局按文件区分；extern 程序级
}

type GlobalWriteFact struct {
    Global      GlobalIdentity
    Writer      string
    File        string
    Line        int
    SourceKind  string // "null" | "param" | "local" | "call" | "opaque"
    SourceParam int
    SourceName  string
    PathCondition string // 所在分支条件（可空）
    WriterDefinite bool  // 该写入在 writer 函数内是否 every-path（不是 consumer 状态）
    Nullable    string // "null" | "maybe-null" | "non-null" | "unknown"
    Callers     []string
    Escape      bool   // 全局地址逃逸 / &g / memcpy(&g,...)
    UnknownWriter bool   // 外部/函数指针/宏写入可能
    Concurrency   bool   // 线程/原子/volatile 风险
}
```

**全局身份**

- `static` 全局：每个 TU 一个对象，按 `(File, Name)` 区分，不能与另一个文件的同名 static 合并；
- `extern` 全局：程序级一个对象，按 `Name` 汇总所有 TU 的 writer；
- 同名 static/extern 混用 → `unknown`，不猜。

**落点与并发约束（重要）**

检测器由 `evidence.RunAllDetectorsWithSkip` **并发执行**（`cli/pipeline.go:291`）。因此，1031 的新事实**不能依赖另一个检测器的产物**，也不能依赖 runs-after-detectors 的 `EnsureFunctionSummaries`。`GlobalWriteIndex` 必须在检测器开始前的阶段构建，并通过 ctx 注入（与 `AliasGraph` 同一模式，`cli/pipeline.go:266`）。MVP 不持久化；如果后续 planner/report 需要跨阶段复用，再合并进 `summary_json`，但检测器阶段的来源始终是这个 pre-detector 索引。

**写入识别**

- 直接赋值 `g = p` / `g = NULL` / `g = malloc(...)`；
- 条件赋值（记录 condition）；
- 简单指针转换 `g = (T *)p`；
- 多个写入函数；
- 跨文件 extern 全局；static 全局只在本 TU 可见。

**不识别 / 标 unknown**

- `memcpy(&g, ...)`、宏写入、`&g` 逃逸、外部函数修改；
- volatile / atomic；
- 多线程并发写；
- 函数指针/间接调用可能写全局；
- 无法确定 writer 集合或全局身份。

### 6.4 消费侧：如何进入 nullability（只允许 may）

**A. 新 origin `global_write`（may-only）**

- 新增检测器（或在 `null_source.go` 内）为每个**解引用全局**的函数发射 `NULL_VALUE`，`origin=global_write`，props 带 writer/source/condition/callers/unknown-writers；
- **不得**把 `global_write` 当作 `definite`：`ProofStatus` 只能是 `may`（或 `unknown`）；`nullSource.definite=false`；不得仅因 writer 摘要把 Consumer 入口状态标成确定 NULL；
- `filter_nullable_source` 可以把它作为 entry-seeded 的 **may** 来源（与 `caller_null`/`global_null` 的 may 语义一致），但必须保留“possible source”证据，不能升级为 `confirmed`；
- tier：
  - 如果所有 in-scan writer 的 source 都是 NULL，且没有 non-null writer、没有外部 writer/escape/concurrency → 仍只能 `suspected`（除非完成 §6.4B 的完整状态证明并评审通过）；
  - 如果至少一个 writer 是参数，且该参数在某个调用点收到 NULL → `suspected`，标注“可能来源”；
  - 如果存在多个 writer / 覆盖 / 未知外部 writer / escape / 并发 → `suspected`/`AI_REQUIRED` 或不出，evidence 列出竞争写入者与不确定性。

**B. Confirmed 的最低条件（评审 P0-3）**

`confirmed` 必须同时满足：

1. NULL 写入来源可确定；
2. 对应调用上下文和调用顺序可证明；
3. Consumer 使用前不存在覆盖该值的其他写入；
4. 不存在无法排除的外部 writer、逃逸写入或并发修改；
5. 解引用路径可达且没有有效 NULL guard。

当前 per-function flow engine 无法证明跨函数全局状态；**Phase 3 不承诺任何 `global_write` confirmed**。如果后续实现调用点内联/调用顺序证明，必须先满足上述 5 条并单独评审，不能在本阶段用“同函数直线顺序”直接推导 Consumer 状态。

**判定边界**

| 场景 | 目标 tier | 条件 |
|---|---|---|
| 所有 writer 均 NULL，无未知 writer/escape/并发，但调用顺序/覆盖未证明 | `suspected` | 来源摘要，非状态 |
| 调用顺序、覆盖、未知 writer、escape、并发全部可证，且可达/无 guard | 未来才讨论 `confirmed`（Phase 3 不实现） | 必须满足 5 条并单独评审 |
| 多 writer / 覆盖 / 未知外部 writer / escape / 并发 | `suspected`/`AI_REQUIRED` 或不出 | 证据不足 |
| 仅“可能写 NULL” | `suspected`，标“可能来源” | 不得描述成确定 NULL |
| static-only 从未写入（现有 `global_null`） | 现有 tier（suspected） | 不是写入摘要 |

**C. 状态污染防护**

- 不能把“一次 NULL 写入”传播为“永久 NULL”；
- 每个 writer 的 `PathCondition`/`WriterDefinite` 必须保留；
- `static` vs `extern` 的可见性要区分：`static` 的“无外部 writer”在单 TU 内可证明；`extern` 默认存在未知外部 writer；
- 线程函数写入 / volatile / atomic → 不做 confirmed；
- `&g` 逃逸、`memcpy(&g,...)`、函数指针调用 → writer 集合不完整，`unknown`。

### 6.5 最小可行实施范围（MVP）

1. 在 `cli/pipeline.go` 的检测器阶段之前构建 `GlobalWriteIndex`（单次遍历，复用 `RepoIndex` / `AliasGraph`），ctx 注入；**不**把全局写入塞进被 3 个检测器各调用一次的 `buildFuncSummaries`；
2. 在 `null_source.go` 新增 `detectGlobalWriteNull`（读 ctx 中的 `GlobalWriteIndex`），为解引用全局的函数发射 `origin=global_write`、`ProofStatus=may` 的 `NULL_VALUE`；
3. `null_analysis.go` / `filter_nullable_source.go` 识别 `global_write`，按 **may-only** 处理：保留候选、输出“可能来源”证据，不做 confirmed；
4. evidence：writer 列表、source kind、condition、覆盖写入、未知外部 writer、escape、线程风险；
5. 测试：Issue §4.4 的 12 类 + 评审新增的 writer/overwrite/escape/concurrency 场景；MVP 不新增 confirmed 断言。

### 6.6 风险

- **may→must 误升级**：全局状态是程序级事实，局部证据不足就确认会大量误报；MVP 默认 suspected，且不承诺 confirmed。
- **并发**：多线程写入无法用当前 CFG 证明，必须 suspected/unknown。
- **外部写入**：`extern` 全局可能被扫描树外修改；除非完整程序扫描，否则不能确认。
- **同名 static**：不同文件的同名 static 是不同对象，不能合并。
- **性能**：全局写入普查需要遍历所有赋值；与 `GLOBAL_ACCESS` 合并可减少一次遍历。

### 6.7 测试映射

Issue §4.4 的 12 类 + 评审新增：

- 单 writer NULL / 单 writer 非 NULL；
- 两个 writer 分别 NULL / 非 NULL；
- 先写 NULL 后被覆盖；
- 条件写入（路径相关）；
- writer 从未被调用；
- 函数指针/外部 writer（writer 集合不完整）；
- 全局地址逃逸（`&g` / `memcpy(&g,...)`）；
- 多线程/volatile/atomic；
- 多层调用、跨文件 extern、同名 static 两个文件；
- 静态初始化（现有 `global_null` 通道）；
- 赋值后 NULL 检查保护；
- 所有场景不得把 may-write 直接断言为 Consumer 当前 NULL。

---

## 7. CWD-SUB-1140：输出参数初始化覆盖

### 7.1 当前代码路径（为什么是“部分支持”）

`07_outparam_contract.c`：

1. `buildFuncSummaries`（`free_summary.go:46`）为 `load_value` 计算 `computeParamWriteState`：
   - `*out = 42` 在 `if (success)` 内；
   - `states` 用 `ReachesAvoiding(Entry, writeNodes, Exit)` 判断不是 every-path → `ParamWrites[0]=false`，`ParamConditionalWrites[0]=true`；
2. `uninit_variable.go:432-490` 看到 `&value`：
   - `hasSummary=true`，`summary.ParamWrites[0]=false`；
   - `summary.ParamConditionalWrites[0]=true`；
   - `outputParamGuardLine` 找不到错误守卫（调用者用 `(void)` 丢弃返回值）；
   - **fallback：`initLine = call.StartLine()`，信任写回惯用法**；
3. 后续 `if (value > 0)` 读取被抑制。

这是**刻意的 false-negative**，注释（`uninit_variable.go:468`）和 `TestUninit_OutputParamUnguarded` 都锁定了它。所以 1140 不是“没有摘要”，而是“摘要没有成功/失败返回路径的精度，调用者侧选择了 fail-open”。

### 7.2 可复用设施

- `FuncSummary.ParamWrites / ParamConditionalWrites`；
- `computeParamWriteState` + `states` 的 CFG must-reach；
- `outputParamGuardLine` 的调用者错误守卫识别；
- `DefiniteInitFilter.hasOutputParamWrite` 的“写穿不可见”降级；
- `function_summary.summary_json` 的 merge/upsert 模式；
- `## Callee Definition` 已能嵌入 callee body。

### 7.3 需要补的事实：Return Contract + 逐路径/字段级覆盖

评审 P0-4 明确：不能假设 `return 0` 成功、非 0 失败。不同 API 可能有多个成功码、多个失败码、负数错误码、枚举返回值、特殊状态码，甚至返回值只表示数量/状态。

**Return Contract Evidence**

```go
type ReturnContract struct {
    SuccessValues []string // 合约规定的成功返回集合
    ErrorValues   []string // 合约规定的失败返回集合
    OtherValues   []string // 未归类/其他返回值
    Source        string   // "project-convention" | "api-contract" | "local-proof" | "unknown"
    Confidence    string   // "proven" | "assumed" | "unknown"
}
```

合约来源必须是可审计的：

- 项目内显式约定（宏/常量/文档/函数注释中能证明的契约）；
- 可信 API contract（`apikb` 中已有语义）；
- 局部可证明语义（函数体内每条 return 的常量/枚举含义可被证明）；
- 以上都没有 → `Source=unknown`，`Confidence=unknown`。

**逐 return path + 字段/子对象覆盖**

```go
type FieldCoverage struct {
    Path   string // "" = 整个参数；"status" / "data" / "nested.field" = 子对象
    Covered bool
    WriteLine int
}

type ParamReturnCoverage struct {
    ReturnValue  string // 原始返回值文本或规范化值
    ReturnClass  string // "success" | "error" | "other" | "unknown"（由 ReturnContract 派生）
    ReturnLine   int
    WriteLines   []int
    WholeParam   bool          // *out = ... / memset(out,...) 等整体写入
    Fields       []FieldCoverage // 字段/子对象级覆盖
    Covered      bool          // 本次 return 对“调用者实际消费目标”是否覆盖
    Condition    string
}

type FuncSummary struct {
    // ... existing fields
    ParamReturnCoverage map[int][]ParamReturnCoverage // param index -> per-return coverage
    ReturnContract      ReturnContract
}
```

关键规则：

- **写入 `out->status` 不等于整个 `Result` 已初始化**；如果调用者读取 `out->data`，必须按字段级覆盖判定，不能把参数级 `ParamWrites` 当作整体已初始化。
- `*out = ...` / `memset(out, ...)` / 返回结构体整体写入 → `WholeParam=true`；
- `out->field = ...` → 只覆盖该 `Fields[].Path`；
- 通过 helper 间接写入：`ParamWrites`（every-path）可视为整体覆盖；`ParamConditionalWrites` 不视为覆盖，除非按 return 路径细分；
- 循环内写入：记录为 conditional，除非能证明循环至少执行一次。

**计算**

- 对每个 `return` 节点，记录返回值文本/常量、所属分支条件、`!ReachesAvoiding(Entry, writeNodes, returnNode)` 是否被写入支配；
- 用 `ReturnContract` 把 return 分成 success/error/other/unknown；
- 若 `ReturnContract.Confidence=unknown`，不得把任何 return 归类为 success/error；
- 持久化到 `summary_json` 的 `return_contract` / `outparam_return_coverage`，与现有 key 合并。

### 7.4 调用者消费

**A. 检查返回值 + 成功分支读取**

```c
int rc = load_value(&value, success);
if (rc != 0) return;
use(value);   // 只有 ReturnContract 证明 rc==0 是 success 且该 return path 覆盖 value 时才不报
```

- 只有 `ReturnContract` 证明该分支是 success，且 success 的每条 return path 都覆盖调用者实际消费的字段/整体 → 不报；
- 合约 unknown、分支与合约不对应、字段未被覆盖 → 不能 dismiss，保持候选/AI。

**B. 检查返回值 + 错误分支读取**

```c
int rc = load_value(&value, success);
if (rc != 0) {
    use(value);   // error path
}
```

- 只有 `ReturnContract` 证明该分支是 error，且该 return path 对实际消费字段/整体未覆盖 → 可 `confirmed`（must-uninit on that path）；
- 合约 unknown / 字段部分覆盖 → `suspected`/AI，不能 confirmed。

**C. 不检查返回值**

```c
load_value(&value, success);
use(value);
```

- 按仓库现行 `confirmed` 定义（must）→ 只能 `suspected`/`AI_REQUIRED`；
- evidence 必须写：callee 存在未覆盖的失败路径、失败路径不写消费字段、调用者未检查返回、读取在调用之后；
- 这是 may 证据，**不得**升级 confirmed；如果评审未来决定采用 may 语义，必须先修改 `AI_JUDGMENT_BOUNDARY.md`。

**D. 调用者传入已初始化变量**

`int value = 0; load_value(&value, ...); use(value);` → 不报（现有 flow 已处理）。

**判定边界**

| 场景 | 目标 tier | 条件 |
|---|---|---|
| A：成功分支 + Return Contract 证明 + 覆盖完整 | 不报 | dismiss |
| B：错误分支 + Return Contract 证明 + 未覆盖 | `confirmed` | must-uninit on that path |
| C：未检查返回值 | `suspected`/`AI_REQUIRED` | may 证据，不得 confirmed |
| D：调用前已初始化 | 不报 | 现有 flow |
| E：字段/子对象不匹配 | `suspected`（或 must 路径下 confirmed） | 实际消费字段未被覆盖 |
| Return Contract unknown | 不 dismiss、不 confirmed | 不能把“检查返回值”当“检查成功” |
| 间接/别名写入覆盖不完整 | `suspected`/AI | 不 confirmed |

**E. 字段/子对象不匹配**

```c
struct Result { int status; char *data; };
int build_result(struct Result *out) { out->status = 0; return 0; }
...
struct Result r;
build_result(&r);
use(r.data);   // status 被写，data 未写
```

- 不得因为 `ParamWrites`/`out->status` 把整个 `r` 判为已初始化；
- 调用者读取的字段不在 `Fields[].Covered` 中 → 按未初始化处理（至少 suspected；若 return path 是 must 且该字段未覆盖，可 confirmed）。

### 7.5 与 `TestUninit_OutputParamUnguarded` 的冲突

Issue 明确要求保留该测试，但需要区分它锁定的是“不产生 Confirmed”还是“不产生任何候选”。

- 现状：测试断言 `candidateForFunc(...) != nil` 即失败，等价于“不产生任何候选”；
- 本方案建议：改为“不产生 `confirmed`；允许 `suspected`，但必须带 outparam/return-contract 证据”；
- 这是一个**行为变更**，必须由架构评审明确批准，不能静默改期望值；
- 如果评审选择保持“完全静默”，则 1140 的 MVP 只能覆盖 A/B/E 场景，C 保持 Remaining Gap。

### 7.6 最小可行实施范围（MVP）

1. `buildFuncSummaries` 抽成 scan-scoped 单次构建（前置，行为保持）；
2. 扩展 `FuncSummary` 的 `ReturnContract` + per-return/字段级覆盖；
3. `uninit_variable.go` 消费：
   - A 场景：只有合约+覆盖完整才 dismiss；
   - B 场景：只有合约+未覆盖完整才 confirmed；
   - C 场景：`suspected`（推荐）或保持静默（评审决定）；
   - E 场景：字段不匹配不得 dismiss/confirm；
   - 合约 unknown → 不 dismiss、不 confirmed；
4. `DefiniteInitFilter.hasOutputParamWrite` 改为优先查摘要，并做字段级比较，而不是任何 `&x` 都降级；外部未知函数仍 fail-open；
5. evidence：`outparam@success` / `outparam@error` / `return-contract@` token、writer 行、成功/失败集合、覆盖字段；
6. 测试：Issue §5.5 的 15 类 + 评审新增的返回合约/字段覆盖场景。

### 7.7 风险

- **返回约定未知**：不能猜 0/nonzero；unknown 时只能 suspected/AI，不能 confirmed。
- **字段/子对象**：参数级写入覆盖不能替代字段级；`out->status` 不代表 `out->data`。
- **误报**：写回惯用法在 C 代码中极常见；C 场景标 suspected 可能产生大量候选，需要体量评估和 per-function 去重。
- **间接写入**：helper / 宏 / 函数指针写入的覆盖可能不完整；未知时不能确认。
- **与现有测试冲突**：见 §7.5。

---

## 8. 跨 Gap 复用校验（“每个事实至少两个消费者”）

| 新事实 | 消费者 1 | 消费者 2 | 说明 |
|---|---|---|---|
| Type Layout（TU/Config） | 1038 字段偏移 OOB | 1029 元素大小 / 字节↔元素换算 | 同时服务 sizeof-misuse / memcpy 长度校验的后续增强 |
| CallSiteBinding | 1029 参数容量 | 1140 `&out` 对象大小 / 1031 参数→全局来源 | 同一调用点普查 |
| Buffer-Length 关联 | 1029 Guard Witness | 1038 数组成员边界 | 只在有证据时建立 |
| Guard Witness（结构化 must/may/unknown） | 1029 符号守卫 | 1038 字段访问守卫 / 1140 返回值守卫 | 复用 CFG + 谓词/对象/稳定性证据 |
| Global Write Summary（来源摘要，may-only） | 1031 nullability | 1029/1038 全局对象容量（可选） | 不直接当 Consumer 状态 |
| Output Param Summary（Return Contract + 字段级） | 1140 调用者消费 | 1031 参数写入全局的置信度 | 复用 `ParamWrites`，细化字段 |
| Return Contract Evidence | 1140 成功/失败分支 | 1031 参数来源的可空性/写入置信度 | 不硬编码 0/nonzero |
| PARAM_BINDING 扩展 | 1029 容量 | 1031 / 1140 实参绑定 | 不破坏现有 taint 消费方 |

---

## 9. 风险总表

| 风险 | 影响 | 缓解 |
|---|---|---|
| Target triple ≠ 完整 ABI 证明（pack/alignment/short-enums/条件编译） | 字段偏移错误 → 误报/漏报 | 按 TU/Config 隔离；provenance/confidence；assumed/unknown 不 confirmed；冲突即 unknown |
| 同名类型跨 TU/宏配置合并 | 布局错误传播 | LayoutKey 含 TU/Config；冲突不合并 |
| 重复宽度/typedef 表 | 三套事实漂移 | Phase 1 先收敛为一张表，再实现 layout |
| 类型系统复杂度（bitfield / packed / anonymous / flexible array） | 布局猜错 | MVP 一律 unknown，不猜 |
| Guard 支配被误当成谓词保护 | 错误 dismiss → 漏报 | 结构化 Guard Witness；只有 `must` 才 dismiss |
| 全局 may-write 被当成 Consumer 入口确定 NULL | 错误 confirmed | 只允许 may 来源；Phase 3 不承诺 confirmed；列出 writer/覆盖/未知源 |
| 0/nonzero 返回约定硬编码 | 错误 success/error 分支 | Return Contract Evidence；unknown → 不 confirmed |
| heuristic 与 compiler-proven 混用 | 证据链不可审计 | finding 保留 provenance；unknown/assumed 降级 |
| 调用点容量体量 | 候选爆炸 | 只在有容量事实 + 常量索引/关联时播种；shape clustering |
| 全局状态跨过程 | 误报 | 默认 suspected；Phase 3 不承诺 confirmed；调用顺序/覆盖/未知 writer/并发全部可证后才讨论 |
| 输出参数写回惯用法 | 大量 suspected | 体量评估；per-function 去重；字段级覆盖；必要时配置开关（不引入未测量缓存） |
| schema 枚举变更 | 迁移成本 | MVP 不新增 event/edge 类型；必要时走 additive migration |
| 增量失效 | 旧事实残留 | graph/events 每次重建；layout 内存重建；`function_summary` 级联删除 |
| 测试守卫 | 新 confirmed 被静默加入 | `TestConfirmedTierPolicy` / `TestDynamicConfirmedUpgradesRegistered` 先登记 |
| 性能 | 新增全树遍历 | 复用同一次 parse / per-scan ctx 注入；Phase 5 对照测量 |
| `buildFuncSummaries` 被 `double_free` / `use_after_free` / `uninit` 三个检测器各调用一次 | 1140 的 per-return-path 扩展会放大 3×，且检测器并发时无法作为跨检测器事实源 | Phase 4 先把 `buildFuncSummaries` 缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 中的结果），再扩展摘要；1031 的全局写入用独立的 pre-detector 索引，不进 summarizer |

---

## 10. 需要架构评审拍板的问题

1. **1038 的 `confirmed` 证明类别**：评审已决定使用独立 layout 语义、不复用 `heap_oob_*`；Phase 1 是否立即在 `AI_JUDGMENT_BOUNDARY.md` 增加“type-layout”证明类别？默认不增加，Phase 1 只出 `suspected`，经独立评审后再升级。
2. **1140 的未检查返回值场景**：评审已决定维持 must 语义；剩余待定是 `TestUninit_OutputParamUnguarded` 是否改为“不 confirmed、允许 suspected”，还是保持完全静默。
3. **1029 的调用点常量越界**：是否同意沿用“常量边界 + 已知容量”的确认语义？前提是 Guard Witness 证据完整、对象/容量关联成立；否则只 suspected。
4. **事实落点**：Type Layout 放 `repofacts` 还是新 `internal/typeinfo`？全局写入用 pre-detector 内存索引，还是持久化到 `function_summary`？（本方案推荐 Type Layout 算法放 typeinfo、census 扩展 repofacts；全局写入用 pre-detector 内存索引。）
5. **ABI 默认值**：评审已决定 `assumed_default_abi` 不得 confirmed；剩余待定是“无 compile_commands 时只出 suspected 还是直接不报”。
6. **宽度表收敛时机**：Phase 1 先做（推荐）还是推迟到 Phase 5？先做会增加 Phase 1 的改动面，但避免第三套表。
7. **持久化策略**：是否接受 MVP 不新增表/枚举，Type Layout 与调用点/全局写入事实放在扫描期内存，只有输出参数摘要扩展 `function_summary.summary_json`？
8. **Phase 1 边界**：评审已决定当前只启动 Phase 1（1038），Phase 1 通过独立评审后才启动 Phase 2；是否确认该门禁？

---

## 11. 代码事实索引（基线 `main@7176ab2`）

| 主题 | 位置 |
|---|---|
| repofacts 事实模型 | `sgre/internal/repofacts/repofacts.go:27`（`FieldFact`）、`:37`（`GlobalArray`）、`:46`（`Facts`）、`:57`（`Build`）、`:340-377`（查询） |
| repofacts 字段/数组解析 | `sgre/internal/repofacts/helpers.go:14`（`typeKeys`）、`:46`（`fieldFacts`）、`:115`（`arrayCapacity`） |
| 缓冲区检测入口 | `sgre/internal/evidence/buffer_overflow.go:28`（`Detect`）、`:932`（`detectArrayOOB`）、`:981`（`checkArrayOOB`）、`:1169`（`findArraySize`）、`:1814`（`heapAllocationSize`） |
| 未校验索引 | `sgre/internal/evidence/buffer_unchecked_index.go:51`（`detectUncheckedIndex`）、`:217`（`externalIndexSource`）、`:317`（`hasIndexBoundsGuard`） |
| PARAM_BINDING | `sgre/internal/graph/interproc.go:120-145`（只绑定 identifier）、`:178`（`persistParamBinding`） |
| CFG | `sgre/internal/graph/control_flow.go:45`（`StmtCFG`）、`:58`（`NodeAt`）、`:179`（`ReachesAvoiding`）、`:221`（`BuildStmtCFG`） |
| GLOBAL_ACCESS | `sgre/internal/graph/shared_access.go:28`（`Build`） |
| 全局别名 | `sgre/internal/graph/alias_builder.go:21`（`BuildInterproceduralAlias`） |
| 静态 NULL 全局 | `sgre/internal/evidence/null_source.go:104`（`detectStaticNullGlobals`）、`:190`（`staticGlobalNeverReassigned`） |
| 输出参数摘要 | `sgre/internal/evidence/free_summary.go:36`（`ParamWrites`）、`:41`（`ParamConditionalWrites`）、`:295`（`computeParamWriteState`）、`:344`（`states`）、`:213`（持久化） |
| 输出参数消费 | `sgre/internal/evidence/uninit_variable.go:432-490`（`&x` 处理、无守卫 fallback） |
| uninit 过滤器 | `sgre/internal/planner/filter_uninit_flow.go:591`（`hasOutputParamWrite`） |
| uninit 已知限制 | `sgre/internal/planner/registry_uninit.go:37-40` |
| null 模型 | `sgre/internal/planner/null_analysis.go:23`（`nullSource`）、`:87`（`buildNullModel`）、`:234`（`hasSourceOrigin`） |
| null 流入口 seed | `sgre/internal/planner/filter_nullable_source.go:405`（`buildFlowResults`）、`:546`（entry-origin 列表）、`:313`（`global-null` tier） |
| 调用点普查 | `sgre/internal/planner/call_sites.go:18`（`callSiteResolver`） |
| typedef/宽度 | `sgre/internal/evidence/typedefs.go:63`（`buildGlobalTypedefs`）、`:310`（`widthOf`） |
| 第二张宽度表 | `sgre/internal/graph/types_width.go:5`（`lp64Widths`）、`:60`（`TypeByName`） |
| compile_commands | `sgre/internal/build/compile_commands.go:28`（`LoadCompileCommands`，仅 `-D/-I`） |
| schema 枚举 | `sgre/internal/db/schema.go:65`（`file_scope_variables`）、`:112-118`（`graph_edges`）、`:129-131`（`security_events`）、`:327`（`function_summary`） |
| pipeline 重建/注入 | `sgre/internal/cli/pipeline.go:119`（`ClearGraph`）、`:242`（`ClearSecurityEvents`）、`:266`（`WithAliasGraph`）、`:312`（`EnsureFunctionSummaries`） |
| AI 边界守卫 | `sgre/internal/planner/zz_ai_judgment_boundary_test.go:20`（`TestConfirmedTierPolicy`） |
| 声明事实不变性 | `sgre/internal/planner/zz_declaration_invariance_test.go:30` |
| 能力夹具 | `sgre/testdata/feedback_watch/README.md`；`sgre/internal/planner/feedback_watch_test.go:36` |
| 基准 | `examples/c-vuln-benchmark/benchmark.md`；`examples/c-vuln-benchmark/scripts/validate-benchmark.py` |

---

## 12. 结论

四类 Gap 的落地不应该被理解为“四个新检测器”，而应该被理解为：

1. **一个类型布局事实层**（1038 打底，1029 复用元素大小）；
2. **一个调用点绑定/容量事实层**（1029 打底，1140/1031 复用）；
3. **一个全局写入摘要**（1031 消费；现有的 `ParamWrites` 提供参数写入置信度，Phase 4 再扩展成功/失败精度）；
4. **一个输出参数成功/失败路径扩展**（1140 消费）。

四者共享同一套 provenance、同一套 CFG/别名/调用点基础设施、同一套 `confirmed` 边界。真正需要新增的“系统”只有 1 个（类型布局），其余都是扩展现有事实。

评审后的硬约束：

- **Layout 是 TU/编译配置相关事实**；target triple 不是完整 ABI 证明；`assumed_default_abi`/`unknown` 不 confirmed。
- **Guard Witness 是结构化证据**；CFG 支配不是谓词保护；只有 `must` 才能 dismiss。
- **Global Write Summary 是来源摘要**；may-write 不得直接变成 Consumer 入口确定 NULL；Phase 3 不承诺 confirmed。
- **1140 不硬编码 0/nonzero**；Return Contract 未知时不得 confirmed；写入覆盖必须到字段/子对象。
- **证据完整性**是每个 Phase 的验收项，不是“命中样例”就算完成。

本轮只做文档修订，不改生产代码；下一步只启动 Phase 1（1038），Phase 1 通过独立评审后再启动 Phase 2。
