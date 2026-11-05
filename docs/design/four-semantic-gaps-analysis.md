# 四类跨过程程序语义 Gap：Phase 0 调研分析

> 对应 Issue #228（CWD-SUB-1029 / 1038 / 1031 / 1140）。
> 本文是架构评审前的 **Phase 0 调研输出**，只描述现状、可复用设施、事实模型与最小实施边界，**不包含生产代码改动**。
> 配套文档：[four-semantic-gaps-implementation-plan.md](four-semantic-gaps-implementation-plan.md)。

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
| CWD-SUB-1038 | 类型大小与字段偏移 | **不支持** | 无；`repofacts` 只有字段形态（array count / pointer），没有 size/offset | Type Layout 事实层（size / align / offset），且必须绑定目标 ABI |
| CWD-SUB-1031 | 全局变量写入值的跨过程传播 | **部分支持**（仅“static 且从未被重写”的 NULL） | `evidence/null_source.go`：`detectStaticNullGlobals`；`planner/filter_nullable_source.go` | 全局写入值摘要（writer → source kind）+ 消费函数的状态不确定性 |
| CWD-SUB-1140 | 输出参数初始化覆盖 | **部分支持**（已有 `ParamWrites` / `ParamConditionalWrites`） | `evidence/free_summary.go` + `evidence/uninit_variable.go` + `planner/filter_uninit_flow.go` | 成功/失败返回路径与写入覆盖的关联；调用者未检查返回值时的证据化降级 |

### 0.2 三个系统性结论（比四个单点更重要）

1. **多数缺口不是“能力不存在”，而是“事实已产生、消费链路没接上”。**
   - `PARAM_BINDING` 已在图里，但只绑定裸标识符实参、不携带实参类型/容量，buffer 检测器也从不读它；
   - 输出参数写入覆盖已由 `FuncSummary.ParamWrites/ParamConditionalWrites` 用 CFG must-reach 证明并持久化，但调用者侧对“未检查返回值的条件写入”采取了刻意的 fail-open；
   - `static` 全局指针“只可能是 NULL”已能确认，但参数→全局→解引用的写入来源没有摘要。
2. **需要新增的事实是 3 个家族，而不是 4 套系统**：Type Layout、调用点绑定/容量、全局写入摘要；输出参数摘要是在现有 `function_summary` 上扩展，guard witness 是过滤器中按 CFG 现算的派生事实。MVP **不新增 SQLite 表、不新增 `security_events` 事件类型、不新增 `graph_edges` 边类型**。
3. **有两个策略问题必须由架构评审拍板**，不能由实现者默认决定：
   - **1038 的字段偏移越界是否算 `confirmed`**：它既不属于现有四类证明手段中的“区间/常量折叠”（字段偏移是布局事实，不是常量表达式），也不是 CFG must 数据流。直接沿用 `heap_oob_write` 会悄悄扩大 `confirmed` 集合，违反 `AI_JUDGMENT_BOUNDARY.md` 的机器守卫精神；需要新增证明类别或新增 category。
   - **1140 的“未检查返回值 + 条件写入”是否应该 `confirmed`**：这是“存在一条失败路径可达读取”的 **may 证明**，而仓库现行 `confirmed` 定义是“每条路径都成立”的 **must 证明**。二者语义冲突，必须显式选择，不能靠改测试期望值绕过。

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
| `GUARD_WITNESS` | **不落库**：由过滤器按 `StmtCFG` + 支配关系现算 | 否 | 新 `ParamCapacityGuardFilter` | 1029；1038（字段访问守卫）；1140（返回值守卫） |
| `TYPE_SIZE / TYPE_ALIGNMENT / FIELD_OFFSET / FIELD_SIZE` | **扩展 `repofacts`**：新增 `TypeLayout` 视图 | 否（`repofacts` 每次扫描重建） | `repofacts`（同一遍 parse） | 1038；1029（元素大小/字节↔元素换算）；sizeof-misuse / memcpy 长度校验（既有能力） |
| `GLOBAL_WRITE_SUMMARY` | **pre-detector 内存事实** `GlobalWriteIndex`（ctx 注入）；如需跨阶段复用再合并进 `summary_json.global_writes` | 否（MVP；`function_summary` 仅在确有跨阶段需求时使用） | 新 `graph/global_write.go` + `cli/pipeline.go` 的 pre-detector 阶段 | 1031；1038/1029（全局对象容量，可选） |
| `OUTPUT_PARAM_SUMMARY` | **扩展现有 `FuncSummary`**：增加按返回值的写入覆盖（success/error path） | 是（同一 `summary_json`） | `free_summary.go` | 1140；1031（参数写入覆盖→全局写入来源） |

**MVP 不新增 SQLite 表、不新增 `security_events` 事件类型、不新增 `graph_edges` 边类型。** 理由：

- `graph_edges.edge_type` 和 `security_events.event_type` 都带 CHECK 枚举（`db/schema.go:116`、`db/schema.go:131`），新增枚举值需要 schema 迁移，且迁移后旧数据库的兼容成本高；
- 语义图与事件表**每次扫描都清空重建**（`cli/pipeline.go:119` 清 graph，`:242` 清 events），把“调用点相关事实”持久化没有跨扫描收益，反而增加失效风险；
- `function_summary` 随 `functions` 级联删除（indexer 变更文件时删 function），增量失效语义已经正确。

### 3.2 事实的 provenance / 可信度 / 调用上下文 / 失效

所有新事实必须携带同一组元数据（对齐 Issue §6）：

```go
// 示意，不落生产代码
type FactMeta struct {
    File      string // 事实来源文件
    Line      int    // 事实来源行
    Function  string // 来源函数（可空）
    Symbol    string // 相关符号
    Evidence  string // "local-array-decl" / "sizeof-arg" / "malloc-arg" / "macro-cap" / ...
    Confidence string // "proven" | "assumed" | "unknown"
    CallSite  string // 仅调用点事实：file:line + callee
}
```

约束：

- **调用点事实不得提升为全局事实**。`f(buf, 16)` 的容量只属于该调用点；同名的另一个调用点容量不同时必须保留两个上下文，不能合并成一个常量。
- 类型布局的 `Confidence` 由 ABI 来源决定：显式 `compile_commands.json` target → `proven`；无 target → `assumed LP64`；target 冲突 / packed / bitfield / flexible array / 未知 typedef → `unknown`，并**禁止**产出 `confirmed`。
- 所有 `unknown` 走 fail-open：不确认，必要时降级为 `suspected`，绝不能把“未知”解释成“安全”。

### 3.3 事实生产时机：pre-detector 共享阶段

检测器是**并发**执行的（`evidence.RunAllDetectorsWithSkip`，`cli/pipeline.go:291`），所以任何“检测器 A 产出、检测器 B 消费”的新事实都是不确定的。四类 Gap 中：

- Type Layout、CallSiteBinding、GlobalWriteIndex 都是**多消费者、跨检测器**的事实，必须在检测器之前构建；
- 构建位置：`cli/pipeline.go` 已有的“图构建完成、`ClearSecurityEvents` 之后、RunAllDetectors 之前”区间，与 `AliasGraph` 相邻（`cli/pipeline.go:266`）；
- 通过 ctx 注入（`graph.WithXxxIndex` 模式），检测器与 planner filter 都读同一份实例；
- 单次构建、单次 parse，避免 `repofacts.Build` 当前被 buffer 检测器与 nullable filter 各建一次（`buffer_overflow.go:33`、`filter_nullable_source.go:1222`）的重复成本；
- 不跨扫描缓存；每次 scan 重建，天然满足失效要求。

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

**D. Guard Witness（符号化 + 支配）**

对形参索引访问，需要证明 `index` 在访问点被一个“以 buffer 真实容量为上界”的检查保护。现有 `hasIndexBoundsGuard` 只支持常量/宏上界，需要扩展：

- 守卫变量：`index`（或 `index` 的 cast/别名，需同一值证明）；
- 守卫上界：`length` 参数，且该参数在**至少一个可达调用点**被关联到 `buffer` 容量；
- 分支方向：`if (index < length)` 的正向分支 / `if (index >= length) return` 的早退分支；
- 支配：`!ReachesAvoiding(Entry, {guardNode}, accessNode)`；`TrueSuccs/FalseSuccs` 判断访问落在守卫的真/假分支；
- 重赋值：检查后 `index` 被重新赋值 → 守卫失效（Issue 的示例）；
- 符号性：`index` 是无符号时 `index >= 0` 恒真；有符号负索引要单独识别；
- 整数溢出：`index * elemSize` 的乘法需溢出检查（复用 `constant_symbols.go` 的折叠能力）；
- 多层条件：先合并同一控制流路径上的多个守卫，再判定。

### 4.4 最小可行实施范围（MVP）

1. **扩展 `PARAM_BINDING` 的 props**（identifier 实参），不把所有实参塞进图边，避免 taint fixpoint 的边膨胀；非 identifier 实参由 `CallSiteBinding` 承载；
2. **新增 per-scan `CallSiteBinding` 索引**（内存，ctx 注入），容量解析复用 `findArraySize` / `GlobalArray` / `heapAllocationSize` 的规则；
3. **新增 `detectParamIndexAccess`**（在 `buffer_overflow.go` 内，不新建 Detector）：只对“buffer 是形参、索引是形参/局部、且至少一个调用点有容量事实”的访问播种；
   - 常量索引 + 容量已知 → `param_oob_read/write`，`suspected` 起步，由过滤器决定是否升级；
   - 变量索引 + 存在 buffer-length 关联 → `param_index_unchecked_read/write`，`suspected`；
4. **新增 `ParamCapacityGuardFilter`**（加入 `chainBufferOverflow`）：
   - 有支配且有效的守卫 → dismiss（写入 `Dismissed` ledger）；
   - 常量索引 × 元素大小 ≥ 容量且无守卫 → 升级 `confirmed`（如果评审通过新增证明类别，见 §10）；
   - 其余保持 `suspected`，evidence 写清容量来源、关联依据、守卫缺失/失效原因；
5. **去重**：同一 `(callee, access line, capacity)` 只出一个候选，多个调用点作为 `callers@` / `Clustered Sites` evidence，不重复 finding；
6. **不改变** `detectUncheckedIndex` 现有的结构体字段索引通道。

### 4.5 确认/降级边界

| 场景 | 目标 tier | 依据 |
|---|---|---|
| 常量索引 + 调用点容量已知 + 无守卫 | `confirmed`（待评审批准 proof class） | 区间/常量 + 对象边界 |
| 变量索引 + 有 buffer-length 关联 + 无守卫 | `suspected` | 关联是证据，索引范围未知 |
| 变量索引 + 守卫上界关联到容量 + 支配 + 无重赋值 | dismiss | 已证明安全 |
| 守卫上界是另一个长度（`packet_len`） | 不 dismiss；容量若可从常量索引证明则 confirmed，否则 suspected | 不误关联 |
| 容量未知 / 元素大小未知 / ABI unknown | `suspected` 或不出 | fail-open |
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
| 有符号负索引 | 识别负索引风险 |

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

### 5.3 需要补的事实：Type Layout

**事实模型（示意）**

```go
type TypeLayout struct {
    Name      string
    Size      int      // bytes
    Align     int      // bytes
    Kind      string   // "primitive" | "struct" | "union" | "array" | "pointer"
    Fields    []FieldLayout
    ABI       string   // "lp64" | "ilp32" | "llp64" | "unknown"
    Assumed   bool     // ABI 是否为默认假设
    Unknown   string   // 非空表示不可用原因
}

type FieldLayout struct {
    Name      string
    Offset    int
    Size      int
    Align     int
    ArrayCount int
    BitWidth  int
    IsPointer bool
}
```

**布局算法**

1. 基本类型：用**一张** ABI 表（LP64 / ILP32 / LLP64），不用宿主机 `sizeof`；
2. typedef：传递解析到基本类型/复合类型；
3. struct：按声明顺序，`offset = alignUp(offset, fieldAlign)`，`structAlign = max(fieldAlign)`，`size = alignUp(offset, structAlign)`；
4. union：`size = max(fieldSize)`，`align = max(fieldAlign)`；
5. 数组：`size = count * elemSize`，`align = elemAlign`；
6. 嵌套 struct：递归；匿名 struct/union 按 C11 规则展平到父偏移；
7. 指针：按 ABI 宽度（LP64/LLP64 = 8，ILP32 = 4）；
8. enum：默认 `int`，但标记 `Assumed`；`-fshort-enums` 或无法确定 → unknown；
9. `packed` / `aligned` / `#pragma pack`：能解析则应用；不能解析 → unknown；
10. 位域 / 柔性数组 / 复杂编译器扩展：**MVP 直接 unknown**，不猜偏移；
11. 任何字段类型无法解析 → 整个 struct unknown，禁止输出部分偏移。

**ABI 来源**

- `compile_commands.json` 增加解析：`-m32` → ILP32；`-m64` / `--target=x86_64-*` → LP64；`--target=*-windows-*` → LLP64；`-target <triple>` 同样处理；
- 多个 TU 的 target 冲突 → `unknown`；
- 没有 `compile_commands.json` → `ABI=lp64 (assumed)`，`Assumed=true`；
- **禁止**用分析机 `unsafe.Sizeof` / `sizeof(void*)` 代替目标 ABI。

**落点**

- 优先扩展 `repofacts`：`Facts` 增加 `layouts map[string]*TypeLayout`，在现有两遍扫描里顺带计算；`Build` 的签名保持不变（ABI 从 `build.CurrentCompileCommands()` 读取），或增加 `BuildWithOptions` 并在 pipeline 里显式注入 ABI；
- 如果为了包依赖方向（`repofacts` 不 import `build`）需要新包，则新建 `internal/typeinfo`，但**必须**让 `repofacts` 与 `evidence` 共用同一个 layout 实例，不能各建一套；
- 收敛重复宽度表：`evidence/typedefs.widthOf` 与 `graph/types_width.lp64Widths` 合并到共享包，二者改为委托。这是 Phase 1 的**前置重构**，否则 1038 会产生第三张表。

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
- 未知布局 / 未知 ABI → 不出 `confirmed`。

**category 与 proof class**

推荐新增 `layout_oob_read` / `layout_oob_write`（而不是复用 `heap_oob_read/write`），因为：

- 现有 `heap_oob_*` 的 confirmed 证明是“常量/区间索引超出已知分配大小”；
- 字段偏移证明是“类型布局 + ABI”；
- 复用会导致 `TestConfirmedTierPolicy` 的 golden 清单无法表达证明类别，且 AI 边界文档会失真。

如果评审决定不新增 category，则 MVP 只能 `suspected`，并在 Remaining Gap 中记录。

### 5.5 最小可行实施范围（MVP）

1. 收敛宽度表 + typedef 解析（前置重构，纯行为保持，补单测）；
2. `repofacts` 增加 Type Layout（基本类型、typedef、struct、union、数组、指针、嵌套 struct；packed/aligned 可选；bitfield/flexible array unknown）；
3. `compile_commands.json` 增加 ABI target 解析；
4. 新增 `detectCastObjectOOB`（或在 `buffer_overflow.go` 内扩展）：
   - 识别 `cast_expression` 到 struct 指针 + 该指针的字段访问；
   - 通过 `AliasGraph` 追到分配基址；
   - 比较 `offset + size` 与分配字节容量；
   - 产出 `layout_oob_read/write`（suspected）或 `heap_oob_*`（如果评审批准复用）；
5. AI evidence：`## Type Layout` 段（字段偏移/大小/ABI/来源）、分配容量、字段访问表达式；
6. 测试：Issue §3.5 的 12 类 + inline/header-split invariance + 不同 ABI 的 compile_commands 变体。

### 5.6 风险

- **ABI 不确定性**：没有 compile_commands 时 LP64 只是假设；Windows LLP64、32 位、packed 都会改变偏移。MVP 必须把 `Assumed` 写进 evidence，并且 `assumed` 不做 confirmed。
- **类型系统复杂度**：typedef 链、匿名 struct、嵌套、位域、flexible array、`__attribute__`、`#pragma pack`。MVP 明确 unknown，不追求全覆盖。
- **第三方头文件**：`repofacts` 已扫描 worktree headers，但第三方 include 路径可能不在 worktree 内；未知 → unknown。
- **性能**：布局计算是同一次 parse 的顺带工作，但嵌套递归/typedef 解析需要注意缓存；不要为每个访问重新计算整个 layout。
- **误报**：`malloc(sizeof(*p))`、`calloc`、`realloc`、指针偏移、union 别名都可能让朴素比较误报；所有安全对照必须先过。

### 5.7 测试映射

Issue §3.5 的 12 类 + 新增：

- `malloc(sizeof(struct T))` / `calloc(n, sizeof(struct T))` 合法；
- 字段偏移越界 / 部分越界；
- 嵌套 struct / union / packed / typedef；
- 不同 ABI（`-m32` vs `-m64`）下同一 fixture 的不同偏移；
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

### 6.3 需要补的事实：Global Write Summary

**事实模型（示意）**

```go
type GlobalWriteFact struct {
    Global      string // 全局符号
    Writer      string // 写入函数
    File        string
    Line        int
    SourceKind  string // "null" | "param" | "local" | "call" | "opaque"
    SourceParam int    // SourceKind=="param"
    SourceName  string // local/param 名
    Condition   string // 所在分支条件（可空）
    Definite    bool   // 是否所有路径都写
    Nullable    string // "null" | "maybe-null" | "non-null" | "unknown"
    Callers     []string
}
```

**落点与并发约束（重要）**

检测器由 `evidence.RunAllDetectorsWithSkip` **并发执行**（`cli/pipeline.go:291`）。因此，1031 的新事实**不能依赖另一个检测器的产物**，也不能依赖 runs-after-detectors 的 `EnsureFunctionSummaries`。`GlobalWriteIndex` 必须在检测器开始前的阶段构建，并通过 ctx 注入（与 `AliasGraph` 同一模式，`cli/pipeline.go:266`）。MVP 不持久化；如果后续 planner/report 需要跨阶段复用，再合并进 `summary_json`，但检测器阶段的来源始终是这个 pre-detector 索引。

**写入识别**

- 直接赋值 `g = p` / `g = NULL` / `g = malloc(...)`；
- 条件赋值（记录 condition）；
- 简单指针转换 `g = (T *)p`；
- 多个写入函数；
- 跨文件全局（`file_scope_variables` 的 `extern` vs `static` 要区分；static 只在本 TU 可见）。

**不识别 / 标 unknown**

- `memcpy(&g, ...)`、宏写入、`&g` 逃逸、外部函数修改；
- volatile / atomic；
- 多线程并发写；
- 函数指针/间接调用可能写全局。

### 6.4 消费侧：如何进入 nullability

**A. 新 origin `global_write`**

- 新增检测器（或在 `null_source.go` 内）为每个**解引用全局**的函数发射 `NULL_VALUE`，`origin=global_write`，props 带 writer/source/condition/callers；
- `filter_nullable_source` 把 `global_write` 加入 entry-seeded 来源集合（与 `global_null` 同路径，`filter_nullable_source.go:546`）；
- tier：
  - 如果所有 in-scan writer 的 source 都是 NULL，且没有 non-null writer、没有外部 writer（static 或完整程序）→ 可以 `suspected`（甚至 `confirmed`，若实现 §6.4B）；
  - 如果至少一个 writer 是参数，且该参数在某个调用点收到 NULL → `suspected`；
  - 如果存在多个 writer / 覆盖 / 未知外部 writer / 并发 → `suspected`，evidence 列出竞争写入者。

**B. 调用顺序（confirmed 的唯一可行形态）**

仓库的 `confirmed` 要求 must 证明。跨函数的“调用顺序 + 当前值 + 无覆盖 + 可达”是全局 must 状态，当前的 per-function flow engine 做不到。MVP 只支持**同一个函数内的直线顺序**：

```c
void run(void) {
    set_buffer(NULL);   // in-tree writer, source=null
    consume_buffer();   // deref in callee
}
```

即便如此，deref 仍在 callee 内；需要在 `run` 里合成一个“调用点 deref”候选（参照 `InterproceduralDetector` 的做法），且要求：

- `set_buffer` 与 `consume_buffer` 之间没有其他写 `g` 的语句；
- 没有分支/循环把两者分开（CFG 直线）；
- `set_buffer` 的写入是 definite NULL；
- `consume_buffer` 内对 `g` 的解引用无守卫；
- 没有其他 in-scan writer。

满足则可在 `run` 的调用点 `confirmed`（新增 proof class 是 CFG must + 调用内联）。否则一律 `suspected`。

**C. 状态污染防护**

- 不能把“一次 NULL 写入”传播为“永久 NULL”；
- 每个 writer 的 `Condition` 必须保留；
- `static` vs `extern` 的可见性要区分：`static` 的“无外部 writer”是可证明的；`extern` 的未知外部 writer 默认存在；
- 线程函数写入 → 不做 confirmed。

### 6.5 最小可行实施范围（MVP）

1. 在 `cli/pipeline.go` 的检测器阶段之前构建 `GlobalWriteIndex`（单次遍历，复用 `RepoIndex` / `AliasGraph`），ctx 注入；**不**把全局写入塞进被 3 个检测器各调用一次的 `buildFuncSummaries`；
2. 在 `null_source.go` 新增 `detectGlobalWriteNull`（读 ctx 中的 `GlobalWriteIndex`），为解引用全局的函数发射 `origin=global_write` 的 `NULL_VALUE`；
3. `null_analysis.go` / `filter_nullable_source.go` 识别 `global_write`，entry seed，tier 逻辑；
4. evidence：writer 列表、source kind、条件、覆盖写入、未知外部 writer、线程风险；
5. 测试：Issue §4.4 的 12 类 + 同函数直线 confirmed 形态（如果评审批准）。

### 6.6 风险

- **误报**：全局状态是程序级事实，局部证据不足就确认会大量误报；MVP 默认 suspected。
- **并发**：多线程写入无法用当前 CFG 证明，必须 suspected/unknown。
- **外部写入**：`extern` 全局可能被扫描树外修改；除非完整程序扫描，否则不能确认。
- **性能**：全局写入普查需要遍历所有赋值；与 `GLOBAL_ACCESS` 合并可减少一次遍历。

### 6.7 测试映射

Issue §4.4 的 12 类：NULL 参数写入、非 NULL 参数写入、两个 writer、覆盖、条件写入、多层调用、跨文件、静态初始化、多调用点、未知 writer、多线程、赋值后 NULL 检查保护。

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

### 7.3 需要补的事实：成功/失败路径覆盖

**扩展现有 `FuncSummary`（不新建类型）**

```go
// 每个输出参数、每个 return 节点一条：该返回路径上是否已被写入覆盖。
type ParamReturnCoverage struct {
    ReturnValue string // "0" / "-1" / "nonzero" / "unknown"
    ReturnLine  int
    WriteLines  []int  // 支配该 return 的写入行（可为空）
    Covered     bool   // 至少一个写入支配该 return
    Condition   string // 该 return 所在分支条件（可空）
}

type FuncSummary struct {
    // ... existing fields
    ParamReturnCoverage map[int][]ParamReturnCoverage // param index -> per-return coverage
    SuccessValues       []string                      // e.g. ["0"]
    ErrorValues         []string                      // e.g. ["-1", "nonzero"]
}
```

这里必须记录“该 return 没有被写入覆盖”（`Covered=false`）这一负事实；只记录写入行无法区分“没写”和“未知”。

**计算**

- 对每个 `return <const>` 节点，用 `!ReachesAvoiding(Entry, writeNodes, returnNode)` 判断写入是否支配该返回；
- 常量返回值的 success/error 分类：
  - 有 `0` 返回 + 非零错误返回 → `0` 为 success；
  - 只有 `0` / 只有非零 → 无法区分，标 unknown；
  - 无常量返回 / 返回结构体 → unknown；
- 持久化到 `summary_json` 的 `outparam_success_writes` / `outparam_return_paths`，与现有 key 合并。

**MVP 限制**

- 只支持常量返回码；不支持 errno / 结构体错误对象 / 输出参数本身携带错误；
- 只支持直接 `*out = ...` / `out->field = ...`；通过 helper 间接写入沿用现有 forwarded-write fixpoint：`ParamWrites`（every-path）视为覆盖所有 return，`ParamConditionalWrites` 不视为覆盖（除非后续把 forwarded 路径也按 return 细分）；
- 循环内写入：记录为 conditional，除非能证明循环至少执行一次。

### 7.4 调用者消费

**A. 检查返回值 + 成功分支读取**

```c
int rc = load_value(&value, success);
if (rc != 0) return;
use(value);   // success path
```

如果摘要证明“所有 success return 都写入了 out”，则 `value` 已初始化 → 不报。

**B. 检查返回值 + 错误分支读取**

```c
int rc = load_value(&value, success);
if (rc != 0) {
    use(value);   // error path, callee did not write
}
```

如果摘要证明“error path 没有写入”且读取在该分支 → 可以 `confirmed`（must-uninit on that path；现有 `TestUninit_OutputParamGuardNearErrorBranch` 已经覆盖类似形态）。

**C. 不检查返回值**

```c
load_value(&value, success);
use(value);
```

- 按仓库现行 `confirmed` 定义（must）→ 只能 `suspected`；
- evidence 必须写：callee 有失败路径、失败路径不写 out、调用者未检查返回、读取在调用之后；
- 如果评审决定采用“存在失败路径即可确认”的 may 语义，则需先修改 `AI_JUDGMENT_BOUNDARY.md`，不能只改代码。

**D. 调用者传入已初始化变量**

`int value = 0; load_value(&value, ...); use(value);` → 不报（现有 flow 已处理）。

### 7.5 与 `TestUninit_OutputParamUnguarded` 的冲突

Issue 明确要求保留该测试，但需要区分它锁定的是“不产生 Confirmed”还是“不产生任何候选”。

- 现状：测试断言 `candidateForFunc(...) != nil` 即失败，等价于“不产生任何候选”；
- 本方案建议：改为“不产生 `confirmed`；允许 `suspected`，但必须带 outparam 证据”；
- 这是一个**行为变更**，必须由架构评审明确批准，不能静默改期望值；
- 如果评审选择保持“完全静默”，则 1140 的 MVP 只能覆盖 A/B 两个场景，C 保持 Remaining Gap。

### 7.6 最小可行实施范围（MVP）

1. 扩展 `FuncSummary` 的 per-return-path 覆盖；
2. `uninit_variable.go` 消费成功/失败路径：
   - A 场景：dismiss；
   - B 场景：保持/升级；
   - C 场景：按评审决定，`suspected`（推荐）或保持静默；
3. `DefiniteInitFilter.hasOutputParamWrite` 改为优先查摘要，而不是任何 `&x` 都降级（外部未知函数仍降级）；
4. evidence：`outparam@success` / `outparam@error` token、writer 行、成功条件；
5. 测试：Issue §5.5 的 15 类 + 原回归。

### 7.7 风险

- **误报**：写回惯用法在 C 代码中极常见；如果不检查返回值就标 suspected，可能产生大量候选。需要体量评估和 per-function 去重。
- **返回码约定**：不是所有函数用 0 表示成功；MVP 只处理明确的 0/非零模式。
- **间接写入**：helper / 宏 / 函数指针写入的覆盖可能不完整；未知时不能确认。
- **与现有测试冲突**：见 §7.5。

---

## 8. 跨 Gap 复用校验（“每个事实至少两个消费者”）

| 新事实 | 消费者 1 | 消费者 2 | 说明 |
|---|---|---|---|
| Type Layout | 1038 字段偏移 OOB | 1029 元素大小 / 字节↔元素换算 | 同时服务 sizeof-misuse / memcpy 长度校验的后续增强 |
| CallSiteBinding | 1029 参数容量 | 1140 `&out` 对象大小 / 1031 参数→全局来源 | 同一调用点普查 |
| Buffer-Length 关联 | 1029 Guard Witness | 1038 数组成员边界 | 只在有证据时建立 |
| Guard Witness | 1029 符号守卫 | 1038 字段访问守卫 / 1140 返回值守卫 | 复用 CFG 支配 |
| Global Write Summary | 1031 nullability | 1029/1038 全局对象容量（可选） | 写入值来源 |
| Output Param Summary | 1140 调用者消费 | 1031 参数写入全局的置信度 | 复用 `ParamWrites` |
| PARAM_BINDING 扩展 | 1029 容量 | 1031 / 1140 实参绑定 | 不破坏现有 taint 消费方 |

---

## 9. 风险总表

| 风险 | 影响 | 缓解 |
|---|---|---|
| ABI 不确定（无 compile_commands / 冲突 / Windows LLP64） | 字段偏移错误 → 误报/漏报 | `Assumed` 标记；assumed 不 confirmed；冲突即 unknown |
| 重复宽度/typedef 表 | 三套事实漂移 | Phase 1 先收敛为一张表，再实现 layout |
| 类型系统复杂度（bitfield / packed / anonymous / flexible array） | 布局猜错 | MVP 一律 unknown，不猜 |
| 调用点容量体量 | 候选爆炸 | 只在有容量事实 + 常量索引/关联时播种；shape clustering |
| 全局状态跨过程 | 误报 | 默认 suspected；只对同函数直线顺序考虑 confirmed |
| 输出参数写回惯用法 | 大量 suspected | 体量评估；per-function 去重；必要时配置开关（不引入未测量缓存） |
| schema 枚举变更 | 迁移成本 | MVP 不新增 event/edge 类型；必要时走 additive migration |
| 增量失效 | 旧事实残留 | graph/events 每次重建；layout 内存重建；`function_summary` 级联删除 |
| 测试守卫 | 新 confirmed 被静默加入 | `TestConfirmedTierPolicy` / `TestDynamicConfirmedUpgradesRegistered` 先登记 |
| 性能 | 新增全树遍历 | 复用同一次 parse / per-scan ctx 注入；Phase 5 对照测量 |
| `buildFuncSummaries` 被 `double_free` / `use_after_free` / `uninit` 三个检测器各调用一次 | 1140 的 per-return-path 扩展会放大 3×，且检测器并发时无法作为跨检测器事实源 | Phase 4 先把 `buildFuncSummaries` 缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 中的结果），再扩展摘要；1031 的全局写入用独立的 pre-detector 索引，不进 summarizer |

---

## 10. 需要架构评审拍板的问题

1. **1038 的 `confirmed` 证明类别**：是否在 `AI_JUDGMENT_BOUNDARY.md` 增加第五类“type-layout（ABI-proven）”，并为 `layout_oob_read/write` 登记？还是 MVP 只出 `suspected`？
2. **1140 的未检查返回值场景**：是否接受“存在失败路径 + 调用者读取”作为 `confirmed`（may 语义），还是维持仓库的 must 语义、只出 `suspected`？
3. **1029 的调用点常量越界**：是否同意沿用 `bounded_copy_overflow` 的“常量边界 + 已知容量”确认语义，在调用点证明后 `confirmed`？
4. **事实落点**：Type Layout 放 `repofacts` 还是新 `internal/typeinfo`？全局写入用 pre-detector 内存索引，还是持久化到 `function_summary`？（本方案推荐 Type Layout 扩展 `repofacts`；全局写入用 pre-detector 内存索引，确有跨阶段需求再持久化。）
5. **ABI 默认值**：没有 `compile_commands.json` 时，允许 LP64 assumed 并只出 `suspected`，还是直接 unknown/不报？
6. **宽度表收敛时机**：Phase 1 先做（推荐）还是推迟到 Phase 5？先做会增加 Phase 1 的改动面，但避免第三套表。
7. **`TestUninit_OutputParamUnguarded` 的期望**：改为“不 confirmed、允许 suspected”，还是保持完全静默？
8. **持久化策略**：是否接受 MVP 不新增表/枚举，Type Layout 与调用点/全局写入事实放在扫描期内存，只有输出参数摘要扩展 `function_summary.summary_json`？

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

四者共享同一套 provenance、同一套 CFG/别名/调用点基础设施、同一套 `confirmed` 边界。真正需要新增的“系统”只有 1 个（类型布局），其余都是扩展现有事实。建议按 §0.3 的顺序分阶段施工，每阶段先补“会失败”的测试，再实现，最后用 `examples/c-vuln-benchmark` + `feedback_watch` 做召回/误报对照。
