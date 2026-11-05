# 四类跨过程程序语义 Gap：实际实施计划

> 对应 Issue #228。
> 配套分析：[four-semantic-gaps-analysis.md](four-semantic-gaps-analysis.md)。
> 本文是 **Phase 0 交付物**：给出可评审的分阶段施工方案、文件级改动面、测试矩阵、验收门槛与度量方法。
> **本 PR 不包含生产代码改动**；实施按本文分阶段、分 PR 进行，每阶段完成后单独评审。

- 基线：`main@7176ab2`（v0.12.2 + PR #227），2026-11-05。
- 前置验证：`go build -buildvcs=false ./...` 通过；`TestFeedbackWatchCapabilityMatrix` 通过。
- 施工顺序：**1038 → 1029 → 1031 → 1140 → 统一回归**（依赖关系见分析文档 §0.3）。

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
- 不引入未测量的全局缓存；不跨扫描缓存新事实。

---

## 2. 交付拆分与评审检查点

| 阶段 | 交付 | 主要事实 | 预计改动量（含测试） | 评审检查点 |
|---|---|---|---|---|
| Phase 0（本 PR） | 分析文档 + 实施计划 | 无 | ~2 个 md | 架构方向、事实模型、确认边界 |
| Phase 1 | 1038 Type Layout 基础层 | TypeLayout | ~1200-1800 行 | 布局算法、ABI 来源、边界 case |
| Phase 2 | 1029 调用点容量 + 关联 + guard | CallSiteBinding、BufferLengthAssoc、GuardWitness | ~1500-2200 行 | 关联证据、guard 支配、体量 |
| Phase 3 | 1031 全局写入摘要 + null 集成 | GlobalWriteIndex | ~1000-1500 行 | 状态污染防护、并发/外部写入 |
| Phase 4 | 1140 输出参数成功/失败覆盖 | OutputParamSummary 扩展 | ~1200-1800 行 | 是否允许 suspected、测试策略 |
| Phase 5 | 统一回归 + 性能 + 最终报告 | 无新事实 | ~300-600 行（测试/脚本/文档） | 验收表、Remaining Gap |

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
- 不在 `buildFuncSummaries`（被 3 个检测器各调用一次）里追加跨检测器事实；1140 的摘要扩展在 Phase 4 先把 `buildFuncSummaries` 缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 结果）。

### 3.2 持久化与失效

| 事实 | MVP 落点 | 失效方式 |
|---|---|---|
| Type Layout | `repofacts.Facts` 的内存扩展 | 每次 scan 重建；不落库 |
| CallSiteBinding | 扫描期 `CallSiteBindingIndex` | 每次 scan 重建；不落库 |
| GlobalWriteIndex | 扫描期内存索引 | 每次 scan 重建；不落库 |
| OutputParamSummary | `function_summary.summary_json`（扩展现有 key） | function 变更时 indexer 删除 function，FK 级联删除 summary |
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
- 任何“为了通过测试”而降低门槛的改动，必须在评审中拒绝。

### 3.4 证据与 AI 消费

新增候选必须能回答：

- 漏洞位置（file:line + function）；
- 相关函数源码（`## Callee Definition` 已有）；
- 参数绑定关系（caller arg → callee param）；
- 调用点上下文（call site file:line + 容量来源）；
- 关键数据流（buffer → length → index）；
- CFG 分支条件 / guard witness；
- 不确定性来源（未知 ABI / 未知容量 / 未解析调用点 / 多 writer / 并发）。

落点：

- `planner/registry_*.go` 的 `BuildEvidence`；
- `planner/hint_tokens.go` 新增 token（必须登记）；
- `planner/evidence_package.go` 的新 section（如有）；
- `extension/shared/agent-body.md` 的研判纪律（仅当新增 token/section 影响 AI 判断时）。

### 3.5 去重与体量

- 1029：同一 `(callee, access line, capacity)` 一个候选；多个调用点作为 `Clustered Sites` / `callers@` evidence；
- 1031：同一 `(consumer function, global)` 一个候选；writers 列表作为 evidence；
- 1140：同一 `(caller function, variable/outparam)` 一个候选；多个 callee/path 折叠；
- 复用 `ShapeKey` / `clusterShapeCandidates` 的既有折叠机制，不新增一套 dedup；
- 每阶段在 benchmark 上统计候选增量；如果某类型候选 > 基线 +20%，先做体量分析，再决定是否收窄播种条件。

### 3.6 性能预算（暂定，评审可调整）

- 单阶段新增扫描时间 ≤ +10%（相对同 corpus 的基线）；
- 峰值 RSS ≤ +50 MB（或 ≤ +5%，以较大者为准）；
- 新增全树遍历必须复用已有 parse / RepoIndex / cfgCache，不能每个候选重新读文件；
- 超过预算的阶段必须给出 profile 与优化方案，或拆分/回退。

---

## 4. Phase 1：CWD-SUB-1038 Type Layout（基础层）

### 4.1 前置重构（必须先做）

1. **收敛宽度表**：把 `evidence/typedefs.widthOf`（LP64 位宽）与 `graph/types_width.lp64Widths`（第二张表）收敛到单一共享实现；
   - 推荐新包 `internal/typeinfo`（或 `repofacts` 子文件）；
   - `typedefs.widthOf` / `graph.TypeByName` 改为委托；
   - 行为保持：现有单测必须全绿，不改变既有位宽结果。
2. **typedef 解析共享**：把 `evidence/typedefs` 的传递解析抽出为共享 API，避免 layout 再写一套。
3. **ABI 配置入口**：扩展 `build/compile_commands.go` 解析 `-m32` / `-m64` / `--target=<triple>` / `-target <triple>`；多 TU 冲突 → `unknown`。

> 如果评审决定 Phase 1 不做收敛，则必须在 PR 中明确记录“新增第三张表”的风险与后续偿还计划；不推荐。

### 4.2 事实模型

```go
type TypeLayout struct {
    Name    string
    Size    int
    Align   int
    Kind    string // primitive | struct | union | array | pointer
    Fields  []FieldLayout
    ABI     string // lp64 | ilp32 | llp64 | unknown
    Assumed bool
    Unknown string
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
| `sgre/internal/typeinfo/*.go`（新） | ABI 表、typedef 解析、布局算法、纯函数单测 |
| `sgre/internal/build/compile_commands.go` | 增加 ABI target 字段与解析；不破坏现有 `-D/-I` |
| `sgre/internal/repofacts/repofacts.go` | `Facts` 增加 `layouts`；`Build` 顺带计算；`LayoutOf(type)` 查询；新增 `WithFacts` / `FactsFromCtx` 以便 pre-detector 注入与测试回退 |
| `sgre/internal/repofacts/helpers.go` | 字段类型拼写、嵌套/匿名/数组/位域识别 |
| `sgre/internal/evidence/typedefs.go` | `widthOf` 委托共享实现 |
| `sgre/internal/graph/types_width.go` | `TypeByName` 委托共享实现（或保留薄封装） |
| `sgre/internal/cli/pipeline.go` | 在检测器前构建一次 `repofacts.Facts` 并 `WithFacts(ctx)` 注入；`buffer_overflow.Detect` / `filter_nullable_source` 改为优先用 ctx 实例，无 ctx 时回退到自建（测试兼容） |

### 4.4 检测器集成

- 新增 `detectCastObjectOOB`（在 `buffer_overflow.go` 内，复用 `bufCtx`，不新建 Detector）：
  - 识别 `p = (T *)malloc(n)` / `p = (T *)raw`；
  - 通过 `AliasGraph` 追到分配基址；
  - 对 `p->field` / `p[i].field` 计算 `offset + size`；
  - 与 `alloc_size` 比较（无符号、溢出安全）；
  - 产出 `layout_oob_read` / `layout_oob_write`（MVP suspected；confirmed 需评审批准新证明类别）。
- 先不做：
  - 指针已偏移的复杂形态（除常量偏移）；
  - 位域 / flexible array / `#pragma pack` 的完整语义；
  - 跨 TU 的 ABI 合并（冲突即 unknown）。

### 4.5 测试矩阵

**纯函数单测（typeinfo）**

- 基本类型（char/short/int/long/long long/float/double/pointer）；
- typedef 链；
- struct 自然对齐、尾部 padding；
- union；
- 嵌套 struct / 匿名 struct / 匿名 union；
- 数组字段；
- packed / aligned（支持或 unknown，必须有明确断言）；
- bitfield / flexible array → unknown；
- ILP32 / LP64 / LLP64 三种 ABI 的 `long` / pointer / struct 偏移差异；
- 未知类型 → unknown，不猜。

**集成测试**

- `malloc(8)` + `struct LargeRecord *` + `record->value` → suspected（或 confirmed，取决于评审）；
- `malloc(sizeof(*record))` + `record->value` → 不报；
- `calloc(n, sizeof(*record))` → 正确容量；
- 字段部分越界（`offset < size`、`offset + fieldSize > size`）；
- 嵌套字段 / union / packed / typedef；
- 第三方头文件类型（worktree header）；
- 未知类型布局 → 不 confirmed；
- `TestDeclarationFactInvariance` 增加 layout 的 inline / header-split 孪生体。

### 4.6 退出标准

- 所有新增单测/集成测试通过；
- `go test ./...`、`go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 全绿；
- benchmark 的既有类型 precision/recall 不下降（Phase 5 统一跑，但 Phase 1 至少跑 `c-vuln-benchmark` 的 `out-of-bounds`/`buffer-overflow` 子集）；
- 性能增量在预算内；
- 文档：`AI_JUDGMENT_BOUNDARY.md`（如果新增 confirmed）；`hint_tokens.go` token 登记。

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
4. **guard**：
   - 上界必须是关联到 buffer 容量的 `length` 参数（或常量/宏）；
   - 用 `!ReachesAvoiding(Entry, guardNodes, accessNode)` 证明支配；
   - `TrueSuccs/FalseSuccs` 判断访问在守卫的哪一侧；
   - 检查后 `index` 重赋值 → 守卫失效；
   - 负索引 / 有符号性单独处理。
5. **间接调用**：未解析的函数指针调用 → 不建立绑定；不猜。
6. **fail-open**：容量/元素大小/ABI 任一 unknown → 不确认；必要时 suspected。

### 5.4 测试矩阵

Issue §2.3 的 10 类 + 新增：

- 固定数组 + `sizeof` + 常量越界 → confirmed（评审批准后）；
- `malloc` + 已知容量 + 常量越界 → confirmed；
- 形参 + 调用点容量 + 常量越界 → confirmed；
- 形参 + `length` 容量 + 有效 guard → 不报；
- 形参 + `length` 容量 + 无 guard → suspected；
- `length` 不是容量 → 不关联；
- 多调用点容量不同 → 保留上下文；
- 多层调用 → 正确传播；
- guard 后 index 重赋值 → 不保护；
- 有符号负索引 → 识别；
- 间接调用/未解析 → 不绑定；
- `int` 数组 + 字节 `sizeof` → 正确换算（不把 16 字节当 16 个 int）；
- `sizeof(*p)` + typedef → 通过 Type Layout 求元素大小。

### 5.5 退出标准

- 新测试全绿；原 `TestFeedbackWatchCapabilityMatrix` 仍绿；
- `feedback_watch` 的 1029 正例开始报告（suspected 或 confirmed），安全对照不报；
- benchmark 中 `out-of-bounds` / `buffer-overflow` 的既有 finding 不丢、no_finding 不新增误报；
- 候选增量 ≤ +20%（或给出体量分析）；
- 性能增量在预算内。

---

## 6. Phase 3：CWD-SUB-1031 全局写入值摘要

### 6.1 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/graph/global_write.go`（新） | 单次遍历，收集 `GlobalWriteFact`；复用 `file_scope_variables` / `GLOBAL_ACCESS` / AliasGraph |
| `sgre/internal/cli/pipeline.go` | pre-detector 构建/注入 `GlobalWriteIndex` |
| `sgre/internal/evidence/null_source.go` | 新增 `detectGlobalWriteNull`：为解引用全局的函数发射 `NULL_VALUE`，`origin=global_write` |
| `sgre/internal/planner/null_analysis.go` | `nullSource` 增加 global_write 字段（writer/source/condition/callers） |
| `sgre/internal/planner/filter_nullable_source.go` | entry-seeded origin 列表加入 `global_write`；tier 逻辑 |
| `sgre/internal/planner/registry_null_deref.go` | evidence：writers / source / condition / 覆盖 / 未知外部 writer |
| `sgre/internal/planner/hint_tokens.go` | `glb-wr@` / `global-writer@` / `no-writer@` 等 token 登记 |

### 6.2 关键实现规则

1. **不把一次 NULL 写入传播为永久 NULL**：每个 writer 保留 `Condition` 与 `Definite`；消费函数按“所有 writer 都可能为 NULL”才给强证据。
2. **static vs extern**：`static` 的“无外部 writer”可证明；`extern` 默认存在未知外部 writer。
3. **多 writer / 覆盖**：evidence 必须列出所有 writer；存在 non-null writer → 不确认。
4. **并发**：线程入口写入 → 不确认；volatile/atomic → 不确认。
5. **confirmed 的唯一形态**：同一函数内直线顺序 `set(NULL); consume();`（CFG 无分支/无中间写入），且 `consume` 内无守卫，且没有其他 writer。其余一律 suspected。
6. **不改变**现有 `detectStaticNullGlobals` 的 static-only 通道；新通道是增量。

### 6.3 测试矩阵

Issue §4.4 的 12 类 + 新增：

- NULL 参数直接写全局 → suspected（或同函数直线 confirmed）；
- 非 NULL 参数写全局 → 不报；
- 两个 writer 分别 NULL / 非 NULL → suspected，evidence 列两者；
- 写入后被覆盖 → 不确认；
- 条件写入 → suspected，condition evidence；
- 多层调用 → 正确传播；
- 跨文件全局 → 正确解析；
- 静态初始化 → 正确（现有通道）；
- 多调用点 → 保留调用点上下文；
- 未知 writer（`&g` 逃逸 / 外部函数）→ suspected 或不出；
- 多线程写 → 不确认；
- 赋值后 NULL 检查保护 → 不报。

### 6.4 退出标准

- 新测试全绿；`TestFeedbackWatchCapabilityMatrix` 中 1031 的 static 正例仍报，安全对照不报；
- `feedback_watch` 的 1031 参数→全局正例开始报告（suspected）；
- 不产生新的 global 相关误报（benchmark no_finding）；
- 性能增量在预算内。

---

## 7. Phase 4：CWD-SUB-1140 输出参数成功/失败覆盖

### 7.1 前置（重要）

- `buildFuncSummaries` 当前被 `double_free` / `use_after_free` / `uninit` 各调用一次；Phase 4 先把它缓存成 scan-scoped 单次构建（首次调用构建、其余检测器复用 ctx 结果），再扩展摘要；
- 确认评审对 §7.4 的测试策略决定。

### 7.2 代码改动面

| 文件 | 改动 |
|---|---|
| `sgre/internal/evidence/free_summary.go` | `FuncSummary` 增加 `ParamReturnCoverage`（每参数每 return 的 `Covered/WriteLines/ReturnValue`）/ `SuccessValues` / `ErrorValues`；CFG per-return 覆盖；持久化 `outparam_return_paths` / `outparam_success_writes`（merge，不覆盖其他 key） |
| `sgre/internal/evidence/uninit_variable.go` | 消费 per-return 覆盖：success/error 分支判定；未检查返回值按评审决定 |
| `sgre/internal/planner/filter_uninit_flow.go` | `hasOutputParamWrite` 优先查摘要；未知外部函数仍 fail-open |
| `sgre/internal/planner/registry_uninit.go` | evidence + KnownLimitations 更新 |
| `sgre/internal/planner/hint_tokens.go` | `outparam@success` / `outparam@error` / `outparam-writer@` 登记 |
| `sgre/internal/planner/zz_uninit_output_param_test.go` | 按评审决定更新 `TestUninit_OutputParamUnguarded`（见 §7.4） |

### 7.3 关键实现规则

1. **success/error 分类**：只处理常量返回码（0 / 非零）；无法确定 → unknown。
2. **per-return 覆盖**：`!ReachesAvoiding(Entry, writeNodes, returnNode)` 证明写入支配该 return。
3. **调用者成功分支**：`if (rc != 0) return; use(out);` + 摘要证明 success 全写 → 不报。
4. **调用者错误分支**：`if (rc != 0) { use(out); }` + 摘要证明 error 未写 → 可 confirmed（must-uninit on that path）。
5. **未检查返回值**：按评审决定：
   - 推荐：`suspected`，evidence 写明 callee 失败路径、未写、调用者未检查；
   - 备选：保持完全静默，记为 Remaining Gap。
6. **未知外部函数**：仍 fail-open（视为写入），不产生新误报。
7. **不改变** `ParamWrites` / `ParamConditionalWrites` 的现有语义；只增加 per-return 精度。

### 7.4 `TestUninit_OutputParamUnguarded` 处理

Issue 要求保留该测试，并明确区分：

- 它锁定的是“不产生 Confirmed”，还是“不产生任何候选”？

现状：断言 `candidateForFunc != nil` 失败，即“不产生任何候选”。

方案（需评审批准）：

- 改为断言“不产生 `confirmed`；允许 `suspected`，且必须带 outparam evidence”；
- 新增一个测试锁定 `suspected` 的 evidence 内容；
- 保留原测试名与原始缺陷语义（不能简单改期望值掩盖问题）；
- 在 PR 描述中解释为什么这是**增加证据化降级**，不是放宽确认门槛。

如果评审选择“保持完全静默”，则 Phase 4 只做 success/error 分支，C 场景列为 Remaining Gap。

### 7.5 测试矩阵

Issue §5.5 的 15 类 + 新增：

- 所有路径初始化 → 不报；
- 条件初始化但所有 success 路径写入 → 不报；
- success 路径存在未写入分支 → 报（suspected 或 confirmed）；
- 调用者不读取 → 不报；
- 调用者读取 → 按路径判定；
- 调用者检查返回值后读取 → success 不报；
- 调用者不检查返回值 → 按评审决定；
- 调用者传入已初始化变量 → 不报；
- 通过 helper 初始化 → 沿用 forwarded-write；
- 提前 return / 多层调用；
- 输出参数结构体字段；
- 指针别名写入；
- 循环内初始化；
- 原 `TestUninit_OutputParamUnguarded` 回归。

### 7.6 退出标准

- 新测试全绿；原 uninit 回归测试（含 `TestUninit_OutputParamGuardNearErrorBranch`、`TestUninit_ConditionalWriteGuard`、`TestUninit_AlwaysWriteParamNotUninit`）全绿；
- `feedback_watch` 的 1140 正例保持报告，安全对照不报；
- 候选增量与 AI 体量有测量；如果 suspected 增量过大，收窄播种或加配置开关（不引入未测量缓存）；
- 性能增量在预算内。

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

### 8.2 基准 corpus

1. `sgre/testdata/feedback_watch`（四类能力夹具，候选级）；
2. `examples/c-vuln-benchmark/src`（39 文件 / 227 用例，precision/recall）；
3. 生成的大规模 C corpus：`go run testdata/perf/gen_codebase.go <dir> 100 50`（规模/内存基线）；
4. 既有的生产 C dogfood 仓库（如果在本机可用）；如果不可用，在最终报告中明确记录“未跑生产仓库”，不能假装跑过。

### 8.3 基线采集（Phase 0 之后、Phase 1 之前）

在 **未改代码** 的基线 commit 上采集：

```bash
cd sgre
go build -buildvcs=false -o ../bin/secguard ./cmd/secguard

# 1) 能力夹具（候选级）
../bin/secguard scan ../sgre/testdata/feedback_watch --db /tmp/sgbase-fw.db

# 2) benchmark（verdict 级；需要 AI 阶段）
../bin/secguard scan ../examples/c-vuln-benchmark/src --db /tmp/sgbase-bench.db
python3 ../examples/c-vuln-benchmark/scripts/validate-benchmark.py --json

# 3) 规模/性能
go run testdata/perf/gen_codebase.go /tmp/sgperf 100 50
/usr/bin/time -l ../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-perf.db

# 4) 增量
../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-inc.db
touch /tmp/sgperf/<one>.c
../bin/secguard scan /tmp/sgperf --db /tmp/sgbase-inc.db
```

记录：

- `scan_runs` 的 `duration_ms / index_ms / graph_ms / detectors_ms / plan_ms / report_ms`；
- `files_indexed / functions_indexed / seed_count / final_count / report_bytes / evidence_bytes`；
- 峰值 RSS；
- 每类型的 `scan_stats.seed_count / final_count`；
- 候选级 confirmed/suspected/possible 数量；
- verdict 级 confirmed/suspected/dismissed、precision/recall；
- AI token 消耗：**当前二进制没有 token 计量字段**，Phase 5 需要：
  - 从 AI host/orchestrator 的 settlement/usage 记录读取；或
  - 在最终报告中明确“未测量”及原因，不能编造数字。

### 8.4 回归对照表（最终报告必须包含）

| 指标 | 基线 | Phase 1 | Phase 2 | Phase 3 | Phase 4 | 变化 |
|---|---|---|---|---|---|---|
| 扫描总时长 | | | | | | |
| detectors_ms | | | | | | |
| plan_ms | | | | | | |
| 峰值 RSS | | | | | | |
| confirmed 数 | | | | | | |
| suspected 数 | | | | | | |
| possible 数 | | | | | | |
| benchmark precision | | | | | | |
| benchmark recall | | | | | | |
| no_finding 新误报 | | | | | | |
| feedback_watch 正例 | | | | | | |
| 增量扫描正确性 | | | | | | |
| AI token | | | | | | |

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
| 性能 | 有前后对照数据 |

---

## 9. 最终报告模板（回答 Issue §11）

```markdown
## 四个 Gap 的解决程度
| Gap | 现状 | Confirmed 形态 | Suspected 形态 | 仍不支持 |

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

## 还有哪些跨过程分析盲区
- 位域/柔性数组/packed：
- 未知 ABI：
- 函数指针/间接调用：
- 多线程全局状态：
- 未知外部 writer：
- 其他 Remaining Gap

## AI Token 消耗
- 测量方式或“未测量”说明
```

---

## 10. 风险与回滚

| 风险 | 触发条件 | 回滚/缓解 |
|---|---|---|
| Type Layout 误报 | assumed ABI / packed / union 别名 | 只 suspected；unknown 不出；回滚到 suspected-only |
| 1029 体量爆炸 | 普通 `buf[i]` 形参被播种 | 收窄为“有容量事实 + 常量索引/关联”；必要时配置开关 |
| 1031 状态污染误报 | 多 writer / 外部写 / 并发 | 默认 suspected；confirmed 仅同函数直线 |
| 1140 写回惯用法误报 | 大量 `fn(&x)` 无返回值检查 | 先做体量评估；必要时保持静默 + Remaining Gap |
| 性能超预算 | 新全树遍历 | 复用 parse/RepoIndex/ctx 注入；profile；拆分或回退 |
| 测试守卫失败 | 新增 confirmed 未登记 | 先登记 `TestConfirmedTierPolicy` / `TestDynamicConfirmedUpgradesRegistered` |
| schema 迁移失败 | 新增枚举/表 | MVP 不新增；如必须，走 additive migration + 回滚脚本 |

---

## 11. 评审决策清单（与分析文档 §10 对应）

实施前必须确认：

1. 1038 是否新增 `layout_oob_*` confirmed proof class；
2. 1140 未检查返回值是否允许 `suspected`（以及测试是否改期望）；
3. 1029 调用点常量越界是否沿用 `bounded_copy_overflow` 的确认语义；
4. Type Layout 放 `repofacts` 还是新 `internal/typeinfo`；
5. 无 `compile_commands.json` 时 ABI 默认策略；
6. 宽度表收敛是否在 Phase 1 前置；
7. MVP 是否接受“不新增表/枚举”的持久化策略；
8. 性能预算（+10% / +50MB）是否接受。

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
- [ ] 候选体量与性能有测量；
- [ ] PR 描述包含改动、测试、风险、Remaining Gap；
- [ ] 人工评审通过后由人合并（不启用 auto-merge）。
