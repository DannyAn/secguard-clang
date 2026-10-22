# null-deref 候选偏多：检视意见与科学改进方案

- **检视对象**：`sgre` v0.9.8（`7319a29`）
- **样本扫描**：`examples/c-vuln-benchmark/.codeagent/secguard-clang/scans/latest/result.sarif`
- **约束**：本文只做检视与方案设计，**不修改任何代码**。
- **结论**：存在比“加候选上限”更科学的方案，因此本文按“检视意见 + 科学改进方案”合并输出。

---

## 0. 结论摘要

1. **这份样例并不能复现“候选泛滥”**：null-deref 原始种子 171 条，过滤后只剩 22 条，最终 **7 条自动确认 finding + 6 条 AI 候选**；6 条候选中 5 条与 benchmark 的 `expected-results.json` 精确对应，另 1 条（`process_buffer`）虽未被 ground truth 枚举，但从语义看是真实的未判空调用结果。也就是说，样例里 null-deref 的候选**精度很高、数量也不多**。

2. **样例真正暴露的是“会随代码规模放大的结构性机制”**，而不是某个过滤器失效：
   - 表达式级 fail-open（字段、下标、参数、未知调用一律“可能为空”）；
   - 跨函数可空性按**函数名**合并，且只有 `bool`，丢失“这是证明出来的还是假设出来的”；
   - `callResultNullSources` 对每个 `x = f()` 都合成一个可空源，**不做调用点契约/参数/守卫分析**；
   - 外部函数只认 4 个非空返回内建，头文件声明不算“已知”，注解不解析；
   - 一旦 `retNullable` 为真，候选被标成 `null@malloc-fail`（提示词说“已证明”），但 `SuspicionLevel` 仍是 `suspected`，于是**已证明的用例仍然送 AI**；
   - `MacroContext` 用“±8 行内出现任意全大写宏”判定，既误伤（样例候选 1 被 `POOL_SECT` 误标）又几乎不生效（`macro_uncertain` 27→27，0 丢弃）；
   - v0.9.5 的 `copyFieldBase` 增加了字段派生候选，但 `aliasRoots` 不能沿字段/指针算术收敛；
   - `caller_null` 对每个未守卫的变量实参播种，而调用方守卫只认“提前 return”一种形式；
   - 没有候选上限是对的（旧的 redis 1060→200 会静默藏尾），但**也没有按根因分组的审查单元**，于是同一个 getter / 同一个外部 API 在 N 个函数里产生 N 条 AI 任务。

3. **最有效的四个杠杆**（不是“把过滤器调严”）：
   - **证明/假设分层**：`proven` 与 `assumed` 分开，只有 `proven` 能自动确认，`assumed` 永远交 AI 或分组复核；
   - **符号级、类型感知的跨函数可空性**：按 FunctionID/链接属性解析调用，返回值必须是“指针类型”才可能为空；
   - **调用点契约**：非空返回、失败即 abort 的分配器、`returns_nonnull`/`nonnull` 注解、声明原型、项目配置；
   - **根因审查单元 + 审查预算**：按“同一个可空源/同一个被调函数参数”聚合，一个根因只评审一次，所有站点保留、可展开、可导出；预算只限制“审查单元数”，绝不丢站点。

4. **预期效果（需 A/B 验证，不先承诺数字）**：
   - 样例上，至少 `find_opt`（候选 1）与 `ResourceHandle_create`（候选 2）可由“已证明可空返回”转为自动确认；`get_shell_cfg`（候选 3）在补齐字段初始化分析后可转；`get_ext_config`（候选 4）必须保持 `external-unknown`，**不能**因为 `retNullable=true` 就自动确认；因此样例 AI 候选预期 **6→3~4**，而不是简单 6→2。
   - 生产上，先做 Phase 0 的 provenance census，再以“候选精度、每 KLOC AI 候选数、每 KLOC 审查单元数、召回率、自动确认精度”五个指标验收。目标建议：候选精度 +10pp 以上、AI 候选数 -30% 以上、审查单元数 -50% 以上、召回率不下降、自动确认精度 ≥95%。

5. **明确反对的做法**：
   - 直接加 `max_candidates` 上限（会重演 redis 的静默截断）；
   - 把所有 `retNullable=true` 的调用结果都自动确认（会把 `get_ext_config` 这种 fail-open 假设变成误报）；
   - 为了减少候选而放宽 `nullable_source`（会损失 ND-07/ND-08 这类真实回归用例）；
   - 只针对 benchmark 调参（样例不是生产语料，必须加生产派生回归集）。

---

## 1. 样本扫描的量化事实

### 1.1 漏斗

样本规模：38 文件 / 275 函数 / 3256 行；全类型 464 个原始种子，65 条 AI 候选，116 条自动确认 finding。

null-deref 单类型漏斗：

| 阶段 | 输入 → 输出 | 减少 | 说明 |
|---|---:|---:|---|
| 原始 `DEREFERENCE` 种子 | 171 | — | 所有成员访问/显式解引用/下标/宏恢复 |
| `sizeof_pseudo_deref` | 171 → 168 | -3 | `sizeof(p->f)` 不是解引用 |
| `non_nullable_array_suppress` | 168 → 141 | -27 | 数组/静态存储必然非空 |
| `array_oob_precedence` | 141 → 141 | 0 | 本类型无路由 |
| `nullable_source` | 141 → 27 | **-114（80.9%）** | 流敏感可空源收敛，主力过滤器 |
| `macro_uncertain` | 27 → 27 | **0** | 本样本完全没有丢弃 |
| `call_reach` | 27 → 27 | 0 | 全部可达 |
| `safe_function_exclude` | 27 → 22 | -5 | 安全函数/非空返回 |
| 去重/抑制 | 22 → 13 | -9 | 再分流为 7 条 confirmed + 6 条 suspected |
| **自动确认 finding** | **7** | — | 不经 AI，直接落 findings |
| **AI 候选** | **6** | — | 全部 `suspected` |

`dismissed.json` 中 null-deref 共丢弃 149 条，按原因：`nullable_source` 114、`non_nullable_array_suppress` 27、`safe_function_exclude` 5、`sizeof_pseudo_deref` 3。

**解读**：过滤器效率 96%，且主力是 `nullable_source`；`macro_uncertain` 在本样本是“空转”。所以“候选偏多”不是“过滤器没干活”，而是**过滤器保留的那一小部分在大型代码库里被重复放大**，以及**该自动确认的 proven 用例被错误地送进 AI**。

### 1.2 六条候选逐条核对

| # | 位置 | 变量 | Hint | 与 ground truth 的关系 | 判定 |
|---|---|---|---|---|---|
| 1 | `src/nat_null_deref_regress.c:42` | `sect` | `null@malloc-fail` `callee@...:27` `src@41` `guard@none` `macro-context` | **ND-15 finding** | 真阳性；`find_opt` 在溢出分支 `return NULL`，属于**证明可空返回**；`macro-context` 来自 7 行外的 `POOL_SECT`（它其实是全大写 static accessor **函数**，不是宏），是启发式误标 |
| 2 | `src/p2_raii_memory.c:46` | `handle` | `null@malloc-fail` `callee@...:14` `src@44` `guard@none` | 未被 ground truth 枚举（P2-01 只覆盖第 16 行的 memory-leak 反例） | 语义上真实：工厂返回 `malloc` 结果，调用方未判空；与 callee 内部第 16 行的解引用（本扫描未单独报告）是同一失败根因 |
| 3 | `src/p5_null_flow.c:80` | `shell_cfg` | `null@malloc-fail` `callee@...:74` `src@79` `guard@none` | **ND-07 finding** | 真阳性；getter 返回 `g_space.shell_conf`，该字段零初始化；当前是 fail-open，补齐字段初始化分析后可成为 proven |
| 4 | `src/p5_null_flow.c:97` | `c` | `null@malloc-fail` `callee@...:91` `src@96` `guard@none` | **ND-08 finding** | 真阳性；但 `get_ext_config` 只是转发一个**未定义外部函数**的返回值。它的 `retNullable` 是 fail-open 推出来的，**不是证明**；tier 应为 `external-unknown`，不是 `malloc-fail` |
| 5 | `src/p5_null_flow.c:121` | `t` | `null@external-unknown` `src@119` `guard@none` | **ND-10 finding** | 真阳性；accessor 可能返回 NULL，tier 正确 |
| 6 | `src/p5_null_flow.c:148` | `t` | `null@external-unknown` `src@147` `guard@none` | **ND-13 finding** | 真阳性；void* 参数有 NULL 检查，契约不成立，tier 正确 |

关键观察：

- **5/6 精确命中 benchmark 的 finding 期望**，另 1 条是未被枚举但语义合理的真实风险；说明样例的候选精度没有问题。
- **4/6 携带 `null@malloc-fail`，但全部是 `suspected`**。提示词对 `malloc-fail` 的定义是“PROVEN-nullable … textbook CWE-476”，这与“还要 AI 判”自相矛盾。
- 这 4 条里只有 `find_opt`（字面 `return NULL`）和 `ResourceHandle_create`（返回 `malloc` 结果）能被当前分析真正证明；`get_shell_cfg` 是字段 fail-open，`get_ext_config` 是外部调用 fail-open。**如果简单地把 `retNullable` 全部升级为自动确认，会把 2 条假设当成证明**。

### 1.3 七条自动确认 finding

| 位置 | 变量 | 语义 |
|---|---|---|
| `src/memory_extra.c:121` | `p` | `malloc` 后直接 `p[0]` |
| `src/network.c:45` | `packet` | `malloc` 后直接 `packet->data = ...` |
| `src/network.c:56` | `packet->data` | 同上，后续字段解引用 |
| `src/p3_edge_case.c:68` | `fc` | `FileCache_create` 内 `malloc` 后直接 `fc->buffer` |
| `src/p5_null_flow.c:19` | `p` | ND-02，`malloc` 后 `return p->value` |
| `src/p5_null_flow.c:136` | `t` | ND-12，调用方显式传 `NULL` |
| `src/p6_new_detectors.c:33` | `p` | `malloc` 后直接 `p[0]` |

其中 ND-02、ND-12 在 ground truth 中；其余 5 条未在 null-deref 的 15 条 ND 用例中枚举，但从源码看都是真实的未判空 `malloc` 解引用。**benchmark 的 expected 集不是穷举的 bug 清单**，不能把“多出来的 finding”直接当误报。

### 1.4 样本能说明什么、不能说明什么

**能说明：**

- 漏斗形状：`nullable_source` 承担 80.9% 的收敛；`macro_uncertain` 在无宏/少宏语料上几乎不工作。
- proven/assumed 混层：4 条 `malloc-fail` 全部进 AI，其中 2 条是假设。
- `macro-context` 的误标：候选 1 的标记只是来自相邻的全大写 accessor 函数，不是守卫也不是不透明宏。
- 跨函数重复根因的形态：候选 2 的 caller 站点与 callee 内部站点是同一个 `malloc` 失败根因。

**不能说明：**

- 不能证明“候选偏多”是误报造成的。样例 6 条候选均为合理缺陷或真实风险，未见明显误报。
- 不能给出生产环境的候选量级。样例是**带注入漏洞的回归 benchmark**，不是生产语料；它的 null-deref 密度（171 seeds / 3256 行）不代表生产。
- 不能验证“加 cap 有效”或“放宽过滤器有效”。这两种做法在样例上都会直接损失 ND-07/ND-08/ND-15 等回归用例。

**因此**：要解释生产项目的“候选偏多”，必须先在真实项目上做一次 **provenance census**（Phase 0），按“来源种类 × 证据强度 × 根因重复度”统计，而不是继续在 benchmark 上调过滤器。

---

## 2. 根因（逐条对照源码验证）

下面按“对候选量的影响”排序。每条给出代码证据、放大机制、样本体现和修复方向。

### R1. 表达式级 fail-open：字段/下标/参数/未知调用一律“可能为空”

**代码证据**

- `sgre/internal/planner/null_flow.go:1350` `exprReturnsNullable`：
  - `identifier` 是参数 → `return true`（`null_flow.go:1362-1364`）；
  - `call_expression` 未定义/未知 → `return true`（`null_flow.go:1399`）；
  - 默认分支把 `field_expression`、`subscript_expression`、`conditional`、`unary`、其他 `binary` 全部视为可能为空（`null_flow.go:1401-1405`）。
- `sgre/internal/planner/null_flow.go:1337` `returnsNullable` 只要任一 `return` 表达式可能为空，就把整个函数标为可空返回。
- `sgre/internal/planner/filter_nullable_source.go:419` 的 `retNullable` 不动点会把这种可空性沿调用链传播。

**放大机制**

任何一个 getter/包装函数，只要满足以下任一条件，就会被标成“可空返回”：

- 返回一个字段（`return g_space.shell_conf`）；
- 返回一个参数（`return p`）；
- 转发一个外部调用（`return external_get_config()`）；
- 返回一个未知表达式（条件、二元、类型转换等）。

随后 `callResultNullSources` 会在**每一个** `x = getter()` 的赋值处合成可空源，调用点只要解引用就成候选。一个被 100 个函数调用的 getter，会产出 100 条候选（去重键是“文件+函数+变量”，不是“被调函数”）。

**样本体现**

- 候选 3（ND-07）`get_shell_cfg` 返回字段；
- 候选 4（ND-08）`get_ext_config` 转发外部调用；
- 这两条都是 fail-open 语义，但只有前者在补齐字段初始化分析后才能证明；后者必须保持假设。

**修复方向**

- 保留 fail-open（开放世界不能假设非空），但把它显式建模为 `NullableAssumed`，与 `NullableProven` 分开。
- 表达式求值返回一个可空性格，而不是 `bool`：
  - `NonNull`：`&x`、字符串字面量、静态数组基址 + 偏移、`returns_nonnull` 调用、已知非空 API、`sizeof`、整数字面量；
  - `NullableProven`：字面 `NULL`、分配器、已知可空 libc、被证明会返回 NULL 的被调函数、零初始化且无写入的指针字段；
  - `NullableAssumed`：未知外部调用、未做 caller census 的指针参数、字段读取、未知表达式。
- 只有 `NullableProven` 允许进入自动确认；`NullableAssumed` 保留为候选/审查单元。

### R2. 跨函数可空性按“函数名”合并，且没有返回类型门控

**代码证据**

- `sgre/internal/planner/filter_nullable_source.go:419` `computeRetNullable` 返回 `map[string]bool`。
- `sgre/internal/planner/filter_nullable_source.go:426-440` 明确注释并实现：
  > name -> functions（same-name overloads are merged conservatively: if any one returns nullable, the name is treated as nullable）
- `definedNames` 也是按名字构建（`filter_nullable_source.go:438-441`）。
- `sgre/internal/planner/filter_nullable_source.go:519-523`：`function_summary.ReturnNullable` 直接置位，**绕过** `mayReturnPointer` 的预过滤。
- `sgre/internal/evidence/null_source.go:84-107` `detectReturnNull`：只要 `return NULL`/`0` 就设置 `ReturnNullable`，**不检查函数返回类型**。
- `sgre/internal/planner/null_flow.go:1563` `isNullLiteralNode`：把数字 `0` 当空值；这在指针上下文正确，但在 `int` 返回函数里是误判。

**放大机制**

- 同名 static 函数分布在不同文件时，只要其中一个返回可空，所有同名调用点都被视为可空。
- `int f() { return 0; }` 这样的函数会被标记为 `ReturnNullable`；如果调用方误用或者名字冲突，会制造完全不存在指针的候选。
- `retNullable` 只有 `true/false`，到下游只能靠 `malloc-fail` 这个标签表达“已证明”，无法表达“这是 fail-open 假设”还是“这是字面 NULL 证明”。

**样本体现**

- 候选 1 的 `find_opt` 是真证明；候选 4 的 `get_ext_config` 是 fail-open，但两者最终都拿 `malloc-fail` 标签。名字级 `bool` 模型无法区分它们。

**修复方向**

- 返回摘要改为按 **FunctionID/符号**：`ReturnSummary{PointerReturn bool, MayNull bool, Proven bool, Witnesses []ReturnSite}`。
- 调用点解析优先用符号（同文件 static、同链接属性、唯一外部定义）；只有无法解析的外部调用才允许按名字 fallback，并强制 `assumed`。
- 返回类型门控：只有 `T *` / `T **` / 函数指针 / 已解析 typedef 的指针返回才可能为空；`int/long/size_t/struct` 等非指针返回直接 `NonNull`。
- `return 0` 仅在指针返回类型下当 NULL；`return NULL` 在非指针函数中应报类型错误而不是可空源。
- 同名多定义且结论不一致时，合并为 `assumed`，不允许自动确认。

### R3. `callResultNullSources` 对每个 `x = f()` 合成源，缺调用点上下文

**代码证据**

- `sgre/internal/planner/null_flow.go:1314-1330`：

```go
func callResultNullSources(body parser.Node, retNullable map[string]bool) []nullSource {
    ...
    callee := rhsCallName(rhs)
    if callee == "" || !retNullable[callee] {
        return
    }
    out = append(out, nullSource{variable: name, line: rhs.StartLine(), origin: callee, definite: false})
}
```

它只做三件事：取赋值目标、取 RHS 调用名、查 `retNullable[name]`。**没有**：

- 返回类型检查（目标/被调返回是否指针）；
- 调用点契约（`returns_nonnull`、abort-on-failure、项目配置）；
- 调用点守卫（`if (!(x = f()))`、`x = f(); if (!x) return;` 由后续 flow kill，但源仍被合成并参与模型）；
- 实参可空性（`f(p)` 的返回值可能依赖 `p`）；
- 符号解析（同名函数）；
- 根因身份（同一个被调函数的多个调用点没有关联）。

**放大机制**

- 每个赋值点一个 `nullSource`，再经 `dedupKey` 按 `(FileID, FunctionName, VariableName)` 去重。于是同一个 getter/工厂在不同函数里各留一条候选。
- 因为 `retNullable` 是名字级 `bool`，一个被大量调用的通用 getter 会把“可空”扩散到整个代码库。
- 因为源被合成后参与 `flow`，即使调用点已经 `if (!x) return;`，源仍存在于模型里；后续 `reaching` 可能被 guard kill，但模型本身没有“这个调用点已检查”的事实，影响 tier 和分组。

**修复方向**

- `nullSource` 增加：`originSymbol`、`returnSite`、`strength`、`callsiteLine`、`witness`。
- 只在“被调返回类型是指针 + 未被契约证明非空 + 调用结果确实进入了解引用路径”时合成。
- 把调用点契约作为 `computeRetNullable` / `callResultNullSources` 的输入，而不是事后过滤。
- 分组键改为 `(originSymbol, returnSite)`，而不是变量名。

### R4. 外部调用 fail-open；非空返回内建只有 4 个；声明不算已知；注解不解析

**代码证据**

- `sgre/internal/evidence/null_source.go:258-323` `detectExternalCall`：
  - `knownFuncs[callName]` 才跳过（`null_source.go:303`）；
  - 否则 `origin := "external_call"`，发 `NULL_VALUE`（`null_source.go:311-320`）。
- `sgre/internal/evidence/null_source.go:339-362` `getKnownFunctionNames`：`known` 只包含**有定义的函数**；头文件声明只提供 `retTypes`，不算 known。
- `sgre/internal/apikb/apikb.go:907-913` `BuiltinNonNullReturning` 只有 `strerror`、`strsignal`、`inet_ntoa`、`ctermid` 四个。
- 没有 `returns_nonnull` / `_Nonnull` / `nonnull` 注解解析（全仓库搜索无实现）。

**放大机制**

- 任何“只有声明、没有定义”的第三方 API（`external_get_config`、SDK 里的 `foo_get()`）都会被当成未知外部调用，进而 fail-open 成可空源。
- `memcpy`、`memset`、`strcpy`、`strcat`、`memmove` 等大量“返回第一个参数”的 libc 函数不在非空集合里；它们的返回值被赋给指针后也可能生成候选。
- 注解本来是最便宜、最精确的契约来源（`__attribute__((returns_nonnull))`、`_Nonnull`），但完全没被利用。

**样本体现**

- 候选 4 的 `get_ext_config` 就是“声明未定义”的外部调用；正确 tier 是 `external-unknown`，不是 `malloc-fail`。

**修复方向**

- 建立**声明式契约表**（配置文件/内置 YAML），而不是继续在 Go 里堆 map：
  - `non_null_returns`（含 libc 返回首参的函数）；
  - `nullable_returns`（现有 libc 可空集合）；
  - `abort_on_failure`（`xmalloc`、`g_malloc`、`sdsnew` 等）；
  - `accessor_contract`（返回值是否依赖参数、是否可能空）。
- 解析常见注解：`__attribute__((returns_nonnull))`、`__attribute__((nonnull(1)))`、`_Nonnull`、`__declspec`、项目宏。
- 头文件声明进入“已知外部符号”表：保留 `external` 属性，但用声明返回类型 + 注解决定契约；未知才 fail-open。
- 扩大 `BuiltinNonNullReturning`：至少补齐 `memcpy/memmove/memset/strcpy/strncpy/strcat/strncat` 等“返回 dest”的函数，并加测试。

### R5. “已证明”与“假设”混层：`malloc-fail` 标签与 `suspected` 自相矛盾

**代码证据**

- 直接调用结果解引用路径（`filter_nullable_source.go:78-99`）：
  - `retNullable[callee]` → `SuspicionLevel = "suspected"`，`NullOriginTier = "malloc-fail"`。
- 变量路径（`filter_nullable_source.go:163-192`）：
  - 只有 `onlyCertainNullableSources`（分配器/已知 libc）会保持 confirmed；其他一律 `suspected`（`:163-165`）；
  - 但 `synthCallee` 分支仍然把 tier 写成 `malloc-fail`（`:180-189`）。
- `hint_tokens.go` / 候选文件 legend 对 `null@malloc-fail` 的定义是“PROVEN-nullable … textbook CWE-476”。

**放大机制**

- 提示词告诉 AI“这是已证明的 textbook 漏洞”，但 `splitBySuspicion` 只自动确认 `confirmed && !MacroContext`，所以这些候选仍然进入 AI 队列。
- 反过来，AI 可能因为“已证明”而 rubber-stamp；真正的 `external-unknown` 又和它混在同一个标签下，降低提示词的信噪比。
- 在样例中，4/6 候选都是这个状态；如果生产里 getter 调用多，这一层会直接贡献大量“本不该送 AI”的任务。

**修复方向**

- 把 `malloc-fail` 拆成：
  - `proven-allocator-fail`（分配器/已知可空 API）；
  - `proven-return-null`（被调函数体证明有 NULL 返回路径）；
  - `assumed-return-null`（fail-open 外部/未知表达式）；
  - `proven-field-null`（字段初始化分析证明为空）；
  - `external-unknown`（仅未知外部调用）。
- 自动确认规则：`cfg-proof`、`proven-*` 可以自动确认；`assumed-*`、`external-unknown`、`caller-arg-unknown` 只能进候选/审查单元。
- 提示词 legend 与 `SKILL.md` 同步更新；`TestVulnTypeSkillConsistency` 必须通过。
- **前提**：先把 R1/R2/R3 的证明做可靠；否则不能升级。

### R6. `MacroContext` 的“±8 行任意全大写宏”启发式

**代码证据**

- `sgre/internal/planner/macro_context.go:23` `macroContextWindow = 8`。
- `sgre/internal/planner/macro_context.go:78-102` `hasMacroContext`：在 `line±8` 内匹配任意 `NAME(...)`，只要 `isAllCapsMacroName` 或已知宏名。
- `sgre/internal/planner/filter_macro_uncertain.go:33` 给候选设置 `MacroContext`。
- `sgre/internal/planner/filter_macro_uncertain.go:35` 只在 `SuspicionLevel != "confirmed" && SourceLine == 0 && MacroContext` 时丢弃。
- `sgre/internal/cli/scan.go:595-603` `splitBySuspicion`：`confirmed && !MacroContext` 才自动确认。

**放大机制**

- **误伤**：候选旁边只要有日志宏、断言宏、访问器宏、迭代宏，就会被标记 `macro-context`；`confirmed` 候选因此被推给 AI。
- **漏放**：`macro_uncertain` 只在 `SourceLine == 0` 时丢弃；有源行的候选即使宏完全不透明也保留。样例 27→27，0 丢弃。
- **语义缺失**：不区分宏是“解引用宏”“守卫宏”“日志宏”“不透明宏”，也不看宏体是否真的包含候选表达式。

**样本体现**

- 候选 1（`nat:42`）的 `macro-context` 来自 7 行外的 `POOL_SECT(node_id)`。`POOL_SECT` 其实是**全大写的 static accessor 函数**，不是宏；它既不守卫也不解引用候选变量。这个标记是启发式噪声，真正的证明是 `find_opt` 的 `return NULL`。

**修复方向**

- 解析 `#define`，建立宏摘要：`params`、`derefParams`、`guardParams`、`returnsExpr`、`opaque`（token paste/未解析嵌套）、`isLogging`、`isAssert`、`isAccessor`。
- 候选级 `MacroInvolvement` 枚举：
  - `None`；
  - `Nearby`（仅相邻，不阻止自动确认）；
  - `DerefInMacro`（候选解引用发生在宏体内，按宏体语义决定）；
  - `OpaqueMacro`（宏体不可解析，保持 suspected）。
- `splitBySuspicion` 只对 `OpaqueMacro`/未解析守卫宏阻止自动确认。
- `filter_macro_uncertain` 只在 `OpaqueMacro && !proven` 时丢弃；不透明但 `proven` 的候选仍保留并交给 AI，而不是静默丢。
- 提示词只对 `DerefInMacro`/`OpaqueMacro` 显示 `macro-context`，`Nearby` 不显示。

### R7. `copyFieldBase` 与 `aliasRoots` 不对称：字段派生候选无法收敛

**代码证据**

- `sgre/internal/planner/null_flow.go:415-430` 创建 `copyFieldBase`：`q = p->f` 时记录 `q` 的 base 是 `p`。
- `sgre/internal/planner/null_flow.go:693-700` 在 transfer 中传播。
- `sgre/internal/planner/null_contract.go:99-121` `aliasRoots` 只处理：
  - `identifier`；
  - `parenthesized_expression`、`cast_expression`；
  - **不处理** `field_expression`、`subscript_expression`、指针算术 `binary_expression`/`pointer_expression`。
- `sgre/internal/planner/null_contract.go:78` `paramAliasUnproven` 依赖 `aliasRoots` 才能把“参数的纯别名”按“caller 未证空”收敛。

**放大机制**

- v0.9.5 增加 `copyFieldBase` 后，`q = p->f` 会继承 `p` 的可空源，这是正确的（通过可能为空的 base 读字段，结果也可能为空）；但它同时制造了新的候选变量 `q`。
- 由于 `aliasRoots` 不认字段读取，`q` 无法走 `paramAliasUnproven` 的收敛规则；即使 `p` 只是一个“caller 未证空”的参数，`q` 仍会留下候选。
- 同理，`q = p + i`、`q = arr[i]` 等派生也无法作为别名收敛。
- 在字段密集的 C 项目里，这会把一个 `p` 的问题放大成 `p`、`p->f`、`q` 多条候选。

**修复方向**

- 引入访问路径模型 `AccessPath{root, fields, index}`：
  - `q = p->f` 记录 `root=p, path=f`；
  - `q = p->f->g` 记录 `root=p, path=f.g`；
  - `q = arr[i]` 记录 `root=arr, index=i`；
  - `q = p + i` 记录 `root=p, offset=i`。
- transfer 时按路径 kill：base 重赋值、字段写入、`free`、`memset` 都要失效对应路径。
- `aliasRoots` 扩展：
  - 字段读取视为“derived from root”，用于**归并到 base 的根因**，而不是再生成一条独立候选；
  - 指针算术/下标视为“alias of root”，可以走 `paramAliasUnproven`；
  - 只有纯 copy/cast 才是“pure alias”，可以直接收敛。
- 字段初始化分析：
  - `= {0}`、`calloc`、`memset(...,0,...)` → 字段初始为空（proven nullable）；
  - `= &x`、静态地址、非空返回 → 非空；
  - 混合/未知 → assumed。
- 去重键从“变量”升级为“根因路径”，避免 `p` 与 `p->f` 重复评审。

### R8. `caller_null` 播种过宽，调用方守卫识别过窄

**代码证据**

- `sgre/internal/evidence/caller_null.go:226-265` `classifyArg`：
  - `identifier` 且未被 `callerGuardsVar` 证明 → 返回 `"null", false`（unknown null source）；
  - 只有 `NULL`、`0`、`&x`、字符串字面量、数组、显式守卫变量被区分。
- `sgre/internal/evidence/caller_null.go:272-299` `callerGuardsVar`：
  - 只认“支配调用的 `if (v == NULL) { return/exit; }`”；
  - 不认 `if (p) f(p);`、`p && f(p)`、`p ? f(p) : ...`、`assert(p)`、`if (!p) goto fail;`、循环条件等。
- `sgre/internal/evidence/caller_null.go:17-30` 的设计说明也明确：未守卫的变量实参一律作为 unknown source。

**放大机制**

- 对每个“解引用参数且无守卫”的被调函数，每个调用点的每个未守卫变量实参都会播种一个 `caller_null` 源。
- 如果调用方用了 `if (p)` 正分支、短路、断言或 goto 守卫，分析器不认，仍播种；这些源在 `nullable_source` 里可能因为与其他源混合而无法被 `onlyUnprovenCallerNullSources` 收敛。
- 没有按 `(callee, param)` 聚合，导致同一参数在 N 个调用点产生 N 条候选/审查任务。

**修复方向**

- 用同一套流引擎做**调用点实参可空性**：
  - 证明非空：`&x`、字符串字面量、数组、已守卫变量、非空返回、已证明非空别名；
  - 证明为空：`NULL`、`0`、`(void*)0`；
  - 未知：其余。
- 扩展守卫识别：正分支、短路、条件表达式、`assert`/项目守卫宏、`goto fail`、`break/continue`、循环条件、`do-while` 回边。
- 只有“被调参数是指针且被解引用、调用点实参未知/为空”才播种；全非空则不播种。
- 按 `(calleeSymbol, paramIndex)` 聚合为审查单元，附带 call-site census（null/unknown/non-null 各多少）。

### R9. 没有候选上限是对的，但缺少“根因分组 + 审查预算”

**代码证据**

- `sgre/internal/planner/planner.go:253-258` 明确不截断：
  > NOT truncate: every deduped candidate is handed to the AI for review. The former max-candidates cap silently hid the tail (redis null-deref 1060 deduped but only 200 surfaced).
- `sgre/internal/planner/planner.go:616` `deduplicateCandidates`。
- `sgre/internal/planner/planner.go:640-650` `dedupKey`：`ConvergeByVariable` 时是 `FileID:FunctionName:VariableName`。
- `sgre/internal/cli/scan.go:595-603` 只把 `confirmed` 自动确认，其余全部进 `needsReview`。

**放大机制**

- 去重键的粒度是“文件+函数+变量”。同一个可空源/同一个被调函数在 N 个函数里出现，就是 N 条候选。
- 每条候选在 AI 侧都是一次完整的证据阅读/判定；即使每条都正确，审查成本也随代码规模线性增长。
- 旧 cap 被移除是因为“静默藏尾”；但移除 cap 后没有补充“聚合 + 预算”层，于是把“藏尾”换成了“尾部淹没审查者”。

**修复方向**

- 引入 `ReviewUnit`（根因审查单元）：
  - 根因键：
    - 调用结果：`(originSymbol, returnSite)`；
    - caller-null：`(calleeSymbol, paramIndex)`；
    - 外部调用：`(externalSymbol, contractStatus)`；
    - 局部变量：`(file, function, variable, sourceKind)`；
    - 字段派生：`(rootType, fieldPath)` 或 `(rootSymbol, fieldPath)`。
  - 站点：所有解引用位置、每站点的 tier/guard/reachability。
  - 强度：按站点取最高（proven > assumed），但逐站点展示。
  - 优先级：强度、definite、可达性、来源新颖度、项目配置。
- 一个审查单元一张卡片，AI 只判定一次根因，站点继承结论；所有站点仍在 JSON/SARIF/报告中导出。
- 预算只限制“每类型审查单元数”和“每单元展示站点数”；溢出进入 `deferred` 桶，**不丢弃**，报告显示 deferred 数量与索引。
- 保留现有 per-variable 去重用于局部缺陷；在它之上做跨函数根因聚合。

### R10. 守卫模型覆盖不足

**代码证据**

- `sgre/internal/planner/guard_model.go:28-56` `buildGuardModel`：
  - 只处理 `if/while/for` 的 `condition`；
  - 加 `assert`/守卫宏的 straight-line kill。
- `sgre/internal/planner/guard_model.go:377-386` `isConditionKind` 明确排除 `do_statement`：
  > do_statement is excluded: its body runs before the condition is evaluated, so it establishes no non-null fact on entry.
- 该排除对“入口”是正确的，但目前也没有为 `do-while` 的**回边**、`goto`、`break/continue`、条件表达式等建立边事实。

**放大机制**

- 守卫识别不足会双向下错：
  - 该收敛的没收敛 → 候选偏多；
  - 该保留的误收敛 → 漏报。
- 在宏/循环/错误处理密集的 C 代码里，`do { ... } while(0)`、`goto fail`、`if (p) { ... }` 非常常见；只认“提前 return”会让 `caller_null` 和 `nullable_source` 的判断偏离真实控制流。

**修复方向**

- 为守卫条件实现一个小型布尔抽象解释器，显式给出 `trueVars`/`falseVars`，覆盖：
  - `&&`、`||`、`!`、`==/!= NULL`、`p`、`!p`；
  - 条件表达式 `p ? a : b`；
  - `assert`/`BUG_ON`/项目守卫宏。
- CFG 边事实扩展到：
  - `if` 的 true/false；
  - `while/for` 的入口/回边/退出；
  - `do-while` 的回边（入口不加 kill）；
  - `goto` 的支配关系；
  - `break/continue` 的退出边。
- 增加跨文件守卫宏/谓词助手摘要（已有部分实现，补齐测试）。

### R11. 目录排除是 basename-only，生产项目会放大噪声

**代码证据**

- `sgre/internal/indexer/file_walker.go:16-19` `DefaultExcludeDirs`：
  `deps, third_party, third-party, vendor, external, node_modules, tests, test, fuzzing, contrib, examples`。
- 只按目录 basename 匹配（`file_walker.go:56`），没有 glob、没有路径前缀默认、没有“生成代码/厂商代码”标记。

**放大机制**

- 生产仓库常见 `sdk/`、`libs/`、`3rdparty/`、`deps/` 的变体、`platform/` 下的 vendor 副本、生成代码目录；basename 不在列表里就会全量扫描。
- 这些目录通常包含大量“只有声明/未知外部调用/宏包装”的代码，正好命中 R1/R3/R4 的 fail-open，产生大量 assumed 候选。

**修复方向**

- 支持 `secguard.toml` 的 glob/路径前缀排除（部分已有 `excludePaths`，补齐默认值与文档）。
- 增加厂商/生成代码标记：`*.min.c`、`generated/`、`*_generated.c`、`@generated` 注释等。
- 报告 excluded 文件/行数，避免“排除后看起来种子变少”不可解释。

### R12. 次要但会叠加的精度问题

| 问题 | 代码证据 | 影响 |
|---|---|---|
| 行序 fallback 一律标 `external-unknown` | `filter_nullable_source.go:201-219` | 无 CFG 时本地 `malloc` 也被说成外部未知，提示词误导 |
| `return 0` 不区分返回类型 | `null_source.go:84-107`、`null_flow.go:1563` | `int` 函数被标可空，名字合并后污染调用点 |
| `function_summary.ReturnNullable` 绕过 `mayReturnPointer` | `filter_nullable_source.go:519-523` | 非指针函数进入 `retNullable` |
| 同名多定义合并 | `filter_nullable_source.go:426-440` | 一个可空定义污染所有同名调用 |
| flow 按变量文本键 | `null_flow.go:146-158` | 作用域遮蔽/同名变量可能串源 |
| `mayReturnPointer` 把 `identifier` 一律视为可能指针 | `null_flow.go:1626-1644` | 整数返回函数未被预过滤 |
| `callerNullDetail` 信息粒度粗 | `filter_nullable_source.go` 变量路径 | AI 难以判断 caller census |
| 源码行 fallback 的 `SourceLine` 可能为 0 | `filter_nullable_source.go:201-219` | `macro_uncertain` 的 `SourceLine == 0` 条件不稳定 |

---

## 3. 为什么“加候选上限”不是科学方案

旧实现曾经有 `max_candidates`，redis 的 null-deref 去重后 1060 条，只暴露 200 条，尾部被静默隐藏。`planner.go:253-258` 的注释就是这次修复的记录。

如果现在为了“候选偏多”重新加 cap：

- **它会隐藏真阳性**：benchmark 的 ND-15（`nat:42`）在 6 条里排第 1，但在生产里排序靠后的真实缺陷会被截掉。
- **它不解决根因**：候选多来自“同一根因重复 + 假设未分层”，cap 只是把重复和假设藏起来。
- **它不可审计**：用户无法知道被截掉的是什么，无法补审。
- **它和“confirmed 自动确认”冲突**：confirmed 不走 AI，cap 只影响 suspected；真正需要治理的是 suspected 的**根因重复度**，不是数量本身。

正确做法是把“候选列表”升级为“审查单元列表”：一个根因一个单元，所有站点保留；预算限制单元数，溢出进入 deferred，不丢站点。这样既不隐藏尾部，又能把 AI 工作量从 O(站点数) 降到 O(根因数)。

---

## 4. 目标模型：五态可空性 + 证据强度 + 根因审查单元

### 4.1 可空性格（nullability lattice）

对每个表达式/变量/字段/调用结果，求值到一个五态格：

| 状态 | 含义 | 典型来源 | 能否自动确认 |
|---|---|---|---|
| `NonNullProven` | 所有路径非空 | `&x`、字符串字面量、静态数组基址 + 偏移、`returns_nonnull`、已知非空 API、守卫覆盖所有路径 | 不产生候选 |
| `NonNullAssumed` | 按契约假定非空 | `void*` 框架缓冲区、项目声明 | 不产生候选，但记录 assumption |
| `Unknown` | 没有证据 | 未解析外部调用、未做 caller census 的参数、字段读取 | 只进审查单元，不自动确认 |
| `NullableAssumed` | fail-open 假定可能为空 | 未知外部调用、未知返回表达式、未初始化字段 | 只进审查单元，不自动确认 |
| `NullableProven` | 有具体证据可能为空 | 字面 `NULL`、分配器失败、已知可空 API、被调函数体证明有 NULL 返回、零初始化字段 | 可自动确认（需无守卫、可达、非不透明宏） |

关键规则：

- **合并**：路径汇合时取“最坏”状态（`NullableProven` > `NullableAssumed` > `Unknown` > `NonNullAssumed` > `NonNullProven`），但保留每路径 witness。
- **guarded**：守卫 kill 只作用于对应变量/路径；不能用“任意一个 guard”清除所有源。
- **strength**：`proven` / `assumed` 两个正交维度，不要用 `malloc-fail` 一个标签同时表达。
- **witness**：每个 `NullableProven` 必须带 witness（字面 NULL 的 return 行、malloc 调用行、零初始化行、caller 传 NULL 的实参行）。没有 witness 的不允许自动确认。

### 4.2 自动确认规则

```
auto_confirm(candidate) =
    candidate.reachability == reachable
    && candidate.deref_guard == unguarded
    && candidate.macro_involvement != OpaqueMacro
    && candidate.source.strength == proven
    && candidate.source.kind in {
         cfg-proof,
         proven-allocator-fail,
         proven-return-null,
         proven-known-nullable-api,
         proven-field-zero-init,
         proven-caller-literal-null
       }
```

其余全部进入 AI 候选/审查单元。`external-unknown`、`caller-arg-unknown`、字段读取未证明、未知表达式一律**不自动确认**。

这条规则直接修复 R5 的矛盾：`find_opt`、`ResourceHandle_create` 可以自动确认；`get_ext_config` 保持 `external-unknown`；`get_shell_cfg` 在字段初始化分析完成前保持 assumed。

### 4.3 根因审查单元（ReviewUnit）

```
ReviewUnit {
  id: hash(vulnType, rootCauseKey)
  rootCauseKey:
    call-result: (originSymbol, returnSite)
    caller-null: (calleeSymbol, paramIndex)
    external:    (externalSymbol, contractStatus)
    field:       (rootTypeOrSymbol, fieldPath)
    local:       (file, function, variable, sourceKind)
  sites: [DerefSite{file, line, function, variable, guard, reachable, tier}]
  strength: max(site.strength)
  priority: score(strength, definite, reachable, novelty, exposure)
}
```

呈现规则：

- 一个单元一张候选卡；卡片包含根因、证据、站点列表（可折叠）、每个站点的 tier/guard。
- AI 只判定一次“这个根因是否成立”；站点继承，但逐站点标记 reachability。
- 所有站点导出到 JSON/SARIF；报告和候选 markdown 都保留完整位置列表。
- 预算：`max_review_units_per_type`（例如 50）、`max_sites_per_unit_display`（例如 20）；超出的单元/站点进入 `deferred`，带索引和计数，绝不丢弃。

---

## 5. 改进方案（分阶段，可由他人实施）

### Phase 0：度量与影子模式（P0，1–2 天）

**目标**：先量化生产项目的候选构成，避免在 benchmark 上调参。

**改动**

- 在 `Candidate` / `EvidenceItem` 增加只读字段（先不改变行为）：
  - `OriginKind`（literal / allocator / known_nullable_api / return_null_path / field_zero_init / caller_literal / caller_unknown / external_unknown / field_read / alias）；
  - `Strength`（proven / assumed）；
  - `OriginSymbol`（FunctionID 或外部符号）；
  - `WitnessLine`；
  - `RootCauseKey`（先按现有信息生成）。
- `audit-report.md` / `dismissed.json` 增加：
  - 候选按 `OriginKind × Strength` 的交叉表；
  - 候选按根因键的重复度直方图（Top N）；
  - `macro_uncertain` 实际丢弃数；
  - `auto-confirm` 按 origin 的分布。
- 增加环境变量/配置 `nullability_shadow=true`：新旧两套 provenance 都计算，只记录差异，不改变输出。
- 在样例 + 1–2 个真实项目上跑基线，产出 `null-deref-provenance-census.md`（内部报告即可，不必入库）。

**验收**

- 不改任何候选/finding 输出；
- 能回答：生产候选里 `external-unknown`、`proven-return-null`、`field`、`caller-null` 各占多少；Top 10 根因重复了多少站点；`macro_uncertain` 是否空转。

### Phase 1：符号级、类型感知的跨函数可空性（P0，3–5 天）

**目标**：让“proven”真的可靠，消除名字级 `bool` 的污染。

**改动**

- 类型解析：
  - 从 `function_definition`/`declaration`/`parameter_declaration`/`field_declaration` 建立 `TypeTable`；
  - 解析 typedef、struct/union 指针、函数指针、数组、qualifiers；
  - 提供 `IsPointerType(typeText)` 与 `ReturnTypeOf(symbol)`。
- 返回摘要：
  - `map[FunctionID]ReturnSummary{PointerReturn, MayNull, Proven, Witnesses []ReturnSite}`；
  - `mayReturnPointer` 改为类型感知，不再把 `identifier` 一律当指针；
  - `detectReturnNull` 只在 `PointerReturn` 时置位；
  - `return 0` 只在指针返回类型下当 NULL。
- 调用点解析：
  - `resolveCallee(call)` 返回候选 FunctionID 集合（同文件 static 优先；外部链接按符号；同名多定义且不一致 → assumed）；
  - `definedNames` 从名字集合改为符号集合；
  - `retNullable` 从 `map[string]bool` 改为 `map[FunctionID]ReturnSummary`；
  - 外部未解析调用保留名字 fallback，但强制 `assumed`。
- 不动点：
  - 按调用图 SCC 迭代；每个函数只在输入摘要变化时重算；
  - 摘要合并规则：任一返回路径 `NullableProven` 且 witness 完整 → proven；否则 assumed。
- `callResultNullSources` 只对 `PointerReturn && MayNull` 的被调函数生成源，并携带 `OriginSymbol`、`ReturnSite`、`Strength`。

**验收**

- 新增单测：
  - `int f(){return 0;}` 不产生可空返回；
  - 两个同名 static 函数，一个返回 NULL、一个返回 `&g`，调用点不得被错误合并为 proven；
  - `return &g`、`return "x"`、`return arr + i` 均为非空；
  - `return external()` 为 assumed，不是 proven。
- benchmark ND-01..ND-15 全部通过；
- 样例 tier：`find_opt`、`ResourceHandle_create` → proven；`get_ext_config` → external-unknown；`get_shell_cfg` → assumed（待 Phase 5 字段分析）。

### Phase 2：调用点契约与外部 API 知识库（P0，3–5 天）

**目标**：把“未知外部调用”从默认可空改成“按契约三态”。

**改动**

- 新增 `CallContract`：
  - `NonNilReturn`（`returns_nonnull`、KB、abort-on-failure）；
  - `NullableReturn`（libc/POSIX、项目配置）；
  - `NonNilParams`（`nonnull(1)`、声明注解）；
  - `ReturnDependsOnArg`（accessor 契约）。
- 配置（`secguard.toml`）：

```toml
[nullability]
non_null_returns = ["xmalloc", "g_malloc", "sdsnew", "memcpy", "strcpy"]
nullable_returns = ["my_lookup", "my_getenv"]
abort_on_failure = ["xmalloc", "g_malloc"]

[nullability.contracts]
"my_accessor" = { returns = "maybe_null", depends_on_arg = 0 }
```

- 注解解析：`__attribute__((returns_nonnull))`、`__attribute__((nonnull(1)))`、`_Nonnull`、`__declspec`、项目宏。
- 声明原型进入“已知外部符号”表：用返回类型 + 注解决定契约；没有契约才 assumed。
- `detectExternalCall` / `callResultNullSources` 改为查 `CallContract`，不再只看 `knownFuncs`。
- 扩大 `BuiltinNonNullReturning`：补齐返回 dest 的 libc 函数；核对 `strdup/strndup/getcwd` 等已由 allocator 集合覆盖的可空 API，补齐 `asprintf/readdir` 等尚未覆盖的可空 API，并加单测。

**验收**

- `get_ext_config` 在样例中保持 `external-unknown`，不因 `retNullable` 被误标 `malloc-fail`；
- `memcpy(...)->field` 不再产生候选；
- 项目配置一个 `non_null_returns` 后，对应候选消失且有测试；
- benchmark 无回归。

### Phase 3：调用点实参可空性与守卫覆盖（P1，3–5 天）

**目标**：把 `caller_null` 从“未守卫就播种”升级为“每个调用点做可空性判定”。

**改动**

- 在 `CallerNullDetector` 内复用 CFG/流分析做调用点实参判定：
  - 若 `evidence` 不能直接依赖 `planner`（`planner` 已依赖 `evidence` 的事件模型），先把 CFG/流求值抽到中立包（如 `internal/nullflow`）或通过接口注入，避免 import cycle；
  - `classifyArg` 返回 `NonNullProven` / `NullProven` / `Unknown`；
  - 识别 `&x`、字符串、数组、非空返回、已守卫变量、已证明非空别名；
  - 识别 `NULL`、`0`、`(void*)0`。
- 扩展 `callerGuardsVar` / 守卫模型：
  - 正分支 `if (p) { f(p); }`；
  - 短路 `p && f(p)`、`p || f(p)` 的方向语义；
  - 条件表达式 `p ? f(p) : ...`；
  - `assert(p)`、`BUG_ON(!p)`、项目守卫宏；
  - `if (!p) goto fail;`、`break/continue`、循环条件；
  - `do-while` 回边（入口不加 kill）。
- 只有“被调参数是指针 + 被解引用 + 实参 unknown/null”才播种；全 non-null 不播种。
- 按 `(calleeSymbol, paramIndex)` 生成 `ReviewUnit`，附 call-site census。

**验收**

- ND-09（void* 直接 cast）、ND-11（普通指针 alias）保持 no_finding；
- ND-12（caller 显式传 NULL）、ND-13（被调有 NULL 检查）保持 finding；
- 新增正分支/短路/assert/goto 守卫的 fixture，均不产生候选；
- 生产 A/B 中 caller-null 审查单元数下降，召回不变。

### Phase 4：宏语义化（P1，2–3 天）

**目标**：把 `MacroContext` 从“±8 行任意全大写宏”升级为“宏体角色”。

**改动**

- 解析扫描范围内的 `#define`（含头文件）：
  - 宏名、参数、body；
  - `derefParams`（body 中解引用的参数）；
  - `guardParams`（body 中做 NULL 检查的参数）；
  - `returnsExpr`（body 返回的表达式是否是参数/字段/调用）；
  - `opaque`（token paste、未解析嵌套宏、条件编译分支）；
  - `isLogging` / `isAssert` / `isAccessor`。
- 候选级 `MacroInvolvement`：
  - 候选解引用表达式是否位于某个宏调用实参内；
  - 若宏体可解析，使用宏体的 deref/guard 语义；
  - 只有 `OpaqueMacro` 或“守卫宏未解析”才阻止自动确认。
- `filter_macro_uncertain`：
  - 丢弃条件改为 `OpaqueMacro && !proven`；
  - 不透明但 proven 的候选保留并交给 AI（附 `macro-opaque` 提示），不静默丢；
  - 统计实际丢弃数，避免“空转”。
- `splitBySuspicion`：
  - 仅 `DerefInMacro`/`OpaqueMacro` 阻止自动确认；
  - `Nearby` 不阻止。
- 更新 `hint_tokens.go` 与 `extension/shared/skills/null-deref/SKILL.md` 的 legend。

**验收**

- 样例候选 1 的 `macro-context` 不再出现（`POOL_SECT` 不是宏；最多作为 `Nearby` 展示上下文），不再阻止自动确认；
- 新增“日志宏相邻但无关”“守卫宏包裹解引用”“不透明宏包裹解引用”三个 fixture；
- `macro_uncertain` 在宏密集语料上有非零丢弃，且无 benchmark 回归。

### Phase 5：字段/访问路径与别名收敛（P1，3–5 天）

**目标**：让 v0.9.5 的字段派生能力与收敛规则对称，避免 `p->f` 放大候选。

**改动**

- 引入 `AccessPath`（root + fields + index/offset）：
  - `q = p->f`、`q = p->f->g`、`q = arr[i]`、`q = p + i` 都记录；
  - transfer 时按路径 kill：base 重赋值、字段写入、`free`、`memset`；
  - 只对指针字段传播可空性。
- `aliasRoots` 扩展：
  - 纯 copy/cast → 现有 `paramAliasUnproven`；
  - 字段读取 → 归并到 root 的根因（`ReviewUnit` 的 field 键），不再单独评审；
  - 指针算术/下标 → alias of root，可走 caller-null 收敛。
- 字段初始化分析：
  - `= {0}`、`calloc`、`memset(...,0,...)` → 字段初始为 NULL（proven nullable）；
  - `= &x`、静态地址、非空返回 → 非空；
  - 混合/未知 → assumed。
- `copyFieldBase` 增加失效条件与路径信息；避免 `q` 继承 base 源后无法收敛。
- 去重键从 `(file, function, variable)` 升级为“根因路径”；同一 root 的多个字段读取合并为一个单元。

**验收**

- `tree = (T*)(resp->group_data); tree[0]` 仍为候选（字段可能为空）；
- `q = p->f` 且 `p` 是“caller 未证空”参数时，不再为 `q` 单独生成候选，而是归并到 `p` 的根因；
- ND-07 的 `g_space.shell_conf` 在零初始化分析后成为 proven；
- 新增字段写入 kill、字段初始化非空、字段混合初始化三个 fixture。

### Phase 6：审查单元与预算（P1，3–5 天）

**目标**：把 AI 工作量从“站点数”降到“根因数”，且不丢任何站点。

**改动**

- `ReviewUnit` 数据结构与生成器（见 4.3）。
- `EvidenceItem` 增加 `UnitID`、`RootCauseKey`、`SiteIndex`、`SiteCount`。
- 候选 markdown 改为“一单元一卡片”，站点列表可折叠；JSON/SARIF 仍逐站点导出。
- 排序：按单元优先级，而不是按站点风险；同一单元的站点连续展示。
- 预算：
  - `max_review_units_per_type`；
  - `max_sites_per_unit_display`；
  - 溢出 → `deferred_units` / `deferred_sites`，报告显示计数与索引；
  - 绝不使用“max candidates”截断。
- AI 指令（`SKILL.md`）：先判根因，再逐站点确认 reachability；不确定时只标记根因，不重复读每个站点。

**验收**

- 样例 6 条候选生成 6 个单元（样例没有重复调用，收益不明显，属于预期）；
- 构造一个 getter 被 20 个函数调用的 fixture，候选站点 20 条、审查单元 1 个；
- 所有站点在 JSON/SARIF/报告中可见；
- deferred 永不导致站点丢失（对比总数）。

### Phase 7：守卫模型、目录排除与次要精度（P2，2–3 天）

**目标**：补齐 R10/R11/R12，降低残余噪声。

**改动**

- 守卫模型：布尔抽象解释器 + CFG 边事实（`goto`、`break/continue`、`do-while` 回边、条件表达式）。
- 目录排除：glob/路径前缀、生成代码标记、excluded 统计。
- 行序 fallback：保留但明确标注 `degraded`，不要把本地分配器说成 external。
- flow 键：从变量文本升级为 `(scope, variable)` 或符号 ID，避免遮蔽。
- `callerNullDetail`：附 caller census 摘要（null/unknown/non-null 计数）。

**验收**

- 新增 `do-while`、`goto fail`、正分支、短路守卫 fixture；
- vendor 目录排除后种子数下降且可解释；
- benchmark 无回归。

### Phase 8：灰度与发布（P0 收尾，随版本）

**目标**：安全上线，可用指标证明效果。

**改动**

- `nullability_v2` 配置开关；
- 影子模式：新分析只记录差异，不改变输出；
- canary：benchmark + 1 个真实项目；
- A/B 达标后默认开启；
- 保留旧路径一个版本，便于回滚；
- 更新 `CHANGELOG.md`、`VERSION`、`hint_tokens.go`、`SKILL.md`、`ADDING_A_VULN_TYPE.md`（如新增字段/步骤）。

**验收**

- 影子模式差异可解释；
- canary 无召回回归；
- 自动确认精度抽样 ≥95%；
- `go test ./...`、`go test -tags nosqlite ...`、`TestVulnTypeSkillConsistency` 全绿；
- benchmark `validate-benchmark.py` 全绿。

---

## 6. 优先级、工作量与验收

| 阶段 | 优先级 | 预估 | 主要收益 | 主要风险 |
|---|---|---|---|---|
| Phase 0 度量/影子 | P0 | 1–2 天 | 用数据定位生产候选构成 | 无行为变化，风险低 |
| Phase 1 符号/类型跨函数 | P0 | 3–5 天 | 让 proven 可靠；消除名字级污染 | 类型解析不完整 → 保守为 assumed |
| Phase 2 调用点契约/KB | P0 | 3–5 天 | 消除外部调用 fail-open 噪声 | 契约表覆盖不足 → 仍 assumed |
| Phase 4 宏语义 | P1 | 2–3 天 | 消除 `macro-context` 误伤；让 `macro_uncertain` 真正工作 | 宏解析复杂 → 不透明即 suspected |
| Phase 6 审查单元/预算 | P1 | 3–5 天 | 直接降低 AI 任务数；不丢站点 | 分组错误 → 需要根因键测试 |
| Phase 3 caller-null/守卫 | P1 | 3–5 天 | 降低 caller-null 重复；提升守卫精度 | 守卫建模错误 → 双向风险 |
| Phase 5 字段/别名 | P1 | 3–5 天 | 消除 `p->f` 候选放大；证明 ND-07 | 路径爆炸 → 限深/限字段 |
| Phase 7 守卫/排除/次要 | P2 | 2–3 天 | 残余噪声与召回补齐 | 低 |

**建议实施顺序**：Phase 0 → 1 → 2 → 4 → 6 → 3 → 5 → 7 → 8。其中 0/1/2 是“证明可信”的前提，4/6 是“AI 工作量”的直接杠杆，3/5 是“重复根因”的治理，7 是收尾。

**总工作量**：约 5 周（单人顺序实施；若 Phase 3/5 并行或复用类型分析，可压缩到 3–4 周）。其中 P0 子集约 2 周可先上线。

---

## 7. 评测协议（A/B）

### 7.1 指标定义

| 指标 | 定义 | 目标 |
|---|---|---|
| `candidate_precision` | 抽样判定为真的候选 / 抽样候选总数 | +10pp 以上 |
| `finding_precision` | 抽样判定为真的 finding / 抽样 finding 总数 | 不下降 |
| `recall` | 命中 expected finding 的用例 / expected finding 总数 | 不下降 |
| `ai_candidates_per_kloc` | AI 候选数 / KLOC | -30% 以上 |
| `review_units_per_kloc` | 审查单元数 / KLOC | -50% 以上 |
| `auto_confirm_precision` | 抽样自动确认 finding 中真实缺陷占比 | ≥95% |
| `ai_turns_per_confirmed` | AI 轮次 / 确认缺陷数 | -20% 以上 |
| `assumed_ratio` | assumed 候选 / 全部候选 | 可观测，不设硬目标 |
| `deferred_sites` | 因预算未展示但保留的站点数 | 必须可导出，不丢失 |

### 7.2 语料

- **回归语料**：`examples/c-vuln-benchmark`，`expected-results.json` 175 例；重点 ND-01..ND-15、P2/P3 对照。
- **生产语料**：选择 3–5 个真实项目（含 NAT / redis 类 C 项目，或用户的生产仓库），固定 commit；至少一个宏密集、一个字段密集、一个外部 SDK 密集。
- **生产派生回归集**：把生产 A/B 中确认的 FP/TP 脱敏后加入 `testdata`，每个案例带 `expect: finding/no_finding` 和根因说明。这是防止 benchmark 过拟合的关键。

### 7.3 流程

1. 冻结语料与 commit；
2. 旧版跑基线，记录候选/ finding/审查单元/耗时；
3. 新版影子模式跑同一语料，记录差异；
4. 对差异候选做盲抽样（每臂 ≥100 条，或全量若少于 100），由人/AI 双盲判定；
5. 计算 precision/recall 的 Wilson 置信区间；用 bootstrap 比较两臂；
6. 只有“召回不降 + 自动确认精度达标 + 候选精度提升”同时满足才默认开启；
7. 如果某阶段未达标，按阶段回滚，不整体回滚。

### 7.4 样例验收（可直接执行）

- `validate-benchmark.py`：ND-01..ND-15 全过；无新增 no_finding 违规。
- 样例 null-deref：
  - 自动确认 finding ≥7（不减少）；
  - AI 候选 6→3~4（`find_opt`、`ResourceHandle_create` 转自动确认；`get_shell_cfg` 视字段分析；`get_ext_config` 保持 external-unknown）；
  - 候选 1 的 `macro-context` 不再出现（或降为 `Nearby` 不阻止自动确认）；
  - `get_ext_config` 的 hint 从 `malloc-fail` 改为 `external-unknown`；
  - `macro_uncertain` 丢弃数可解释（样本可以为 0，但生产宏密集语料必须 >0）。
- 所有输出仍保留 6 个站点（即使转为 finding/单元），不得丢失位置。

---

## 8. 风险与反模式

### 8.1 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| 过度收敛 → 漏报 | 类型/契约/守卫规则过严，真实可空路径被抑制 | 每个 narrowing 规则配 no_finding + finding 双向 fixture；A/B 召回门禁 |
| 自动确认不健全 | 把 assumed 当 proven，产生误报 finding | 只有带 witness 的 proven 才能自动确认；影子模式 + 抽样审计 |
| 类型解析不完整 | typedef/函数指针/宏类型解析失败 | 解析失败 → assumed，不升级；记录 unresolved 类型统计 |
| 宏模型不完整 | 宏体不可解析 | 标记 `OpaqueMacro`，保持 suspected；不静默丢 |
| 分组掩盖站点 | 一个单元只展示部分站点 | JSON/SARIF 全量导出；UI 可展开；deferred 计数校验 |
| benchmark 过拟合 | 只针对 175 例调参 | 生产派生回归集；多项目 A/B；盲抽样 |
| 性能退化 | 符号解析/SCC/字段路径增加扫描时间 | 缓存、按需分析、限深；记录 phase timing |
| 输出兼容性 | 新增 tier/字段破坏下游 | 保留旧字段一个版本；SARIF 新增 properties 而非改旧值；文档同步 |

### 8.2 反模式（明确不要做）

1. **不要加 `max_candidates` 硬上限**：会重演 redis 1060→200 的静默截断。
2. **不要把所有 `retNullable=true` 自动确认**：`get_ext_config` 会变成误报。
3. **不要为了降候选放宽 `nullable_source`**：会丢 ND-07/ND-08/ND-15。
4. **不要把 `macro-context` 窗口从 ±8 调小/调大**：问题不是窗口大小，是“没有宏体语义”。
5. **不要只改 `SuspicionLevel` 不改 provenance**：那只是把 AI 队列换个名字，证据仍然不可审计。
6. **不要用 `return 0` 统一当 NULL**：必须看返回类型。
7. **不要用函数名做跨函数证明**：同名 static/重载会污染；符号解析失败就 assumed。
8. **不要静默丢弃任何站点**：deferred 也必须可导出、可计数、可复查。

---

## 9. 附录

### 9.1 样本复现与核对命令

```bash
# 查看审计漏斗
sed -n '/### null-deref/,/### out-of-bounds/p' \
  examples/c-vuln-benchmark/.codeagent/secguard-clang/scans/latest/audit-report.md

# 查看null-deref候选索引
cat examples/c-vuln-benchmark/.codeagent/secguard-clang/scans/latest/candidates/null-deref/_index.md

# 查看丢弃原因
python3 - <<'EOF'
import json
d=json.load(open('examples/c-vuln-benchmark/.codeagent/secguard-clang/scans/latest/dismissed.json'))
for v in d['by_vuln_type']:
    if v['vulnerability_type']=='null-deref':
        print(json.dumps(v, indent=2))
EOF

# 运行benchmark校验
python3 scripts/validate-benchmark.py \
  --expected examples/c-vuln-benchmark/expected-results.json \
  --sarif examples/c-vuln-benchmark/.codeagent/secguard-clang/scans/latest/result.sarif
```

### 9.2 关键代码索引

| 主题 | 文件:行 |
|---|---|
| 返回表达式可空性 | `sgre/internal/planner/null_flow.go:1337`、`:1350`、`:1399`、`:1401` |
| 调用结果合成可空源 | `sgre/internal/planner/null_flow.go:1314` |
| 名字级 `retNullable` | `sgre/internal/planner/filter_nullable_source.go:419`、`:426`、`:519` |
| 直接调用结果 tier/分流 | `sgre/internal/planner/filter_nullable_source.go:78-106` |
| 变量路径 tier/分流 | `sgre/internal/planner/filter_nullable_source.go:109-193` |
| 行序 fallback | `sgre/internal/planner/filter_nullable_source.go:201-219` |
| 外部调用 fail-open | `sgre/internal/evidence/null_source.go:258-323` |
| 已知函数名 | `sgre/internal/evidence/null_source.go:339-362` |
| `return NULL` 检测 | `sgre/internal/evidence/null_source.go:84-107` |
| 非空返回内建 | `sgre/internal/apikb/apikb.go:907-913` |
| 可空返回内建 | `sgre/internal/apikb/apikb.go:941-980` |
| caller-null 播种 | `sgre/internal/evidence/caller_null.go:226-265` |
| caller 守卫 | `sgre/internal/evidence/caller_null.go:272-299` |
| 宏上下文 | `sgre/internal/planner/macro_context.go:23`、`:78-102` |
| 宏过滤器 | `sgre/internal/planner/filter_macro_uncertain.go:33-35` |
| 自动确认分流 | `sgre/internal/cli/scan.go:595-603` |
| 去重键 | `sgre/internal/planner/planner.go:640-650` |
| 不截断注释 | `sgre/internal/planner/planner.go:253-258` |
| `copyFieldBase` | `sgre/internal/planner/null_flow.go:415-430`、`:693-700` |
| `aliasRoots` | `sgre/internal/planner/null_contract.go:99-121` |
| 守卫模型 | `sgre/internal/planner/guard_model.go:28-56`、`:377-386` |
| 目录排除 | `sgre/internal/indexer/file_walker.go:16-19` |
| null-deref 注册 | `sgre/internal/planner/registry.go:726-734` |
| 解引用播种 | `sgre/internal/evidence/dereference.go:24-56`、`:223-240` |

### 9.3 建议新增/修改的测试

| 测试 | 目的 |
|---|---|
| `TestReturnNullableIntFunction` | `int f(){return 0;}` 不被标可空 |
| `TestReturnNullableSameNameStatics` | 同名 static 不互相污染 |
| `TestReturnNullableAnnotation` | `returns_nonnull` 不产生源 |
| `TestExternalContractNonNilReturn` | `memcpy` 返回值不产生源 |
| `TestExternalAccessorAssumed` | 声明未定义 accessor 保持 external-unknown |
| `TestMacroNearbyDoesNotBlockAutoConfirm` | 相邻宏不阻止自动确认 |
| `TestMacroOpaqueStaysSuspected` | 不透明宏包裹解引用保持 suspected |
| `TestCallerPositiveGuard` | `if (p) f(p);` 不播种 |
| `TestCallerShortCircuitGuard` | `p && f(p)` 不播种 |
| `TestCallerAssertGuard` | `assert(p); f(p);` 不播种 |
| `TestFieldZeroInitProven` | `= {0}` 字段可证明为空 |
| `TestFieldWriteKillsSource` | 字段写入 kill base 源 |
| `TestAliasFieldConvergesToRoot` | `q = p->f` 归并到 p 的根因 |
| `TestReviewUnitGrouping` | 20 个调用点 → 1 个审查单元 |
| `TestDeferredSitesPreserved` | 预算溢出仍导出全部站点 |
| `TestNoCandidateCap` | 任何情况下不截断候选 |

### 9.4 术语

- **proven**：有具体 witness 的机器证明（字面 NULL、分配器、已知可空 API、被调函数体 NULL 返回、零初始化字段、caller 字面 NULL）。
- **assumed**：开放世界/fail-open 假设（未知外部调用、未解析返回表达式、未做 caller census 的参数、未证明字段）。
- **根因**：一个可空来源（被调函数返回、caller 参数、外部 API、字段路径、局部赋值）。
- **审查单元**：一个根因 + 其所有解引用站点。
- **deferred**：超出审查预算但被保留、可导出、可复查的单元/站点。

---

**一句话总结**：候选偏多的根因不是“过滤器不够严”，而是“proven 与 assumed 没分层、跨函数按名字合并、同一根因按站点重复计数”。先把证明做可靠（Phase 1/2），再把宏和字段的假设标清楚（Phase 4/5），最后用根因审查单元承接 AI 预算（Phase 6）；不要用 cap，也不要用放宽过滤器换数量。
