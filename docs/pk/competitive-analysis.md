# SecGuard vs 业界顶尖 C 安全分析工具 — 竞品分析

> 评估日期：2026-08-19 · 评估版本：v0.2.1 · 对标工具：CodeQL (GitHub)、Infer (Meta)、Coverity (Synopsys)、Semgrep

## 1. 能力对比矩阵

| 维度 | CodeQL | Infer | Coverity | Semgrep | **sgre** |
|------|--------|-------|----------|---------|----------|
| 路径敏感数据流 | ✅ 深度 | ✅ bi-abduction | ✅ 深度 | ❌ 纯 syntactic | ✅ CFG 基 reaching-definitions |
| 过程间分析 | ✅ 1-CFA+ | ✅ 按需 | ✅ 深度 | ❌ | ⚠️ 0-CFA + 形参敏感返回摘要 |
| 值分析/区间域 | ✅ RangeAnalysis | ✅ Inferbo | ✅ | ❌ | ⚠️ RangeAnalysis lite（变量界定 + 守卫界 + AI fallback） |
| 别名分析 | ✅ | ✅ | ✅ | ❌ | ✅ 单层（q=p/p->f/p[i]） |
| 污点追踪 | ✅ 路径敏感 | ✅ | ✅ | ✅ syntactic | ✅ source→sink fixpoint |
| suppression 闭环 | ✅ // lgtm | ✅ | ✅ dismiss 持久化 | ✅ --suppress | ✅ DB 回读 + 候选过滤 |
| baseline diff | ✅ | ✅ | ✅ | ✅ --diff | ✅ --baseline <scan-id> |
| CI gate | ✅ 非零退出 | ✅ | ✅ | ✅ --error | ✅ --fail-on confirmed/suspected |
| SARIF codeFlows | ✅ 完整 | ⚠️ | ✅ | ✅ | ✅ 2 步 source→sink |
| 并行分析 | ✅ | ✅ | ✅ | ✅ | ✅ builder/detector/planner 并行 |
| 超时控制 | ✅ --time-limit | ✅ | ✅ | ✅ --timeout | ✅ --timeout |
| 增量索引 | ✅ | ✅ | ✅ | ✅ | ✅ SHA256 checksum 跳过 |
| 修复建议 | ⚠️ query 帮助 | ⚠️ | ✅ | ✅ 规则 | ✅ 12+ 类型 BAD/GOOD 模板 |
| 检测器覆盖 | 60+ 语言 | C/ObjC/Java | 20+ 语言 | 50+ 语言 | 22 detector / 20 CWE（C 专用） |
| 回归测试 | ✅ 大规模 | ✅ | ✅ | ✅ | ✅ 69 夹具 / 233 测试函数 |
| fuzzing | ✅ | ✅ | ✅ | ✅ | ❌ |

## 2. sgre 定位

**已超过 Semgrep**（C 语义分析维度）：路径敏感数据流、过程间污点、别名分析都是
Semgrep 的纯 syntactic 模式匹配做不到的。

**接近 Infer 的 intra-procedural 深度**：null_flow/lifetime/double_free/uninit_flow
的 CFG 基数据流与 Infer 的分离逻辑在同一层级，但 Infer 的 bi-abduction 做了 must
释放分析，sgre 只做 may。

**与 CodeQL/Coverity 有 3 个核心差距**：值分析、工程闭环、过程间上下文敏感性。

## 3. 偏弱项（按影响排序）

### 弱项 1：无值分析/区间域

- **影响**：`malloc(n * sizeof(T))` 溢出、`strncpy(dst, src, n)` 中 n>sizeof(dst)
  无法检测——这是 CWE-190/787 最经典的 CVE 模式
- **业界对标**：CodeQL RangeAnalysis、Infer Inferbo（区间域）
- **sgre 现状**：`integer_overflow.go` 显式排除 sizeof 表达式；`strncpy` 被列入
  SafeFunctions 完全跳过

### 弱项 2：suppression 闭环缺失

- **影响**：AI 每次重审同一批误报，狗粮场景重复劳动；`dismissed.json` 是死信
  （写出但无代码回读）；DB `status='dismissed'` 从不用于跳过再上报
- **业界对标**：CodeQL `// lgtm`、Semgrep `--suppress`、Coverity dismiss 持久化
- **sgre 现状**：`ClearSecurityEvents` 每次从零重跑

### 弱项 3：无 CI gate + SARIF 缺 codeFlows/suppressions

- **影响**：扫描恒返回 0，无法阻断 CI；GitHub UI 无法导航 source→sink、无法区分
  新旧 finding
- **业界对标**：CodeQL CLI、Semgrep CLI 均支持非零退出；SARIF codeFlows 是 GitHub
  Code Scanning 的导航基础
- **sgre 现状**：SARIF 只有 rules/results/locations，无 codeFlows/suppressions/
  fingerprints

### 弱项 4：全串行 + 无超时

- **影响**：多核机器 N 倍浪费；病态文件可挂死整个扫描
- **业界对标**：所有业界工具均并行+超时
- **sgre 现状**：5 graph builder + 22 detector + 20 planner 全串行；无
  context.WithTimeout

### 弱项 5：0-CFA 过程间分析

- **影响**：不按调用点区分上下文，同一函数被不同调用方调用时可能误报/漏报
- **业界对标**：CodeQL 1-CFA+、Infer 按需上下文敏感
- **sgre 现状**：`interproc.go` 的 PARAM_BINDING/RETURN 边是 0-CFA（每函数一份
  摘要，不按调用点区分）

## 4. 测试覆盖率（go test -cover 实测）

| 包 | 覆盖率 |
|---|---|
| internal/evidence | 81.7% |
| internal/log | 84.2% |
| internal/planner | 78.5% |
| internal/indexer | 76.9% |
| internal/graph | 59.4% |
| internal/cli | 45.0% |
| internal/parser | 33.0% |
| internal/report | 23.6% |
| internal/db | 21.1% |
| cmd/secguard | 0.0% |
| internal/agent | 0.0% |
| internal/apikb | 0.0% |
| internal/skills | 0.0% |

## 5. 改进路线图

| 优先级 | 改进 | 目标 | 状态 |
|--------|------|------|------|
| P0 | suppression 持久化回路 + baseline diff | dismissed.json 回读，候选过滤 | ✅ 已完成 |
| P0 | CI gate (--fail-on) + SARIF suppression/fingerprints | 非零退出码，GitHub UI 闭环 | ✅ 已完成 |
| P0 | 补齐 malloc(n*sizeof(T)) 溢出 + strncpy 大小比对 | 覆盖两个高频 CVE 模式 | ✅ 已完成 |
| P1 | 并行检测器 + 分析超时 | errgroup + context.WithTimeout | ✅ 已完成 |
| P1 | SARIF codeFlows + 结构化证据链 | source→sink 导航 | ✅ 已完成 |
| P2 | 值分析/区间域 | RangeAnalysis lite | ✅ 变量界定 + 守卫界 + AI fallback（见 §7） |
| P2 | 1-CFA 过程间分析 | 按调用点区分摘要 | 🚧 进行中（形参敏感返回摘要，见 §8） |

## 6. v0.2.1 反向自检修复

在 v0.2.1 的发布前反向自检中，发现并修复了两个并行化引入的回归（详见 CHANGELOG）：

1. **`parser.ParseCached` 数据竞争（崩溃级）**：并行 graph builder / detector / planner 共享同一
   `Parser`，但 `ParseCached` 直接读写 `cache`/`parsers` 两个 map 无锁——多 goroutine 并发解析同一文件
   时触发 "concurrent map writes" panic 与数据竞争。已加 `sync.Mutex` 串行化 map 访问与 tree-sitter
   Language 引用计数操作；新增 `TestParseCached_Concurrent`（-race）回归门禁。
2. **strncpy 有界拷贝溢出双重上报**：`checkBoundedCopyOverflow` 命中溢出后返回 false 导致回落通用
   buffer-overflow 路径，同一调用被上报两次（`bounded_copy_overflow` + `buffer_overflow`）。已改为
   bounded-copy 大小比对为权威处理路径，命中即跳过通用路径；`TestBoundedCopyOverflow` 断言单次上报。

上述修复均通过 `go test -race ./...` 全量竞态检测（0 数据竞争）。

## 7. v0.2.1+ 值分析攻坚（对标 CodeQL RangeAnalysis / Infer Inferbo）

针对弱项 1（无值分析/区间域）的第一阶段：不追求完整数值抽象解释域，而是实施
**"变量界定 + AI fallback"** 三层置信度方案——静态分析识别溢出风险形态，无法静态证明
的模糊情形（变量是否真的能到极值）交给 AI Agent 推理论证。

### 新增识别的 CWE-190 模式

| 模式 | 类别 | 静态判定 | 例 |
|------|------|----------|-----|
| `var * var` | `size_calc_overflow` | suspected | `malloc(n * m)` |
| `var * sizeof(T)` | `size_calc_overflow` | suspected | `malloc(n * sizeof(int))`（CVE-2021-43267） |
| `calloc(n, m)` 双变量 | `size_calc_overflow` | suspected | `calloc(count, size)` |
| `param * const` | `size_mul_const_overflow` | suspected | `malloc(n * 4)` |
| `param + const` / `param + var` | `size_add_overflow` | possible | `malloc(n + 1)` |
| `param - const` | `size_sub_overflow` | possible | `malloc(n - 1)` |

### 核心设计：把"证明不了"交给大模型

变量界定模式（`param * const` / `param + const` / `param - const`）以"操作数是函数
形参（caller/攻击者可控）"为门控，emit 为 suspected/possible 候选，携带表达式与形参
来源证据。AI Agent 的 skill（`integer-overflow/SKILL.md`）给出推理规则：形参来自
argv/getenv/recv 且无 clamp → confirmed；形参被有界守卫/strlen 界定 → false-positive。

这是 SecGuard 相对 CodeQL/Coverity 的差异化打法：**不硬造一个可能出错的区间域，而是
把区间推理外包给具备代码语义理解与 API 契约知识的大模型**。代价是 AI 推理成本；收益
是召回率（覆盖 CodeQL/Coverity 靠区间域才抓到的变量界定溢出）且无静态误判。

### CWE-787 变量长度越界（strncpy）

同一"变量界定 + AI fallback"打法扩展到有界拷贝：

| 模式 | 类别 | 静态判定 | 例 |
|------|------|----------|-----|
| `strncpy(dst, src, n)` 常量 `n > sizeof(dst)` | `bounded_copy_overflow` | confirmed | `strncpy(dst, src, 256)` 且 `dst[128]` |
| `strncpy(dst, src, n)` 变量 `n` 是形参 | `bounded_copy_var_size` | possible | `strncpy(dst, src, n)` 且 `dst[16]` |

**同时修复两个静默漏报 bug**（此前 `bounded_copy_overflow` 从未到达 AI Agent）：

1. `bounded_copy_overflow` 类别未加入 buffer-overflow 的 seed 允许列表（`Categories`），
   事件在 planner 播种阶段被丢弃。
2. `SafeFunctionFilter` 因 `strncpy` 属 SafeFunctions 而把该候选排除——bounded-copy 类别
   是检测器对"安全函数实际溢出"的显式裁决，安全函数排除不得覆盖它。

### Annex K `_s` 安全函数契约分析

各大公司已约定俗成使用 `_s` 安全函数，但它们**不是无条件安全**。`_s` 函数的
安全契约是三方的：`destination_capacity`（显式参数）必须**如实**反映真实缓冲区，
且 `source_length`/`count`（所需大小）必须装进该容量。sgre 按契约建模
（`SecureFuncSpec`：capacity 参数 + count 参数索引），覆盖完整清单：

`memcpy_s` / `memmove_s` / `memset_s` / `strcpy_s` / `strncpy_s` / `strcat_s` /
`strncat_s` / `sprintf_s` / `snprintf_s` / `vsprintf_s` / `vsnprintf_s` /
`asctime_s` / `ctime_s`。（`gmtime_s`/`localtime_s` 是线程安全 struct 返回变体、无容量
参数；`scanf_s`/`sscanf_s`/`fscanf_s` 用逐转换宽度参数，均另行处理。）

| 契约违约 | 类别 | 静态判定 | 例 |
|------|------|----------|-----|
| 容量参数（常量）> 真实缓冲区 | `secure_copy_overflow` | confirmed | `char dst[8]; memcpy_s(dst, 100, src, 50)` |
| 所需大小 > 声明容量（常量） | `secure_constraint_violation` | suspected | `memcpy_s(dst, 16, src, 64)` / `strcpy_s(dst, 4, "hello")` |
| 容量参数是形参（caller 可控） | `secure_copy_var_size` | possible | `memcpy_s(dst, sz, src, 8)` |
| 容量参数 = `sizeof(dst)`（数组） | — | 抑制 | `memcpy_s(dst, sizeof(dst), src, 8)` |

判定逻辑对齐契约语义：`actual capacity >= required → SAFE`；`required > declared
capacity → constraint violation`（handler 截断或 abort，实现相关）；`declared capacity
> actual → overflow`。`sizeof(ptr)` 指针宽度误用仍由 `sizeof-misuse`（CWE-467）覆盖。
这是相对"把 `_s` 当无条件安全排除"的普通扫描器的差异化能力，也契合 Repository
Facts + Contract/Memory skill 架构。

### 守卫常量传播（RangeAnalysis lite 收尾）

`IntOverflowGuardFilter` 从只处理 `size_calc_overflow` 扩展为同时收敛
`size_add_overflow` / `size_mul_const_overflow`：当所有变量操作数被前置
`if (op < CONST)` 守卫界定到小常量（< 32768），加法/乘常量运算不可能溢出，候选直接
丢弃——这就是区间域的"轻量"版本，用守卫界替代完整抽象解释。

### memcpy/memmove 变量长度越界（BoundedCopyFunctions 解耦）

`checkBoundedCopyOverflow` 从 SafeFunctions 分支中解耦，`strncpy`/`strncat`/`memcpy`/
`memmove` 统一做大小-容量比对，但保留各自的保守默认：

| 情形 | 判定 |
|------|------|
| 常量 `n > capacity`（任意有界拷贝） | `bounded_copy_overflow`（confirmed） |
| 常量 `n <= capacity` 的 copy 类（strncpy/memcpy/memmove） | 抑制（可证恰好装下） |
| 常量 `n <= capacity` 的 append 类（strncat） | 回落通用路径（已有内容未知，不可证安全） |
| 变量 `n` 是形参 + 已知容量 | `bounded_copy_var_size`（possible，AI 推理） |
| 未知容量 / 局部 `n`（strncpy） | 抑制（名义安全） |
| 未知容量 / 局部 `n`（memcpy/memmove/strncat） | 回落通用路径（保守标记） |

这样 `char dst[8]; memcpy(dst, src, 16)` 从笼统的 suspected 升级为 confirmed，
`memcpy(dst, src, 8)` 恰好装下不再误报，而未知容量的 memcpy 仍保守标记——精度提升
且无召回回退。

### scanf_s / sscanf_s / fscanf_s 逐转换宽度校验

`_s` 输入函数的契约不同于拷贝类：没有单一容量参数，而是**每个 `%s`/`%c`/`%[`
转换后跟一个缓冲区大小参数**。sgre 解析常量格式串、对齐 `(buffer, size)` 变参对、
逐个比对大小参数 vs 真实容量：

| 模式 | 类别 | 静态判定 | 例 |
|------|------|----------|-----|
| 宽度参数（常量）> 真实容量 | `secure_scanf_overflow` | confirmed | `char buf[10]; scanf_s("%s", buf, (rsize_t)100)` |
| 宽度参数是形参（caller 可控） | `secure_scanf_var_size` | possible | `sscanf_s(s, "%s", buf, sz)` |
| 宽度参数 = `sizeof(buf)`（数组） | — | 抑制 | `scanf_s("%s", buf, (rsize_t)sizeof(buf))` |

支持 `%d` 等非缓冲区转换与 `%s` 交错（`"%d %s"`）正确对齐，`%%`/`%*`（赋值抑制）
不计入参数。这是相对"把 `_s` 当无条件安全"的普通扫描器的又一处差异化。

## 8. v0.2.1+ 1-CFA 过程间上下文敏感（对标 CodeQL 1-CFA）

针对弱项 5（0-CFA 过程间分析）的第一阶段：**形参敏感的返回污点摘要**。

### 问题

0-CFA 的 `retTainted` 只有"函数是否返回污点"一个布尔值，无法表达
`char *id(char *s) { return s; }` 这类 passthrough 函数——它返回污点**当且仅当**
形参被污染，这是调用点（上下文）属性。

### 方案：把"是否被污染"从函数级下推到形参级

| 结构 | 含义 |
|------|------|
| `retTainted`（0-CFA） | 函数无条件返回污点（直接返回 getenv/argv 等） |
| `returnsParam`（新增） | 函数返回污点当且仅当某形参被污染（含多级传递） |

调用点传播（`x = g(args)`）：

- `retTainted[g]` → `x` 直接 gen 为污点（无条件，既有行为）。
- `returnsParam[g][i]` 且 `args[i]` 是污点源（getenv/argv）→ `x` gen 为污点。
- `returnsParam[g][i]` 且 `args[i]` 是裸标识符 `v` → 注入数据流 copy `x = v`，
  复用共享 reaching-sources 引擎让 `x` 继承 `v` 的污点。

`returnsParam` 是**跨函数 fixpoint**：基例 `return <param>` 逐字返回；归纳步
`return g(args)` 中若 `g` 返回其第 j 形参、且 `args[j]` 是 f 的形参，则 f 也
返回污点当且仅当该形参被污染——于是 `wrap2(s) { return id(s); }` 的多级
passthrough 也能正确传播。

于是 `id(getenv("CMD"))`（gen）、`x = getenv(...); id(x)`（copy）、
`wrap2(getenv(...))`（多级）都能传播污点到 sink，而 `id("literal")` /
`wrap2("literal")` 不产生污点——这正是 CodeQL 1-CFA 靠上下文克隆才拿到的精度，
sgre 用**形参敏感摘要 + 共享数据流引擎**以更低成本逼近。

### 形参污点回流函数体（entry seeding）

此前 `paramTainted`（形参被某调用方污染）只用于 sink 直接是形参的情形；sink 是
**由污染形参派生的局部变量**时（`char *cmd = s; system(cmd)`）形参污点没有回流
进函数体，导致漏报。现把被污染的形参作为**函数入口的污点种子**注入共享数据流
引擎（`flowAnalyzer.entrySeeds` → `IN[entry]`），使形参污点流经 copy / passthrough
传播到局部 sink：

```c
void sink(char *s) { char *cmd = s; system(cmd); }   // cmd 由污染形参派生
void caller(void) { sink(getenv("CMD")); }           // 形参 s 被污染 → cmd 被污染
```

这是"按调用点上下文"的正向半面：callee 带着 caller 的污点上下文求值，`cmd = s`
（copy）与 `cmd = build_cmd(s)`（passthrough）都正确传播，不再漏报。

### 待续（完整 1-CFA）

- 按调用点克隆摘要（真 1-CFA）：同一函数不同调用方传入不同上界/污点，分别
  求值（当前已覆盖"返回污点"与"形参污点回流"两个维度，但仍是合并所有调用点的
  may-taint 摘要，未按调用点区分形参**界定**/上界）——这是正面硬刚 CodeQL 的
  最后一段。