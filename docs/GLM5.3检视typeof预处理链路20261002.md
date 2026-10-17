# typeof 预处理链路检视（2026-10-02）

> 检视与修复分离：本报告只产出问题清单，修复由其他 AI Agent 依据本清单执行。
> 检视重点：`typeof(expr)` 预处理重写链路（用户生产验证发现该类代码存在一定程度误报）。

## 基线

- Commit：`a081fac`（v0.8.2 + double-free 指针参数修复后），工作区 clean
- 已知前提：tree-sitter-c v0.24.2 grammar 不含 typeof（GCC 扩展），`sgre/internal/parser/parser.go` 的 `preprocessGccExtensions` 将 `typeof(expr)` / `__typeof(expr)` / `__typeof__(expr)` / `typeof_unqual(expr)` 统一重写为 `void *`（等长空格填充，保持行/列位置）
- 验证方式：源码静态分析 + 本地 CLI 二进制端到端 scan + 临时单测实证（已清理，关键断言随本报告落档）

## 核心结论

typeof 重写链路的**正确性设计（等长 padding、词边界、字符串/注释跳过、多种拼写）是好的**，已有 3 个 FP 修复锁定测试（`TestUncheckedReturn_TypeofAndMultiAssignFP`）覆盖常规形态。但存在两类结构性缺陷：

1. **`replaceTypeofAt` 内部的括号深度扫描不感知字符串/注释**（与外层 `skipNonCode` 不对称）——注释/字符串含括号时产生"截断过短破坏注释"或"括号失衡不重写"两类解析事故，前者已被端到端实证为 **unchecked-return 误报**；
2. **`void *` 统一近似是类型语义破坏性重写**——值类型（含 double）被变成指针类型，端到端实证为 **divide-by-zero 浮点豁免失效误报**；类型敏感检测（浮点豁免、符号/宽度、表示比较）全部失真。

**共 8 项：2 CRITICAL / 3 HIGH / 3 MEDIUM。**

---

## 问题清单

### TF-01（CRITICAL，已端到端实证）括号深度扫描不感知注释 → 重写截断在注释中间 → AST 错乱 → unchecked-return 误报

- **定位**：`sgre/internal/parser/parser.go:234-247`（`replaceTypeofAt` 的 depth 扫描循环只数 `(`/`)`，不调用 `skipNonCode`）
- **机制**：外层主循环用 `skipNonCode` 跳过字符串/注释，但一旦匹配到 `typeof(` 进入 `replaceTypeofAt`，其括号平衡扫描对注释内的括号照数不误：
  - 注释含 `)`：depth 提前归零 → 重写截断在**注释中间** → 注释体被覆盖为 `void *`、剩余 `*/)` 裸露 → AST 解析失败/错乱
- **实证**（端到端 + 单测）：
  - fixture `caseF_comment_paren`：`typeof(nodes->leafs /* trailing comment with ) inside */) w = (typeof(nodes->leafs))malloc(sizeof(*nodes->leafs));` **带 null check**（`if (w == NULL) return;`）→ 产生 `unchecked-return on 'malloc(...)'` 候选——malloc 的赋值链因 AST 错乱断裂、null check 失效 → **误报**
  - 单测：`typeof(int /* x ) y */) v = 0;` 重写后为 `void *            y */) v = 0;` → `HasError() = true`
- **影响**：生产代码中"typeof 参数表达式后跟注释"并不罕见（如 `typeof(p->field /* in bytes */)`），每一处都可能产生 unchecked-return / null-source / resource-leak 等**依赖赋值链的检测器误报**
- **修复建议**：`replaceTypeofAt` 的 depth 扫描循环内复用 `skipNonCode`（遇字符串/注释先跳过、再计数括号），与外层主循环保持同一扫描语义

### TF-02（HIGH，已单测实证）注释/字符串含不配对 `(` → depth 失衡 → 不重写 → typeof 保留 → 解析失败或静默误析

- **定位**：同 TF-01（`parser.go:234-247`）
- **机制**：注释/字符串内的 `(` 使 depth 多加 1，找不到平衡 `)`（`k` 扫到文件尾）→ `depth != 0` → `continue` → **不重写**：
  - `typeof(int /* x ( y */) v = 0;` → 不重写，tree-sitter 错误恢复后 `HasError() = false`（**静默误析**：`typeof(...)` 被解析为 call_expression、`v = 0` 与其断链成独立赋值）→ 依赖赋值链的检测器产生与 TF-01 同款误报，且**检测器完全无感知**
  - `typeof("(") v = 0;` → 不重写 → `HasError() = true`（解析失败）
- **影响**：静默误析形态（HasError=false）比解析失败更危险——没有任何告警，检测结果直接失真
- **修复建议**：与 TF-01 同一处修复（depth 扫描复用 `skipNonCode`）；修复后补"注释含 `(` / `)` / 字符串含括号"三类锁定测试

### TF-03（HIGH，已单测实证）宏定义体内的 typeof 被静默破坏，宏参数引用被删除

- **定位**：`parser.go:142-168`（`preprocessGccExtensions` 不跳过 `#define` 行）
- **实证**：`#define SWAP_T(x) typeof(x)` 重写后变为 `#define SWAP_T(x) void *`——**宏体从 `typeof(x)` 变成 `void *`，宏参数引用 `x` 被静默删除**，且 `HasError() = false` 无任何告警
- **影响**：
  - 该宏以非指针类型使用时（`SWAP_T(int) m = 0;`），使用处类型被错误处理（叠加 TF-04 的类型破坏）
  - 宏体被破坏后，扫描器侧与编译器侧的宏语义分叉，AI classifier 拿到的证据与真实编译语义不一致
- **修复建议**：`skipNonCode` 增加 `#define` / `#include` 等预处理指令行的跳过（typeof 出现在指令行内不重写），或至少保留宏参数引用（如 `#define SWAP_T(x) char *` 之类仍需权衡——推荐整行跳过，保留原始形态）

### TF-04（CRITICAL，已端到端实证）`void *` 统一近似是类型语义破坏性重写 → divide-by-zero 浮点豁免失效误报

- **定位**：`parser.go:150`（`replacement := []byte("void *")`）+ `sgre/internal/evidence/divide_by_zero.go:501`（浮点类型豁免）
- **机制**：`typeof(expr)` 被统一重写为 `void *`，**声明变量的类型信息全部丢失**。值类型（含 `double`）被变成指针类型：
  - `typeof(ratio) d = ratio;`（ratio 是 `double`）→ 重写后 `void * d = ratio;` → divide_by_zero 的浮点类型豁免（按声明类型判定）看不到 `double` → `d / n` 被当作整数除法分析
- **实证**（端到端）：fixture `caseH_float_typeof`：`typeof(ratio) d = ratio; return d / n;` → **产生 `divide-by-zero on 'n'` 候选**。原语义是浮点除法（IEEE，除以 0 不触发 CWE-369），**干净误报**
- **其他影响**（漏报/失真方向，未逐一端到端）：
  - `typeof(u32) n = a - b;` → 符号/宽度信息丢失 → integer-overflow / sign-conversion 判定失效（漏报）
  - uninit 的值/指针分类按 `void *` 失真（值变量被当指针）
  - `data_representation.go` 的 int↔float 表示比较按 `void *` 失真
- **修复建议**（自洽方案，按改动量递增）：
  1. **最小闭环**：`Tree` 增加重写记录（原始行号 → 原始 typeof 参数文本），检测器在需要类型信息的判定点（divide_by_zero 浮点豁免、argument_type、data_representation、uninit 分类）查该记录：声明来自 typeof 重写的变量，类型视为 UNKNOWN——divide-by-zero 对 UNKNOWN 类型保守 skip（浮点与整数除法皆不可证），而非误报
  2. **中期**：预处理层按 `typeof` 参数表达式做轻量类型启发（含 `->`/`.`/`[0]`/`*` → 指针近似；`sizeof`/字面量 → 数值近似），减少值类型被改成指针的比例
  3. **长期**：升级 tree-sitter-c 至支持 typeof 的版本（需评估 grammar 兼容性），删除整个重写层

### TF-05（HIGH）检测器事件 expression 属性使用重写后失真文本，与 candidate evidence 的 Code Context 不一致

- **定位**：`parser.go:313-318`（`Node.Text()` 从重写后的 `t.src` 切）+ 各 detector 的 `emitEvent`（如 `sgre/internal/evidence/argument_type.go:149` 的 `"expression": arg.Text()`）
- **机制**：检测器事件的 `expression` 属性来自 `Node.Text()`（重写后 src）→ 含 typeof 的行显示 `(void *         )...` 失真文本；而 candidate evidence 的 Code Context 由 `sgre/internal/report/snippet.go:108` 从**磁盘原始文件**读 → 显示原始 `typeof(...)` 形态。**AI classifier 同时拿到两份互相矛盾的证据**
- **影响**：AI 研判基于失真 expression 或在两份证据间摇摆，可能误判；报告读者看到的 expression 与源码对不上
- **修复建议**：`Tree` 同时保留原始 src，`emitEvent` 的文本属性统一从原始 src 切（或提供 `Node.OriginalText()`）；至少对含 typeof 重写记录的行回退到原始文本

### TF-06（MEDIUM，已端到端实证）typeof 声明形态触发 memory-leak 别名误报（ML-02 已知根因）

- **定位**：`sgre/internal/evidence/memory_leak.go:267`（`findFrees` 按变量名收集、无别名分析，前轮 ML-02/ML-05 已记录）
- **实证**（端到端）：fixture `caseC_alias_free`：`typeof(nodes->leafs) v = malloc(...); typeof(nodes->leafs) q = v; free(q);` → **产生 `memory-leak on 'v'` 候选**（v 经 q 释放未被识别）
- **性质**：根因非 typeof 链路（前轮已记录的 ML-02），本轮实测确认 typeof 声明形态同样触发——用户生产 typeof 误报的可能形态之一
- **修复建议**：按前轮 memory-leak 清单 ML-02 项执行（引入别名分析/消费 AliasBuilder 边），本项无需单独修复；修复后用本 fixture（typeof 形态）作为回归用例

### TF-07（MINOR，静态分析）skipNonCode 对未闭合字符串/注释返回 len(result)，后续 typeof 全部不重写

- **定位**：`parser.go:187/195/203`
- **机制**：文件中存在未闭合字符串或注释（语法错误代码）时，`skipNonCode` 返回 `len(result)`，主循环一次跳到文件尾 → 其后所有 `typeof(` 均不重写 → 解析失败/误析
- **影响**：低（依赖上游代码本身有语法错误），但与 TF-01/02 叠加时会放大误报面
- **修复建议**：未闭合的 `"`/`'` 可按行边界截断（未闭合字符串不可能跨行，除拼接）；未闭合块注释保持现状并记录

### TF-08（MEDIUM，已端到端对照实证，补充发现）uninit 对"裸指针声明未初始化 + 解引用"不检出（检测盲区，非 typeof 回归）

- **定位**：uninit 检测的候选生成范围（malloc 跟踪 heap 变量 + 栈值变量；裸指针声明未初始化不在范围）
- **实证**（端到端对照）：`struct leaf_s *p; p->x = 0;`（无 typeof）与 `typeof(nodes->leafs) p; p->x = 0;` **均无 uninit 事件**——对照组无事件说明非 typeof 引入的回归，而是检测盲区本身
- **影响**：未初始化指针解引用是真实世界极常见的缺陷形态（CWE-457 / CWE-822 家族），当前完全不检出
- **修复建议**：单独立项评估（uninit 链路新增裸指针未初始化跟踪），与 typeof 链路修复解耦

---

## 验证状态

| 项目 | 验证方式 | 状态 |
|------|---------|------|
| TF-01 | 端到端 scan（caseF unchecked-return 误报）+ 单测（重写文本 + HasError=true） | 已实证 |
| TF-02 | 单测（`/* ( */` 不重写 HasError=false 静默误析；`"("` HasError=true） | 已实证 |
| TF-03 | 单测（宏定义体重写文本） | 已实证 |
| TF-04 | 端到端 scan（caseH divide-by-zero 干净误报） | 已实证 |
| TF-05 | 源码分析（Node.Text vs snippet.go 磁盘读） | 已回源、未端到端 |
| TF-06 | 端到端 scan（caseC memory-leak 误报） | 已实证 |
| TF-07 | 源码分析 | 静态结论 |
| TF-08 | 端到端对照 scan（对照与 typeof 形态均无事件） | 已实证 |

- 基线单测：`go test ./internal/parser/` 全绿（临时验证测试已清理）；`TestUncheckedReturn_TypeofAndMultiAssignFP` 锁定的 3 个常规 FP 修复有效
- 端到端：本地 CLI 二进制 + fixture 三轮 scan（常规形态 / uninit 对照 / 类型敏感），全程未修改任何源码

## 修复优先级

1. **TF-01 + TF-02**（同一处修复，`replaceTypeofAt` depth 扫描复用 `skipNonCode`）——直接消除"注释/字符串含括号"整类误报与静默误析
2. **TF-04**（typeof 重写记录 + 检测器类型 UNKNOWN 保守处理）——消除值类型（含 double）被变指针导致的 divide-by-zero 等类型敏感误报/漏报
3. **TF-03**（预处理指令行跳过）、**TF-05**（事件文本用原始 src）
4. **TF-06**（归入前轮 memory-leak ML-02 项）、**TF-08**（uninit 裸指针盲区单独立项）、**TF-07**（MINOR）

## 给修复 Agent 的补充说明

- 修复 TF-01/02 后，需把本报告的三类实证 fixture 形态（注释含 `)`、注释含 `(`、字符串含括号）转为**正式回归测试**（含 finding / no_finding 对照），并落到 `examples/c-vuln-benchmark`
- 修复 TF-04 时注意：`Tree` 增加重写记录属于 parser 包 API 变更，需同步 `Parse` / `ParseCached` 两条路径与既有调用方
- 用户生产误报形态若与本报告不符，优先用**用户原帖精确代码形态**复现（参考 TF-01 的 caseF 形态与 TF-04 的 caseH 形态）