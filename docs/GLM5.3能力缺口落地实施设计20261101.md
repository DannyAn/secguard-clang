# sgre 能力缺口落地实施设计（唯一开工文档）

- **输入**：`docs/GLM5.3领域专家检视sgre能力缺口20261101.md`（缺口清单 GAP-01~12，基线 140f4ca）
- **日期**：2026-11-01。本文是三轮设计（原设计 → E2E 补全 → V3 原地修复）的**融合终稿**，旧的三份设计文档已删除，本文为唯一执行依据。
- **用户核心约束**：零误报优先（保产品检测口碑）、扫描性能不劣化（Wall-clock ≤ +5%）。全部落点经源码回验（file:line 为证）。

---

## 0. 总纲

### 0.1 三条铁律

1. **零误报优先于检出率**。confirmed 只允许四类可证判据之一，禁止 may-analysis 晋级（对齐 ADDING_A_VULN_TYPE.md:39-42）：

   | 判据类 | 定义 | 使用项 |
   |---|---|---|
   | AST 确定性 | 节点结构本身即证明（`return &local`） | GAP-01/04/05(confirmed 部分) |
   | 常量可证 | 字面量/宏折叠后可判定（`x << 40`） | GAP-06/07/08 |
   | 区间/CFG 证明 | RangeFacts/guardModel/DefiniteValueAt 的 must 结论 | GAP-07/09 |
   | 数据流 must | freed-state 类 must 收敛 | （本轮无新增） |

2. **拿不准就 suspected，suspected 也拿不准就不出**。每项的"不触发清单"与触发条件同等重要。
3. **性能预算受控**。每个新检测器是单遍 AST 遍历（signal_handler.go "sound and cheap" 样板：无命中早退）；引擎增强给出增量预算与回退开关。

### 0.2 验证协议（每批必走，缺一不算完成）

1. **单测**：detector 正/负用例 + planner tier 断言（六步清单第 6 步）。
2. **benchmark 第七步**：`examples/c-vuln-benchmark/src/` 新增 TP/FP fixture + `expected-results.json` 登记 + `scripts/validate-benchmark.py` 的 `DETECTOR_T` 映射登记。
3. **端到端**：构建本地 CLI 二进制，写 C 文件跑 `secguard scan`，同时查 candidates SARIF 与 auto-confirmed 双口径。
4. **A/B 对照**：pre/post 二进制在**互相独立的干净目录**各跑首轮扫描（suppression index 会污染对比）；既有 finding 集合零回归 + 新类型按预期出现 + 严重度分布对照表。
5. **nosqlite 子集**绿。
6. **E2E 五步**（extension 面）：双 guard 必跑（`go test ./internal/skills/` 含 severity 一致性断言 + `python3 release/check-extension-consistency.py`）；SKILL Hint Tokens 表与 buildHintParts 发射逐 token 人工核对语义（guard 只查拼写）；candidates 文档渲染断言（`_index.md` 行 + `NNN_*.md` 的 Verdict Facts/hint 渲染——AI 输入契约，渲染错=AI 全错）；install.sh 展开冒烟（新 SKILL/ci 模板进 `.claude/`/`.opencode/` 产物）；可选 agent 冒烟（任一宿主对小项目跑真实研判，确认 SKILL 分类规则可执行）。

### 0.3 批次总览（每批独立可交付可回退）

| 批 | 内容 | 新 type | 风险 |
|---|---|---|---|
| B1 | GAP-01 栈逃逸 + GAP-04 invalid-free + GAP-05 switch 检查 | 3 | 低（纯 AST） |
| B2 | GAP-06 移位 UB + GAP-07 INT_MIN + GAP-08 chmod（含 DefiniteValueAt 引擎项） | 0 | 低 |
| B3 | **B3-a severity 刻度修复链** + B3-b 行内豁免 + CI 模板 | 0 | 低（severity 是用户可见语义需公告） |
| B4 | GAP-02 函数指针调用解析 + GAP-03 compile_commands | 0 | 中（A/B 严控） |
| B5 | GAP-09 污点长度 | 1 | 中高（放最后） |

依赖：B1/B2/B3 相互独立；B4 独立；B5 最后（需 B1-B4 的 A/B 基线做对照）。

---

## 1. GAP-01 栈地址逃逸 —— 新 type `stack-address-escape`（CWE-562）

### 1.1 检出形态

| 形态 | 示例 | tier |
|---|---|---|
| M1a return 取地址 | `return &local;` / `return &local.f;` | **confirmed** |
| M1b return 局部数组衰减 | `int arr[4]; return arr;`（含 VLA） | **confirmed** |
| M1c return 数组元素地址 | `return &arr[2];` | **confirmed** |
| M2 存入全局/堆 | `g_ptr = &local;` / `obj->cb_ctx = &local;` | suspected |
| M3 异步注册传参 | `pthread_create(&t, NULL, body, &local)`（第 4 参） | suspected |

### 1.2 不触发清单（FP 防护）

- `static` 局部（storage_class 检查——**confirmed 形态唯一标准豁免，必须实现**）；字符串字面量返回；`return &global` / `return global_arr`；按值返回 struct；`return ptr`（局部指针的值）；普通同步调用传参 `helper(&local)`（**v1 不触发**，极常见合法惯用法）；goto-cleanup label 块内 return 同 M1 判定无特判。

### 1.3 架构落点

- Detector `sgre/internal/evidence/stack_escape.go`（forEachFile + FindAll，无命中早退）：遍历 `function_definition`，收集本函数 locals（declarator 名 + storage_class + array 形态），扫 return_statement 与赋值/调用点。
- 注册：evidence/registry.go `RegisterDetector`；schema.go:131 event_type enum 增 `STACK_ESCAPE`（漏加=静默零事件）。
- Planner `registry_stack_escape.go`：FilterChain `"default"`；CategoryConfidence：`return_stack_address→confirmed`，`escape_via_store`/`escape_via_async_arg→suspected`。
- skills：`allSkillSpecs` 增条目 + `extension/shared/skills/stack-address-escape/SKILL.md`。
- hint tokens（hint_tokens.go 注册 + evidence_package.go buildHintParts 同步）：`object@<name>`、`static@no|yes`、`escape@return|store|async-arg`。
- props：`category / variable / expression / origin=<声明行>:<逃逸行> / storage=auto|static`。

### 1.4 SKILL.md 要点（E2E 契约）

- frontmatter：`cwe: CWE-562, severity: CRITICAL, domain: security`（type 默认级=最典型 confirmed shape 级：return 悬垂是确定性 UB）。
- Classification Rules：`escape@return`+`static@no`→**confirmed**；`escape@async-arg` 且注册函数体可读且不复制 arg→**confirmed**；`escape@store` 全局生命周期≤局部或目标 static→**dismissed**；async-arg 注册后立即 join（同步用法）→**dismissed**。
- Common FP：static 局部（管道已豁免，防 AI 误翻案）；返回全局/参数地址；pthread arg 在 join 前全程存活且线程只读。
- Severity Matrix：return 形态=critical；store/async-arg=high。
- Fix Suggestions：传出参数 / static 限定 / 堆分配。

### 1.5 benchmark

TP：`se01_return_addr.c`/`se02_return_array.c`/`se03_return_field_addr.c`（M1 系）、`se04_store_global.c`/`se05_pthread_arg.c`（suspected）；FP：`se10_static_local.c`/`se11_return_global.c`/`se12_return_string.c`/`se13_helper_arg.c`。TP 污点源形态用函数参数；FP 与 TP 行间隔 >3。

### 1.6 性能 / 已知局限

单遍 O(声明数)；<0.5%。M2 仅显式赋值 RHS（一层中转不追踪）；M3 白名单仅 pthread_create 第 4 参（config `[escape] async_registrants` 扩展留 TODO）；多层宏包裹 return 不展开。

---

## 2. GAP-04 invalid free —— 新 type `invalid-free`（CWE-761，Legacy CWE-762）

### 2.1 检出形态

判定对象：deallocator 调用实参（层层剥 cast_expression/parenthesized）：

| 形态 | 示例 | tier |
|---|---|---|
| F1 栈对象 | `int a[8]; free(a);` / `free(&local);` / `free(&local.f);` | **confirmed** |
| F2 数组中段 | `free(&arr[5]);` / `free(arr + 2);` | **confirmed** |
| F3 全局数组 | `free(g_arr);` | **confirmed** |
| F4 堆基址偏移 | `p=malloc(n); free(p+4);`（基址=alloc 别名，复用 findAliases） | **confirmed** |
| F5 realloc 同族 | `realloc(a, n)`（a 为栈数组） | **confirmed** |

### 2.2 不触发清单

`free(ptr)`（指针变量值——合法主流形态，宁可漏）；F4 基址未知（非 alloc 别名）不触发；`free(NULL)` 特判跳过；多参数 deallocator 只判第一指针型实参（UF-11 教训）。

### 2.3 架构落点 / SKILL 要点

- Detector `invalid_free.go`：复用 free_summary.go 的 deallocator 集与 `getCallArgs`（free_summary.go:647）；F4 复用 findAliases。
- `registry_invalid_free.go` FilterChain default，全 confirmed。schema enum 增 `INVALID_FREE`。
- hint tokens：`pointee@stack|global-array|heap-offset`、`base@<file>:<line>`（F4 基址出处）、`free@<call-line>`。
- SKILL frontmatter `severity: CRITICAL`（对齐 free 家族 double-free/UAF）。Classification：`pointee@…`→**confirmed**（管道 AST/别名已证，AI 复核形态）；宏包裹的 `free(PTR_VAR)` 误入→**false-positive**。Common FP：宏展开实参（AI 须读 `## Macro Definition`）；cast 包裹合法堆指针别名（极罕见）。Matrix：栈对象/数组中段=critical；全局数组=high。
- props：`category=free_stack_object|free_global_array|free_offset_pointer / pointee_kind / base_origin(仅F4)`。

### 2.4 benchmark / 性能

TP：`if01`~`if05`（对应 F1~F5）；FP：`if10_free_ptr_var.c`/`if11_free_null.c`/`if12_free_unknown_offset.c`。
单遍调用点扫描+查表；F4 别名查询 O(函数语句数)；<0.5%。局限：宏展开实参不识别；函数指针间接 free 不识别（未来随 GAP-02 收益）。

---

## 3. GAP-05 switch 控制流检查 —— 新 type `switch-fallthrough`（单 type 双 category，CWE-484/478）

三维度判断：触发机制同类（switch AST）、缺陷语义相近、CWE 不同→单 type 双 category + CategoryCWEs（injection 模式）。

### 3.1 检出形态（**全 suspected，零 confirmed**）

| 形态 | 触发条件 |
|---|---|
| fallthrough | case 体非空、末尾无终结语句、无豁免注释 |
| missing_default | switch 条件类型可解析为**枚举**、case 未穷举、无 default |

**终结语句集**：break/continue/return/goto/确定性 noreturn 调用（exit/_Exit/_exit/abort/longjmp/__builtin_trap/__builtin_unreachable）。
**空体连续标签**（`case 1: case 2: stmt`）不触发。**豁免注释集**（大小写不敏感，case 末语句到下一 case 之间）：`fall through`/`fallthrough`/`falls through`/`fallthru`/`fall-through`（GCC 同款）。

### 3.2 不触发清单

switch 条件类型解析失败（非枚举 int 直量）→ missing_default **不触发**（int 省略 default 是海量合法写法）；枚举解析失败不触发；嵌套 switch 内层 break 视为外层终结（漏报方向，known-gap）；空 default 视为已防御。

### 3.3 架构落点 / SKILL 要点

- Detector `switch_flow.go`：`FindAll("switch_statement")` 单遍；枚举成员从 `enum_specifier` enumerator 提取；条件类型经 typedefs 表（buildGlobalTypedefs 已覆盖跨文件）解析。
- `registry_switch_fallthrough.go`：`Categories: [fallthrough, missing_default]`；`CategoryCWEs: {fallthrough: CWE-484, missing_default: CWE-478}`；DefaultSuspicion suspected。schema enum 增 `SWITCH_FLOW`。
- hint tokens：`case_end@<末语句kind>`、`comment@none|fallthrough`、`enum@<名>(covered N/M)`、`fall@yes`。
- SKILL frontmatter `severity: MEDIUM`。Classification：`fall@yes`+`comment@none`+下一 case 独立语义动作（命令字/消息类型表）→**confirmed**（AI 确认）；同语义递进惯用法→**dismissed**；枚举未穷举+外部可控→**confirmed**；上游已归一化→**dismissed**。Common FP：fallthrough 阶梯惯用法；**明确告知 AI**：管道已实施注释豁免与 int 不触发，剩下形态里故意 fallthrough 仍常见——判据是"两 case 是否独立语义动作"。Matrix：missing_default+外部可控=high；普通 fallthrough=medium。
- AI 负载护栏（三层）：①引擎层——候选 > 全量 15% → 收紧"尾为任意调用"档不触发 + `[switch] fallthrough_markers` config 扩豁免集；②编排层——既有机制自动生效（>100 dedicated+range split；agent-body.md:288 pattern 复用对同函数多 case 收益最大）；③A/B 验收层——**新指标**：AI 候选总量增量与预计 dispatch 批次增量；switch-fallthrough 单 type 候选 > 全量 10% 即触发引擎层收紧（不等 15%）。自定义 noreturn 函数 config 化（`[switch] noreturn_functions`）作为升级通道写 SKILL。

### 3.4 benchmark / 性能

TP：`sf01_fallthrough.c`/`sf02_fallthrough_call.c`/`sf03_missing_default_enum.c`；FP：`sf10_comment_exempt.c`/`sf11_empty_case_chain.c`/`sf12_int_switch_no_default.c`；known-gap：`sf13_break_nested.c`。
单遍 switch 扫描+枚举查表；<0.3%。

---

## 4. GAP-06 移位 UB —— integer-overflow 扩展 category（CWE-190/CWE-758）

### 4.1 前置基建 ×2

1. **widthOf(typeSpelling) (int, bool)**（typedefs.go 新增）：LP64 基础表（char/int8_t→8；short/int16_t→16；int/int32_t/unsigned 变体→32；long/long long/int64_t/intptr_t/size_t→64）；typedef 传递解析；**解析失败返回 false → 不触发**（宽度未知宁漏）。字面量默认 int/32。GAP-03 落地后消费 `-m32`/`-m64` 切换宽度基准（升级路径写注释）。
2. **DefiniteValueAt(v, line) (int64, bool)**（range_analysis.go 新增，见 §5.1）——移位计数变量形态复用。

### 4.2 检出形态

| 形态 | 判定 | tier |
|---|---|---|
| 移位计数 ≥ 宽度 | `x << 40`（x 为 int32 族）；计数为字面量 **或 DefiniteValueAt 单点可证** | **confirmed**（category `shift_count_ub`→CWE-758） |
| 移位计数为负 | `x << -1` | **confirmed** |
| 有符号左移常量溢出 | `1 << 31`（有符号字面量/有符号常量） | **confirmed**（category `shift_signed_overflow`→CWE-190） |

### 4.3 不触发清单

unsigned/宽度足够（`1u<<31`、`uint64_t x; x<<40`）不触发；负值右移（实现定义非 UB）不触发；计数变量且无单点证明不触发（宁漏勿误）；宏形态经 ConstantEnv 可解→同常量判定，解不出不触发。

### 4.4 落点

integer_overflow.go 既有遍历内增 `shift_expression` 分支（:402 注释明示该 token 原被排除——本轮补上）；`registry_integer_overflow.go` Categories 增两 category（均 confirmed）；**既有 integer-overflow/SKILL.md 同步**（token 表增 `shift_count@<N>≥width`/`shift_base@signed-literal`/`width@<N>`；Classification 增两行；Common FP 增三形态）——category 扩展同样触发 skills guard。
benchmark：TP `sh01_shift_over_width.c`/`sh02_shift_negative.c`/`sh03_signed_literal_shift.c`；FP `sh10_unsigned_shift.c`/`sh11_wide_type_shift.c`/`sh12_var_shift.c`（无单点证明不触发）。

---

## 5. GAP-07 INT_MIN/-1 —— divide-by-zero 扩展 category `int_min_div`（CWE-190）

### 5.1 引擎能力：DefiniteValueAt 单点区间证明（原地修复项）

**根因识别**：definite-zero 早已存在文本级私有实现 `isDefiniteZeroDivisor`（divide_by_zero.go:219，字符串+ConstantEnv）——能力存在但未引擎化不可复用。绕开它做"常量对收窄"是将就；**原地修复=能力引擎化**：

1. `range_analysis.go` 新增 `DefiniteValueAt(v string, line int) (int64, bool)`：单点区间证明（变量唯一赋值为常量 + 本函数内无重写——复用 reassignedIn must 判定 + ConstantEnv 宏折叠）。
2. **迁移**：`isDefiniteZeroDivisor` 调用点改 `DefiniteValueAt(...)==0`，行为零变化（definite-zero 既有 pinned 回归测试必须保持绿）。
3. **三处受益**：GAP-07 INT_MIN 变量形态（漏报翻检出）；GAP-06 移位计数变量；definite-zero 自身可维护。

### 5.2 检出形态

| 形态 | 判定 | tier |
|---|---|---|
| 常量对 | `INT_MIN / -1`、`-2147483648 % -1`（宏经 CollectMacroValues 解出） | **confirmed** |
| 已知值变量 | `x = INT_MIN; … x / -1`（DefiniteValueAt(x)==INT_MIN 且除数单点/常量含 -1） | **confirmed** |

### 5.3 不触发清单（明确收窄理由写 SKILL）

`x / -1`（x 无单点证明）**不触发**——绝大多数 x 非 INT_MIN，静态证不了值域就出局；除数变量不触发；无符号被除数不触发；long 上下文（`-2147483648L`/宽类型）不触发（widthOf 参与判定，仅 32 位 int 族成立）。

### 5.4 落点

divide_by_zero.go 既有除法遍历内增分支；`registry_divide_by_zero.go` Categories 增 `int_min_div`（CategoryCWEs {int_min_div: CWE-190}，主 CWE-369 不动）confirmed。hint tokens：`dividend@INT_MIN`、`divisor@-1`、`assign@line`。
**divide-by-zero/SKILL.md 同步**：Classification 增行；Detection Logic 说明变量形态不触发是 deliberate scope（防 AI 困惑）。
benchmark：TP `im01_const_pair.c`/`im02_macro_int_min.c`/`im03_assigned_const.c`；FP `im10_var_dividend.c`/`im11_unsigned.c`/`im12_long_ctx.c`。

---

## 6. GAP-08 权限设置 —— path-traversal 扩展 category `permission_setting`（CWE-732）

### 6.1 检出形态

| 形态 | 判定 | tier |
|---|---|---|
| chmod other-writable + 非临时字面量路径 | `chmod("/etc/app.conf", 0666)`——`(mode & 0o002) != 0` 且路径不以 `/tmp/`/`/var/tmp/`/`/dev/shm` 开头 | **confirmed**（category `world_writable_file`） |
| chmod other-writable + 变量路径 | mode 字面量可证、路径不可证 | suspected |
| open/fchmod + O_CREAT + mode 含 other-write | umask 过滤不可证 | suspected（禁止 confirmed） |

### 6.2 不触发清单

mode 为变量/宏不可解不触发；/tmp 系前缀不触发；`umask(0)` 单独出现不触发；world-readable（0o004）不触发（只盯 other-**writable**）。

### 6.3 落点

path_traversal.go（该 detector 已感知 chmod/chown）新增 mode 实参判定分支；`registry_path_traversal.go` Categories 增 `permission_setting`（CategoryCWEs {permission_setting: CWE-732}；CategoryConfidence {world_writable_file: confirmed}）。**path-traversal/SKILL.md 同步**：token `mode@<octal>`/`path@literal|var`；Classification 增行；/tmp 豁免写 Common FP。
benchmark：TP `pm01_chmod_666.c`/`pm02_chmod_var_path.c`；FP `pm10_tmp_path.c`/`pm11_mode_var.c`/`pm12_readable_only.c`。性能可忽略。

---

## 7. GAP-10 severity —— 刻度原地修复 + 双轨统一（本设计最重要的产品缺陷修复）

### 7.1 两层既有缺陷（先修刻度，再统一双轨）

- **缺陷 A**：静态轨不存在——auto-confirm/classify 硬编码 `"high"`（cli/scan.go:696、classify.go:189），与 AI 轨（SKILL Severity Matrix per-shape，agent-body.md:294-308）双轨割裂。
- **缺陷 B（根因）**：**既有刻度 HIGH 通胀**——实测 25 type 分布 CRITICAL×4/HIGH×13/MEDIUM×8/**LOW×0**：null-deref、除零、死锁、信号处理器等 DoS 类与 buffer-overflow、format-string 等内存破坏类同档 HIGH；13/25 定 HIGH + LOW 空档 = `### Findings by Severity` 区分度失效。

### 7.2 刻度判据（业界共识：影响面 × 可利用性）

CRITICAL=写原语/RCE/长期凭据失守；HIGH=完整性机密性局部失守/提权/高价值链式；MEDIUM=DoS（崩溃/挂起/耗尽）/链式前置/场景依赖；LOW=健壮性/风格。对标 Sonar/Coverity/Polyspace/Cppcheck 通行分布：DoS 类不进最高档、健壮性类进最低档、写原语类必进最高档。

### 7.3 修正后完整定级表（29 type，金字塔 6/7/15/1）

| 级 | type |
|---|---|
| **CRITICAL** ×6 | double-free、use-after-free、injection、hardcoded-secret、**stack-address-escape**（新）、**invalid-free**（新） |
| **HIGH** ×7 | buffer-overflow、out-of-bounds、format-string、path-traversal、race-condition、crypto-misuse、**unbounded-length-copy**（新） |
| **MEDIUM** ×15 | null-deref↓、divide-by-zero↓、integer-overflow↓、deadlock↓、signal-handler↓、sizeof-misuse↓（六项自 HIGH 降级）、memory-leak、resource-leak、uninit、argument-type、dangerous-function、data-representation、implicit-contract、signed-compare、**switch-fallthrough**（新） |
| **LOW** ×1 | unchecked-return↓（自 HIGH 两级降级——健壮性问题业界最低档，现状与内存破坏同档是最失真项） |

**CategorySeverity 语义全覆盖**（category 语义差异就是 severity 差异的地方必须覆盖；实施时以 registry_*.go 实际 category 全集为准）：

| type | CategorySeverity |
|---|---|
| injection | command→CRITICAL、sql→HIGH、argument→MEDIUM、xml_xpath→MEDIUM、xml→LOW、log→LOW |
| buffer-overflow | heap_oob_write→CRITICAL、format_overflow（可控变体）→CRITICAL、其余默认 HIGH |
| format-string | 可控格式串→CRITICAL、其余 HIGH |
| race-condition | toctou→HIGH、data_race→MEDIUM、lock_order→MEDIUM |
| integer-overflow | size_calc 链→HIGH、其余 MEDIUM |
| crypto-misuse | weak-key→HIGH、weak-algorithm/weak-random→MEDIUM |
| path-traversal | permission_setting→MEDIUM |

**决策记录**：静态轨不做暴露面（exposure）加权——静态判定污点可控性/可达性精度不足（错标风险高）；AI 轨 Matrix 已含 exposure 维度。分工：静态轨=粗而稳（type+category 两级），AI 轨=细而贵（shape+exposure）。

### 7.4 双轨统一（单一真源方向：registry 权威）

1. `VulnTypeSpec` 增 `DefaultSeverity` + `CategorySeverity`（按 7.3 表落位）；暴露 `SeverityFor(vulnType, category) string`（含 config `[severity]` 覆盖合并，覆盖后与 frontmatter 的漂移属用户明示决策，guard 只断言 registry 默认值）。
2. **registry 是唯一权威**（与 CWE 单一真源纪律同构）；SKILL frontmatter `metadata.severity` 是**派生校验面**：`TestVulnTypeSkillConsistency` 扩展断言 frontmatter（小写化）== registry DefaultSeverity，漂移即 build 失败。
3. **一致性原则**：frontmatter type 默认级 = 最典型 confirmed shape 级（frontmatter 与 Matrix 典型行不得矛盾）。
4. 消费点：cli/scan.go:696 与 classify.go:189 硬编码替换为 `planner.SeverityFor(...)`；SARIF level 映射（sarif.go:161-181 已按 severity 驱动）零改动自动传导；markdown SeverityCounts 自然生效；report.go `--severity`/SyncPerFinding 的 AI 覆盖优先级保持更高（既有 `if u.Severity != ""` 逻辑）。
5. **25 个既有 SKILL 双重修正**：frontmatter 按 7.3 降级 7 项 + **Severity Matrix 锚点重校**（Matrix 典型行锚定新 type 默认级，变体级上下浮动自洽——只改 frontmatter 不改 Matrix 会制造新不一致）。
6. schema severity enum 已存在（schema.go:157）零 DDL；AI update 路径不动。

### 7.5 用户可见影响与公告义务

SARIF level 分布变化（null-deref 等类 confirmed 从 error→warning，error 条目下降）；report.md 分布从 HIGH 通胀变金字塔。**CHANGELOG 显著段落公告"severity 刻度修正，非问题减少"**。历史 finding 无包袱（DB 即建即用）；benchmark 只断言 finding/no_finding 零影响；CI 门禁尚未发布零既有用户影响。

### 7.6 验证专项

单测：每 type SeverityFor 断言 + config 覆盖断言 + guard 一致性断言。A/B：**修正前后 severity 分布对照表**（4/13/8/0 → 6/7/15/1）+ SARIF level 分布变化清单，逐条确认与 7.3 一致——severity 是用户可见语义，偏差必须穷举。

---

## 8. GAP-11 in-source suppression —— `// secguard-disable-next-line:`

### 8.1 语法

```
// secguard-disable-next-line: <type>[,<type>...] [reason=...]
<目标行>
```

type 名精确匹配 registry 名（kebab-case）；支持 `all` 通配；索引期校验 type 不在 `planner.AllVulnTypes()` 且非 all → Warn（不 fail，防拼写错静默无效）。同行形式 `code(); // secguard-disable-line: <type>` 一并支持。**块注释 `/* secguard-disable-next-line: ... */` 支持**（收集器剥 `/*`…`*/` 包装统一处理；仅宏体内部的豁免注释不支持——真实限制写文档）。

### 8.2 架构落点（三段）

1. 索引期收集：indexer indexFile 时 `FindAll("comment")` 正则匹配 → 新表 `inline_suppressions(file_id, line, vuln_type, reason)`（schema.go 增表 DDL + Store CRUD；DB 即建即用无 migration）。
2. planner 前置 filter：`filter_inline_suppression.go` 挂在**所有 filter chain 最前**（filter_chain.go 组装处，先于 call_reach/safe_function）：候选 (file, line) 命中（next-line：suppression.line+1==candidate.line；disable-line：==）→ drop。不产 finding 不进 AI 候选（与 dismissed 不入库语义对齐）。**disable 优先于一切判定**（含 auto-confirmed——用户明示意图）；幂等；行号漂移属用户维护责任（indexer 每次重建即最新）。
3. 可见性：`secguard status` 增 suppressed 计数段；scan 日志 `inline_suppressions_applied=N`。

### 8.3 用户文档面

README.md/README-CN.md 新章节"In-source suppression"（语法、all 通配、reason 惯例、与 dismissed 语义区别：豁免=用户明示永不报；dismissed=AI 判定非缺陷；审计入口=inline_suppressions 表+scan.log）；QUICKSTART.md 三行示例。**AI 侧零改动**（豁免候选不生成，AI 永远看不到，无需任何指令）。

### 8.4 验证 / 性能

带豁免已知 TP fixture → no_finding；无豁免对照 → finding（红绿对照，行间隔 >3）。索引期一次 comment 扫描 O(注释数)；planner 查表 O(候选数)。风险：纯减法理论零 FP。

---

## 9. GAP-02 函数指针 / ops-table 间接调用解析 —— CALL 图与 interproc 双落点

### 9.1 现状（实证）

`obj->fn()`：callee 位 field_expression → extractCallName（call_graph.go:200-207）返回全文本 → funcMap 不命中 → external 边（:74-84），真实目标丢失。`(*fp)()`：parenthesized → 空 → 无边（:69-70）。`collectAddrRefs`（:219-258）已识别 &f/初始化列表/实参/赋值四类值位置引用打 ADDR_TAKEN 自环，但只记名字集合不记 slot→target 映射。`InterprocBuilder`（interproc.go:35，funcByName :74-81）独立重扫同样不解析间接调用 → PARAM_BINDING/RETURN 边断 → retNullable/free summary 对 ops-table 目标全部失效。

### 9.2 设计：FuncPtrWriteBuilder + slot key 双档

**新 Pass（索引期）`FuncPtrWriteBuilder`**（新文件 `graph/funcptr_writes.go`，插在 CallGraphBuilder 之前——index.go:78 builder 序列首位）：
- 遍历全库 AST：`assignment_expression`（RHS 是 funcMap 命中 identifier，LHS 是 field_expression 取 field_identifier 名或 identifier 函数指针变量名）→ 记录 slot→target；`initializer_pair`（designated `.open = my_open`，value 命中 funcMap）→ 记录 designator 名→target。
- 持久化新表 `func_ptr_writes(slot_name, target_name, file, line)`。
- **slot key 双档**：档 1 优先 `(类型名, 字段名)`——调用点对象声明类型可解析时（`struct file_ops *ops` 声明在本函数/文件）与赋值侧宿主类型可解析时，同名不同 struct 字段天然分离；档 2 退化 `(字段名)`——类型不可解析（opaque/深层传递）时。**不设全路径文本档**（`h->open` vs `dev->open` 拼写漂移漏连伤害召回）。

**消费点 1（CallGraphBuilder）**：调用点 function 子节点为 field_expression → 提取 field_identifier 名（+可解析类型名）查表 → targets 非空 → 每 target 建真实 CALL 边（props 增 `{"indirect":"true","via":"<slot>"}`，删除无消费价值的 external 兜底边）；表空维持现状 external 边。parenthesized（`(*fp)(x)`）→ 剥 paren 取内层 identifier（fp）查表同上；剥不到 identifier（`(*ops[i])()`）维持跳过。

**消费点 2（InterprocBuilder）**：interproc.go 调用点循环同逻辑注入 → PARAM_BINDING/RETURN 边恢复 → retNullable/free summary/调用点 census 对间接目标生效。

### 9.3 误报/性能分析 + 回退

新增边不产新检测规则——影响全部是可达性与 summary 封闭度：call_reach 可达集变大（此前被剪候选回流，召回上升）；concrete chain 补全 → boundary fail-open 判定更准（预期 auto-dismiss 量下降、AI 候选上升）；retNullable 三态重分布（assumed→proven 方向为增益）。误连（档 2 同名字段）只导致 summary 更保守**不产 FP**。
A/B 三指标：AI 候选增量、auto-confirmed 增量、Wall-clock。阈值：AI 候选 > 20% 或 Wall-clock > +10% → 收紧 slot key 仅档 1 → 再超 → config `[graph] indirect_call_resolution = "off"|"typed-field"|"field"` 总开关回退。性能：单遍 O(赋值+初始化节点数)；索引期预估 +2-4%。

### 9.4 实施第一步：AST 形态探针

tree-sitter-c fork v0.24.4 node-types 已含所需全部节点（call_expression/field_expression/parenthesized_expression/initializer_pair/field_designator——已验证，**本轮零 fork 需求**）。落地第一步写探针测试 dump `(*fp)(x)`、`dev->open(x)`、`.open = my_open` 三形态实际节点结构，以探针实证为准修正提取逻辑；探针转正回归测试。

### 9.5 验证

单测：三形态建边断言 + 无记录不建边断言。端到端：ops-table 样例（struct file_ops + 赋值 + 间接调用 + 目标函数内 NULL 解引用）→ 修复前目标 boundary fail-open/不可达、修复后 caller-arg summary 生效。A/B：三指标 + 既有 25 类 finding 零回归（允许 tier 重分布，须逐条列出定性）。

---

## 10. GAP-03 compile_commands.json 消费 —— C1 档（全局并集 + 自动探测优先）

### 10.1 分档决策

parser 现状：无 -I 搜索链（QuotedIncludePaths value_refs.go:52-73 仅引号同目录）、无 -D 注入、无 cpp 展开层（preproc 节点原样留 AST，宏能力全部从源码 #define 单向提取）。**C1（本轮）**：解析 JSON → -D 数值宏并入常量环境、-I 进 include 片段搜索链，全局并集语义（与全库一体索引架构一致；冲突 -D 取后见值+Warn）。**C2（暂缓）**：per-TU 精确环境、条件编译求值、系统头解析——引入 TU 维度等于重造编译器前端，留待真实需求驱动。

### 10.2 入口：自动探测优先（E2E 修订，MCP 宿主可达性关键）

已核查 MCP `secguard_scan.ts:122` 只传 `--db` + targetPath **不透传新 flag**——纯 CLI flag 方案宿主用户不可达。三通道优先级：**flag > config > 自动探测**（`<target>/compile_commands.json` → `<target>/build/compile_commands.json` CMake 标准位）。命中即加载（日志注明来源）；全不命中维持现状（**零配置时行为与现状逐字节一致**，零风险渐进采纳）；探测命中但解析失败 → Warn 降级继续扫（半可用优于不可用）。

### 10.3 落点

1. CLI flag `--compile-commands <path>`（index 与 scan 两入口：cli/index.go:17 与 cli/pipeline.go:70 段，仿 parseExcludeFlag）+ config `[scan] compile_commands`（config.go Scan 段，flag > config > 探测）。
2. 解析器新文件 `internal/build/compile_commands.go`：读 JSON 数组，兼容 `arguments` 数组与 `command` 字符串（shell 粗分词不引新依赖）；提取 `-I<dir>`/`-I <dir>`、`-DNAME`/`-D NAME`/`-DNAME=VAL`、`-UNAME`；其余忽略。file 字段仅 Warn 日志。
3. -D 消费：数值型并入 `parser.ConstantEnv`（新增 MergeDefines 或用现有 Merge）+ `symbols.MacroIndex`（secguard def 可查）；函数式/非数值 Warn 跳过。
4. -I 消费：`parser` 新函数 `QuotedIncludePathsWithSearch(file, root, searchDirs)`（旧签名委托新函数兼容）→ 两消费方切换（call_graph.go:240、evidence/caller_null.go:796）：include 片段 census 按 [文件同目录, …searchDirs] 定位。尖括号系统头 C1 仍不解析。
5. **传递链注意**：parser 实例有两处（cli/index.go:57 与 indexer.go:40 内部）——配置须同时到达（indexer 增 SetExtraMacroDefines/SetIncludeDirs setter 仿 SetExcludeDirs；ConstantEnv 注入点在 evidence 层 buildGlobalConstants typedefs.go:87 合并）。

### 10.4 验证 / 性能 / 风险

fixture 项目带 compile_commands.json（-D MAX_LEN=4096 + -I inc/）→ 无配置按未知处理、有配置按 4096 收敛（红绿）；include 片段在 -I 目录被 census 命中。JSON 一次解析+常量合并+每片段多查几个目录，均可忽略。-D 改变常量折叠结果=检测面变化（正是目的），A/B 干净目录对比列出差异定性；误配属用户输入责任，Warn 可追溯。

---

## 11. GAP-09 污点长度字段 —— 新 type `unbounded-length-copy`（CWE-1284）

**FP 风险最高，最后批次，v1 最小面 + 全 suspected + guard 豁免。**

### 11.1 检出链（v1）

- **污点源**（返回值=外部长度）：recv/recvfrom/recvmsg/read/pread/fread 返回值（出参 `*len` 形态 v1 不做）。
- **传播**：返回值→局部变量单次赋值（`len = recv(...)`，一层；算术 `len+1` 不追踪）。
- **sink**：malloc/calloc/memcpy/memmove/strncpy/alloca（len 实参）。
- **guard 豁免（CFG must）**：len 到 sink 前存在**上界 guard**（`len > MAX` 错误分支 / `if (len <= MAX)` 后继达 sink）→ 不触发。复用 guardModel（已 CFG 化）。**下界检查（`len < 0`）不算上界 guard**（负检查后 len 仍可巨大）。常量含宏数值（ConstantEnv 可解）。
- **tier：全部 suspected**（协议信任边界是语义判断，机器证不了）。

### 11.2 不触发清单

有上界 guard；截断惯用法（`if (len > sizeof(buf)) len = sizeof(buf);` clamp——guardModel 赋值收敛覆盖）；二跳传播/出参长度/struct 字段长度（v1 不做）；返回值仅用于错误检查不进 sink。

### 11.3 落点 / SKILL

- Detector `unbounded_length.go`：taint 判定 detector 内自做一层返回值→变量→sink 轻量追踪（参照 unchecked-return checkedVars 全函数窗口模式；不复用 injection 的 planner 层 filter 链）。
- `registry_unbounded_length.go`：DefaultSuspicion suspected（无 CategoryConfidence）；FilterChain default。schema enum 增 `UNBOUNDED_LENGTH`。
- hint tokens：`taint@<source-fn>:<line>`、`guard@none-upper`（CFG 证明全路径无上界 guard——核心 verdict fact）、`sink@<fn>:<line>`、`alloc_size@<var>`。**BuildVerdictFacts 必做**：`guard@none-upper: no upper-bound check dominates the sink (CFG proof)` + provenance。
- SKILL frontmatter `severity: HIGH`。Classification：`guard@none-upper`+`taint@recv` 族+sink 为 alloc/copy 长度→**confirmed**（AI）；本地文件 read/fread 且大小受控→**dismissed**；下游 clamp/截断→**dismissed**。Common FP：`n < 0` 检查后大值（**明确告知 AI 这不是上界**）；本地受控 fd。Matrix：网络/IPC 源=high；本地文件源=medium。Fix：上界 guard / `memcpy(min(len, cap), ...)`。

### 11.4 benchmark / 性能 / 回退

TP：`ul01_recv_malloc.c`/`ul02_memcpy_len.c`/`ul03_len_var_hop.c`；FP：`ul10_guarded.c`/`ul11_clamped.c`；`ul12_negative_check_only.c`（只有 <0 检查仍触发——TP 方向注明）；known-gap：出参长度、二跳。每函数一次污点小追踪 O(函数语句数) <1%。回退：候选 > 全量 10% → config disabled_types 既有通道直接关（零代码回退）。

---

## 12. GAP-12 PR 级 CI 模板（纯交付物）

`extension/shared/ci/`（新目录，随发布包分发，不自动安装进用户仓库）：`github-pr.yml`（PR 触发→安装 release 二进制→`secguard pr --sarif`→`github/codeql-action/upload-sarif` 上传+门槛示例）、`gitlab-mr.yml`（MR 触发→`secguard mr`→artifact）、`README.md`（放置位置、secguard.toml 联动（`.codeagent/` 位置教训）、门槛策略）。`release/build-packages.sh` 打包段收录；**`release/check-extension-consistency.py` 增 ci/ 三件套存在性校验**（防丢，与 v0.5.4 tools 未注册同类事故预防）。风险零（不进运行时链路）。

---

## 13. E2E 联动设计（extension/shared 全链路）

### 13.1 新 type 的容量分型与编排

- 分型（command-instructions.md Batch Capacity 体系）：新 4 type 全部 **light**（行级 ±8 行证据）；heavy=whole-function-embedding 目前仅 integer-overflow。
- **capacity 参数一个数值都不改**（CONTEXT_BUDGET/MAXTURNS/HOST_AGENT_TIMEOUT/SPLIT 阈值均不动——改 MAXTURNS 触发三平台 steps 联动，check-extension-consistency.py 校验不触发）。类型数 25→29 由既有机制消化（批次数增量=新 type 候选量/N_type）。
- command-instructions.md 唯一新增文字：light/heavy 段后补一句"新增 light types（stack-address-escape / invalid-free / switch-fallthrough / unbounded-length-copy）按 light 分型参与既有编排规则"（防编排器对陌生 type 保守误判）。
- **auto-confirmed 零 AI 预算**（command-instructions.md:217-218 既有规则）：B1/B2 的 confirmed 形态全部不进 AI 研判；AI 负载增量只来自 suspected tier。A/B 分 confirmed/suspected 口径列增量。GAP-11 正贡献（planner drop→AI 负载直接下降）；B4 boundary 正向联动（CALL 边补全→boundary fail-open 候选下降→agent-body.md:267-271 shortcut 触发量下降→AI wall-clock 下降，增量可能为负=预期内）。

### 13.2 MCP 工具面（零改动论证）

不新增 MCP 工具→8 工具三处一致校验不触发；secguard_status 是字符串透传（secguard_status.ts:68-73）→suppressed 计数自动透传（description 文案补一句）；secguard_types registry 派生→新 type 自动出现→agent-body.md:292"只报 types 返回的类型"自动覆盖；MAXTURNS/steps 零改动。compile_commands 的 MCP 可达性由自动探测方案解决（§10.2）。

### 13.3 文档更新清单（每批交付物）

| 文件 | 批次 | 内容 |
|---|---|---|
| CHANGELOG.md | 每批 | `## [未发布]` 逐项累积（**不 bump 版本**——发布是维护者决策）；B3 必含 severity 刻度修正显著公告 |
| CLAUDE.md | B1/B4 | 新增件补一句（FuncPtrWriteBuilder/func_ptr_writes 表/inline_suppressions 表/compile_commands 通道/registry severity 字段） |
| AGENTS.md | — | **零改动**（不动 MAXTURNS/不加 MCP 工具/不动 upsert 键） |
| README.md / README-CN.md | B3/B4 | suppression 章节、compile_commands 自动探测、CI 模板指引 |
| QUICKSTART.md | B3 | suppression 三行示例 |
| docs/config.md | B2/B3/B4 | `[severity]`、`[switch] fallthrough_markers`/`noreturn_functions`、`[graph] indirect_call_resolution`、`[scan] compile_commands` |
| extension/shared/skills/ | B1/B2/B5 | 4 新 SKILL + 3 既有 SKILL 增补（integer-overflow/divide-by-zero/path-traversal） |
| extension/shared/command-instructions.md | B1 | §13.1 一句 light 分型说明 |
| extension/shared/agent-body.md | — | **零改动**（severity 纪律/Matrix 机制已覆盖新 type；boundary shortcut 无需改） |

---

## 14. 实施批次与 commit 计划（每批全绿才进下一批）

| 批 | commits |
|---|---|
| B1 | ①GAP-01 全套（detector+registry+skill+schema+单测+benchmark） ②GAP-04 全套 ③GAP-05 全套 ④command-instructions light 说明+CLAUDE.md |
| B2 | ⑤typedefs widthOf+单测 ⑥DefiniteValueAt 引擎化+isDefiniteZeroDivisor 迁移+pinned 回归 ⑦GAP-06 shift 分支 ⑧GAP-07 int_min 分支 ⑨GAP-08 permission 分支 ⑩3 既有 SKILL 增补+benchmark |
| B3-a | ⑪registry severity 字段+29 type 刻度落位 ⑫SeverityFor+config 覆盖 ⑬scan.go/classify.go 接入 ⑭guard 扩展 ⑮25 既有 SKILL frontmatter 修正+Matrix 重校 ⑯A/B 分布对照+CHANGELOG 公告 |
| B3-b | ⑰inline_suppressions 表+收集（含块注释）+filter ⑱status/日志可见性+README/QUICKSTART ⑲CI 模板+打包+校验 |
| B4 | ⑳AST 形态探针（转正回归） ㉑FuncPtrWriteBuilder+表 ㉒CallGraph 调用点解析（slot 双档） ㉓Interproc 同步 ㉔config 开关+config.md ㉕compile_commands 解析器+自动探测+接线 ㉖benchmark/A/B |
| B5 | ㉗unbounded-length 全套 |

每批全绿门槛：`go build/test ./...` + nosqlite 子集 + `release/check-extension-consistency.py` + benchmark validator + 端到端双口径 + 干净目录 A/B + E2E 五步（§0.2-6）。

## 15. 风险总表与回退

| 风险 | 触发信号 | 回退 |
|---|---|---|
| B1 confirmed 误报 | 任何一例 confirmed FP | 修判据或降 suspected；disabled_types 关 |
| B3 severity 分布争议 | 用户/冒烟反馈 | config `[severity]` 覆盖零代码 |
| B4 AI 候选暴涨 | A/B 增量 > 20% | slot key 收紧仅档 1 → 再超 `[graph] indirect_call_resolution=off` |
| B4 confirmed 重分布 | A/B tier 差异 | 逐条定性（assumed→proven 为增益方向）；异常回退 |
| B5 候选噪音 | > 10% | disabled_types 既有通道零代码 |
| 扫描变慢 | 任一批 Wall-clock > +5% | 该批独立 revert（批次=回退单元） |
| switch-fallthrough 候选爆 | 单 type > 全量 10%（A/B 验收档） | 收紧"尾为任意调用"档+config 扩豁免集（引擎层 15% 档同策） |

## 16. 纪律对齐清单（实施逐项打勾）

- 新 vuln type（stack-address-escape/invalid-free/switch-fallthrough/unbounded-length-copy）逐个走 ADDING_A_VULN_TYPE.md 六步 + benchmark 第七步（validator DETECTOR_T 映射）。
- 四平行清单同步：planner registry / allSkillSpecs / skill dirs / schema event_type enum——`TestVulnTypeSkillConsistency` + `TestSeedEventTypesInSchema` 双 guard 兜底。
- hint token 先注册后使用（hint_tokens.go），SKILL token 表与 buildHintParts 严格一致（zz_hint_protocol_guard_test.go 拒绝未注册拼写）+ 人工核对语义。
- props Go 类型与 JSON 类型严格一致（CrossFunction bool/string 静默失败教训）。
- benchmark TP fixture 污点源用函数参数形态；FP 与 TP 行间隔 >3。
- 端到端验证同时查 auto-confirmed 口径；A/B 干净目录。
- 新 SKILL 先写 frontmatter severity 再写 registry DefaultSeverity，两者小写化相等（guard 强制），值取自 §7.3 表。
- `extension/shared/` 是源，`.claude/`/`.opencode/` 是展开产物——只改 shared，安装冒烟只验证展开。
- CHANGELOG 累积 `## [未发布]`，不碰 VERSION/root.go/protocol.go。

## 17. tree-sitter-c fork 需求结论

**本轮零硬需求**（所需节点 fork v0.24.4 全具备，node-types.json 已验证）。预留触发条件（写入 fork 仓库 backlog 沟通项，不在本轮）：B4 探针发现 GNU 扩展初始化形态解析不完整 → 提 grammar 增强；GAP-03 C2（条件编译求值）如启动 → 评估 preproc_if 宏表达式求值支撑。