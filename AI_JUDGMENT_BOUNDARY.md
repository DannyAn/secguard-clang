# AI 研判边界（AI Judgment Boundary）

> 本文档是 SecGuard-Clang「确定性管线（sgre）vs AI 研判」边界的唯一权威定义。
> 商家/用户询问「哪些会交给 AI 研判、哪些不会」时，以此为准。v0.8.0 为雏形。

## 一句话规则

**`confirmed`（确定性，sgre 自己判）= sgre 用语义图 / CFG / 区间分析证明该缺陷在
「每条路径」上都成立；其余一律 `suspected` / `possible`（启发式，交给 AI 研判）。**

判据只有一条：**是「证明」还是「启发式」**。证明 → sgre 判；启发式 → AI 判。

## 三个层级

| 层级 | 含义 | 谁判定 | 依据 |
|---|---|---|---|
| `confirmed` | 确定性缺陷（每条路径成立） | sgre | 下面「证明手段」四类 |
| `suspected` | 启发式命中，但图/区间未证明 | AI | 各 skill 的 `false-positive` 规则 |
| `possible` | 理论可能（需证明可达/真实） | AI | 各 skill 的 `false-positive` 规则 |

## 证明手段（什么能标 `confirmed`）

只有这四类，缺一不可（每条在 `TestConfirmedTierPolicy` 中登记）：

1. **CFG must 数据流**（全路径成立）：definite null（`p = NULL` 后全路径 deref）、
   must freed（全路径 free 后再 use）、must double-free、must uninit、
   确定性泄漏（无 free / escape / transfer 任一节点）。
2. **区间 / 常量折叠**：除数恒为 0（`x/0`、常量符号 0）、字面量整数溢出
   （`definite_overflow`）、常量索引越界 / 索引区间 `lo >= 容量`。
3. **字面量本身命中**：弱加密算法（DES/3DES/MD5/SHA-1/RC4/`rand()`）、
   hardcoded-secret 的**值本身** secret-shaped、`_s` 函数给出撒谎容量、
   `sizeof(pointer)` 这类无条件成立。
4. **类型固有**（无需数据流）：signal-handler 的异步不安全 API、dangerous-function
   的禁用 API——「调用即命中」（例外：dangerous-function 的 `assert_usage`
   是否用于校验入参需意图判断，归 `suspected`）。

## 什么交给 AI 研判（`suspected` / `possible`）

1. **may 数据流**（只在部分路径成立）：maybe-null、条件 free / 条件泄漏 / 条件 OOB。
   路径遍历的「外部可达」也属于这一类：可达性证明不了字符串里能出现 `../`。
2. **名字 / 启发式**：函数名含 `alloc`/`open`/`join` 等、taint 未证明、格式串非字面量但未到 sink。
   unchecked-return 的 `contract@unknown` 属于此类：callee 仅凭名字匹配，失败契约未证明。
3. **参数 / 跨函数 / 宏**：外部函数契约未知、macro-context（宏语义不可见）、参数驱动的值。
4. **未校验的外部索引**：固定长度数组成员以**结构体字段**为下标、且函数内没有与容量
   相等的边界检查（`array_oob_read_unchecked` / `array_oob_write_unchecked`）。
   字段的真实取值范围是运行期契约（配置/输入侧可能校验过，也可能没有），管线证明不了；
   只播种字段来源索引（普通形参/循环变量不播种）以守住候选体量，链条证据
   （`idx-src@` / `elem-field@` / `oob-escape@`）交 AI 判「越界读 → 空指针解引用」。

**根因 + 后果 = 一条 finding（链条只做元数据）**：越界读（CWE-125）与随后的空指针
解引用（CWE-476）在语义上是「缺失边界检查」这一个根因的后果。后果性 CWE 不单独出
候选/finding（否则同一根因被计两次、精度被污染，且 CWE-476 侧依赖「越界内存恰为
NULL」这一未证明假设）。链条以 `cwe-chain@CWE-125→CWE-476` token / 候选
`## Vulnerability Chain` 段 / SARIF `properties.cwe_chain` 导出，AI 在 verdict 的
`reasoning` 中同时陈述两段 CWE——与 `ArrayOOBPrecedenceFilter`「OOB 覆盖同位置
空指针候选」的既有取向一致。

## AI 的契约（写进 `agent-body.md`）

- `suspicion_level` 是 **prior，不是 verdict**：AI 不重推数据流。
- `confirmed` 候选只看 `_index.md` 的 Source + Hint 行，confirm 或 dismiss；
  不打开源文件、不打开 Evidence 文件。
- `suspected` / `possible`：先看 index 行的 Hint，不够才开 `## Code Context`；
  按 skill 规则 `confirm` 或 `dismiss`。
- **macro-context 永不盲 confirm**：必须读 Code Context 搞清宏语义，看不清 → dismiss。
- **unchecked-return `contract@unknown`**：Hint 标 `contract@unknown` 的候选，
  其 callee 仅凭名字启发式匹配（`alloc` 子串 / `*_new` / `*_dup`），失败契约未证明。
  AI 必须从 Code Context 证明 callee 返回失败哨兵（`NULL` / `-1` / error code），
  否则 **dismiss**——「名字像 allocator」不是缺陷证据。
- `dismissed` 必须引用证据（guard 行 / `_s` 安全调用 / 契约 / 读过的 file:line），
  否则被审计为「未研判即弃」。

## 机器守则（machine guard）

- 三层词汇固定为 `confirmed` / `suspected` / `possible`（`ranker.go` 的
  `confidenceValue` 已锁顺序 confirmed > suspected > possible）。
- 静态 `confirmed` 集合（registry 的 `CategoryConfidence == "confirmed"` +
  `DefaultSuspicion == "confirmed"`）在 `sgre/internal/planner/zz_ai_judgment_boundary_test.go`
  的 `TestConfirmedTierPolicy` 中登记为黄金清单：**新增任何 auto-confirm 必须在此
  登记其证明手段，否则构建失败**——防止「confirmed」被悄悄加到启发式上。

### 动态升级登记（v0.10.0 起）

filter 在 `Apply` 中把候选升级为 `confirmed` 同样受机器守卫约束：

1. 该 filter 必须实现 `planner.ProofRegistrar` 接口（`DeclaredProofs() []Proof`），
   为每条升级路径声明证明类别（`Proof.Class` 四选一：cfg-must-dataflow /
   interval-or-const-fold / literal / type-inherent）、规则名（`Proof.Rule`）、
   可审计的证据描述（`Proof.Evidence`）与建议的测试引用（`Proof.TestRef`）。
2. `TestDynamicConfirmedUpgradesRegistered` 持有一份**已审阅的 filter 黄金清单**
   （当前 12 个：NullableSourceFilter / LifetimeFilter / DoubleFreeFilter /
   TaintSourceFilter / RangeFilter / RangeOOBFilter / ReturnCheckFilter /
   LockOrderFilter / SharedAccessFilter / DefiniteInitFilter / LeakProofFilter /
   HardcodedSecretProofFilter），逐 filter 断言 ProofRegistrar 实现、声明的
   ProofClass 集合与黄金清单一致；**新增任何"filter 内升级 confirmed"的代码
   路径而未在此登记，构建失败**。
3. `TestConfirmedTierPolicy` 管静态（registry 声明），
   `TestDynamicConfirmedUpgradesRegistered` 管动态（filter Apply 升级）；
   两者一起覆盖"confirmed"的全部来源，任何一处绕过都会让构建失败。

## v0.8.0 完整确认覆盖（25 个 vuln 类型，两层 confirmed）

`confirmed` 有两个来源：**静态**（registry 里写死）与**动态**（planner filter 在
收敛时用图/CFG/区间/taint 证明后升级）。下表是 v0.8.0 的完整快照：

| 类型 | confirmed 来源 | 证明手段 |
|---|---|---|
| null-deref | 动态 `NullableSourceFilter`（must-null） | CFG must 数据流 |
| buffer-overflow | 静态 6 categories + 动态 `RangeOOBFilter` | 常量/区间 |
| memory-leak | 动态 `LeakProofFilter`（definite） | CFG 无 free/escape/transfer |
| injection | 动态 `TaintSourceFilter`（taint 达 sink） | taint 数据流 |
| resource-leak | 动态 `LeakProofFilter`（definite） | CFG 无 release/escape/transfer |
| uninit | 动态 `DefiniteInitFilter`（must） | CFG must 数据流 |
| use-after-free | 动态 `LifetimeFilter`（must freed） | CFG must 数据流 |
| double-free | 动态 `DoubleFreeFilter`（must） | CFG must 数据流 |
| format-string | 动态 `TaintSourceFilter`（taint 达 format） | taint 数据流 |
| integer-overflow | 静态 `definite_overflow` | 常量折叠 |
| race-condition | 动态 `SharedAccessFilter`（同全局写） | graph 边 |
| hardcoded-secret | 动态 `HardcodedSecretProofFilter`（值本身） | 字面量 |
| deadlock | 动态 `LockOrderFilter`（环） | graph 边 |
| crypto-misuse | 静态 weak_algorithm / weak_random / undersized_key | 字面量（弱算法/弱随机/密钥不足） |
| out-of-bounds | 静态 2 categories + 动态 `RangeOOBFilter` | 常量/区间 |
| divide-by-zero | 动态 `RangeFilter`（除数恒 0） | 区间/常量 |
| unchecked-return | 动态 `ReturnCheckFilter` | 契约表 |
| sizeof-misuse | 静态 `sizeof_pointer` | 字面量 |
| signed-compare | 静态 `signed_compare` | 字面量 |
| signal-handler | 静态 default | 类型固有 |
| dangerous-function | 静态 default（`assert_usage` / `obsolete_api_conditional` 除外 → suspected） | 类型固有 |

**故意留在 `suspected` 的类型 / 类别（需要「意图/语义」研判，无法确定性证明）：**

| 类型 | 为什么不能 auto-confirm |
|---|---|
| path-traversal（CWE-22） | 「外部数据到达路径参数」只证明调用方能**影响**这个字符串，不证明字符串里能出现目录逃逸分量（`../`）——内容未知，且调用方可能已做校验。确定性层要求缺陷在**每条路径**上成立，因此 `TaintSourceFilter` 不再为它升级 `confirmed`，一律 `suspected` 交 AI 研判。（编译期常量路径——字面量 / 字符串宏 / `static const char` / 仅由常量拼装的缓冲区——在检测器层直接抑制，不产候选，见 `path_traversal.go` 的 `buildStringConstants`。） |
| `dangerous-function` 的 `obsolete_api_conditional`（`inet_addr`） | 规则自身写明其风险是「运行期可控字符串 + 未检查 `INADDR_NONE`」的**条件**风险，不是「调用即缺陷」；名字匹配证明不了这个条件，故降为 suspected 交 AI 按实参来源与返回值检查研判 |
| argument-type（CWE-686） | 显式指针 cast 可能是**有意的** ABI/opaque 边界——「不兼容」≠「缺陷」，需 AI 判意图 |
| data-representation（CWE-843） | base 元素类型靠「数 `*`」解析，typedef/数组退化会数错——类型错配的「证明」不够可靠，需 AI 判实际表示 |

其余类型的 `suspected` 尾巴（如 maybe-null、条件泄漏、未达 sink 的 taint、名字启发式）
本质都是「**只在部分路径成立 / 未证明**」，属于同一原则：证明 → confirmed，启发式 → AI。

