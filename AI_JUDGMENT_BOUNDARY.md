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
   的禁用 API——「调用即命中」。

## 什么交给 AI 研判（`suspected` / `possible`）

1. **may 数据流**（只在部分路径成立）：maybe-null、条件 free / 条件泄漏 / 条件 OOB。
2. **名字 / 启发式**：函数名含 `alloc`/`open`/`join` 等、taint 未证明、格式串非字面量但未到 sink。
3. **参数 / 跨函数 / 宏**：外部函数契约未知、macro-context（宏语义不可见）、参数驱动的值。

## AI 的契约（写进 `agent-body.md`）

- `suspicion_level` 是 **prior，不是 verdict**：AI 不重推数据流。
- `confirmed` 候选只看 `_index.md` 的 Source + Hint 行，confirm 或 dismiss；
  不打开源文件、不打开 Evidence 文件。
- `suspected` / `possible`：先看 index 行的 Hint，不够才开 `## Code Context`；
  按 skill 规则 `confirm` 或 `dismiss`。
- **macro-context 永不盲 confirm**：必须读 Code Context 搞清宏语义，看不清 → dismiss。
- `dismissed` 必须引用证据（guard 行 / `_s` 安全调用 / 契约 / 读过的 file:line），
  否则被审计为「未研判即弃」。

## 机器守则（machine guard）

- 三层词汇固定为 `confirmed` / `suspected` / `possible`（`ranker.go` 的
  `confidenceValue` 已锁顺序 confirmed > suspected > possible）。
- 静态 `confirmed` 集合（registry 的 `CategoryConfidence == "confirmed"` +
  `DefaultSuspicion == "confirmed"`）在 `sgre/internal/planner/zz_ai_judgment_boundary_test.go`
  的 `TestConfirmedTierPolicy` 中登记为黄金清单：**新增任何 auto-confirm 必须在此
  登记其证明手段，否则构建失败**——防止「confirmed」被悄悄加到启发式上。
