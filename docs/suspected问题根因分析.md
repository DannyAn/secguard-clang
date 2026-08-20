# suspected 遗留偏多：根因分析与分层解决映射

> 触发：生产报告（`docs/suspected问题偏多.md`）确认 3 个 / 疑似 18 个，疑似数远超确认数。
> 本文回答两个问题：**① 当前 A1–A4 设计哪里不合理；② 每一类 suspected 该在 sgre 哪一层解决、什么残余才该留给新增的 A5 层。**
> 依据：`sgre/internal/planner/`、`sgre/internal/evidence/`、`sgre/internal/report/`、`extension/shared/` 的当前实现。

---

## 1. 结论先行

**suspected 偏多不是 A1–A4 的"逻辑写错了"，而是 A1–A4 对 null-deref 之外的 19 个类型只"盖了一层桩"。**

- 四级收敛（`Filter 1..4`：nullable source → call reach → data flow → guard）在架构文档 §7 里只对 **null-deref** 做了完整设计，也只在 null-deref / uninit / use-after-free 三个类型上真正落了地。
- 其余类型在 `planner.getFilters()` 里走 **`default` 链**：`CallReachFilter` + `SafeFunctionFilter`。这两个过滤器只能做"可达性"和"已知安全白名单"——它们能丢掉死代码和 `xmalloc` 之类的安全包装，但**回答不了任何语义问题**（除数能不能是 0、污点到不到 SQL、返回值有没有被用）。
- 于是这些类型的候选**原样涌入 A5**，而它们统一的 `DefaultSuspicion` 都是 `"suspected"`。A5（AI Agent）被迫做 A3/A4 该做的"确定性语义证明"，而不是它本应做的"业务上下文推理"。

一句话：**加 A5 是对的，但方向反了——现在 A5 在替 A3/A4 背锅。正确顺序是先把 A3/A4 的确定性收敛补全，A5 只接"语义图证明不了"的残余。**

---

## 2. 六个具体设计缺陷（自检发现）

### 缺陷 1：`default` 过滤链是"语义空壳"（根因）

`planner.go` `getFilters()` 的 default 分支：

```go
default:
    return []Filter{
        NewCallReachFilter(p.store, p.callReachCache),
        NewSafeFunctionFilter(p.store),
    }
```

这条链覆盖了 **divide-by-zero、crypto-misuse、unchecked-return、signed-compare、sizeof-misuse、deadlock、race-condition、buffer-overflow、out-of-bounds、hardcoded-secret** 十个类型。它只做两件事：

| 过滤器 | 能做什么 | 不能做什么 |
|--------|---------|-----------|
| `CallReachFilter` | 丢掉"入口不可达"的函数 | 判断"除数是否为 0" / "污点是否到达" |
| `SafeFunctionFilter` | 丢掉 `apikb` 白名单里的安全 API/wrapper | 判断"这个除法/调用在业务上是否危险" |

结论：凡是被分到 default 链的类型，**收敛管道从设计上就是一条"不过滤的通道"**，候选数与 seed 几乎一致。生产报告里 `divide-by-zero (42处)` 就是直接证据——42 个除法全部走到 A5，AI 既证不了 42 个除数都为 0，也证不了它们都非 0，于是大部分落成"疑似"。

### 缺陷 2：suspicion 分层是"类型级一刀切"，不是"证据级"（crypto-misuse 案例）

`registry.go` 里 `crypto-misuse` 只有 `DefaultSuspicion: "suspected"`，没有 `CategoryConfidence`。

但 detector（`crypto_misuse.go`）已经精确地区分了 category：
- `weak_algorithm`（DES/MD5/SHA1/RC4）——**算法本身被证明不安全**，无论业务上下文如何都是确定的缺陷，应当 `confirmed`。
- `undersized_key`（key < 16 字节）——**确定性**，应当 `confirmed`。
- `weak_random`（rand/srand）——**依赖上下文**（用于 token/key 是缺陷，用于 UI/测试不是），才需要 AI 判断。

对比 `buffer-overflow`/`out-of-bounds`/`integer-overflow` 都已经用 `CategoryConfidence` 做了"detector 证明过的 category → confirmed"。crypto-misuse 漏了这张表，等于把 3 处"确定性弱算法"白白送进 A5 当疑似。

### 缺陷 3：可复用的流引擎（`flowAnalyzer`）只接了 2 个类型

`null_flow.go` 已经沉淀出一套单调数据流引擎（`flowAnalyzer` / `flowResult`，gen/kill/copy + CFG），这是 CLAUDE.md 明确说的"shared best practice"。但它当前只被消费于：

- `filter_nullable_source.go`（null-deref）
- `filter_uninit_flow.go`（uninit）

而 **divide-by-zero、injection、unchecked-return、integer-overflow 各自在用 ad-hoc 的正则/行号近似**，没接这套引擎：

- divide-by-zero：`range_analysis.go` 的 `AnalyzeBounds` 是**同函数内 + 行号区间近似**，`filter_int_overflow.go` 的 `operandBounds` 是**局部常量界**（`guardMaxBound=32768`）。
- 后果：`int d = get_count(); ... a/d;` 这种跨函数除数来源、`if (n < SIZE_MAX - 1)` 这种 caller clamp 契约，**语义图里本来有（CALL 边 + function_summary 表），但没人消费**。

### 缺陷 4：detector 过度近似，把"该排除的"变成了"suspected"（injection 案例）

`injection.go` 的 `detectSQLInjection` 对**每一个** `sqlite3_exec` 无条件发事件（不看 SQL 是否是常量字面量），对 sprintf 里含 `SELECT/INSERT/UPDATE/DELETE` 的也发。

但**常量 SQL（`sqlite3_exec(db, "SELECT ...", ...)`，无任何变量拼接）根本不是注入**。没有字符串常量传播分析，这些候选全部落到 `"suspected"`。生产报告里 `injection (7处): SQL 查询需验证转义` 大概率 7 处都是这类常量 SQL 误报——本应在 detector 层就被判"安全"，却流到 A5。

### 缺陷 5：detector 与 planner 的职责边界混乱（divide-by-zero 案例）

divide-by-zero 的守卫/范围分析（`divisionGuarded`、`AnalyzeBounds.NonZeroAt`）做在 **detector** 里，而不是 planner 的 filter 里。这违背架构文档自己的分层原则（detector 只产证据，planner 做收敛）：

- 后果一：守卫分析**一次性、不可审计**——被守卫挡掉的候选没有进 `Dismissed` ledger，收敛 trail 断掉。
- 后果二：planner 无法复用、无法组合。对比 null-deref，`GuardFilter` 在 planner 里，有 `Dismissed{Filter, Reason}` 审计。
- 正确形态：detector 只发 `DIVIDE_BY_ZERO` 证据（含 divisor 文本），planner 加一个 `DivideByZeroFilter` 做守卫/范围收敛，并复用 `flowAnalyzer`。

### 缺陷 6：`function_summary` 表建了，但只喂 null-deref

架构文档 §6.5 把 `function_summary` 列为"AI Agent 关键输入"（函数契约：return nullable / param clamp / side effect）。但当前只有 `evidence/null_source.go` 写它。

divide-by-zero 需要"这个函数会不会返回 0"、integer-overflow 需要"这个参数的 caller 是否 clamp 过"、unchecked-return 需要"这个 wrapper 是否内部 abort"——这些**契约都该沉淀进 function_summary**，让 A4 的 filter 直接消费，而不是让 A5 每次去追调用链。

---

## 3. 分层解决映射（核心交付）

> 原则：**能由语义图确定性证明的，在 sgre 层（detector A3 / planner A4）解决；语义图证不了的（业务上下文、部分校验是否足够、短读是否可接受），才留给 A5。**

| 疑似类型 | 报告数量 | 当前卡点 | 应在哪层解决 | 具体做法 | 留给 A5 的残余 |
|---------|---------|---------|-------------|---------|--------------|
| **divide-by-zero** | 42 | 守卫分析同函数行号近似，无数据流/跨函数 | **A4 filter + A2 语义图** | 新增 `DivideByZeroFilter`：用 `flowAnalyzer` 追踪除数来源；用 `function_summary` 记录"可能返回 0"的契约（如 `strlen`、`get_count()`）；把 detector 里的 `divisionGuarded`/`AnalyzeBounds` 下移到 filter 以保留审计 | 除数来自外部输入且图上无界（如 `n` 来自网络字段）→ 让 AI 结合业务上下文判断 |
| **integer-overflow** | 1 | guard filter 只认局部常量界 `guardMaxBound=32768`，无 caller 契约 | **A4 filter** | 扩展 `IntOverflowGuardFilter` 读 `function_summary` 的"caller clamp"契约，做跨函数界传播（`in_len + 1` 的 `in_len` 若被所有 caller 证明 `< SIZE_MAX-1` 则排除） | 参数真能到极端值、需追原始来源（argv/getenv/recv 长度）→ AI 追调用链 |
| **crypto-misuse** | 3 | 全类 `DefaultSuspicion=suspected` | **A3 分类（registry）** | 加 `CategoryConfidence: {weak_algorithm: confirmed, undersized_key: confirmed, weak_random: suspected}`——零成本，纯分类修正 | 仅 `weak_random`（rand/srand 是否用于安全上下文）需要 AI |
| **injection** | 7 | detector 对常量 SQL 无条件发事件 | **A3 detector** | `detectSQLInjection` 增加字符串常量判定：`sqlite3_exec(db, "常量SQL")` 且无变量拼接 → 不发事件（或标 safe）；只对"含变量/非字面量格式串"的 SQL 发事件 | 部分黑名单 sanitization、TOCTOU 窗口 → AI 判断校验是否足够 |
| **unchecked-return** | 4 | 无 use-site 分析，wrapper 白名单覆盖不足 | **A3 detector + A4 filter** | detector 增加"结果是否随后被解引用"分析（`malloc` 结果直接 `->` 解引用 → 升级为 confirmed 的 null-deref 近亲）；`apikb` 补目标仓的 `xmalloc`/`SAFE_MALLOC` 类 wrapper | 短读可接受（`read(fd,&ch,1)` 循环）、业务上"返回-1也无所谓" → AI 判断 |

**三个"不是问题"的类型，不要误伤：** `hardcoded-secret`（DefaultSuspicion=confirmed）、`out-of-bounds`/`buffer-overflow`（已用 CategoryConfidence 标 confirmed）分层是**对的**，保持。

---

## 4. A5 的正确定位（不是补丁，是语义推理层）

A5（AI Agent 逐条二次确认）本身**没有错**，它是架构文档"AI Agent 是推理引擎"原则的落地。错的是把它当成了 A3/A4 缺口的遮羞布。

正确边界：

```
A3 detector   → 只产证据（可近似，但不要把"常量SQL"这类确定性安全当候选）
A4 planner    → 用语义图做确定性收敛（守卫/数据流/跨函数契约），产出 confirmed/排除 + 少量真正可疑的
A5 AI Agent   → 只对 A4 证不了的残余做"业务上下文推理"，并给出 confirmed/suspected/dismissed
```

**衡量 A5 是否合格的指标**：A5 之后留下的 `suspected` 应该**几乎全部是"图上无界 + 业务上需要人判断"的真残余**（外部输入除数、部分校验、短读语义），而不是"常量 SQL"、"弱算法"这种确定性结论。

---

## 5. 落地优先级建议

按"投入产出比 + 直接消灭 suspected"排序：

1. **P0（零成本，纯分类）**：给 `crypto-misuse` 补 `CategoryConfidence`——直接消灭报告里 3 处疑似中的弱算法类。
2. **P0（detector 一行判定）**：`injection` 的常量 SQL 不产候选——直接消灭 7 处疑似中的常量 SQL 误报。
3. **P1（复用已有引擎）**：新增 `DivideByZeroFilter`，把 detector 里的守卫分析下移到 filter 并接 `flowAnalyzer` + `function_summary`——这是 42 处除法的最大收敛杠杆。
4. **P1（契约沉淀）**：给 `integer-overflow` 的 guard filter 接 `function_summary` 的 caller clamp 契约。
5. **P2（语义判断）**：`unchecked-return` 增加"结果是否被解引用"分析 + 目标仓 wrapper 白名单。
6. **P3（A5 流程化）**：把 A5 做成"只对 `suspected` 档逐条复核 + 输出 `_c/_s/_x` 后缀"的显式阶段（`markdown.go` 的 `statusSuffix` 已具备 `_c/_s/_x`，只差把它变成强制流程 + 在 report.md 里给研发一个 confirmed 优先视图）。

---

*本分析基于当前代码实现（2026-08 快照），所有文件引用为 `sgre/` 与 `extension/shared/` 的实际路径。*
