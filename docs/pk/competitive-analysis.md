# SecGuard vs 业界顶尖 C 安全分析工具 — 竞品分析

> 评估日期：2026-08-19 · 评估版本：v0.2.1 · 对标工具：CodeQL (GitHub)、Infer (Meta)、Coverity (Synopsys)、Semgrep

## 1. 能力对比矩阵

| 维度 | CodeQL | Infer | Coverity | Semgrep | **sgre** |
|------|--------|-------|----------|---------|----------|
| 路径敏感数据流 | ✅ 深度 | ✅ bi-abduction | ✅ 深度 | ❌ 纯 syntactic | ✅ CFG 基 reaching-definitions |
| 过程间分析 | ✅ 1-CFA+ | ✅ 按需 | ✅ 深度 | ❌ | ⚠️ 0-CFA（无上下文敏感） |
| 值分析/区间域 | ✅ RangeAnalysis | ✅ Inferbo | ✅ | ❌ | ⚠️ 变量界定 + AI fallback（无完整区间域） |
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
| P2 | 值分析/区间域 | RangeAnalysis lite | 🚧 进行中（变量界定 + AI fallback，见 §7） |
| P2 | 1-CFA 过程间分析 | 按调用点区分摘要 | 待排 |

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

### 待续

- 完整区间域（RangeAnalysis lite）：`if (n < 100)` 守卫后的常量传播，用于把
  `param + const` 从 possible 提升为 confirmed/直接丢弃。
- 1-CFA 过程间上下文敏感：按调用点区分形参界定（同一函数不同调用方传入不同上界）。