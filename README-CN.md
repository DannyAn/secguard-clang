<div align="center">

> **中文版** · [English version](README.md)

# SecGuard-Clang

### AI 增强的 C 语言程序安全分析平台

**通过 5 级收敛管线解决"候选爆炸"问题——将 ~600 个原始候选收敛为 ~10 个高质量证据包（A1–A4），再经第 5 层二次审查（A5）提升真漏洞、剔除误报。**

`v0.3.2` · `Go 1.25` · `Tree-sitter` · `SQLite` · `OpenCode / Claude Code / DeepSeek Harness`

</div>

---

## 🏆 为什么 SecGuard 是世界级的？

**一句话：SecGuard 是唯一为 AI Agent 而生的 C 语言安全分析平台。** 传统扫描器（CodeQL / Infer / Coverity / Semgrep）为"人看报告"而生，动辄输出上千条原始告警，直接丢给 LLM 会把它淹没。SecGuard 用 4 级确定性收敛（A1–A4）把 ~600 条压成 ~10 条高置信证据，再经第 5 层（A5）对每条疑似逐条二次确认，只留下真正"需人工判断"的残余。

### 别人没有、我们独有的（蓝海）

1. **连"安全函数"的误用都能抓** —— 业界普遍把 `memcpy_s` / `strcpy_s` / `scanf_s` 这类 `_s` 函数当"无条件安全"直接跳过，SecGuard 按契约逐个校验容量参数：`char buf[10]; memcpy_s(buf, 100, src, 50)` 这种"说谎的 size"照样抓出溢出。
2. **把大模型当分析引擎** —— 静态分析证明不了的模糊边界（变量 `n` 会不会真的把 `malloc(n)` 撑爆），SecGuard 识别出来、带证据交给 AI 推理，而不是硬造一个可能出错的数学域。

### 与业界顶尖工具对标（✅ 强 · ⚠️ 追平 · ❌ 弱）

| 能力 | CodeQL | Infer | Coverity | Semgrep | **SecGuard** |
|---|---|---|---|---|---|
| 路径敏感数据流 | ✅ | ✅ | ✅ | ❌ | ✅ |
| 跨函数分析 | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| 污点追踪 | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| 别名分析 | ✅ | ✅ | ✅ | ❌ | ✅ |
| 数值范围分析 | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| 误报抑制 / 基线对比 / CI 拦截 | ✅ | ✅ | ✅ | ✅ | ✅ |
| SARIF 代码导航 | ✅ | ⚠️ | ✅ | ✅ | ✅ |
| 并行 + 超时 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 增量索引 | ✅ | ✅ | ✅ | ✅ | ✅ |
| 修复建议 | ⚠️ | ⚠️ | ✅ | ✅ | ✅ |
| **AI Agent 原生** | ❌ | ❌ | ❌ | ❌ | ✅ |

> 完整逐项说明（含 SecGuard 的实现机制）见 [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md)。

### 硬指标（可自行验证）

| 指标 | 数值 |
|---|---|
| 漏洞类型 / 检测器 | **20 种 / 22 个**，CWE 全映射 |
| 收敛效率 | ~600 原始告警 → **~10 证据包**（~4.5ms） |
| 基准回归门禁 | 77 用例，**精度 100% / 召回 100%**（TP=43 / FP=0 / TN=34 / FN=0） |
| 回归测试 | 74 个安全夹具 · 244 个测试函数，`go test -race` 0 数据竞争 |
| 交付形态 | Linux / Windows / macOS 静态二进制 + OpenCode / Claude Code / DeepSeek Harness 三平台 |

### 真实规模实测：Redis（约 21 万行 C 代码）

为证明收敛效果在工业级 C 代码上同样成立（而不只是基准集），我们对 **Redis** 跑了完整管线
（`src/`，231 个文件 · 6,001 个函数 · 68,512 个图节点 · 100,508 条图边）。第三方 `deps/`
按默认 `--exclude` 跳过。

| 阶段 | 数量 |
|---|---|
| 原始安全事件（22 个检测器） | 96,230 |
| 进入收敛管线的候选 | 63,766 |
| **收敛后的证据包（SARIF 结果）** | **2,931** — **约 22 倍压缩** |
| 端到端墙钟时间 | **约 6.5 分钟**（索引 1.8s · 构图 20s · 检测 33s · 收敛约 5.6 分钟） |

分类型收敛效果（候选 → 证据包）：

| 类型 | 候选 → 证据包 | 压缩率 |
|---|---|---|
| use-after-free | 9,779 → 43 | 99.6% |
| null-deref | 48,861 → 872 | 98.2% |
| double-free | 241 → 17 | 92.9% |
| format-string | 32 → 13 | 59.4% |
| memory-leak | 16 → 0 | 100% |
| buffer-overflow | 286 → 218 | 23.8% |
| integer-overflow | 134 → 104 | 22.4% |
| … 全部 20 类型 | 63,766 → 2,931 | 约 22× |

复现命令：

```bash
secguard scan --db /tmp/redis.db <path-to-redis>
```

### 白话结论

- **比 Semgrep 强**：Semgrep 只做文本模式匹配，SecGuard 真正分析代码的执行路径、数据流和跨函数传播。
- **追平 Infer**：单函数内的精确分析能力同层。
- **逼近 CodeQL / Coverity**：已实现轻量数值范围分析（守卫感知的界传播），抑制 null-deref 和除零误报；剩余差距在完整抽象解释区间域，已用"AI 推理兜底"补上大部分，详见 [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md)。

---

## 什么是 SecGuard？

SecGuard 不是一个传统的静态分析工具。它是一个 **AI Agent 的安全分析扩展**——部署到 OpenCode 或 Claude Code 中，让 AI Agent 具备深度 C 代码安全审计能力。

核心思路：传统静态分析器会产生大量原始候选（false positive 率），直接交给 AI 会**上下文爆炸**。SecGuard 在底层用语义图 + 数据流分析做 4 级确定性收敛（A1–A4），只把高质量证据包交给 AI Agent 做首轮分类，再经第 5 层（A5）对每条疑似发现二次审查，提升真漏洞、剔除误报。

```
                    ┌──────────────────────────────────────────────────┐
                    │              AI Agent (OpenCode / Claude Code)      │
                    │                                                      │
                    │  secguard scan ──→ 收敛后的证据包 ──→ 分类判定       │
                    │  secguard plan  ──→ 单类型证据   ──→ 分类判定       │
                    │  secguard report ──→ 写入 findings                  │
                    └────────────────────────┬─────────────────────────┘
                                             │ shell 调用
                    ┌────────────────────────▼─────────────────────────┐
                    │           secguard 二进制 (sgre 引擎)               │
                    │                                                      │
                    │  index → graph → detect → plan(收敛) → report       │
                    └────────────────────────┬─────────────────────────┘
                                             │
                    ┌────────────────────────▼─────────────────────────┐
                    │              SQLite 语义图 (sgre.db)                │
                    │                                                      │
                    │  Layer 1: 程序事实  (files, functions, variables)   │
                    │  Layer 2: 语义图    (call graph, data flow, CFG)    │
                    │  Layer 3: 安全证据  (security_events)               │
                    │  Layer 4: 发现     (findings, AI 写入)              │
                    └──────────────────────────────────────────────────┘
```

## 架构

### 管线流程

SecGuard 运行**5 级收敛管线**：A1–A4 是确定性的（在语义图上能证的证、能证伪的证伪）；
**A5 是复合补全层**——对每条疑似发现二次审查，解决语义图*证不了*的残余
（外部输入除数、部分校验、短读语义、TOCTOU 窗口），靠 AI 的业务上下文推理拍板。

```
 C 源代码
    │
    ▼
┌───────────────┐
│  A1 Indexer    │  tree-sitter 增量索引（按 checksum 跳过未变更文件）
│  (Tree-sitter) │  → Layer 1: 程序事实
└───────┬───────┘
        ▼
┌───────────────┐
│  A2 Semantic   │  调用图 + 数据流 + 可达性 + 语句级 CFG
│  Graph Builder │  → Layer 2: 语义图
└───────┬───────┘
        ▼
┌───────────────┐
│  A3 Detectors  │  22 个自注册检测器: null-deref, buffer-overflow, injection, ...
│  (evidence)    │  → Layer 3: 安全证据 (security_events)
└───────┬───────┘
        ▼
┌───────────────┐
│  A4 Planner    │  4 级收敛（确定性，在 planner 内部）
│  (收敛引擎)    │
└───────┬───────┘
        │  ~600 原始候选
        │     ▼  Filter 1: 可空源分析 (reaching-sources 数据流)
        │   ~200
        │     ▼  Filter 2: 调用可达性 (call graph)
        │    ~80
        │     ▼  Filter 3: 数据流验证 (CFG + guard)
        │    ~30
        │     ▼  Filter 4: 去重 + 风险排序
        │    ~10  高质量证据包
        ▼
┌───────────────┐
│  AI Agent      │  首轮: 按漏洞类型逐批分类 + 结构化判定依据补全
│  (分类判定)    │  → Layer 4: findings (status + summary/reasoning/exception_check/fix_strategy)
└───────┬───────┘
        ▼
┌───────────────┐
│  A5 Second-    │  对每条疑似发现，重新读取 file:line 处源码逐一判定
│  Round Review  │  → review_status = confirmed (提升) / dismissed (剔除) / suspected-kept
│  (复合补全层)  │  持久化 review_reasoning；只留下真正"需人工判断"的残余
└───────┬───────┘
        ▼
┌───────────────┐
│  Report        │  SARIF 2.1 + Markdown + per-finding Markdown (_confirmed/_suspected/_dismissed)
└───────────────┘
```

A1–A4 解决语义图能证明的（confirmed）和能证伪的（drop）——它们产不出推理链和修复策略。
首轮分类补上这块：对每条发现写 `summary` / `reasoning` / `exception_check` / `fix_strategy`
（确定性引擎合成不了的"为什么信它 + 怎么修"）。A5 再复合一层，对每条疑似二次确认，
所以经过 A5 仍留下的 `suspected` 是真正"需人工判断"的情形——而非图本已知道的确定性结论。
最终报告通过 `EffectiveStatus()` 统计 A5 之后的裁决。

### 4 层数据模型

| 层 | 内容 | 稳定性 | 表 |
|----|------|--------|-----|
| **Layer 1** | 程序事实 | 最稳定 | `files`, `functions`, `variables`, `expressions`, `types`, `locations` |
| **Layer 2** | 语义图 | 稳定 | `graph_nodes`, `graph_edges` (CALL, DATA_FLOW, OWNERSHIP_TRANSFER, RELEASE, ALIAS, PARAM_BINDING, RETURN) |
| **Layer 3** | 安全证据 | 中等 | `security_events` (NULL_VALUE, DEREFERENCE, BUFFER_ACCESS, ...) |
| **Layer 4** | 发现 | 最易变 | `findings` (首轮写 `status`；A5 二次审查写 `review_status` / `review_reasoning`) |

### 多平台扩展架构

```
extension/
├── shared/                    ← 单一事实来源（编辑这里）
│   ├── agent-body.md          ← AI Agent 提示词（工作流 + 分类规则）
│   ├── command-instructions.md ← /secguard 命令指令
│   └── skills/                ← 20 个漏洞类型 skill
│       ├── null-deref/SKILL.md
│       ├── buffer-overflow/SKILL.md
│       └── ...
├── opencode/                  ← OpenCode 薄包装
│   ├── tools/*.ts             ← 7 个 TypeScript 工具
│   └── extension.json
├── claude-code/               ← Claude Code 薄包装
│   └── ...
└── deepseek-harness/          ← DeepSeek Harness 薄包装（Agent preset）
    ├── preset.yml             ← preset 元数据
    └── agent.cordis.yml       ← Cordis 组合（persona + 工具 + skill 根）
```

OpenCode / Claude Code 构建时 `release/build-packages.sh` 将 `shared/` 展开安装到 `.opencode/` 和 `.claude/`。
DeepSeek Harness 用 `release/install-dsh.sh` 把 preset 装到 `~/.dsh/.agent-presets/secguard/`（skills 从 `shared/` 拷贝）。

## 快速开始

### 方式一：从发行包安装（推荐）

```bash
# 下载发行包
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.3.2.zip -o secguard.zip
unzip secguard.zip

# 安装（自动检测 OS × 架构，装到 OpenCode + Claude Code）
./install.sh

# 验证
secguard --version
```

安装脚本支持以下选项：

```bash
./install.sh --target opencode       # 只装 OpenCode 扩展
./install.sh --target claude-code    # 只装 Claude Code 扩展
./install.sh --no-binary             # 只装扩展，跳过二进制
./install.sh --verify                # 安装后自检
./install.sh --uninstall --yes       # 卸载
```

### 方式二：从源码构建

```bash
git clone https://github.com/DannyAn/secguard-clang.git
cd secguard-clang

# 构建二进制 + 安装扩展
./build.sh --install

# 或者只构建二进制
./build.sh              # → bin/secguard

# 构建发行包
./build.sh --package
```

### 方式三：DeepSeek Harness（DSH）

SecGuard 提供了 DSH 的 Agent preset（Cordis 组合），装上后在 DSH 里选
「SecGuard 安全审计」preset 即可让 Agent 具备 C 安全审计能力：

```bash
# 1) 确保 secguard 二进制在 PATH 上（见方式一/二）
# 2) 安装 DSH preset（把组合 + 20 个 skill 装到 ~/.dsh/.agent-presets/secguard/）
./release/install-dsh.sh

# 3) 在 DSH 里选择「SecGuard 安全审计」preset，然后对话：
#    > 扫描 src/ 目录的安全漏洞
#    > 看看有没有 buffer-overflow, null-deref 问题
```

DSH 的"角色"即 persona（`agent.cordis.yml` 里的 `dsh-persona`）；外部用户选这个
preset 即得到一个专注 C 安全审计的 Agent，无需接触 OpenCode/Claude Code。

### 在 AI Agent 中使用

安装后，在 OpenCode、Claude Code 或 DeepSeek Harness 中直接对话：

```
> 扫描 src/ 目录的安全漏洞
> 看看有没有 null-deref, buffer-overflow 问题
> 审计 ./src 的安全性
```

AI Agent 会自动调用 `secguard scan`，加载对应 skill，分类判定，输出报告。

### 直接使用 CLI

```bash
# 完整扫描（索引 + 检测 + 收敛 + 报告）
secguard scan ./src

# 查看支持的漏洞类型
secguard types

# 查看索引状态
secguard status

# 对单个漏洞类型运行收敛
secguard plan null-deref

# 查询 findings
secguard report

# 执行 SQL 查询
secguard db "SELECT * FROM findings WHERE status='confirmed'"
```

## 支持的漏洞类型（20 种）

| 漏洞类型 | CWE | 漏洞类型 | CWE |
|---------|-----|---------|-----|
| `null-deref` | CWE-476 | `hardcoded-secret` | CWE-798 |
| `buffer-overflow` | CWE-787 | `deadlock` | CWE-667 |
| `memory-leak` | CWE-401 | `crypto-misuse` | CWE-327 |
| `injection` | CWE-78 | `out-of-bounds` | CWE-125 |
| `resource-leak` | CWE-404 | `divide-by-zero` | CWE-369 |
| `uninit` | CWE-457 | `unchecked-return` | CWE-252 |
| `use-after-free` | CWE-416 | `path-traversal` | CWE-22 |
| `double-free` | CWE-415 | `sizeof-misuse` | CWE-467 |
| `format-string` | CWE-134 | `signed-compare` | CWE-681 |
| `integer-overflow` | CWE-190 | `race-condition` | CWE-362 |

每种类型有对应的 AI Agent skill（`extension/shared/skills/<type>/SKILL.md`），提供分类规则和误报识别指南。

## CLI 命令

| 命令 | 说明 |
|------|------|
| `secguard scan <path>` | 完整管线：索引 + 全部检测器 + 收敛 + 报告 |
| `secguard plan <vuln>` | 对单个漏洞类型运行收敛管线 |
| `secguard index <path>` | 仅索引（不跑检测器和收敛） |
| `secguard status` | 索引状态（文件数、函数数、陈旧度） |
| `secguard types` | 列出所有漏洞类型 + CWE（JSON） |
| `secguard schema [table]` | 查询表 schema（列名/类型，写 SQL 前用） |
| `secguard report` | 输出全部 findings（JSON） |
| `secguard db <sql>` | 在 sgre.db 上执行 SQL 查询（只读） |

全局选项：`--db <path>`（覆盖 DB 路径）、`--exclude <dirs>`（排除目录）、`--version`、`--help`

## 输出

扫描结果写入 `.codeagent/secguard-clang/scans/<scan-id>/`：

```
scans/2026-08-17_062452_e32eb1/
├── result.sarif                    ← SARIF 2.1（IDE/CI 集成）
├── report.md                      ← Markdown 摘要（候选列表）
├── audit-report.md                ← AI 审计报告（分类统计）
└── findings/                      ← 逐条证据，按漏洞类型分组
    ├── buffer-overflow/
    │   ├── 001_allocator_99.md
    │   └── 002_parser_20.md
    ├── null-deref/
    │   └── 001_network_45.md
    └── ...
```

## 技术栈

| 组件 | 技术 | 说明 |
|------|------|------|
| **核心引擎** | Go 1.25 | 单一静态二进制，跨平台 |
| **数据库** | SQLite (modernc.org/sqlite) | 纯 Go，无 CGo 依赖 |
| **解析器** | Tree-sitter + tree-sitter-c | 增量解析 C 语法 |
| **交叉编译** | zig (musl/mingw) | Linux/Windows 静态二进制 |
| **AI 扩展** | TypeScript/Bun | 7 个 OpenCode 工具 |
| **AI 平台** | OpenCode + Claude Code | 共享核心 + 薄包装 |

## 项目结构

```
secguard-clang/
├── sgre/                          # Go 模块（核心引擎）
│   ├── cmd/secguard/              # CLI 入口
│   └── internal/
│       ├── cli/                   # CLI 命令实现
│       ├── db/                    # SQLite schema + CRUD
│       ├── indexer/               # Tree-sitter 索引器
│       ├── parser/                # 解析器包装
│       ├── graph/                 # 语义图构建（调用图/数据流/CFG）
│       ├── evidence/              # 22 个安全检测器
│       ├── planner/               # A4: 4 级收敛管线 + 13 个过滤器
│       ├── agent/                 # AI Agent 集成
│       ├── report/                # SARIF + Markdown 报告
│       └── log/                   # 结构化日志
├── extension/                     # 多平台 AI Agent 扩展
│   ├── shared/                    # 共享核心（skills + agent prompt）
│   ├── opencode/                  # OpenCode 包装
│   └── claude-code/               # Claude Code 包装
│   └── deepseek-harness/          # DeepSeek Harness 包装（Agent preset）
├── release/                       # 构建/安装工具
├── examples/                      # 示例和基准测试
│   └── c-vuln-benchmark/          # 23 文件 / 77 测试用例 / 20 类型
├── docs/                          # 设计文档
├── build.sh                       # 构建入口
└── .github/workflows/             # CI 发布工作流
```

## 测试

```bash
cd sgre

# 全套测试（需 SQLite + tree-sitter）
go test ./...

# 无 SQLite 子集（mock store）
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/

# 收敛基准
go test -tags nosqlite -bench=. ./internal/planner/

# 安全测试夹具
go test -run TestSecurity ./internal/evidence/
```

## 设计原则

1. **表按程序事实类型组织**，不按漏洞类型——避免 schema 爆炸
2. **Skills 是查询消费者**，永不创建表——保持关注点分离
3. **AI Agent 只接收收敛后的证据包**，永不接触原始候选——这是管线的核心价值
4. **CWE 映射的单一事实来源**——`VulnTypeSpec.CWE` 是唯一真相，所有消费者派生自它
5. **按漏洞类型分批处理**——避免 AI Agent 上下文爆炸

## 性能

- 收敛管线（600 候选 → ≤30）：**~4.5ms**
- 增量索引：按 checksum 跳过未变更文件
- 大代码库生成器：`go run testdata/perf/gen_codebase.go testdata/perf/large_codebase 100 50`

## 相关文档

- [CLAUDE.md](CLAUDE.md) — 架构权威说明（Claude Code 工作指南）
- [CHANGELOG.md](CHANGELOG.md) — 变更记录
- [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md) — 竞品分析（vs CodeQL / Infer / Coverity / Semgrep）
- [docs/output-protocol.md](docs/output-protocol.md) — 输出契约
- [docs/parallelization-design.md](docs/parallelization-design.md) — 并行化设计
- [examples/c-vuln-benchmark/](examples/c-vuln-benchmark/) — 漏洞基准测试集

## License

Proprietary © Zhuque Security
