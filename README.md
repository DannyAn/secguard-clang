<div align="center">

# SecGuard-Clang

### AI 增强的 C 语言程序安全分析平台

**通过 4 级收敛管线解决"候选爆炸"问题——将 ~600 个原始候选收敛为 ~10 个高质量证据包，交由 AI Agent 分类判定。**

`v0.3.0` · `Go 1.25` · `Tree-sitter` · `SQLite` · `OpenCode / Claude Code`

</div>

---

## 🏆 为什么 SecGuard 是世界级的？

**一句话：SecGuard 是唯一为 AI Agent 而生的 C 语言安全分析平台。** 传统扫描器（CodeQL / Infer / Coverity / Semgrep）为"人看报告"而生，动辄输出上千条原始告警，直接丢给 LLM 会把它淹没。SecGuard 用 4 级收敛把 ~600 条压成 ~10 条高置信证据，让 AI 只判断真正可疑的。

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
| 基准回归门禁 | 53 用例，**精度 100% / 召回 100%**（TP=26 / FP=0 / TN=27 / FN=0） |
| 回归测试 | 69 个安全夹具 · 233 个测试函数，`go test -race` 0 数据竞争 |
| 交付形态 | Linux / Windows / macOS 静态二进制 + OpenCode / Claude Code 双平台 |

### 白话结论

- **比 Semgrep 强**：Semgrep 只做文本模式匹配，SecGuard 真正分析代码的执行路径、数据流和跨函数传播。
- **追平 Infer**：单函数内的精确分析能力同层。
- **逼近 CodeQL / Coverity**：唯一差距在"数值范围分析"，已用"AI 推理兜底"补上大部分，详见 [docs/pk/competitive-analysis.md](docs/pk/competitive-analysis.md)。

---

## 什么是 SecGuard？

SecGuard 不是一个传统的静态分析工具。它是一个 **AI Agent 的安全分析扩展**——部署到 OpenCode 或 Claude Code 中，让 AI Agent 具备深度 C 代码安全审计能力。

核心思路：传统静态分析器会产生大量原始候选（false positive 率），直接交给 AI 会**上下文爆炸**。SecGuard 在底层用语义图 + 数据流分析做 4 级收敛，只把高质量证据包交给 AI Agent 分类。

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

```
 C 源代码
    │
    ▼
┌───────────────┐
│  Tree-sitter   │  增量索引（按 checksum 跳过未变更文件）
│  Indexer       │  → Layer 1: 程序事实
└───────┬───────┘
        ▼
┌───────────────┐
│  Semantic      │  调用图 + 数据流 + 可达性 + 语句级 CFG
│  Graph Builder │  → Layer 2: 语义图
└───────┬───────┘
        ▼
┌───────────────┐
│  22 Detectors  │  null-deref, buffer-overflow, injection, ...
│  (自注册)      │  → Layer 3: 安全证据 (security_events)
└───────┬───────┘
        ▼
┌───────────────┐
│  Planner       │  4 级收敛管线
│  (收敛引擎)    │
└───────┬───────┘
        │
        │  ~600 原始候选
        │     │
        │     ▼  Filter 1: 可空源分析 (reaching-sources 数据流)
        │   ~200
        │     │
        │     ▼  Filter 2: 调用可达性 (call graph)
        │    ~80
        │     │
        │     ▼  Filter 3: 数据流验证 (CFG + guard)
        │    ~30
        │     │
        │     ▼  Filter 4: 去重 + 风险排序
        │    ~10  高质量证据包
        │
        ▼
┌───────────────┐
│  AI Agent      │  按漏洞类型逐批分类: confirmed / suspected / false-positive
│  (分类判定)    │  → Layer 4: findings
└───────┬───────┘
        ▼
┌───────────────┐
│  Report        │  SARIF 2.1 + Markdown + per-finding Markdown
└───────────────┘
```

### 4 层数据模型

| 层 | 内容 | 稳定性 | 表 |
|----|------|--------|-----|
| **Layer 1** | 程序事实 | 最稳定 | `files`, `functions`, `variables`, `expressions`, `types`, `locations` |
| **Layer 2** | 语义图 | 稳定 | `graph_nodes`, `graph_edges` (CALL, DATA_FLOW, OWNERSHIP_TRANSFER, RELEASE, ALIAS, PARAM_BINDING, RETURN) |
| **Layer 3** | 安全证据 | 中等 | `security_events` (NULL_VALUE, DEREFERENCE, BUFFER_ACCESS, ...) |
| **Layer 4** | 发现 | 最易变 | `findings` (AI Agent 写入) |

### 双平台扩展架构

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
└── claude-code/               ← Claude Code 薄包装
    └── ...
```

构建时 `release/build-packages.sh` 将 `shared/` 展开到两个平台包装中，安装到 `.opencode/` 和 `.claude/`。

## 快速开始

### 方式一：从发行包安装（推荐）

```bash
# 下载发行包
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.3.0.zip -o secguard.zip
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

### 在 AI Agent 中使用

安装后，在 OpenCode 或 Claude Code 中直接对话：

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

扫描结果写入 `.codeagent/zhuque-secguard/scans/<scan-id>/`：

```
scans/2026-08-17_062452_e32eb1/
├── sarif.sarif                    ← SARIF 2.1（IDE/CI 集成）
├── report.md                      ← Markdown 摘要（候选列表）
├── audit-report.md                ← AI 审计报告（分类统计）
├── buffer-overflow/
│   ├── 001_allocator_99.md       ← 逐条证据
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
│       ├── planner/               # 4 级收敛管线 + 13 个过滤器
│       ├── agent/                 # AI Agent 集成
│       ├── report/                # SARIF + Markdown 报告
│       └── log/                   # 结构化日志
├── extension/                     # 多平台 AI Agent 扩展
│   ├── shared/                    # 共享核心（skills + agent prompt）
│   ├── opencode/                  # OpenCode 包装
│   └── claude-code/               # Claude Code 包装
├── release/                       # 构建/安装工具
├── examples/                      # 示例和基准测试
│   └── c-vuln-benchmark/          # 19 文件 / 53 测试用例 / 20 类型
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
