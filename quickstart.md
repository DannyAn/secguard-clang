# SecGuard 快速开始

> AI 增强的 C 程序安全分析平台 — 4 层收敛管线 + AI Agent 推理

- [English README](README.md) · [中文 README](README-CN.md)
- 架构权威说明：[CLAUDE.md](CLAUDE.md)

## 1. 前置条件

| 依赖 | 最低版本 | 用途 |
|------|---------|------|
| Go | 1.25+ | 从源码构建 secguard 二进制 |
| CGo (C 编译器) | gcc/clang | tree-sitter-c 需要 CGo |
| SQLite | 内置 (modernc.org/sqlite) | 无需系统安装 |
| OpenCode / Claude Code / DeepSeek Harness | 最新版 | AI Agent 交互（三选一） |

> 使用发行包安装（见第 2 节）无需 Go 和 C 编译器。

检查环境：

```bash
go version          # 需要 1.25+
gcc --version       # 或 clang --version
```

## 2. 安装

### 2.1 从发行包安装（推荐）

```bash
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.3.2.zip -o secguard.zip
unzip secguard.zip
./install.sh
secguard --version   # 输出: 0.3.2
```

`install.sh` 支持：

```bash
./install.sh --target opencode     # 只装 OpenCode
./install.sh --target claude-code  # 只装 Claude Code
./install.sh --no-binary           # 只装扩展，跳过二进制
./install.sh --verify              # 安装后自检
./install.sh --uninstall --yes     # 卸载
```

### 2.2 从源码构建（开发者）

```bash
git clone https://github.com/DannyAn/secguard-clang.git
cd secguard-clang

# 构建二进制 + 安装扩展
./build.sh --install

# 或只构建二进制
./build.sh              # → bin/secguard

# 构建发行包
./build.sh --package
```

开发模式快速部署（构建 + 装到用户级配置目录）：

```bash
./deploy.sh                    # 构建二进制 + 安装 OpenCode + Claude Code
./deploy.sh opencode           # 仅 OpenCode
./deploy.sh claude-code        # 仅 Claude Code
./deploy.sh --no-binary        # 跳过二进制构建
```

### 2.3 DeepSeek Harness（DSH）

```bash
# 1) 确保 secguard 在 PATH 上（见 2.1/2.2）
# 2) 安装 DSH preset（组合 + 20 个 skill → ~/.dsh/.agent-presets/secguard/）
./release/install-dsh.sh

# 3) 在 DSH 里选择「SecGuard 安全审计」preset，然后对话：
#    > 扫描 src/ 目录的安全漏洞
```

## 3. CLI 命令

| 命令 | 说明 |
|------|------|
| `secguard scan <path>` | 完整管线：索引 + 检测 + 收敛 + 报告（最常用） |
| `secguard plan <vuln>` | 对单个漏洞类型运行收敛管线 |
| `secguard index <path>` | 仅索引（不跑检测器和收敛） |
| `secguard status` | 索引状态（文件数、函数数、陈旧度） |
| `secguard types` | 列出全部 20 种漏洞类型 + CWE |
| `secguard schema [table]` | 查询表 schema（写 SQL 前用） |
| `secguard report` | 输出全部 findings（JSON） |
| `secguard db <sql>` | 在 sgre.db 上执行 SQL（只读） |

全局选项：`--db <path>`（覆盖 DB 路径）、`--exclude <dirs>`（排除目录）、`--version`、`--help`

```bash
# 完整扫描
secguard scan ./my-project

# 指定数据库路径（避免污染默认库）
secguard scan ./my-project --db /tmp/my-analysis.db

# 单独收敛某类漏洞
secguard plan null-deref
secguard plan buffer-overflow

# 查询结果
secguard report
```

默认数据库路径：`./sgre.db`。

## 4. 在 AI Agent 中使用

安装后，在 OpenCode、Claude Code 或 DeepSeek Harness 中直接对话：

```
> 扫描 src/ 目录的安全漏洞
> 看看有没有 null-deref, buffer-overflow 问题
```

### 4.1 OpenCode / Claude Code（`/secguard` 命令）

```
/secguard ./my-project
```

触发 `security-auditor` 子代理执行完整流程：

```
secguard scan ./project → 收敛证据包 → 加载匹配 skill → 逐条分类
                       → confirmed / suspected / false-positive → 结果表格 + 修复建议
```

`security-auditor` 是 `mode: subagent`，不会通过自然语言自动触发，需用 `/secguard` 或
`@security-auditor` 显式调用。

### 4.2 DeepSeek Harness

在 DSH 里选择「SecGuard 安全审计」preset（persona = `dsh-persona`），直接对话即可，无需
接触 OpenCode / Claude Code。

## 5. 完整使用示例

```bash
# 命令行直接扫描基准集
secguard scan ./examples/c-vuln-benchmark/src

# 校验基准（77 用例 · 精度/召回 100%）
python3 scripts/validate-benchmark.py \
    --sarif .codeagent/zhuque-secguard/scans/latest/sarif.sarif \
    --expected examples/c-vuln-benchmark/expected-results.json

# 在 OpenCode / Claude Code 中：
#   /secguard ./examples/c-vuln-benchmark/src
```

## 6. 架构简述

```
C 源码
  ↓
Tree-sitter 解析 → AST
  ↓
Indexer → 程序语义图 (SQLite)
  ↓
22 个检测器 → ~600 原始候选 (security_events)
  ↓
4 层收敛管线:
  L1: 可空源分析 (reaching-sources 数据流)
  L2: 调用可达性 (call graph)
  L3: 数据流验证 (CFG + guard)
  L4: 去重 + 风险排序
  ↓
~10 高质量证据包
  ↓
AI Agent (security-auditor / DSH preset)
  ↓
分类: confirmed / suspected / false-positive
  ↓
SARIF + Markdown 报告
```

## 7. 故障排除

### 7.1 `secguard` 命令不存在

```bash
which secguard            # 应输出 ~/.local/bin/secguard 或 bin/secguard
# 若为空，重新安装（2.1）或重新构建（2.2）
```

### 7.2 构建失败：CGO 相关

```bash
CGO_ENABLED=1 go build -o bin/secguard ./cmd/secguard   # 从 sgre/ 目录

# 缺少 C 编译器：
# macOS:  xcode-select --install
# Ubuntu: sudo apt install gcc
```

### 7.3 构建失败：依赖问题

```bash
# 从 sgre/ 目录，无网络沙箱环境：
cd sgre
GONOSUMDB='*' GOFLAGS=-mod=mod go mod tidy
GONOSUMDB='*' GOFLAGS=-mod=mod CGO_ENABLED=1 go build -o ../bin/secguard ./cmd/secguard
```

### 7.4 `secguard scan` 报数据库错误

```json
{"error":"failed to open database: ..."}
```

原因通常是当前目录无写权限。解决：指定 `--db` 路径：

```bash
secguard scan ./my-project --db /tmp/sgre.db
```

### 7.5 OpenCode 中 `/secguard` 命令不出现

```bash
ls ~/.config/opencode/extensions/zhuque-secguard/
ls ~/.config/opencode/commands/secguard.md
# 不存在则重新部署：./deploy.sh opencode
```

### 7.6 `secguard report` 返回空数组

**预期行为**：`secguard scan` 产出证据包，findings 由 AI Agent 分类后写入。若未运行
AI Agent 分类，`secguard report` 返回 `[]`。

```
secguard scan → 证据包 → AI Agent 分类 → 写入 findings → secguard report
```

### 7.7 `secguard scan` 输出包含日志行

**设计行为**：日志输出到 stderr（NDJSON），JSON 结果输出到 stdout。

```bash
secguard scan ./src 2>/dev/null          # 仅 JSON
secguard scan ./src 1>results.json 2>logs.ndjson   # 分别保存
```

## 8. 支持的漏洞类型（20 种）

完整列表见 [README-CN.md](README-CN.md) 或 `secguard types`：

`null-deref` · `buffer-overflow` · `memory-leak` · `injection` · `resource-leak` ·
`uninit` · `use-after-free` · `double-free` · `format-string` · `integer-overflow` ·
`race-condition` · `hardcoded-secret` · `deadlock` · `crypto-misuse` ·
`out-of-bounds` · `divide-by-zero` · `unchecked-return` · `path-traversal` ·
`sizeof-misuse` · `signed-compare`

每种类型有对应的 AI Agent skill（`extension/shared/skills/<type>/SKILL.md`），提供
分类规则与误报识别指南。
