<div align="center">

> **中文版** · [English version](README.md)

# SecGuard-Clang

### 面向 AI Agent 的 C 语言安全分析

**发现 C 代码里的内存、注入与并发漏洞，并得到一份简短、带证据的真实问题清单，而不是成千上万条噪音告警。**

`v0.8.0` · `Go 1.25` · `Tree-sitter` · `SQLite` · `OpenCode / OpenCode-NGA / Claude Code / Claude CAC / DeepSeek Harness`

</div>

---

## 什么是 SecGuard？

SecGuard-Clang 是一个分成两层、各司其职的 C 语言安全分析平台：

- **确定性引擎**（`sgre`）负责索引代码库、构建语义图（调用图、数据流、控制流、别名与污点边）、运行自注册检测器，并把原始证据收敛成一份简短的“可疑位置”清单——项目内部称之为 *候选（candidates）*。凡是语义图能够*证明*的缺陷，引擎会直接自动确认，不需要 AI 参与。
- **AI Agent 层**只复核剩余的线索——每条线索都带有精确的源语句、管线预计算的 Hint 和小范围代码上下文——然后对每个候选给出一个二元裁决：`confirmed`（持久化并附上推理与修复建议）或 `dismissed`（排除，不持久化）。

价值在于两层之间的边界。传统扫描器会把每一条原始告警都吐出来，用大量误报淹没大模型、耗尽上下文窗口。SecGuard 只把紧凑的、已收敛的证据交给模型，让模型把推理预算花在确定性管线无法判定的那部分案例上。

## 它有什么不同

- **证据打包，而不是告警倾倒。** 扫描阶段会按类型生成候选索引（`Source` + `Hint` + `Evidence`）和逐候选代码上下文，Agent 基于结构化证据分类，而不是重新翻读整个仓库。
- **校验契约，而不是无条件豁免。** `_s` 函数不会被想当然地当成安全函数。`char buf[10]; memcpy_s(buf, 100, src, 50)` 是“说谎的 size”，会被判为溢出；而正确的 `memcpy_s(dst, sizeof(dst), src, 8)` 则不会。
- **二元裁决。** 每个候选最终只会是 `confirmed` 或 `dismissed`。不会留下一堆 `suspected` 让开发者事后慢慢挑；`findings/` 和 `result.sarif` 里只有真正可行动的结果。
- **产物可复现。** 一次扫描会产出 `report.md`、`audit-report.md`、`result.sarif`、`result.xlsx` 和 `findings/` 目录，全部从同一个 SQLite 数据库重新推导。
- **在工程师原本的工作流里工作。** 同一个核心以薄封装形式发布到 OpenCode、OpenCode-NGA、Claude Code、Claude CAC 和 DeepSeek Harness，另提供独立 CLI 供 CI 使用。

## 管线

```
 C 源代码
    │
    ▼
┌────────────────┐   tree-sitter 增量索引（按 checksum 跳过未变更文件）
│  Indexer        │
└───────┬────────┘
        ▼
┌────────────────┐   调用图 + 数据流 + CFG + 别名/所有权边
│  Semantic graph │
└───────┬────────┘
        ▼
┌────────────────┐   32 个自注册检测器
│  Detectors      │   （null-deref、buffer-overflow、injection …）
└───────┬────────┘
        ▼
┌────────────────┐   收敛过滤器：nullable-source、call-reach、
│  Planner        │   dataflow、dedup + 风险排序
└───────┬────────┘
        │
        ├── 可证明的缺陷 ──────────────► 自动确认（无需 AI 复核）
        │
        └── 剩余线索 ──► 证据包 ──► AI Agent
                              │
                              │  单轮二元裁决
                              ▼
                        confirmed → 持久化 + 修复建议
                        dismissed → 排除，不持久化
                              │
                              ▼
┌────────────────┐   report.md · audit-report.md · result.sarif ·
│  Report / audit │   result.xlsx · findings/
└────────────────┘
```

确定性阶段只处理它能证明或证伪的部分。AI 阶段只负责分类残余线索，并为每一条 confirmed 发现补上确定性引擎无法生成的 `summary`、`reasoning`、`exception_check` 和 `fix_strategy`。

## 支持的漏洞类型

SecGuard 内置 24 类漏洞类型，CWE 映射有单一事实源：

| 类型 | CWE | 类型 | CWE |
|---|---|---|---|
| `null-deref` | CWE-476 | `use-after-free` | CWE-416 |
| `buffer-overflow` | CWE-787 | `double-free` | CWE-415 |
| `out-of-bounds` | CWE-125 | `uninit` | CWE-457 |
| `memory-leak` | CWE-401 | `unchecked-return` | CWE-252 |
| `resource-leak` | CWE-404 | `format-string` | CWE-134 |
| `injection` | CWE-78 | `integer-overflow` | CWE-190 |
| `path-traversal` | CWE-22 | `divide-by-zero` | CWE-369 |
| `crypto-misuse` | CWE-327 | `hardcoded-secret` | CWE-798 |
| `deadlock` | CWE-667 | `race-condition` | CWE-362 |
| `dangerous-function` | CWE-676 | `signed-compare` | CWE-681 |
| `sizeof-misuse` | CWE-467 | `signal-handler` | CWE-479 |
| `argument-type` | CWE-686 | `data-representation` | CWE-843 |

每种类型都有对应的 Agent 技能，位于 `extension/shared/skills/<type>/SKILL.md`，包含分类规则与误报识别指南。

## 快速开始

### 从发布包安装

```bash
curl -L https://github.com/DannyAn/secguard-clang/releases/latest/download/secguard-0.8.0.zip -o secguard.zip
unzip secguard.zip

# 安装到所有受支持的 Agent 环境 + CLI 二进制
./install.sh

# 或只安装某一个环境
./install.sh --target opencode       # OpenCode
./install.sh --target opencode-nga   # OpenCode-NGA
./install.sh --target claude-code    # Claude Code
./install.sh --target claude-cac     # Claude CAC
./install.sh --no-binary             # 只装扩展，跳过二进制
./install.sh --verify                # 安装后自检
```

### 从 AI Agent Market 安装平台插件

每次发布还提供 `secguard-clang-plugins-<version>.zip`，内含每个平台的自包含插件（`secguard-clang-opencode`、`secguard-clang-opencode-nga`、`secguard-clang-claude-code`、`secguard-clang-claude-cac`）。把对应插件上传到市场的 extension 发布入口，然后在 Agent TUI 中安装即可。所有平台的命令命名空间都是 `secguard-clang`。完整矩阵见 `release/plugins-README.md`。

### 从源码构建

```bash
git clone https://github.com/DannyAn/secguard-clang.git
cd secguard-clang
./build.sh                 # 构建二进制 → bin/secguard
./build.sh --install       # 安装二进制 → ~/.local/bin
./build.sh --package       # 构建发布包
./deploy.sh all            # 构建并安装 Agent 扩展
```

`./deploy.sh` 支持 `opencode`、`opencode-nga`、`claude-code`、`claude-cac`、`dsh` 或 `all`，并可用 `--no-binary` 跳过二进制构建。

### DeepSeek Harness

```bash
./release/install-dsh.sh
```

然后在 DeepSeek Harness 中选择 **SecGuard Security Audit** preset。

## 使用

在 Agent 里直接用自然语言提问：

```
> 扫描 src/ 目录的安全漏洞
> 重点看 null-deref 和 buffer-overflow 问题
```

也可以用斜杠命令直接驱动 Agent。命名空间在各平台都是 `secguard-clang`，但分隔符不同：
OpenCode 用 `/`，Claude Code / Claude CAC 用 `:`——即 `/secguard-clang/secguard` 与
`/secguard-clang:secguard`：

```text
# 全量扫描——整仓重跑，大仓较慢
/secguard-clang/secguard ./src   # 索引 + 建图 + 检测 + 收敛 + 自动确认 + 候选

# 增量检视——只看变更行，大仓很快
/secguard-clang/pr               # PR/MR diff；base 默认取与 main/master 的 merge-base
/secguard-clang/mr               # /pr 的 GitLab 别名
/secguard-clang/diff HEAD~1      # 任意 git diff；base 默认 HEAD~1

/secguard-clang/metrics          # 扫描性能与收敛指标
```

增量命令跑同一条管线，但只保留「sink 行或源头行落在变更行上、且指纹未在既往 findings 中
出现」的候选——适合检视一个变更集，而不会把历史问题重新翻出来。不在 git 仓库里时它们会直接
报错，而不是悄悄降级成全量扫描。

或直接使用 CLI（很少需要——主要用于 CI 与脚本）：

```bash
secguard scan ./src        # 索引 + 建图 + 检测 + 收敛 + 自动确认 + 候选
secguard diff HEAD~1       # 只检视变更行（base 默认 HEAD~1）
secguard pr                # PR/MR diff（base 取与 main/master 的 merge-base）
secguard report            # 读取已持久化的发现
secguard plan null-deref   # 单类型收敛
secguard types             # 权威漏洞类型 + CWE
secguard status            # 索引状态
secguard metrics           # 扫描性能与收敛指标
secguard schema findings   # 写 SQL 前先看表结构
secguard db "SELECT ..."   # 对 sgre.db 执行只读 SQL
```

`secguard types` / `schema` / `db` 只有 CLI（与 MCP）形态；Agent 侧的斜杠命令只有
`secguard`、`pr`、`mr`、`diff`、`metrics` 五个。

## 输出

扫描结果写入 `.codeagent/secguard-clang/scans/<scan-id>/`：

```
scans/<scan-id>/
├── candidates.sarif              # 候选阶段（未分类线索，level "note"）
├── result.sarif                  # 裁决阶段（仅 confirmed）
├── report.md                     # 裁决阶段报告
├── audit-report.md               # 每类型管线 + AI 分类统计
├── result.xlsx                   # 可行动发现导出
├── candidates/<type>/            # 管线证据，按漏洞类型分组
│   └── 001_allocator_99.md       # 内嵌代码上下文的线索
└── findings/<type>/              # 人工复核面——仅 confirmed 裁决
    └── 001_allocator_99_confirmed.md
```

`findings/` 与 `result.sarif` 只包含 confirmed 结果。dismissed 候选不会生成文件、也不会持久化；分类轨迹保留排除理由以便审计。让 CI 直接指向 `result.sarif`：它不可能包含未分类的线索。

每个裁决文件都是自包含的——位置、证据链、报告行附近的源码、AI 推理与例外检查，以及可直接粘贴的修复建议。用 `--context-lines <n>` 调节内嵌源码窗口，传 `0` 可不内嵌源码。

## 架构

### 4 层数据模型

| 层 | 内容 | 稳定性 | 表 |
|---|---|---|---|
| **1. 程序事实** | 文件、函数、变量、表达式、类型、位置 | 最稳定 | `files`、`functions`、`variables`、`expressions`、`types`、`locations` |
| **2. 语义图** | 调用/数据流/控制流/别名/所有权边 | 稳定 | `graph_nodes`、`graph_edges` |
| **3. 安全证据** | 收敛前的检测器事件 | 中等 | `security_events` |
| **4. 发现** | AI 确认与自动确认的裁决 | 最易变 | `findings` |

### 多平台扩展

```
extension/
├── shared/                      # 单一事实源
│   ├── agent-body.md            # 子代理角色 + 分类契约
│   ├── command-instructions.md  # /secguard 工作流
│   └── skills/                  # 24 个漏洞类型技能
├── opencode/                    # OpenCode 封装 + 9 个 MCP 工具
├── opencode-nga/                # OpenCode-NGA 封装（复用同一套工具）
├── claude-code/                 # Claude Code 封装
├── claude-cac/                  # Claude CAC 封装
└── deepseek-harness/            # DeepSeek Harness Agent preset
```

`shared/` 是权威来源。`release/build-packages.sh` 把它展开到各平台包，`release/check-extension-consistency.py` 负责保证工具注册、Agent 权限和 turn 预算跨平台一致。

## 技术栈

| 组件 | 技术 | 说明 |
|---|---|---|
| 核心引擎 | Go 1.25 | 单一静态二进制，跨平台 |
| 数据库 | SQLite（`modernc.org/sqlite`） | 纯 Go，无 CGo 依赖 |
| 解析器 | Tree-sitter + tree-sitter-c | 增量 C 解析 |
| 交叉编译 | zig（musl/mingw） | 静态 Linux/Windows 二进制 |
| AI 扩展 | TypeScript/Bun | 9 个 OpenCode MCP 工具 |
| Agent 环境 | OpenCode、OpenCode-NGA、Claude Code、Claude CAC、DeepSeek Harness | 共享核心 + 薄封装 |

## 项目结构

```
secguard-clang/
├── sgre/                          # Go 模块（核心引擎）
│   ├── cmd/secguard/              # CLI 入口
│   └── internal/
│       ├── cli/                   # 命令实现
│       ├── db/                    # SQLite schema + CRUD
│       ├── indexer/               # tree-sitter 索引器
│       ├── parser/                # 解析器封装
│       ├── graph/                 # 语义图构建
│       ├── evidence/              # 自注册检测器
│       ├── planner/               # 收敛管线 + 过滤器
│       ├── report/                # SARIF / Markdown / XLSX 报告
│       └── log/                   # 结构化日志
├── extension/                     # 多平台 AI Agent 扩展
├── release/                       # 构建/安装工具
├── examples/c-vuln-benchmark/     # C 漏洞基准
├── docs/                          # 设计文档
├── build.sh                       # 构建入口
└── .github/workflows/             # CI 发布工作流
```

## 测试

```bash
cd sgre
go test ./...                        # 完整测试套件（SQLite + tree-sitter）
go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/   # 无 SQLite 子集
```

`examples/c-vuln-benchmark` 是一套自包含的 C 回归用例，用作检测器与 planner 变更的 CI 门禁。

## 设计原则

1. **按程序事实组织表，而不是按漏洞类型建表。** 避免检测覆盖增长时 schema 爆炸。
2. **技能是查询消费者。** 技能只分类证据，从不建表。
3. **AI 只看到已收敛的证据。** 原始候选不进 Agent 上下文。
4. **CWE 映射单一事实源。** `planner.VulnTypeSpec.CWE` 是权威来源，消费者都从它派生。
5. **dismissed 不持久化。** 复核面保持干净，最终计数来自 audit 汇总，而不是文件列表。

## 相关文档

- [CLAUDE.md](CLAUDE.md) — 架构与工作指南
- [CHANGELOG.md](CHANGELOG.md) — 发布记录
- [docs/output-protocol.md](docs/output-protocol.md) — 输出契约
- [docs/parallelization-design.md](docs/parallelization-design.md) — 并行调度设计
- [examples/c-vuln-benchmark/](examples/c-vuln-benchmark/) — 漏洞基准套件
- [README.md](README.md) — English version

## License

Licensed under the [Apache License 2.0](LICENSE). © An Gang
