# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。所有显著变更记录于此。

## [0.1.3] - 2026-08-17

安装验证后的缺陷修复（Bugfix release）。

### 修复

- **skill 缺少 YAML frontmatter**：为 `uninit` 与 `resource-leak` 两个 skill 的 `SKILL.md` 补充 YAML frontmatter（`name` / `description` / `license` / `compatibility` / `metadata`）。此前 OpenCode 因缺少 frontmatter 无法识别并加载这两个 skill，导致扫描时 agent 报 `Skill "uninit" not found`；其余 18 个 skill 均已具备 frontmatter。

## [0.1.2] - 2026-08-16

生产环境审计暴露的缺陷修复（Bugfix release）。重点解决扫描输出截断、上下文爆炸、CWE 缺口与检测器归属错误，并修复 Windows/Linux 交叉编译与发布组装流程，使 CI 发布可端到端跑通。

### 修复

- **扫描输出截断**：`secguard_scan` / `secguard_plan` 工具不再透传原始 JSON（曾导致 117KB+ 的工具输出被截断），改为只返回元数据（`scan_id`、`output_dir`、各类型候选计数）；Agent 改从 `report.md` 读取候选详情。
- **上下文爆炸**：重写 `agent-body.md` / `command-instructions.md` 的 Full/Filtered 工作流为按类型分批处理——每批只加载 1 个 skill、读取 ≤5 个源文件、写入 1 种类型的 findings，消除一次性「加载全部 skills + 读取全部源码」的模式。
- **CWE 缺口**：`crypto-misuse` 的 `VulnTypeSpec` 增加 `LegacyCWEs`（`CWE-326`/`CWE-338`），`injection` 保留 `CWE-89` 作为遗留 CWE；`AllCWEs()` 现返回 23 项（20 个规范 CWE + 3 个遗留 CWE），历史 finding 可继续写入。
- **findings 表结构未文档化**：`agent-body.md` 记录 findings 表列名（`file_path`、`line_number`，而非 `file`/`line`），避免 Agent 猜列名导致查询失败。
- **检测器函数归属错误**：`detectUndersizedKey` 按声明行所在函数（`funcLineRange`）归属 undersized-key 事件，此前所有事件都被错误归属到 `funcs[0]`。
- **CWE 单一事实来源**：`VulnTypeSpec` 新增 `CWE` 字段并派生 `AllCWEs()` / `CWEForType()` / `TypeForCWE()`；`db.SupportedFindingCWEs` 在启动时由 `planner.AllCWEs()` 注入，`report` 不再硬编码 CWE→类型映射。
- **跨扫描隔离**：`secguard scan` 的 findings 列表改为按 `scan_id` 过滤（`ListFindingsByScanID`），不再把其它扫描的 findings 混入当前输出。
- **scan_id 校验**：显式 `--output-dir` 的 basename 必须匹配 `YYYY-MM-DD_HHMMSS_xxxx` 格式（防路径穿越 / 任意 scan_id 注入）；`report` 写入 finding 前校验 `scan_id` 存在。
- **`security_events` 查询封堵**：`secguard db` 对该表的禁用改为词边界正则，覆盖 `main.security_events`、字符串字面量与 `pragma_table_info('security_events')` 等变体。

### 构建与 CI

- **zig 0.14.1 下载 URL**：修正 artifact 命名（`zig-linux-x86_64-…` → `zig-x86_64-linux-…`），旧 URL 返回 404 导致 Windows 交叉编译（进而整个发布）失败。
- **Windows 交叉编译环境**：与 `lib.sh build_target` 对齐，补充 `CGO_CFLAGS/CGO_CXXFLAGS`、本地 zig cache、`TMPDIR`、`GOFLAGS`，修复 tree-sitter-c cgo 交叉编译的 `AccessDenied`。
- **`ZIG` 未绑定变量**：`build-packages.sh` 在 `set -u` 下将 `ZIG` 初始化为空，修复 `--assemble-only` 步骤的 `ZIG: unbound variable`。
- **claude-code 源包装文件未被追踪**：`.gitignore` 把 `.claude/` 锚定为根目录 `/.claude/`，并追踪 `extension/claude-code/.claude/` 下的源包装文件，修复 CI checkout 缺失导致的 assemble 失败（`cannot stat .../commands/secguard.md`）。

### 变更

- **发布工具目录重命名**：`extension/dist/` 重命名为顶层 `release/`（构建/安装工具而非分发产物），`dist/` 保持为唯一分发输出目录；移除过时的 `deploy/` 目录，文档路径同步更新。

## [0.1.1] - 2026-08-16

部署验证后的缺陷修复（Bugfix release）。

### 修复

- **`.codeagent` 输出位置**：扫描结果现在解析到启动目录（被扫描项目），而不是 git 仓库根，避免在嵌套项目（如 `examples/c-vuln-benchmark/src`）下审计时把结果写到仓库根。
- **单次扫描单目录**：`secguard_scan` 不再预创建输出目录（改由 Go 二进制创建），并移除遗留的 `secguard_quick_scan` 工具，一次扫描只产生一个 scan 目录。
- **报告表格**：汇总/报告表增加 `Skill` 列、报告头（代码仓绝对路径 + 扫描目录）与简洁的观察项表。
- **`/secguard` 直接执行**：命令 frontmatter 不再声明 `agent:`，避免被包装成 subagent 转发后被压成纯文本，表格直接作为终端输出。
- **agent 模式**：`security-auditor` 由 `subagent` 改为 `all`，可被直接调用，也为后续按 skill 并发调度预留编排能力。
- **安装/卸载清理**：install/uninstall 会清理旧版平铺式安装（`~/.config/opencode` 下的 tools/skills/agents），避免与新扩展目录并存漂移。

## [0.1.0] - 2026-08-15

首个可部署版本（First deployable release）。

### 特性

- **20 种漏洞类型**：null-deref、buffer-overflow、memory-leak、injection、resource-leak、uninit、use-after-free、double-free、format-string、integer-overflow、race-condition、hardcoded-secret、deadlock、crypto-misuse、out-of-bounds、divide-by-zero、unchecked-return、path-traversal、sizeof-misuse、signed-compare。
- **4 层数据模型**（SQLite）：程序事实 → 语义图（调用图 / 数据流 / 控制流）→ 安全证据 → 发现。
- **22 个安全证据检测器**，基于 tree-sitter 的 C 语法解析，自注册于 `registry.go`。
- **漏斗式收敛流水线**：候选从原始线索收敛为去重后的高置信证据包，**无候选数量上限**（AI Agent 分批复核全部去重候选）。
- **跨函数图分析**：null-deref 的「到达空值源」数据流、use-after-free 的「free→use」控制流可达性。
- **多平台 AI Agent 扩展**：OpenCode 与 Claude Code 双平台（shared-core + thin-wrapper），`security-auditor` 子代理负责分类与落库。
- **报告输出**：SARIF 2.1 + Markdown 摘要 + 逐条 finding 详情。
- **基准回归门禁**：`examples/c-vuln-benchmark` 53 用例，TP=26 / FP=0 / TN=27 / FN=0（精度 100%、召回 100%）。

### 已知限制

- 依赖 **CGO**（tree-sitter 运行时与 C 语法解析器为 C 实现），因此无法用 `CGO_ENABLED=0` 纯静态构建；Linux 产物为 zig/musl 静态链接。
- 仅支持 **C**（`.c` / `.h`）；C++/Objective-C 暂未覆盖。
- `memory-leak` / `resource-leak` 仍使用检测器内的路径分析（旧 `BuildCFG`），尚未迁移到新的语句级 CFG（需所有权转移感知）。
- 去重后的候选仍需 AI Agent 分类确认，流水线自身不产出最终 verdict。

### 本次发布前的版本一致性修复

- 统一版本号为 `0.1.0`：`internal/cli.Version` 改为 `var` 以支持 `-ldflags -X` 注入，`VERSION` 文件、构建脚本 `build_target` 均已同步。
- 修正 OpenCode 扩展层硬编码的「15 种类型 / <=30 候选上限」描述，改为以 `secguard types`（Go 二进制）为唯一权威来源。
