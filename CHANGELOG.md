# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。所有显著变更记录于此。

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
