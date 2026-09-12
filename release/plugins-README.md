# SecGuard-Clang 插件包

SecGuard 面向 AI Agent Market 的插件发布包。每次发布产出两个 zip：

- `secguard-<version>.zip` —— 统一一键安装包（直接下载跑 `install.sh`）。
- `secguard-clang-plugins-<version>.zip` —— **插件聚合包，内含 4 个逐平台 zip**（一次下载取全部平台）。

## 逐平台插件 zip（上传 Market「extension 发布入口」用）

解压聚合包后得到 4 个逐平台 zip。每个 zip 顶层是插件安装名 `secguard-clang/`（Market 据此
把插件装到 `plugins/` 或 `extensions/` 下），manifest 都在 `secguard-clang/` 内、可直接上传：

| 文件 | 平台 |
|------|------|
| `secguard-clang-opencode-<version>.zip` | OpenCode 官方 |
| `secguard-clang-opencode-nga-<version>.zip` | OpenCode 开源分支（定制版） |
| `secguard-clang-claude-code-<version>.zip` | Claude Code 官方 |
| `secguard-clang-claude-cac-<version>.zip` | Claude Code 开源分支（定制版 CAC） |

每个 zip 自包含：平台原生 plugin 清单（`.cac-plugin/` / `.claude-plugin/` / `package.json`）
+ 22 个 skills + `bin/secguard` 调度 shim + 5 个 OS×架构二进制（darwin/linux/windows ×
amd64/arm64）。定制版（claude-cac / opencode-nga）另带 `codeagent-extension.json`
（CodeAgent 扩展清单）；官方版不带。

**发布流程（以 claude-cac 为例）**：

1. 解压聚合包，取 `secguard-clang-claude-cac-<version>.zip`。
2. 在 AI Agent Market 发布入口选择「extension」类型，上传该 zip。
3. 满足入口校验后发布成功。
4. 目标机器（Linux x86_64 / arm64 均可）进入 AI Agent 的 TUI，用 extension/plugin 命令安装该插件名 + 版本。
5. 重启 TUI，插件被识别后输入命令执行：
   - Claude Code / CAC：`/secguard-clang:secguard`
   - OpenCode：`/secguard-clang/secguard`

## 二进制解析（双路径）

- **OpenCode**：工具自动优先用插件内嵌 `bin/` 二进制，无则回退 PATH 上的 `secguard`。
- **Claude Code / CAC**：`/secguard` 命令通过 `${CLAUDE_PLUGIN_ROOT}/bin` 优先用内嵌二进制；
  agent 内部的 `secguard` Bash 调用走 PATH（市场安装时建议同时把 CLI 装到 PATH，或由企业市场编排 PATH）。

## 校验

- 聚合包内 `manifest.json` 记录每个逐平台 zip 的 sha256。
- `SHA256SUMS` + 各 zip 的 `.sha256`。
- 逐平台 zip 内 `bin/secguard --version` 输出包版本号。
