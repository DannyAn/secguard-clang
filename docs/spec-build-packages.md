# 需求规格说明书：SecGuard 构建打包与发行

| 字段 | 值 |
|------|-----|
| 文档标题 | SecGuard 构建打包与发行需求规格 |
| 文档版本 | v1.2 |
| 创建日期 | 2026-08-11 |
| 修改日期 | 2026-08-11 |
| 状态 | 草案（待评审）——已更新：补充 uninstall.sh 与安装验证 |
| 作者 | spec-requirement-agent |
| 关联项目 | secguard-clang |

---

## 1. 项目概述

### 1.1 背景

SecGuard-Clang 是 AI 增强的 C 语言安全分析器。当前根目录 `build.sh` 仅构建 Go 二进制到 `bin/secguard`，不具备发行打包能力。项目已存在 `release/build-packages.sh` 实现了基础打包，但存在以下缺陷：

- 版本号硬编码为 `0.1.0`，无版本管理机制
- 仅构建当前平台二进制，无跨平台（darwin/linux × amd64/arm64）支持
- 无校验和（sha256）生成
- 未集成到根目录 `build.sh`，开发者需单独运行 `release/build-packages.sh`
- 专用扩展包（opencode/claude-code）内未包含独立 `install.sh`，依赖统一包的安装脚本
- 安装脚本无卸载能力、无幂等性保证、无安装清单记录
- README/安装提示仅列出 4 个 skills，实际有 14 个
- 统一包安装到 `~/.config/opencode/` 与 `~/.claude/`，与 `deploy.sh` 的 `extensions/secguard-clang/`、`skills/secguard-clang/` 路径不一致
- `deploy.sh`、`extension/install.sh`、`release/build-packages.sh`、`release/install.sh` 四个脚本各自重复实现了同一个 `expand_includes()` 函数（约 15 行），改一处须改四处，违反 DRY
- 缺少独立的卸载入口脚本，用户须以 `install.sh --uninstall` 形式卸载，不直观
- 缺少安装后的健康检查/验证能力，无法快速诊断"装了但没装对"的问题

### 1.2 目标

1. **统一发行包**：构建一个 `.zip`，内含 `install.sh` 与 `uninstall.sh`，支持安装到 OpenCode、ClaudeCode 或全部。
2. **OpenCode 专用扩展包**：构建一个可直接被 OpenCode 作为 extension 加载的 `.zip`。
3. **ClaudeCode 专用扩展包**：构建一个可作为 ClaudeCode plugin/extension 安装的 `.zip`。
4. 将打包能力集成到根目录 `build.sh`，保留原有 `--test`/`--install` 行为。
5. 消除 `expand_includes` 等公共函数的重复实现，统一维护于 `release/lib.sh`，同时保证发行包安装脚本自包含可移植。
6. 提供独立的 `uninstall.sh` 卸载入口与 `install.sh --verify` 安装验证能力，便于运维与故障诊断。

### 1.3 利益相关者

| 角色 | 关注点 |
|------|--------|
| 安全工程师 | 一键安装、跨平台二进制、独立卸载入口、安装验证 |
| 平台用户（OpenCode） | extension 可直接加载、无需手动展开模板 |
| 平台用户（ClaudeCode） | plugin 可被发现、权限自动合并 |
| 发行维护者 | 版本管理、校验和、可重复构建、单一函数源、跨版本卸载 |

### 1.4 约束

- CON-1：Go 模块位于 `sgre/`，所有 `go` 命令须在该目录执行。
- CON-2：依赖 CGO（modernc.org/sqlite 实为纯 Go，但 tree-sitter 需 CGO），`CGO_ENABLED=1`。
- CON-3：发行包须同时支持 macOS（darwin）与 Linux，amd64 与 arm64。
- CON-4：扩展源码真实来源为 `extension/shared/`，平台包装使用 `{{include shared/...}}` 指令，打包时须展开。
- CON-5：不得将 `.gocache`、`.gotmp`、`sgre.db`、`.DS_Store` 等临时/缓存文件打入发行包。
- CON-6：命名遵循 kebab-case 目录、snake_case 变量（项目偏好）。
- CON-7：安装脚本须用 bash，`set -euo pipefail`。
- CON-8：发行包内 `install.sh`、`uninstall.sh` 须自包含，不得在运行时 `source` 包外文件（解压路径不可控）。

---

## 2. 功能需求（EARS 格式）

### 2.1 版本管理

- **REQ-VER-01**：**WHEN** 根目录存在 `VERSION` 文件 **THE SYSTEM SHALL** 读取其内容作为版本号（去除首尾空白）。
- **REQ-VER-02**：**WHEN** `VERSION` 文件不存在且项目为 git 仓库 **THE SYSTEM SHALL** 使用 `git describe --tags --always --dirty` 作为版本号。
- **REQ-VER-03**：**WHEN** 上述均不可得 **THE SYSTEM SHALL** 回退到默认版本 `0.0.0-dev`。
- **REQ-VER-04**：**WHEN** 指定 `--version <x.y.z>` 参数 **THE SYSTEM SHALL** 使用该显式版本号并覆盖其它来源。
- **REQ-VER-05**：**WHEN** 版本号确定 **THE SYSTEM SHALL** 将其写入发行包内的 `VERSION` 文件与 `manifest.json`。

### 2.2 跨平台二进制构建

- **REQ-BIN-01**：**WHEN** 执行打包且未指定 `--os`/`--arch` **THE SYSTEM SHALL** 为以下四个目标构建二进制：`darwin/amd64`、`darwin/arm64`、`linux/amd64`、`linux/arm64`。
- **REQ-BIN-02**：**WHEN** 指定 `--os <os>` 或 `--arch <arch>` **THE SYSTEM SHALL** 仅构建匹配的目标。
- **REQ-BIN-03**：**WHEN** 构建每个目标 **THE SYSTEM SHALL** 设置 `GOOS`、`GOARCH`、`CGO_ENABLED=1`，输出命名 `secguard-<os>-<arch>`。
- **REQ-BIN-04**：**WHEN** 跨平台构建因 CGO 交叉编译工具链缺失而失败 **THE SYSTEM SHALL** 记录警告并回退为仅构建本机目标，不中断整体打包。
- **REQ-BIN-05**：**WHEN** 指定 `--test` **THE SYSTEM SHALL** 在构建前运行 `go test ./...`（在 `sgre/` 下），测试失败则中止打包。

### 2.3 统一发行包（master zip）

- **REQ-MASTER-01**：**WHEN** 打包完成 **THE SYSTEM SHALL** 生成 `dist/secguard-<version>.zip`。
- **REQ-MASTER-02**：**THE SYSTEM SHALL** 使统一包内顶层目录为 `secguard-<version>/`，包含：
  - `secguard-<os>-<arch>`（每个目标一个二进制）
  - `install.sh`（统一安装脚本，可执行，自包含）
  - `uninstall.sh`（独立卸载脚本，可执行，自包含）
  - `VERSION`、`manifest.json`、`README.md`、`LICENSE`（若存在）
  - `shared/`（agent-body.md、command-instructions.md、skills/*/SKILL.md，共 14 个 skill）
  - `opencode/`（展开模板后的 extension.json、opencode.json、commands/、agents/、tools/、plugins/）
  - `claude-code/`（.claude-plugin/plugin.json、.claude/、hooks/）
- **REQ-MASTER-03**：**WHEN** 打包 **THE SYSTEM SHALL** 对所有含 `{{include shared/...}}` 的文件执行模板展开，展开后不再保留 `{{include}}` 指令。
- **REQ-MASTER-04**：**THE SYSTEM SHALL** 排除 `.gocache`、`.gotmp`、`*.db`、`.DS_Store`、`__pycache__`、`.git` 等文件。

### 2.4 OpenCode 专用扩展包

- **REQ-OC-01**：**WHEN** 打包完成 **THE SYSTEM SHALL** 生成 `dist/secguard-extension-opencode-<version>.zip`。
- **REQ-OC-02**：**THE SYSTEM SHALL** 使该包根目录（无顶层包裹目录）可直接作为 OpenCode extension 目录内容，包含：
  - `extension.json`、`opencode.json`
  - `commands/secguard.md`（已展开）
  - `agents/security-auditor.md`（已展开）
  - `tools/secguard_*.ts`
  - `plugins/secguard-context.ts`
  - `skills/*/SKILL.md`（14 个）
  - `install.sh`（OpenCode 专用安装脚本，可执行，自包含）
  - `uninstall.sh`（OpenCode 专用卸载脚本，可执行，自包含）
  - `VERSION`、`manifest.json`
- **REQ-OC-03**：**WHEN** OpenCode 加载该 extension **THE SYSTEM SHALL** 保证 `extension.json` 的 `version` 字段与包版本一致。

### 2.5 ClaudeCode 专用扩展包

- **REQ-CC-01**：**WHEN** 打包完成 **THE SYSTEM SHALL** 生成 `dist/secguard-extension-claude-code-<version>.zip`。
- **REQ-CC-02**：**THE SYSTEM SHALL** 使该包根目录可直接作为 ClaudeCode plugin 目录内容，包含：
  - `.claude-plugin/plugin.json`（plugin 元数据，version 字段同步）
  - `commands/secguard.md`（已展开）
  - `agents/security-auditor.md`（已展开）
  - `hooks/hooks.json`
  - `skills/*/SKILL.md`（14 个）
  - `bin/secguard-<os>-<arch>`（多平台二进制，或本机单一二进制）
  - `install.sh`（ClaudeCode 专用安装脚本，可执行，自包含）
  - `uninstall.sh`（ClaudeCode 专用卸载脚本，可执行，自包含）
  - `VERSION`、`manifest.json`
- **REQ-CC-03**：**WHEN** 安装该包 **THE install.sh SHALL** 将权限项合并进用户 `~/.claude/settings.json`（幂等，不重复添加）。

### 2.6 install.sh（统一包安装脚本）

- **REQ-INST-01**：**THE install.sh SHALL** 接受参数 `--target <opencode|claude-code|all>`（默认 `all`）。
- **REQ-INST-02**：**THE install.sh SHALL** 接受参数 `--prefix <path>` 覆盖默认安装根（OpenCode 默认 `~/.config/opencode`，ClaudeCode 默认 `~/.claude`）。
- **REQ-INST-03**：**THE install.sh SHALL** 接受参数 `--bin-dir <path>` 覆盖二进制安装目录（默认 `/usr/local/bin`，无写权限时回退 `~/.local/bin`）。
- **REQ-INST-04**：**THE install.sh SHALL** 接受参数 `--no-binary` 跳过二进制安装。
- **REQ-INST-05**：**THE install.sh SHALL** 接受参数 `--uninstall` 执行卸载（依据安装清单文件删除已安装文件）。
- **REQ-INST-06**：**WHEN** 安装 **THE install.sh SHALL** 选择与当前 `uname -s`/`uname -m` 匹配的二进制；若无匹配 **THE install.sh SHALL** 报错并列出包内可用目标。
- **REQ-INST-07**：**WHEN** 安装 OpenCode **THE install.sh SHALL** 将 extension 安装到 `<prefix>/extensions/secguard-clang/`（与 `deploy.sh` 路径一致）。
- **REQ-INST-08**：**WHEN** 安装 ClaudeCode **THE install.sh SHALL** 将 plugin 安装到 `<prefix>/skills/secguard-clang/`（与 `deploy.sh` 路径一致）。
- **REQ-INST-09**：**WHEN** 安装完成 **THE install.sh SHALL** 在安装根写入 `.secguard-install-manifest`（记录版本、时间、已安装文件列表），供卸载使用。
- **REQ-INST-10**：**WHEN** 重复安装同一版本 **THE install.sh SHALL** 覆盖已有文件且不报错（幂等）。
- **REQ-INST-11**：**WHEN** 安装不同版本 **THE install.sh SHALL** 先卸载旧版本文件（依据 manifest）再安装新版本。
- **REQ-INST-12**：**WHEN** 卸载 **THE install.sh SHALL** 仅删除 manifest 中记录的文件，不删除用户其它文件；删除空目录。
- **REQ-INST-13**：**WHEN** 未指定 `--target` 且为交互终端 **THE install.sh SHALL** 提示用户选择平台。
- **REQ-INST-14**：**THE install.sh SHALL** 自包含运行，不包含任何 `source` 包外文件的语句（展开函数已在打包时内联注入，见 REQ-LIB-03）。
- **REQ-INST-15**：**THE install.sh SHALL** 接受参数 `--verify` 执行安装验证（健康检查），不执行安装或卸载（详见 2.12 节）。

### 2.7 OpenCode/ClaudeCode 专用 install.sh

- **REQ-INST-OC-01**：**THE OpenCode 专用 install.sh SHALL** 仅安装 OpenCode extension（无 `--target` 参数），接受 `--prefix`、`--bin-dir`、`--no-binary`、`--uninstall`、`--verify`，且自包含（不 source 外部 lib.sh）。
- **REQ-INST-CC-01**：**THE ClaudeCode 专用 install.sh SHALL** 仅安装 ClaudeCode plugin，接受相同参数，并执行权限合并（REQ-CC-03），且自包含（不 source 外部 lib.sh）。

### 2.8 build.sh 集成

- **REQ-BUILD-01**：**THE build.sh SHALL** 保留原有 `--test`、`--install`、`--help` 行为不变。
- **REQ-BUILD-02**：**WHEN** 指定 `--package` 或 `--dist` **THE build.sh SHALL** 执行打包流程（调用打包逻辑），产物输出到 `dist/`。
- **REQ-BUILD-03**：**THE build.sh SHALL** 接受 `--version <x.y.z>`、`--os <os>`、`--arch <arch>`、`--target <opencode|claude-code|all|master>` 透传给打包逻辑。
- **REQ-BUILD-04**：**WHEN** 指定 `--package` 且未指定 `--test` **THE build.sh SHALL** 不强制运行测试（但可透传 `--test`）。
- **REQ-BUILD-05**：**WHEN** 打包成功 **THE build.sh SHALL** 在终端打印产物列表（路径、大小、sha256）。

### 2.9 共享函数库（lib.sh）

> 设计原则：**构建侧共享 + 安装侧自包含**。构建脚本在源码树中运行，路径固定，可安全 `source` 公共函数库；发行包安装脚本解压到用户环境独立运行，路径不可控，必须自包含。

- **REQ-LIB-01**：**THE SYSTEM SHALL** 在 `release/lib.sh` 中维护构建侧公共函数，至少包含 `expand_includes()`（模板展开），作为该函数的唯一真实来源（single source of truth）。
- **REQ-LIB-02**：**WHEN** `build-packages.sh` 与 `deploy.sh` 运行 **THE SYSTEM SHALL** 通过 `source release/lib.sh` 加载公共函数，不得各自重复实现 `expand_includes`（消除当前 4 处重复实现）。
- **REQ-LIB-03**：**WHEN** 生成任一 zip 包内 `install.sh` 或 `uninstall.sh` **THE build-packages.sh SHALL** 将 `expand_includes` 等展开函数以源码形式**内联注入**到该脚本文件体中，使该脚本运行时不依赖外部 `lib.sh`。
- **REQ-LIB-04**：**THE 任一 zip 包内 install.sh 或 uninstall.sh SHALL** 不包含 `source .../lib.sh` 或任何引用包外路径的 `source` 语句，确保解压到任意路径均可独立运行（可移植）。
- **REQ-LIB-05**：**WHEN** `lib.sh` 中 `expand_includes` 实现变更 **THE SYSTEM SHALL** 仅修改 `lib.sh` 一处，构建脚本通过 `source` 自动获得新实现，安装/卸载脚本通过打包时内联注入自动获得新实现（无需手工同步多份副本）。

### 2.10 校验和与 manifest

- **REQ-SUM-01**：**WHEN** 每个 zip 生成完成 **THE SYSTEM SHALL** 生成对应 `.sha256` 文件（内容为 `<hash>  <filename>`）。
- **REQ-MAN-01**：**THE manifest.json SHALL** 包含：`version`、`build_date`（UTC ISO8601）、`go_version`、`targets`（os/arch 列表）、`skills`（14 个 skill 名列表）、`files`（包内文件相对路径与 sha256）。

### 2.11 卸载脚本（uninstall.sh）

> 设计原则：**独立入口 + 共享底层逻辑**。`uninstall.sh` 作为与 `install.sh` 平级的独立脚本，便于用户直接调用；其卸载逻辑与 `install.sh --uninstall` 共享同一底层实现（打包时内联注入），避免重复维护。

- **REQ-UNINST-01**：**THE SYSTEM SHALL** 提供独立脚本 `uninstall.sh`，与 `install.sh` 平级置于发行包顶层（统一包）或包根目录（专用包），可执行，自包含（不 source 外部 lib.sh，展开函数由打包时内联注入）。
- **REQ-UNINST-02**：**THE uninstall.sh SHALL** 接受参数 `--target <opencode|claude-code|all>`（默认 `all`），仅卸载指定平台的已安装文件，不影响其它平台。
- **REQ-UNINST-03**：**WHEN** 卸载 **THE uninstall.sh SHALL** 依据安装清单 `.secguard-install-manifest` 定位并删除之前安装的文件；**WHEN** 当前包版本与已安装版本不同 **THE uninstall.sh SHALL** 仍能依据 manifest 卸载历史安装（跨版本卸载）。
- **REQ-UNINST-04**：**WHEN** 删除文件完成 **THE uninstall.sh SHALL** 清理因卸载而产生的空目录，**THE uninstall.sh SHALL NOT** 删除 manifest 未记录的用户其它文件。
- **REQ-UNINST-05**：**THE uninstall.sh SHALL** 接受参数 `--prefix <path>` 与 `--bin-dir <path>` 覆盖默认路径（语义与 install.sh 一致，用于定位 manifest 与二进制）。
- **REQ-UNINST-06**：**WHEN** 卸载前且为交互终端 **THE uninstall.sh SHALL** 展示将删除的文件清单并要求用户确认；**WHEN** 指定 `--yes`（或 `-y`）**THE uninstall.sh SHALL** 跳过确认直接执行。
- **REQ-UNINST-07**：**WHEN** 卸载 ClaudeCode（`--target claude-code` 或 `all`）**THE uninstall.sh SHALL** 从用户 `~/.claude/settings.json` 移除 secguard 相关权限项（幂等，多次执行不报错，不删除用户其它权限项）。
- **REQ-UNINST-08**：**THE uninstall.sh SHALL** 功能等价于 `install.sh --uninstall`（相同参数语义、相同文件删除范围、相同权限清理行为）；二者共享底层卸载逻辑（打包时由 `build-packages.sh` 将同一份卸载函数内联注入到 `install.sh` 与 `uninstall.sh`，避免重复实现）。

### 2.12 安装验证（verify）

> 设计选择：采用 `install.sh --verify` 形式，**不**新增独立 `verify.sh`。理由：(1) 保持入口收敛，避免再增独立脚本扩大维护面与包内文件数；(2) verify 与 install 共享大量上下文（路径解析、平台检测、二进制定位、manifest 读取），复用 install.sh 已有逻辑更自然；(3) 与 `--uninstall` 模式对称，install.sh 既是安装入口也是卸载/验证入口，符合单一主入口直觉；(4) 独立 `uninstall.sh` 已存在是因为卸载是高频独立操作、用户期望直接调用，而验证通常紧跟安装后执行，`install.sh --verify` 已足够便利。

- **REQ-VERIFY-01**：**THE install.sh SHALL** 以 `--verify` 子模式提供安装验证能力（不新增独立 `verify.sh`）；**WHEN** 指定 `--verify` **THE install.sh SHALL** 仅执行验证检测，不执行任何安装或卸载动作。
- **REQ-VERIFY-02**：**WHEN** 验证 **THE install.sh SHALL** 检测 secguard 二进制：(a) 文件存在；(b) 可执行（`-x`）；(c) 执行 `secguard --version` 输出的版本与包版本（`VERSION` 文件或 manifest）匹配。
- **REQ-VERIFY-03**：**WHEN** 验证 **THE install.sh SHALL** 检测 extension/plugin 关键文件齐全，至少包括：`extension.json` 或 `plugin.json`（视平台）、`commands/secguard.md`、`agents/security-auditor.md`、14 个 `skills/*/SKILL.md`。
- **REQ-VERIFY-04**：**WHEN** 验证 **THE install.sh SHALL** 检测平台发现路径正确性：OpenCode 安装路径为 `<prefix>/extensions/secguard-clang/`；ClaudeCode 安装路径为 `<prefix>/skills/secguard-clang/`；路径不存在或关键文件缺失则该项判失败。
- **REQ-VERIFY-05**：**WHEN** 验证 ClaudeCode **THE install.sh SHALL** 检测 `~/.claude/settings.json` 已合并 secguard 权限项（7 项 `Bash(secguard *)` 等存在）。
- **REQ-VERIFY-06**：**WHEN** 验证完成 **THE install.sh SHALL** 输出通过/失败项清单（每项标注 ✓/✗ 与说明），**THE install.sh SHALL** 以退出码反映整体结果：`0` 表示全部通过，非 `0` 表示存在问题（任一项失败）。

---

## 3. 非功能需求

### 3.1 可移植性
- **NFR-PORT-01**：打包脚本须在 macOS（bash 3.2+）与 Linux（bash 4+）上运行。
- **NFR-PORT-02**：安装脚本须在 macOS 与 Linux 上运行，不依赖 `gnu coreutils` 特有选项（避免 `sed -i` 差异，优先 python3 处理文本）。
- **NFR-PORT-03**：zip 包内 `install.sh`、`uninstall.sh` 须可解压到任意路径独立运行，不依赖源码树中 `release/lib.sh` 的存在。

### 3.2 可靠性
- **NFR-REL-01**：打包须可重复构建——相同输入（源码、版本、目标）产生字节相同的 zip（排除时间戳影响，zip 使用固定时间戳或 `zip -X`）。
- **NFR-REL-02**：任一目标二进制构建失败不得损坏其它产物（尽力而为，记录错误继续）。

### 3.3 安全性
- **NFR-SEC-01**：发行包不得包含密钥、`.env`、`credentials.json`、`sgre.db`、个人配置。
- **NFR-SEC-02**：安装脚本不得 `curl`/`wget` 远程内容，仅安装包内文件。
- **NFR-SEC-03**：权限合并须保留用户已有 `deny` 列表，不覆盖整个 settings.json。

### 3.4 性能
- **NFR-PERF-01**：打包（含 4 目标二进制构建 + 3 个 zip）须在 5 分钟内完成（典型开发机）。

### 3.5 可维护性
- **NFR-MAINT-01**（构建侧共享）：`release/lib.sh` 为公共函数（`expand_includes` 等）的唯一真实来源；`build-packages.sh` 与 `deploy.sh` 在源码树中运行，路径固定，**须通过 `source release/lib.sh` 复用**，不得重复实现（DRY，消除当前 4 个脚本各自重复 `expand_includes` 的问题）。
- **NFR-MAINT-01a**（安装侧自包含）：zip 包内 `install.sh`、`uninstall.sh` 解压到用户环境独立运行，路径不可控，**不得 `source` 外部 `lib.sh`**；打包时由 `build-packages.sh` 将展开函数**内联注入**到生成的脚本中，使其运行时自包含、无外部依赖、可移植。
- **NFR-MAINT-02**：新增 skill 须自动被打包包含（glob `skills/*/SKILL.md`），无需修改打包脚本。

---

## 4. 接口需求

### 4.1 build.sh CLI

```
./build.sh [--test] [--install] [--package] [--version <v>] [--os <os>] [--arch <arch>] [--target <t>] [--help]
```

| 参数 | 说明 |
|------|------|
| `--test` | 构建前运行测试 |
| `--install` | 安装二进制到 `~/.local/bin` |
| `--package` | 执行发行打包 |
| `--version` | 显式版本号 |
| `--os` | 限定目标 OS（darwin/linux） |
| `--arch` | 限定目标架构（amd64/arm64） |
| `--target` | 限定包类型（master/opencode/claude-code/all，默认 all） |

### 4.2 install.sh CLI（统一包）

```
./install.sh [--target <opencode|claude-code|all>] [--prefix <path>] [--bin-dir <path>] [--no-binary] [--uninstall] [--verify] [--yes] [--help]
```

| 参数 | 说明 |
|------|------|
| `--target` | 安装/卸载/验证目标平台（默认 all） |
| `--prefix` | 覆盖默认安装根 |
| `--bin-dir` | 覆盖二进制安装目录 |
| `--no-binary` | 跳过二进制安装 |
| `--uninstall` | 执行卸载 |
| `--verify` | 执行安装验证（健康检查），不安装不卸载 |
| `--yes`/`-y` | 跳过交互确认（卸载时） |

### 4.3 uninstall.sh CLI（统一包与专用包）

```
./uninstall.sh [--target <opencode|claude-code|all>] [--prefix <path>] [--bin-dir <path>] [--yes] [--help]
```

| 参数 | 说明 |
|------|------|
| `--target` | 卸载目标平台（默认 all），仅删除指定平台文件 |
| `--prefix` | 覆盖默认安装根（用于定位 manifest） |
| `--bin-dir` | 覆盖二进制目录（用于定位已安装二进制） |
| `--yes`/`-y` | 跳过删除确认 |

> 专用包内 `uninstall.sh` 无 `--target` 参数（仅卸载该专用平台），其余参数相同。

### 4.4 zip 包结构

**统一包** `secguard-<version>.zip`：
```
secguard-<version>/
  install.sh          # 自包含，展开函数已内联注入
  uninstall.sh        # 自包含，独立卸载入口，卸载逻辑内联注入
  VERSION
  manifest.json
  README.md
  LICENSE
  secguard-darwin-amd64
  secguard-darwin-arm64
  secguard-linux-amd64
  secguard-linux-arm64
  shared/
    agent-body.md
    command-instructions.md
    skills/<14 skills>/SKILL.md
  opencode/
    extension.json
    opencode.json
    commands/secguard.md
    agents/security-auditor.md
    tools/secguard_*.ts
    plugins/secguard-context.ts
  claude-code/
    .claude-plugin/plugin.json
    .claude/
      settings.json
      commands/secguard.md
      agents/security-auditor.md
    hooks/hooks.json
```

> 注：`release/lib.sh` **不打入**任何 zip 包，仅存在于源码树供构建脚本 `source`。

**OpenCode 专用包** `secguard-extension-opencode-<version>.zip`（根目录即 extension）：
```
extension.json
opencode.json
install.sh            # 自包含，展开函数已内联注入
uninstall.sh          # 自包含，独立卸载入口
VERSION
manifest.json
commands/secguard.md
agents/security-auditor.md
tools/secguard_*.ts
plugins/secguard-context.ts
skills/<14 skills>/SKILL.md
```

**ClaudeCode 专用包** `secguard-extension-claude-code-<version>.zip`（根目录即 plugin）：
```
.claude-plugin/plugin.json
install.sh            # 自包含，展开函数已内联注入
uninstall.sh          # 自包含，独立卸载入口
VERSION
manifest.json
commands/secguard.md
agents/security-auditor.md
hooks/hooks.json
skills/<14 skills>/SKILL.md
bin/secguard-<os>-<arch>
```

---

## 5. 数据需求

- **DATA-01**：`manifest.json` schema 见 REQ-MAN-01。
- **DATA-02**：`.secguard-install-manifest` 为 JSON，含 `version`、`install_date`、`target`、`files`（绝对路径列表）、`bin_path`。
- **DATA-03**：`extension.json` 的 `version` 字段须与包版本同步（打包时覆写）。
- **DATA-04**：`.claude-plugin/plugin.json` 的 `version` 字段须与包版本同步。

---

## 6. 验收标准

| ID | 验收标准 |
|----|---------|
| AC-01 | 执行 `./build.sh --package` 后 `dist/` 存在 3 个 zip + 3 个 sha256 文件 |
| AC-02 | 统一包解压后 `install.sh --target all` 在干净环境成功安装，`/secguard` 命令可用 |
| AC-03 | 统一包 `install.sh --uninstall` 删除所有已安装文件，`/secguard` 不再可用 |
| AC-04 | 重复执行 `install.sh --target all` 不产生错误且文件不变（幂等） |
| AC-05 | OpenCode 专用包解压后目录结构可被 OpenCode 直接作为 extension 加载 |
| AC-06 | ClaudeCode 专用包解压后目录结构可被 ClaudeCode 作为 plugin 发现 |
| AC-07 | 包含全部 14 个 skills（非仅 4 个） |
| AC-08 | `manifest.json` 中 `version` 与 zip 文件名版本一致 |
| AC-09 | `.sha256` 文件校验通过：`shasum -c secguard-*.sha256` |
| AC-10 | 包内无 `.gocache`、`.gotmp`、`*.db`、`.DS_Store` |
| AC-11 | `./build.sh`（无 `--package`）行为与改造前完全一致（向后兼容） |
| AC-12 | 在 macOS arm64 上安装统一包，自动选择 `secguard-darwin-arm64` 二进制 |
| AC-13 | 安装路径与 `deploy.sh` 一致（`extensions/secguard-clang/`、`skills/secguard-clang/`） |
| AC-14 | ClaudeCode 安装后 `~/.claude/settings.json` 含 7 项 secguard 权限，重复安装不重复添加 |
| AC-15 | `release/lib.sh` 存在且定义 `expand_includes`；`build-packages.sh` 与 `deploy.sh` 均通过 `source` 引用，无重复实现 |
| AC-16 | 任一 zip 包内 `install.sh` 不含 `source .../lib.sh` 语句，解压到任意临时目录可独立运行 |
| AC-17 | 修改 `lib.sh` 中 `expand_includes` 实现后，重新打包生成的 `install.sh` 自动包含新实现，无需手工同步 |
| AC-18 | 统一包与各专用包内均存在可执行的 `uninstall.sh`；直接执行 `./uninstall.sh` 可完成卸载，效果等价于 `install.sh --uninstall` |
| AC-19 | 安装 v1.0 后安装 v1.1，再执行 `uninstall.sh --target claude-code`，仅删除 ClaudeCode 平台文件，OpenCode 文件不受影响；且依据 v1.1 的 manifest 能卸载 v1.0 残留文件（跨版本卸载） |
| AC-20 | 执行 `uninstall.sh` 前展示将删除的文件清单；加 `--yes` 跳过确认；卸载后清理空目录且不删除用户其它文件 |
| AC-21 | 安装成功后执行 `install.sh --verify`，输出全部项 ✓ 且退出码为 0；人为删除一个 skill 后再执行 `--verify`，对应项 ✗ 且退出码非 0 |
| AC-22 | `install.sh --verify` 检测项覆盖：二进制存在/可执行/版本匹配、extension/plugin 关键文件齐全（含 14 skills）、平台发现路径正确、ClaudeCode 权限已合并；每项独立标注通过/失败 |

---

## 7. 现有资产与改造范围

| 资产 | 处置 |
|------|------|
| `build.sh` | 扩展：新增 `--package` 等参数，调用打包逻辑 |
| `release/build-packages.sh` | 重构为打包核心，修复版本/跨平台/校验和/skills 列表/路径一致性；`source lib.sh` 复用公共函数；打包时将展开函数与卸载函数内联注入各 `install.sh` 与 `uninstall.sh` |
| `release/install.sh` | 重构：新增 `--target`/`--prefix`/`--uninstall`/`--verify`、manifest、幂等、路径对齐 deploy.sh；自包含（展开函数与卸载函数由打包时内联注入，不 source lib.sh） |
| `release/uninstall.sh` | **新增**：独立卸载脚本，与 install.sh 平级；接受 `--target`/`--prefix`/`--bin-dir`/`--yes`；依据 manifest 卸载（支持跨版本）；卸载 ClaudeCode 时移除 settings.json 权限项；自包含（卸载逻辑由打包时内联注入，不 source lib.sh）；功能等价于 `install.sh --uninstall`，共享同一份底层卸载函数 |
| `release/install-opencode.sh` | 重构：专用安装，对齐路径，自包含；新增 `--verify` |
| `release/install-claude-code.sh` | 重构：专用安装，权限合并，对齐路径，自包含；新增 `--verify` |
| `release/uninstall-opencode.sh` | **新增**：OpenCode 专用卸载脚本，自包含 |
| `release/uninstall-claude-code.sh` | **新增**：ClaudeCode 专用卸载脚本，含权限移除，自包含 |
| `release/lib.sh` | **新增**：构建侧共享函数库，含 `expand_includes` 等公共函数与卸载底层函数（单一真实来源）。**仅**被源码树中运行的 `build-packages.sh`、`deploy.sh` 通过 `source` 复用；**不打入任何 zip 包**；zip 内 `install.sh`/`uninstall.sh` 不 source 它，所需函数在打包时由 `build-packages.sh` 内联注入 |
| `deploy.sh` | 改为 `source release/lib.sh` 复用 `expand_includes`（消除重复实现）；其余开发模式部署行为不变，与发行包安装并存 |
| `extension/install.sh` | 已删除：其重复的 `expand_includes` 实现移除，统一由 `lib.sh` 提供 |
| `VERSION` | 新增（根目录）：版本号来源 |

---

## 8. 风险与假设

- **假设-1**：构建机已安装 Go 1.25+、python3、zip。
- **假设-2**：跨平台 CGO 交叉编译可能需要对应 C 工具链；缺失时回退本机构建（REQ-BIN-04）。
- **假设-3**：`lib.sh` 仅在源码树中被 `source`，其路径相对于仓库根固定为 `release/lib.sh`，构建脚本可安全引用。
- **风险-1**：macOS 自带 `zip` 与 Linux `zip` 时间戳处理差异，可能影响可重复构建（NFR-REL-01），需用 `zip -X` 或固定时间。
- **风险-2**：ClaudeCode plugin 加载机制可能变化，须以 `deploy.sh` 当前路径为准。
- **风险-3**：内联注入展开函数会增大 `install.sh`/`uninstall.sh` 体积（约 15 行），须保证注入位置与脚本其余逻辑无变量名冲突（建议注入函数加 `sg_` 前缀，如 `sg_expand_includes`）。
- **风险-4**：跨版本卸载依赖 manifest 完整性；若用户手工删除过 manifest 或 manifest 损坏，`uninstall.sh` 须能给出明确提示并回退为按约定路径启发式清理（REQ-UNINST-03 须处理 manifest 缺失降级）。
- **风险-5**：`install.sh --verify` 检测二进制版本须执行 `secguard --version`，若二进制存在但执行失败（如动态库缺失），须判为失败并给出具体错误而非整体崩溃。
