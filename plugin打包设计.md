# SecGuard 插件打包设计方案（完善稿）

> 状态：待评审。本文是对 `plugin打包设计.md` 草稿的完善，把"粗糙方案"收敛成一份可执行、可评审的设计。
> 阅读顺序：先看 §0 结论，再按 §3 决策逐条确认；§9 是实施计划，确认设计后才动手。

---

## 0. 结论速览（TL;DR）

1. **采用"方案二改良"**：保留现有 `secguard-<version>.zip`（一键安装包，直装用），**新增**一套独立的「插件包」产物，专门服务于 AI Agent Market 远程安装。
2. **插件按"平台"打包，不按"平台 × 架构"拆分**：产 4 个插件目录（opencode / opencode-nga / claude-code / claude-cac），每个目录内嵌 **全 5 架构二进制** + 一个 `bin/secguard` 启动 shim。
3. **二进制"统一命名 + 区分架构 + 双路径可调用"**：靠 `bin/secguard`（shim，统一名）+ `bin/secguard-<os>-<arch>[.exe]`（区分架构）+ 「先内嵌、后 PATH」的解析顺序一次性解决草稿里标记的"最大风险"。
4. **主产物 = 逐平台 zip**（manifest 在 zip 根，可直接上传 Market「extension 发布入口」），**全部内嵌进一个聚合包** `secguard-clang-plugins-<version>.zip`（一次下载取 4 平台）；**发布页只挂 2 个 zip**（统一包 + 聚合包），避免逐平台 zip 铺满下载页。

---

## 1. 背景与目标

SecGuard 目前已有 4 个 AI Agent 平台的扩展（`extension/{opencode,opencode-nga,claude-code,claude-cac}/`）和一个统一安装包 `secguard-<version>.zip`。草稿想解决的问题是：

- 把扩展打成**可被各 AI Agent Market 远程安装**的插件包（而不是只能下载统一包后跑 `install.sh`）。
- 明确打包产物形态（一个 zip 还是多个 zip）。
- 解决插件内二进制的**命名与调用**问题（Market 装到缓存目录、非 Market 装到 PATH，两条路径都要能调通）。

目标（本设计要达成）：

| 编号 | 目标 |
|------|------|
| G1 | 用户通过 AI Agent 的 plugin/extension 命令安装后，`/secguard` 立即可用，无需再手动装二进制。 |
| G2 | 用户直接下载统一包跑 `install.sh` 后，同样可用（两条安装路径互不打架）。 |
| G3 | 插件包可发布到各平台 Market，也可转存到企业内部 Market / 断网环境离线安装。 |
| G4 | 二进制在插件内命名统一（`bin/secguard`），同时能按 os/arch 选对二进制。 |
| G5 | 产物、版本号、skills 数量与现有发布流程一致，可重复构建，有校验和。 |

---

## 2. 现状梳理（我们已有什么）

**统一安装包** `dist/secguard-<version>.zip`（`release/build-packages.sh` 产出，当前 v0.6.1）：

```
secguard-<version>/
  secguard-darwin-amd64 / -arm64 / linux-amd64 / linux-arm64 / windows-amd64.exe
  shared/            # agent-body.md + command-instructions.md + skills/<22>
  opencode/          # package.json + index.ts + commands/ + agents/ + tools/
  opencode-nga/      # codeagent-extension.json + opencode.json + ... + plugins/
  claude-code/       # .claude-plugin/plugin.json + .claude/ + hooks/
  claude-cac/        # .cac-plugin/plugin.json + .cac/ + hooks/
  install.sh / uninstall.sh   # 自包含，跑 install.sh 装到对应平台目录 + 二进制装到 PATH
  VERSION / manifest.json / README.md / LICENSE
```

**各平台插件清单（manifest）**：

| 平台 | manifest | 安装到 | 备注 |
|------|----------|--------|------|
| opencode | `package.json`（npm 插件）+ `index.ts` | `~/.config/opencode/plugins/secguard-clang/` | TS tools 内 `findSecguard` 已支持「内嵌→PATH」 |
| opencode-nga | `codeagent-extension.json` + `.codeagent-extension-install.json` | `~/.config/opencode/extensions/secguard-clang/` | 开源分支，manifest 改名 |
| claude-code | `.claude-plugin/plugin.json` | `~/.claude/plugins/`（cache + marketplace 注册） | 官方插件 |
| claude-cac | `.cac-plugin/plugin.json` | `~/.cac/plugins/cache/.../` | 开源分支，另需 marketplace.json 注册 |

**二进制矩阵**：`darwin/amd64`、`darwin/arm64`、`linux/amd64`、`linux/arm64`、`windows/amd64`（5 个目标，`build-packages.sh` 已构建）。

**skills**：当前 22 个（`extension/shared/skills/*/`，打包脚本 glob 自动发现）。

**结论**：扩展内容和 5 架构二进制都已在统一包里"齐全"，缺的只是"按平台切开、内嵌二进制、接上 Market 目录规范"这一步。

---

## 3. 行业调研结论（业界怎么做的）

来源（要点）：
- Claude Code 官方插件市场：[plugin-marketplaces](https://code.claude.com/docs/en/plugin-marketplaces)（[中文](https://code.claude.com/docs/zh-CN/plugin-marketplaces)）——市场是**一个 git 仓库里的 `marketplace.json` 目录**，插件是目录，安装后**复制到缓存目录**（自包含，不能引用 `../`）。
- Claude Code 插件里引用自身文件用 `${CLAUDE_PLUGIN_ROOT}`（hooks / mcp / lsp 通用，二进制同理）。
- 多 harness 打包实践（[wshobson/agents authoring](https://raw.githubusercontent.com/wshobson/agents/main/docs/authoring.md)、[skill-packager-skill](https://github.com/yaniv-golan/skill-packager-skill)）：市场/注册表是"生成并提交的目录"，插件目录自包含，按平台产出各自 manifest。
- VS Code 生态（AI Agent Market 的原型）：原生模块按平台拆 `.vsix`（`*-darwin-arm64` / `*-linux-x64` / `*-win32-x64`），CLI 与扩展分开发布。

**可直接套用的三条行业惯例**：

1. **市场 = git 仓库 + `marketplace.json` 目录**；插件 = 目录，安装即复制到缓存 → 插件必须**自包含**（二进制在插件目录内，用 `${CLAUDE_PLUGIN_ROOT}` 引用）。
2. **CLI 与插件分开发布**：命令行工具一个包、插件另一个包（对应草稿"方案二"的直觉）。
3. **统一入口 + 平台变体**：对外暴露一个稳定入口（如 `bin/secguard`），内部按 os/arch 放置变体，由 shim/解析器选型。

---

## 4. 关键决策（逐条，含推荐与理由）

### D1 — 单一包 vs 双包

| 方案 | 描述 | 结论 |
|------|------|------|
| 方案一 | 只保留一个 `secguard-<version>.zip`，插件塞进统一包 | ❌ 不推荐 |
| 方案二（改良，**推荐**） | `secguard-<version>.zip`（直装）+ `secguard-clang-plugins-<version>.zip`（Market）并存 | ✅ |

**理由**：两类消费者的诉求不同——直装用户要"一条 `install.sh` 全搞定"（含 PATH 二进制、多平台全装）；Market 用户要"一个可被 plugin/extension 命令识别的自包含目录"。混在一个包里会让 Market 无法识别（它认 manifest 目录，不认 `install.sh`），也让统一包徒增体积。业界（VS Code / Claude Code）也是 CLI 与插件分开发布。

**保留统一包不变**（不破坏现有 `install.sh` 用户），**新增**插件包，是零风险增量。

### D2 — 插件包粒度：按"平台"还是按"平台 × 架构"

| 方案 | 产物数 | 单个大小 | 结论 |
|------|--------|----------|------|
| A（**推荐**）按平台，内嵌全 5 架构 | 4 个目录 | ~50MB/目录 | ✅ |
| B 按"平台 × 架构"（草稿的 8 个 zip） | 4×5 = 20 个 | ~10MB/个 | ⚠️ 仅当体积敏感时 |

**理由**：Market 的目录（`marketplace.json` 的 `plugins[].name`）**没有 os/arch 维度**——它按"插件名"安装，装完由宿主把目录复制到缓存。若拆成 20 个"平台×架构"，Market 无法自动选型，用户得自己挑 os/arch，且 20 个产物维护成本高、发布 assets 爆炸。按平台打包、内嵌全架构二进制，Market 装完即自包含可用，符合 Claude Code 插件 `${CLAUDE_PLUGIN_ROOT}` 自包含惯例。

草稿里"8 个插件 = 4 平台 × 2 linux 架构"是简写，正确结论是：**4 个平台 × 全 5 架构**（见 D4）。

### D3 — 二进制命名与解析（草稿标记的"最大风险"，核心机制）

需求拆成三条：① 统一命名（commands/skills 调 `secguard` 一个名）；② 区分架构（选对二进制）；③ 双路径（Market 缓存目录 / 非 Market 的 PATH）。

**机制（三件套）**：

1. `bin/secguard` —— POSIX sh 启动 shim，**统一入口名**，内容检测 os/arch 后 `exec` 对应二进制。
2. `bin/secguard-<os>-<arch>[.exe]` —— 5 个架构变体，**区分架构**。
3. **解析顺序 = 先内嵌、后 PATH**：
   - 各平台调用 `secguard` 前，把插件根 `bin/` 前置到 `PATH`（Claude Code/CAC 用 `${CLAUDE_PLUGIN_ROOT}`），或由 TS 工具 `findSecguard` 优先找 `<pluginDir>/bin/secguard`（OpenCode 已具备，补一个候选即可）。
   - Market 安装 → 内嵌 `bin/secguard` 命中；非 Market 安装 → 内嵌不存在，回退 PATH 上的 `secguard`。

**为什么用 shim 而不是"装一个固定名二进制"**：Market 安装是宿主把插件目录复制进缓存，**不跑我们的脚本**，所以插件必须"出厂即自带一个可用的 `bin/secguard`"。shim 是唯一能在不区分 os/arch 的单一文件名下、跨平台自动选型的可移植方案。

> **明确语义：`bin/secguard` 不是任何架构的二进制本体，而是调度 shim；没有"默认架构"这一说。** 5 个架构二进制始终以 `secguard-<os>-<arch>[.exe]` 命名并列存在，`bin/secguard` 只在运行时按 `uname` 选型 `exec`。**严禁**把某个架构的二进制直接改名为 `bin/secguard` 塞进去——那会让 Market 装到其它 os/arch 时跑错或直接失败。

shim 参考实现（构建时从 `release/` 模板注入，见 §9）：

```sh
#!/bin/sh
# bin/secguard — 统一入口，按 os/arch 选型
PLUGIN_BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "$(uname -s)" in
  Darwin) OS=darwin ;; Linux) OS=linux ;;
  MINGW*|MSYS*|CYGWIN*) OS=windows ;;
  *) OS=$(uname -s | tr 'A-Z' 'a-z') ;;
esac
case "$(uname -m)" in
  x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH=$(uname -m) ;;
esac
BIN="$PLUGIN_BIN_DIR/secguard-${OS}-${ARCH}"
[ "$OS" = "windows" ] && BIN="$PLUGIN_BIN_DIR/secguard-${OS}-${ARCH}.exe"
exec "$BIN" "$@"
```

Windows 另配 `bin/secguard.cmd`：

```cmd
@echo off
setlocal
"%\~dp0secguard-windows-amd64.exe" %*
```

（OpenCode 的 TS tools 不依赖 shim，直接用 `findSecguard` 选 `bin/secguard-<os>-<arch>`，只是**为求一致**也允许统一走 shim；实现时二者取一即可，行为等价。）

### D4 — 平台与架构覆盖

草稿只列了 linux（amd64/arm64）。**应覆盖全 5 架构**（darwin/amd64、darwin/arm64、linux/amd64、linux/arm64、windows/amd64），与统一包/发布矩阵一致；否则插件包在 macOS/Windows 上装不了，等于回归。

> dsh（deepseek-harness）走的是 `~/.dsh/.agent-presets/` 的 agent preset 机制（`install-dsh.sh`），不是 plugin Market，**不在本设计范围内**；若后续要上 DSH 市场再单独设计。

### D5 — 命名与版本规范

> **核心原则：两层身份解耦。** 用户在乎的「TUI namespace/command」由 manifest `name` 决定；市场里"互不撞名"由**目录名 + 市场 entry 名**决定。二者独立，不要混为一谈。

**第一层：TUI namespace + command（用户输入，全平台一致，绝不带平台后缀）**

- manifest `name` **保持 `secguard-clang` 不变**（`.claude-plugin/plugin.json`、`.cac-plugin/plugin.json`、`codeagent-extension.json`、`package.json` 的 `name`；OpenCode 的 `index.ts` 里 `id: "secguard-clang"` + 命令前缀 `secguard-clang/${name}` 也照旧）。
- 结果：所有 AI Agent 里 namespace 都是 `secguard-clang`、命令都是 `secguard`，仅分隔符随平台原生语法：
  - OpenCode / OpenCode-NGA：`/secguard-clang/secguard`（OpenCode 用 `/` 分隔）
  - Claude Code / Claude-CAC：`/secguard-clang:secguard`（Claude Code 用 `:` 分隔）
- **绝不**把 `-opencode`/`-claude-code` 后缀写进 manifest `name`——否则 TUI 会变成 `/secguard-clang-<platform>:secguard`，正是要避免的。

**第二层：市场/打包身份（互不撞名）**

- **目录名 = 市场 entry 名 = `secguard-clang-<platform>`**，platform ∈ `opencode | opencode-nga | claude-code | claude-cac`（kebab-case，修正草稿的 `claudecac`/`claudecode`，与 `extension/` 目录名一一对应）。
- 这一层只用于：zip 内目录布局、`marketplace.json` 的 `plugins[].name`、安装 key（`secguard-clang-<platform>@<marketplace>`）。不进入 manifest `name`，不影响 TUI。

**版本与文件名**

- **版本**：跟随项目 `VERSION`（当前 0.6.1），插件包版本 = 统一包版本，**不引入独立版本号**（草稿的 `1.0` 弃用）。所有 manifest 的 `version` 字段打包时覆写一致。
- **zip 文件名**：`secguard-clang-plugins-<version>.zip`（聚合包）。

### D6 — 发布载体：marketplace 目录 vs zip

| 载体 | 用途 | 结论 |
|------|------|------|
| git 仓库 + `marketplace.json` | 各平台 Market 远程安装（首选） | ✅ |
| `secguard-clang-plugins-<version>.zip` | 转存到企业内部 Market / 断网 | ✅ 并存 |

两者内容相同（4 个插件目录 + marketplace 目录），zip 只是把 git 仓库内容打包，方便"转存"。

---

## 5. 目标产物清单

| 产物 | 说明 | 新增/保留 |
|------|------|-----------|
| `dist/secguard-<version>.zip` | 统一一键安装包 | **保留不变** |
| `dist/secguard-clang-plugins-<version>.zip` | **插件聚合包**：内含 4 个逐平台 zip + README + manifest.json（记录各 zip sha256） | **新增** |
| `dist/SHA256SUMS` + 各 zip `.sha256` | 校验和（统一包 + 聚合包，共 2 个 zip） | 扩展现有 |

> **发布页只挂 2 个 zip**（统一包 + 聚合包），避免逐平台 zip 铺满下载页影响体验；逐平台 zip 内嵌在聚合包里，用户解压后挑对应平台上传 Market。

聚合 zip 解压后：

```
secguard-clang-plugins-<version>/
  secguard-clang-opencode-<version>.zip       # 逐平台 zip ×4
  secguard-clang-opencode-nga-<version>.zip
  secguard-clang-claude-code-<version>.zip
  secguard-clang-claude-cac-<version>.zip
  manifest.json                         # 版本 + 各逐平台 zip 的 sha256
  README.md                             # 插件包专用说明（各平台安装方式）
  VERSION / LICENSE
```

逐平台 zip 内部（以 claude-cac 为例，zip 顶层是插件安装名 `secguard-clang/`）：

```
secguard-clang-claude-cac-<version>.zip
  secguard-clang/                        # 插件安装名 —— Market 据此装到 plugins/ 或 extensions/
    codeagent-extension.json             # CodeAgent 扩展清单（定制版 Market「extension 入口」校验）
    .cac-plugin/plugin.json              # 平台原生 plugin 清单
    commands/  agents/  hooks/hooks.json
    skills/<22>/SKILL.md
    bin/secguard + secguard-<os>-<arch>[.exe]  (5 架构)
    VERSION
```

---

## 6. 各平台插件目录结构（逐平台）

> 共同点：`bin/` 内 5 架构二进制 + shim；skills 已展开（无 `shared/` 包裹）；`{{include}}` 已展开。

**secguard-clang-opencode/**（npm 插件）：

```
package.json                  # version 覆写
index.ts
commands/{secguard,diff,pr,mr,metrics}.md   # 已展开
agents/security-auditor.md                   # 已展开
tools/secguard_*.ts
skills/<22>/SKILL.md
bin/secguard + secguard-<os>-<arch>[.exe]
```

**secguard-clang-opencode-nga/**：

```
codeagent-extension.json       # version 覆写
.codeagent-extension-install.json   # source 在安装时替换为实际目录
opencode.json
package.json                   # version 覆写
index.ts
plugins/secguard-context.ts
commands/...  agents/security-auditor.md  tools/secguard_*.ts
skills/<22>/SKILL.md
bin/...
```

**secguard-clang-claude-code/**：

```
.claude-plugin/plugin.json     # version 覆写
commands/{secguard,diff,pr,mr,metrics}.md
agents/security-auditor.md
hooks/hooks.json
skills/<22>/SKILL.md
bin/...
```

**secguard-clang-claude-cac/**：

```
.cac-plugin/plugin.json        # version 覆写
codeagent-extension.json       # CodeAgent 扩展清单（定制版 Market「extension 入口」校验）
commands/...  agents/security-auditor.md  hooks/hooks.json
skills/<22>/SKILL.md
bin/...
```

---

## 7. 二进制解析在各平台的落地（"双路径可调用"）

| 平台 | 调用点 | 现有 | 需改 |
|------|--------|------|------|
| opencode / opencode-nga | TS tools 的 `findSecguard`（`tools/*.ts`） | 已支持「`<worktree>/.opencode/bin/secguard` → PATH」 | 候选列表**新增 `<pluginDir>/bin/secguard`**（`pluginDir` 已在 `index.ts` 算好） |
| claude-code / claude-cac | 命令 `/secguard` 的 `!` shell 注入 | `!secguard status ...`（依赖 PATH） | 改为 `!PATH="${CLAUDE_PLUGIN_ROOT:+${CLAUDE_PLUGIN_ROOT}/bin:}${PATH}" secguard status ...` |
| claude-code / claude-cac | hooks.json（当前只 `echo`，不调二进制） | — | 若未来 hook 要跑 secguard，同用 `${CLAUDE_PLUGIN_ROOT}/bin/secguard` |

**统一规则**：Market 安装 → `${CLAUDE_PLUGIN_ROOT}`/`<pluginDir>` 有值，内嵌 `bin/secguard` 命中；非 Market（PATH 安装）→ 变量为空，回退 `secguard`（PATH）。`${VAR:+...}` 的防御写法保证变量未设时前缀为空、不污染 PATH。

---

## 8. Market 发布约定（Web「extension 发布入口」）

> 以用户实际流程为准：AI Agent Market 的「extension 发布入口」接收**单个逐平台 zip**，校验 zip 根里的清单文件，通过后发布；目标机器用 extension/plugin 命令按「插件名 + 版本」远程安装。**不引入 marketplace.json**（那是 git 市场目录 schema，当前无应用场合）。

- 上传物 = 聚合包解压出的逐平台 zip（`secguard-clang-<platform>-<version>.zip`），zip 根即插件根，清单在根：
  - claude-cac：`.cac-plugin/plugin.json` + `codeagent-extension.json`
  - claude-code：`.claude-plugin/plugin.json`（官方，不带 codeagent-extension.json）
  - opencode-nga：`codeagent-extension.json`（+ `package.json`）
  - opencode：`package.json`
- 各平台安装命令不同（`/plugin install`、`opencode plugin add` 等），但**插件目录结构一致**，本设计产出的是"目录内容"，与安装命令解耦。

---

## 9. 打包流程改动

在 `release/build-packages.sh` 内新增一个 `build_plugins` 阶段（复用 `lib.sh` 的 `expand_includes`/`set_json_version`/`write_manifest`），流程：

1. 复用已构建的 5 架构二进制（不重复构建）。
2. 对 4 个平台，各自组装插件目录：
   - 从 `extension/<platform>/` 拷贝平台文件，`expand_includes` 展开 `{{include}}`（claude-code/cac 的 `.claude/commands`、`.cac/commands` 展平为顶层 `commands/`）。
   - 从 `extension/shared/skills/` 展开 skills 到 `<plugin>/skills/`。
   - 拷贝 `bin/secguard-<os>-<arch>[.exe]` + 注入 `bin/secguard`（shim）、`bin/secguard.cmd`。
   - `set_json_version` 覆写各 manifest `version`；claude-cac 额外写 `codeagent-extension.json`（CodeAgent 定制版扩展清单，与 install.sh 装到 cache 目录时一致）；claude-code 官方只用 `.claude-plugin/plugin.json`，不写该清单。
   - 每个目录建完即 `validate_plugin_dir` 校验（manifest/commands/agents/skills 数/bin 齐全）。
3. **逐平台打独立 zip**：把插件目录重命名为 `secguard-clang`（插件安装名）后 `zip -r secguard-clang`，zip 顶层是 `secguard-clang/`（Market 据此装到 plugins/ 或 extensions/），产出 `secguard-clang-<platform>-<version>.zip`（进临时目录，不单独发布）。
4. 生成聚合包：把 4 个逐平台 zip 收进 `secguard-clang-plugins-<version>/` + `manifest.json`（记录各 zip sha256）+ `VERSION` + `README.md`，打 `secguard-clang-plugins-<version>.zip`。
5. 对 2 个发布 zip（统一包 + 聚合包）写 `.sha256` + 汇总 `SHA256SUMS`；`release.yml` 无需改（`dist/secguard-*.zip` glob 只命中这 2 个）。

新增源文件（进 git，打包时注入，不手改产物）：`release/shim-secguard.sh`（bin/secguard shim）、`release/shim-secguard.cmd`（windows 入口）、`release/plugins-README.md`（插件包说明）。

---

## 10. 一致性守卫与测试

- 扩展现有 `release/check-extension-consistency.py`（或新增校验）：断言 4 个插件目录的 manifest `name`/`version`、skills 数（=22）、`bin/` 5 架构二进制齐全且 `bin/secguard` shim 存在、`{{include}}` 已无残留。
- 在 CI 加一条冒烟：解压聚合 zip → 再解压某个逐平台 zip → 校验 `bin/secguard` 存在、5 架构二进制存在、各 manifest version 与包一致。
- 本地验收（`--verify` 风格）：
  - 模拟 Market 安装（拷贝插件目录到缓存）后，`"${CLAUDE_PLUGIN_ROOT}/bin/secguard" --version` 输出正确版本。
  - 删除内嵌 `bin/` 后回退 PATH `secguard` 也能跑（非 Market 路径）。

---

## 11. 分阶段实施计划

| 阶段 | 内容 | 产物 |
|------|------|------|
| P1 | `lib.sh` 增 shim 注入 + `build_plugins` 组装逻辑（先只产 4 目录 + marketplace + zip） | 聚合 zip 可出 |
| P2 | OpenCode `findSecguard` 增 `<pluginDir>/bin/secguard` 候选；Claude 命令 `!` 行改 `${CLAUDE_PLUGIN_ROOT}` 前缀 | 双路径可调 |
| P3 | 一致性守卫 + CI 冒烟 + `release.yml` 发布聚合 zip | 可发布 |
| P4 | 文档（README / CHANGELOG）+ 本地/CI 验收 | 收尾 |

---

## 12. 风险、迁移与待确认事项

**风险**

- **体积**：每插件目录内嵌 5 架构二进制 ≈ 50MB，4 目录 ≈ 200MB。若不可接受，退到 D2 的 B 方案（20 个按架构 zip）或"市场目录内嵌、聚合 zip 按架构再分包"。
- **安装 key 迁移**：市场 entry 名改为 `secguard-clang-<platform>` 后，`installed_plugins.json` 的 key 从 `secguard-clang@local-secguard` 变为 `secguard-clang-<platform>@<marketplace>`（manifest `name` 仍是 `secguard-clang`，不影响 TUI）。属机械迁移，install/uninstall/verify 里硬编码的 plugin_name 字面量需同步。
- **`${CLAUDE_PLUGIN_ROOT}` 语义**：以 Claude Code 实际提供的变量为准（官方文档为 `${CLAUDE_PLUGIN_ROOT}`）；实现前用真实安装验证一次，避免变量名/可用场景偏差。
- **marketplace `source` 相对路径**只对 git 托管有效；zip 转存后由目标市场改写 source，文档需写明。
- **Claude Code 市场安装的二进制解析（待真机验证）**：bundled `bin/` + `/secguard` 命令 `!` 行的 `PATH` 前置只覆盖"状态检查"这一次调用；agent-body 里 `secguard scan/plan/report` 等 Bash 调用仍走 PATH。市场安装无 postInstall 钩子，无法把 bundled `bin/` 注入 PATH——需在真实 Claude Code 上验证 `${CLAUDE_PLUGIN_ROOT}` 是否注入到 agent 的 Bash 环境、以及 `Bash(secguard *)` 权限对 `PATH=… secguard` 前缀的匹配。若都不成立，Claude Code 市场路径按行业默认"CLI 与插件分装"（二进制仍需 PATH），bundled `bin/` 供企业市场自行编排 PATH/转存。OpenCode 无此问题（`findSecguard` 已直选 bundled 二进制）。
- **opencode-nga `.codeagent-extension-install.json`**：已定案为**保留**（与 master zip 的 opencode-nga 布局一致，模板 `source: {{OC_TARGET_DIR}}` 由安装方替换）。市场宿主若不替换、且 loader 强制读该字段，则 `source` 会是占位符——需在真实 NGA 上验证 loader 是否强依赖该值。

**待你拍板（影响实现，请先确认）**

1. **D2 粒度**：接受"按平台内嵌全 5 架构"（推荐，体积大但简单、Market 原生），还是要"按平台 × 架构拆 20 个"（体积小但 Market 不能自动选型）？
同意你的推荐：按平台内嵌全 5 架构

2. **D4 覆盖**：确认覆盖全 5 架构（darwin/linux/windows × amd64/arm64），而非草稿的仅 linux？
同意全覆盖5架构

3. **manifest `name` / TUI namespace**：
检视结论：**manifest `name` 保持 `secguard-clang`（两层身份解耦）**。TUI namespace 与命令全平台一致（OpenCode `/secguard-clang/secguard`，Claude Code `/secguard-clang:secguard`）；市场互不撞名由「目录名 + 市场 entry 名 `secguard-clang-<platform>`」承担，不写进 manifest `name`。