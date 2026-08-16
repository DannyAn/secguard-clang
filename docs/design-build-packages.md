# SecGuard 构建打包与发行技术设计文档

| 字段 | 值 |
|------|-----|
| 文档标题 | SecGuard 构建打包与发行技术设计 |
| 文档版本 | v1.0 |
| 创建日期 | 2026-08-11 |
| 状态 | 草案（待评审） |
| 关联需求规格 | `docs/spec-build-packages.md` v1.2 |
| 关联项目 | secguard-clang（Go module `github.com/DannyAn/secguard-clang`，位于 `sgre/`） |
| 作者 | spec-design-agent |

---

## 1. 设计概述

### 1.1 上下文视图

本设计覆盖 SecGuard-Clang 的"构建 → 打包 → 发行 → 安装 → 验证 → 卸载"全生命周期工具链。系统边界内的输入为：源码树（`sgre/` + `extension/`）、`VERSION` 文件、git 标签；输出为：三个发行 zip 包（统一包 + OpenCode 专用包 + ClaudeCode 专用包）及其 sha256 校验文件，以及用户环境中的安装结果与安装清单。

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        构建侧（源码树内运行）                          │
│                                                                     │
│  build.sh ──┬─ 无 --package → 原有构建行为（向后兼容）                │
│             └─ --package → release/build-packages.sh          │
│                                  │                                  │
│                                  ├── source lib.sh（共享函数）        │
│                                  ├── resolve_version()               │
│                                  ├── build_target() ×4（跨平台）     │
│                                  ├── expand_includes()（模板展开）   │
│                                  ├── 组装三包 + 内联注入 install/    │
│                                  │   uninstall 脚本                  │
│                                  ├── sha256 + manifest.json          │
│                                  └── 输出到 dist/                    │
│                                                                     │
│  deploy.sh ──── source lib.sh（复用 expand_includes，消除重复）       │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼  zip 包（自包含）
┌─────────────────────────────────────────────────────────────────────┐
│                     安装侧（用户环境独立运行）                        │
│                                                                     │
│  secguard-<ver>.zip 解压                                            │
│    ├── install.sh  （sg_* 函数已内联注入，不 source 外部 lib.sh）    │
│    │     ├── --target all/opencode/claude-code                      │
│    │     ├── --uninstall  → 共享 sg_uninstall()                     │
│    │     └── --verify     → sg_verify()                             │
│    └── uninstall.sh（sg_* 函数已内联注入，独立入口）                  │
│          └── 等价 install.sh --uninstall                            │
│                                                                     │
│  安装结果：                                                          │
│    ~/.config/opencode/extensions/zhuque-secguard/  （OpenCode）      │
│    ~/.claude/skills/zhuque-secguard/               （ClaudeCode）    │
│    ~/.claude/settings.json（权限合并）                                │
│    <bin-dir>/secguard                               （二进制）       │
│    <安装根>/.secguard-install-manifest             （安装清单）      │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.2 整体架构

系统由三层组成：

1. **共享函数层（`release/lib.sh`）**：构建侧公共函数的唯一真实来源。分为两个区域：
   - **构建侧专用区**：`resolve_version`、`build_target`、`write_manifest`、`sha256_file` 等，仅在源码树中运行，不注入发行包。
   - **可注入区**（`# @@SG_INJECT_START@@` ~ `# @@SG_INJECT_END@@` 标记包裹）：`sg_expand_includes`、`sg_select_binary`、`sg_write_install_manifest`、`sg_read_install_manifest`、`sg_merge_permissions`、`sg_remove_permissions`、`sg_uninstall_platform`、`sg_verify_platform`、`sg_confirm_action` 等，全部以 `sg_` 前缀命名，打包时内联注入到 zip 内 `install.sh`/`uninstall.sh`。

2. **打包核心层（`release/build-packages.sh`）**：编排版本解析、跨平台构建、模板展开、三包组装、内联注入、校验和与 manifest 生成。

3. **安装/卸载/验证层（发行包内 `install.sh` + `uninstall.sh`）**：自包含脚本，运行时仅依赖 bash + python3 + 标准工具（`cp`/`mkdir`/`rm`/`uname`/`shasum`/`zip` 不需要），通过内联注入的 `sg_*` 函数完成全部工作。

### 1.3 设计原则

| 原则 | 含义 | 落实点 |
|------|------|--------|
| 构建侧共享 | 源码树中路径固定，公共函数集中维护、`source` 复用 | `lib.sh` 单一真实来源；`build-packages.sh`、`deploy.sh` 均 `source` 它 |
| 安装侧自包含 | 发行包解压到任意路径可独立运行，不依赖源码树 | 打包时内联注入 `sg_*` 函数；zip 内脚本无 `source .../lib.sh` |
| DRY | 消除当前 4 处 `expand_includes` 重复实现 | `lib.sh` 唯一来源；`deploy.sh` 改为 `source` |
| 幂等 | 重复安装不报错、不重复添加权限 | 安装覆盖文件；权限合并用集合去重 |
| 可重复构建 | 相同输入产生字节相同的 zip | `go build -trimpath`；`zip -X` 不存额外时间戳；固定 manifest build_date 取源码 mtime 或固定值 |
| 路径一致 | 发行包安装路径与 `deploy.sh` 开发部署路径完全一致 | OpenCode → `<prefix>/extensions/zhuque-secguard/`；ClaudeCode → `<prefix>/skills/zhuque-secguard/` |
| 单一主入口 | `install.sh` 既是安装入口也是卸载/验证入口 | `--uninstall`/`--verify` 子模式；另提供 `uninstall.sh` 独立入口等价于 `install.sh --uninstall` |
| 类型/命名安全 | 注入函数加 `sg_` 前缀避免与脚本局部变量冲突；snake_case 变量、kebab-case 目录 | 全部 `sg_*` 命名 |

---

## 2. 模块/文件结构设计

### 2.1 文件清单与职责

#### 2.1.1 新增文件

| 文件路径 | 职责 | 是否打入 zip |
|----------|------|--------------|
| `VERSION` | 根目录版本号来源（单行文本，如 `1.2.0`） | 打入统一包顶层、各专用包根 |
| `release/lib.sh` | 构建侧共享函数库（构建专用区 + 可注入区），单一真实来源 | **不打入任何 zip** |
| `release/uninstall.sh` | 源码树中的卸载脚本模板（含 `# @@SG_LIB_INJECT@@` 占位标记），打包时注入 `sg_*` 后放入 zip | 以注入后副本打入 zip |
| `release/uninstall-opencode.sh` | OpenCode 专用卸载脚本模板 | 以注入后副本打入 OpenCode zip |
| `release/uninstall-claude-code.sh` | ClaudeCode 专用卸载脚本模板 | 以注入后副本打入 ClaudeCode zip |
| `release/install.sh.tmpl` | 统一包 install.sh 模板（含占位标记与平台分发逻辑） | 以注入后副本打入统一包 |
| `release/install-opencode.sh.tmpl` | OpenCode 专用 install.sh 模板 | 以注入后副本打入 OpenCode zip |
| `release/install-claude-code.sh.tmpl` | ClaudeCode 专用 install.sh 模板 | 以注入后副本打入 ClaudeCode zip |

> 说明：现有 `release/install.sh`、`install-opencode.sh`、`install-claude-code.sh` 将重构为 `.tmpl` 模板（含占位标记）。打包时 `build-packages.sh` 对模板执行"内联注入"生成最终脚本。源码树中保留一份已注入的 `install.sh`（供开发者本地试运行）由 `build-packages.sh --sync-templates` 同步生成，非必须。

#### 2.1.2 修改文件

| 文件路径 | 改造内容 |
|----------|----------|
| `build.sh` | 新增 `--package`/`--dist`/`--version`/`--os`/`--arch`/`--target` 参数；无 `--package` 时行为完全不变（向后兼容，AC-11） |
| `release/build-packages.sh` | 重构为打包核心：`source lib.sh`；版本解析；跨平台构建；模板展开；三包组装；内联注入；校验和；manifest |
| `release/install-opencode.sh` | 重构为 `.tmpl`：对齐路径 `extensions/zhuque-secguard/`；新增 `--prefix`/`--bin-dir`/`--uninstall`/`--verify`/`--yes`；自包含 |
| `release/install-claude-code.sh` | 重构为 `.tmpl`：对齐路径 `skills/zhuque-secguard/`；权限合并；新增相同参数；自包含 |
| `deploy.sh` | 移除内联 `expand_includes`，改为 `source "$SCRIPT_DIR/release/lib.sh"`；其余开发部署行为不变 |
| `extension/install.sh` | 已删除（其 `expand_includes` 重复实现移除，统一由 `lib.sh` 提供；若仍有本地安装需求，改为调用 `release/install.sh.tmpl` 注入后副本） |

#### 2.1.3 不变文件

`sgre/`（Go 模块）、`extension/shared/`、`extension/opencode/`、`extension/claude-code/` 源码内容不变（仅打包时被读取、展开、组装）。

### 2.2 文件依赖关系

```text
build.sh
  └─(无 --package)─→ 原有 go build（不变）
  └─(--package)───→ release/build-packages.sh
                      ├─ source ─→ release/lib.sh
                      ├─ 读取 ──→ VERSION / git describe
                      ├─ 读取 ──→ sgre/（go build）
                      ├─ 读取 ──→ extension/{shared,opencode,claude-code}/
                      ├─ 模板 ──→ release/install*.sh.tmpl
                      ├─ 模板 ──→ release/uninstall*.sh（模板）
                      ├─ 注入 ──→ lib.sh 可注入区 → 生成 zip 内脚本
                      └─ 输出 ──→ dist/*.zip + dist/*.sha256

deploy.sh
  └─ source ─→ release/lib.sh（复用 sg_expand_includes / expand_includes）

zip 内 install.sh / uninstall.sh
  └─ 内联 ─→ sg_* 函数（打包时注入，运行时无外部依赖）
```

---

## 3. 关键流程设计

### 3.1 打包流程

```text
build-packages.sh 主流程：

  1. source lib.sh
  2. 解析 CLI 参数（--version/--os/--arch/--target/--test）
  3. version = resolve_version "$EXPLICIT_VERSION"
  4. 若 --test：在 sgre/ 下运行 go test ./...，失败则 exit 1
  5. targets = compute_targets "$OS_FILTER" "$ARCH_FILTER"
     → 默认 [(darwin,amd64),(darwin,arm64),(linux,amd64),(linux,arm64)]
  6. 对每个 (goos,goarch) in targets：
       bin = build_target "$goos" "$goarch" "$version"
       若失败：记录警告；若全部失败则回退本机目标（REQ-BIN-04）
  7. skills = glob extension/shared/skills/*/SKILL.md（自动发现 14 个）
  8. 对每个需要展开的文件调用 expand_includes（构建侧，source 自 lib.sh）
  9. 覆写 extension.json / plugin.json 的 version 字段为 $version（DATA-03/04）
 10. inject_block = extract_inject_block lib.sh   # 提取 @@SG_INJECT_START@@~END@@
 11. 组装统一包：
       - 创建临时目录 secguard-<version>/
       - 复制 4 个二进制 secguard-<os>-<arch>
       - 复制 shared/、opencode/（已展开）、claude-code/（已展开）
       - 生成 install.sh = inject_into(install.sh.tmpl, inject_block)
       - 生成 uninstall.sh = inject_into(uninstall.sh 模板, inject_block)
       - 写入 VERSION、manifest.json、README.md、LICENSE
       - 排除 .gocache/.gotmp/*.db/.DS_Store/__pycache__/.git
       - zip -X -r secguard-<version>.zip secguard-<version>/
 12. 组装 OpenCode 专用包（根目录即 extension，无顶层包裹目录）：
       - 复制 extension.json、opencode.json、commands/、agents/、tools/、plugins/、skills/
       - 注入 install.sh / uninstall.sh（专用模板）
       - VERSION、manifest.json
       - zip -X -r secguard-extension-opencode-<version>.zip .
 13. 组装 ClaudeCode 专用包（根目录即 plugin）：
       - 复制 .claude-plugin/、commands/、agents/、hooks/、skills/、bin/
       - 注入 install.sh / uninstall.sh（专用模板）
       - VERSION、manifest.json
       - zip -X -r secguard-extension-claude-code-<version>.zip .
 14. 对每个 zip 生成 .sha256（shasum -a 256）
 15. 打印产物列表（路径、大小、sha256）
```

### 3.2 安装流程（install.sh，非 --uninstall/--verify 模式）

```text
install.sh 主流程：

  1. set -euo pipefail
  2. sg_* 函数已内联注入（无 source）
  3. 解析 CLI：--target（默认 all）/--prefix/--bin-dir/--no-binary/--yes
  4. 检测当前平台：cur_os=$(uname -s | lowercase)，cur_arch=$(uname -m 映射 → amd64/arm64)
  5. 读取包版本：version=$(cat "$PKG_DIR/VERSION")
  6. 解析安装路径：
       opencode_prefix = ${prefix:-$HOME/.config/opencode}
       claude_prefix   = ${prefix:-$HOME/.claude}
       oc_target_dir   = $opencode_prefix/extensions/zhuque-secguard
       cc_target_dir   = $claude_prefix/skills/zhuque-secguard
       bin_dir         = ${bin_dir:-/usr/local/bin}，无写权限则回退 $HOME/.local/bin
  7. 若已存在 .secguard-install-manifest 且版本不同：
       调用 sg_uninstall_platform 旧版本（按 manifest 卸载，REQ-INST-11）
  8. 若 --target 含 opencode：install_opencode()
       - mkdir -p $oc_target_dir/{commands,agents,tools,plugins,skills}
       - 复制 extension.json、opencode.json
       - 复制并展开 commands/*.md、agents/*.md（包内已展开，直接复制）
       - 复制 tools/*.ts、plugins/*.ts
       - 复制 skills/*/SKILL.md（glob，自动 14 个）
       - 记录已安装文件列表到 installed_files[]
  9. 若 --target 含 claude-code：install_claude_code()
       - mkdir -p $cc_target_dir/{.claude-plugin,commands,agents,hooks,skills,bin}
       - 复制 .claude-plugin/plugin.json、hooks/hooks.json
       - 复制 commands/*.md、agents/*.md
       - 复制 skills/*/SKILL.md
       - sg_merge_permissions $claude_prefix/settings.json（幂等合并 7 项权限）
       - 记录已安装文件列表
 10. 若非 --no-binary：
       bin = sg_select_binary "$PKG_DIR" "$cur_os" "$cur_arch"
       若无匹配二进制：报错并列出包内可用目标，exit 1（REQ-INST-06）
       cp bin → $bin_dir/secguard；chmod +x
       记录 $bin_dir/secguard 到 installed_files[]
 11. sg_write_install_manifest：
       写入 $opencode_prefix/.secguard-install-manifest（或 $claude_prefix）
       含 version、install_date、target、files[]、bin_path
 12. 打印安装摘要
```

### 3.3 卸载流程（uninstall.sh 或 install.sh --uninstall）

```text
uninstall.sh 主流程（与 install.sh --uninstall 共享 sg_uninstall_platform）：

  1. set -euo pipefail；sg_* 已内联注入
  2. 解析 CLI：--target（默认 all）/--prefix/--bin-dir/--yes
  3. 定位 manifest：
       manifest_path = ${prefix:-$HOME/.config/opencode}/.secguard-install-manifest
       若不存在，尝试 $HOME/.claude/.secguard-install-manifest
       若均不存在：警告"未找到安装清单"，回退启发式清理（按约定路径删除
       zhuque-secguard 目录与 bin/secguard，REQ-UNINST-03 降级，风险-4）
  4. manifest = sg_read_install_manifest "$manifest_path"
  5. 待删除文件列表 = manifest.files 中匹配 --target 的子集
  6. 若交互终端且未 --yes：
       展示文件清单，sg_confirm_action "确认卸载？" ，否 → exit 0
  7. 对每个 file in 待删除列表：
       rm -f "$file"；记录已删
  8. 若 --target 含 claude-code：
       sg_remove_permissions $HOME/.claude/settings.json（移除 7 项 secguard 权限，幂等）
  9. 清理空目录：自底向上 rmdir 空的 zhuque-secguard/、其父 skills/ 或 extensions/（仅当空）
 10. 若 manifest 中所有文件已删：rm manifest_path
 11. 打印卸载摘要
```

### 3.4 验证流程（install.sh --verify）

```text
sg_verify_platform 主流程：

  1. set -euo pipefail；sg_* 已内联注入
  2. 解析 CLI：--target（默认 all）/--prefix/--bin-dir
  3. overall_pass=true；results=()
  4. 二进制检测（若非 --no-binary 上下文）：
       a. bin_path=$bin_dir/secguard
       b. check "二进制存在" : [ -f "$bin_path" ]
       c. check "二进制可执行" : [ -x "$bin_path" ]
       d. check "版本匹配" :
            installed_ver=$("$bin_path" --version 2>&1 | extract version)
            [ "$installed_ver" = "$pkg_version" ]
          若执行失败（如动态库缺失）→ 该项 ✗ 并记录错误（风险-5），不整体崩溃
  5. 若 --target 含 opencode：
       check "extension.json 存在" : [ -f "$oc_target_dir/extension.json" ]
       check "commands/secguard.md 存在" : [ -f "$oc_target_dir/commands/secguard.md" ]
       check "agents/security-auditor.md 存在" : [ -f ... ]
       check "plugins/secguard-context.ts 存在" : [ -f ... ]
       for skill in 14 skills: check "skills/<skill>/SKILL.md 存在"
       check "平台发现路径正确" : [ -d "$oc_target_dir" ]
  6. 若 --target 含 claude-code：
       check "plugin.json 存在" : [ -f "$cc_target_dir/.claude-plugin/plugin.json" ]
       check "commands/secguard.md 存在" ...
       check "agents/security-auditor.md 存在" ...
       check "hooks/hooks.json 存在" ...
       for skill in 14 skills: check ...
       check "平台发现路径正确" : [ -d "$cc_target_dir" ]
       check "权限已合并" : sg_check_permissions_merged $HOME/.claude/settings.json
  7. 输出每项 ✓/✗ 与说明
  8. exit $overall_pass ? 0 : 1
```

---

## 4. lib.sh 函数清单

> 所有函数定义于 `release/lib.sh`。可注入区函数以 `sg_` 前缀命名，由 `# @@SG_INJECT_START@@` / `# @@SG_INJECT_END@@` 标记包裹。构建侧专用函数无前缀。

### 4.1 构建侧专用函数（不注入）

#### `resolve_version`
- **签名**：`resolve_version <explicit_version>`
- **入参**：`$1` = 显式版本号（可为空）
- **出参**：stdout 输出版本号字符串
- **职责**：三级回退（详见 §9）。`$1` 非空 → 用之；否则 `VERSION` 文件存在 → 读取去空白；否则 git 仓库 → `git describe --tags --always --dirty`；否则 `0.0.0-dev`。
- **伪代码**：
  ```bash
  resolve_version() {
      local explicit="$1"
      if [ -n "$explicit" ]; then echo "$explicit"; return; fi
      if [ -f "$PROJECT_ROOT/VERSION" ]; then
          local v; v=$(tr -d '[:space:]' < "$PROJECT_ROOT/VERSION")
          if [ -n "$v" ]; then echo "$v"; return; fi
      fi
      if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
          local v; v=$(git -C "$PROJECT_ROOT" describe --tags --always --dirty 2>/dev/null)
          if [ -n "$v" ]; then echo "$v"; return; fi
      fi
      echo "0.0.0-dev"
  }
  ```

#### `build_target`
- **签名**：`build_target <goos> <goarch> <version>`
- **入参**：`$1`=GOOS，`$2`=GOARCH，`$3`=version
- **出参**：stdout 输出二进制绝对路径；失败时返回非 0
- **职责**：设置 `GOOS`/`GOARCH`/`CGO_ENABLED=1`，在 `sgre/` 下 `go build -trimpath -o dist/secguard-<os>-<arch> ./cmd/secguard`。CGO 交叉编译失败时返回非 0（由调用方决定回退）。
- **伪代码**：
  ```bash
  build_target() {
      local goos="$1" goarch="$2" version="$3"
      local out="$DIST_DIR/secguard-${goos}-${goarch}"
      ( cd "$SGRE_DIR" && \
        GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=1 \
        go build -trimpath -o "$out" ./cmd/secguard ) && echo "$out"
  }
  ```

#### `sha256_file`
- **签名**：`sha256_file <file_path>`
- **出参**：stdout 输出 sha256 hex
- **职责**：`shasum -a 256 "$1" | cut -d' ' -f1`（macOS/Linux 兼容）。

#### `write_manifest`
- **签名**：`write_manifest <pkg_root> <version> <targets_csv> <skills_csv>`
- **职责**：生成包内 `manifest.json`（schema 见 §7.1）。用 python3 生成保证 JSON 合法。

#### `expand_includes`（构建侧别名）
- **签名**：`expand_includes <input_file> <output_file> <shared_dir>`
- **职责**：模板展开，将 `{{include shared/<name>}}` 替换为 `shared/<name>` 文件内容。实现委托给 `sg_expand_includes`（可注入区），构建侧直接调用同一实现，确保 DRY。
- **说明**：`deploy.sh` 与 `build-packages.sh` 调用此函数；其内部调用 `sg_expand_includes`，故逻辑唯一。

#### `extract_inject_block`
- **签名**：`extract_inject_block <lib_sh_path>`
- **出参**：stdout 输出 `# @@SG_INJECT_START@@` 与 `# @@SG_INJECT_END@@` 之间的内容（含 `sg_*` 函数定义）
- **职责**：供打包时内联注入使用。用 awk 提取标记区间。

#### `inject_into`
- **签名**：`inject_into <template_path> <inject_block>`
- **出参**：stdout 输出注入后的完整脚本
- **职责**：将 `$inject_block` 替换模板中的 `# @@SG_LIB_INJECT@@` 占位标记。

### 4.2 可注入区函数（sg_ 前缀，打包时内联注入到 zip 内脚本）

> 以下函数位于 `# @@SG_INJECT_START@@` ~ `# @@SG_INJECT_END@@` 之间。它们不得引用任何包外路径或 `source` 外部文件；所需数据通过参数传入。

#### `sg_expand_includes`
- **签名**：`sg_expand_includes <input_file> <output_file> <shared_dir>`
- **职责**：同 `expand_includes` 的实现体。zip 内安装脚本一般不需要展开（包内文件已展开），但保留以备专用包内命令文件需二次展开的场景。

#### `sg_select_binary`
- **签名**：`sg_select_binary <pkg_dir> <os> <arch>`
- **出参**：stdout 输出匹配的二进制路径；无匹配时返回非 0
- **职责**：在 `$pkg_dir` 下查找 `secguard-<os>-<arch>`。`uname -m` 映射：`x86_64`→`amd64`，`aarch64`/`arm64`→`arm64`。无匹配时 stderr 列出包内所有 `secguard-*` 候选。
- **伪代码**：
  ```bash
  sg_select_binary() {
      local pkg_dir="$1" os="$2" arch="$3"
      local bin="$pkg_dir/secguard-${os}-${arch}"
      if [ -f "$bin" ]; then echo "$bin"; return 0; fi
      echo "ERROR: no binary for ${os}/${arch}. Available:" >&2
      ls "$pkg_dir"/secguard-* 2>/dev/null >&2 || echo "  (none)" >&2
      return 1
  }
  ```

#### `sg_write_install_manifest`
- **签名**：`sg_write_install_manifest <manifest_path> <version> <target> <bin_path> <files_csv>`
- **职责**：用 python3 写出 `.secguard-install-manifest` JSON（schema 见 §7.2）。`files_csv` 为已安装文件绝对路径列表（冒号或换行分隔）。

#### `sg_read_install_manifest`
- **签名**：`sg_read_install_manifest <manifest_path>`
- **出参**：stdout 输出 JSON 内容；不存在时返回非 0
- **职责**：读取并校验 JSON 合法性。损坏时返回非 0（触发启发式清理回退）。

#### `sg_merge_permissions`
- **签名**：`sg_merge_permissions <settings_path>`
- **职责**：将 7 项 `Bash(secguard *)` 权限幂等合并进 `settings.json` 的 `permissions.allow`（详见 §8）。

#### `sg_remove_permissions`
- **签名**：`sg_remove_permissions <settings_path>`
- **职责**：从 `permissions.allow` 移除 7 项 secguard 权限，保留其它项与 `deny` 列表（详见 §8）。

#### `sg_check_permissions_merged`
- **签名**：`sg_check_permissions_merged <settings_path>`
- **出参**：返回 0 若 7 项全在；非 0 若缺失
- **职责**：供 `--verify` 使用。

#### `sg_uninstall_platform`
- **签名**：`sg_uninstall_platform <platform> <prefix> <bin_dir> <manifest_path> <yes>`
- **职责**：核心卸载逻辑，被 `uninstall.sh` 与 `install.sh --uninstall` 共同调用。读取 manifest → 过滤 platform → 确认 → 删除文件 → 移除权限 → 清理空目录。
- **说明**：此函数是 REQ-UNINST-08"共享底层卸载逻辑"的落实点。打包时同一份定义注入到 `install.sh` 与 `uninstall.sh`。

#### `sg_verify_platform`
- **签名**：`sg_verify_platform <platform> <prefix> <bin_dir> <pkg_version>`
- **出参**：退出码 0/1
- **职责**：核心验证逻辑（详见 §3.4）。

#### `sg_confirm_action`
- **签名**：`sg_confirm_action <prompt>`
- **出参**：返回 0 若用户确认（y/yes）；非 0 若拒绝
- **职责**：交互确认。非交互终端（stdout 非 tty）自动返回 0（避免卡死）。

#### `sg_detect_arch`
- **签名**：`sg_detect_arch`
- **出参**：stdout 输出 `amd64` 或 `arm64`
- **职责**：`uname -m` 映射。

#### `sg_detect_os`
- **签名**：`sg_detect_os`
- **出参**：stdout 输出 `darwin` 或 `linux`
- **职责**：`uname -s` 映射（Darwin→darwin，Linux→linux）。

---

## 5. install.sh / uninstall.sh 内联注入机制

### 5.1 机制概述

`lib.sh` 的可注入区用标记注释包裹：

```bash
# @@SG_INJECT_START@@
sg_expand_includes() { ... }
sg_select_binary() { ... }
sg_merge_permissions() { ... }
# ... 其它 sg_* 函数 ...
# @@SG_INJECT_END@@

# 以下是构建侧专用函数（不注入）
resolve_version() { ... }
build_target() { ... }
```

模板脚本（`install.sh.tmpl`）在函数定义区之前包含占位标记：

```bash
#!/bin/bash
set -euo pipefail

# @@SG_LIB_INJECT@@

PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
# ... 脚本主体 ...
```

### 5.2 注入实现（`extract_inject_block` + `inject_into`）

```bash
extract_inject_block() {
    local lib_path="$1"
    awk '/^# @@SG_INJECT_START@@$/{flag=1;next} /^# @@SG_INJECT_END@@$/{flag=0} flag' "$lib_path"
}

inject_into() {
    local tmpl_path="$1" inject_block="$2"
    # 用 python3 替换占位标记，避免 sed 多行替换的跨平台差异
    python3 -c "
import sys
tmpl = open('$tmpl_path').read()
block = sys.stdin.read()
assert '# @@SG_LIB_INJECT@@' in tmpl, 'inject marker missing'
sys.stdout.write(tmpl.replace('# @@SG_LIB_INJECT@@', block))
    " <<< "$inject_block"
}
```

### 5.3 打包时调用

```bash
inject_block=$(extract_inject_block "$LIB_SH")
# 统一包
inject_into "$DIST_DIR/install.sh.tmpl" "$inject_block" > "$MASTER_ROOT/install.sh"
chmod +x "$MASTER_ROOT/install.sh"
inject_into "$DIST_DIR/uninstall.sh.tmpl" "$inject_block" > "$MASTER_ROOT/uninstall.sh"
chmod +x "$MASTER_ROOT/uninstall.sh"
```

### 5.4 自包含保证（REQ-LIB-04 / AC-16）

- 注入后脚本中 `sg_*` 函数以源码形式存在，运行时无需 `source`。
- 模板中**禁止**出现 `source .../lib.sh` 或任何引用包外路径的 `source`。打包后由 `build-packages.sh` 执行静态检查：`grep -n 'source.*lib\.sh' "$MASTER_ROOT/install.sh"` 必须无匹配，否则打包失败。
- `sg_` 前缀避免与脚本局部变量/函数名冲突（风险-3）。

### 5.5 单一来源保证（REQ-LIB-05 / AC-17）

修改 `lib.sh` 可注入区中任一 `sg_*` 函数 → 重新打包 → `extract_inject_block` 自动提取新实现 → 注入到所有 zip 内脚本。无需手工同步多份副本。

---

## 6. 跨平台构建设计

### 6.1 GOOS/GOARCH 矩阵

| GOOS | GOARCH | 二进制名 | 说明 |
|------|--------|----------|------|
| darwin | amd64 | `secguard-darwin-amd64` | macOS Intel |
| darwin | arm64 | `secguard-darwin-arm64` | macOS Apple Silicon |
| linux | amd64 | `secguard-linux-amd64` | Linux x86_64 |
| linux | arm64 | `secguard-linux-arm64` | Linux aarch64 |

默认构建全部 4 个（REQ-BIN-01）。`--os`/`--arch` 过滤（REQ-BIN-02）。

### 6.2 CGO 交叉编译回退策略（REQ-BIN-04）

```text
对每个 (goos, goarch) in targets:
    if build_target goos goarch version 成功:
        记录二进制路径
    else:
        记录警告 "CGO 交叉编译 <goos>/<goarch> 失败（可能缺 C 工具链）"
        标记该目标失败

if 全部目标失败:
    记录警告 "所有跨平台目标失败，回退本机构建"
    build_target $(go env GOOS) $(go env GOARCH) version
    若本机也失败 → exit 1（中止打包）

# 部分失败不中断整体打包（NFR-REL-02），manifest.targets 只记录成功的目标
```

### 6.3 构建环境变量

```bash
export CGO_ENABLED=1
export GOFLAGS=-mod=mod
export GONOSUMDB='*'
export GOCACHE="$SGRE_DIR/.gocache"   # 私有缓存，不污染用户环境
export TMPDIR="$SGRE_DIR/.gotmp"
export PATH="/opt/homebrew/bin:$PATH"  # macOS Homebrew 工具链
```

`go build -trimpath` 去除路径信息，配合 `zip -X` 实现可重复构建（NFR-REL-01）。

### 6.4 二进制命名与选择

- 打包时命名 `secguard-<os>-<arch>`，放入统一包顶层、ClaudeCode 包 `bin/`。
- 安装时 `sg_select_binary` 按 `sg_detect_os`/`sg_detect_arch` 匹配，复制为 `<bin-dir>/secguard`（去掉平台后缀）。
- OpenCode 专用包不含二进制（OpenCode 通过 PATH 调用），统一包与 ClaudeCode 包含二进制。

---

## 7. manifest 与安装清单设计

### 7.1 包内 manifest.json（打包时生成，描述包内容）

**写入时机**：`build-packages.sh` 组装每个 zip 时，由 `write_manifest` 生成，放入包根。

**Schema**（REQ-MAN-01 / DATA-01）：

```json
{
  "version": "1.2.0",
  "build_date": "2026-08-11T00:00:00Z",
  "go_version": "go1.25.0",
  "targets": [
    {"os": "darwin", "arch": "amd64"},
    {"os": "darwin", "arch": "arm64"},
    {"os": "linux",  "arch": "amd64"},
    {"os": "linux",  "arch": "arm64"}
  ],
  "skills": [
    "null-deref", "buffer-overflow", "memory-leak", "injection",
    "resource-leak", "uninit", "use-after-free", "double-free",
    "format-string", "integer-overflow", "race-condition",
    "hardcoded-secret", "deadlock", "crypto-misuse"
  ],
  "files": {
    "install.sh": "a1b2c3...",
    "secguard-darwin-arm64": "d4e5f6...",
    "shared/skills/null-deref/SKILL.md": "..."
  }
}
```

- `build_date`：为可重复构建，取 `VERSION` 文件 mtime 或固定值（非当前时间），UTC ISO8601。
- `go_version`：`go version` 输出解析。
- `files`：包内所有文件相对路径 → sha256。

### 7.2 安装清单 .secguard-install-manifest（安装时生成，供卸载用）

**写入时机**：`install.sh` 安装完成后，由 `sg_write_install_manifest` 写入安装根（`<opencode_prefix>` 或 `<claude_prefix>`）。

**Schema**（DATA-02）：

```json
{
  "version": "1.2.0",
  "install_date": "2026-08-11T14:30:00Z",
  "target": "all",
  "bin_path": "/usr/local/bin/secguard",
  "files": [
    "/Users/me/.config/opencode/extensions/zhuque-secguard/extension.json",
    "/Users/me/.config/opencode/extensions/zhuque-secguard/commands/secguard.md",
    "/Users/me/.claude/skills/zhuque-secguard/.claude-plugin/plugin.json",
    "/usr/local/bin/secguard"
  ]
}
```

- `files`：**绝对路径**列表，卸载时逐个 `rm -f`。
- 跨版本卸载（REQ-UNINST-03 / AC-19）：`uninstall.sh` 读取此 manifest，即使当前包版本不同，仍按 manifest.files 删除历史安装文件。
- manifest 缺失/损坏降级（风险-4）：`sg_uninstall_platform` 检测 manifest 不可读时，按约定路径启发式清理（删除 `<prefix>/extensions/zhuque-secguard/`、`<prefix>/skills/zhuque-secguard/`、`<bin-dir>/secguard`），并提示用户。

### 7.3 读写时机

| 时机 | 文件 | 操作 |
|------|------|------|
| 打包 | `manifest.json` | `write_manifest` 生成 |
| 打包 | `*.sha256` | `sha256_file` 生成 |
| 安装 | `.secguard-install-manifest` | `sg_write_install_manifest` 生成（覆盖旧版） |
| 安装前 | `.secguard-install-manifest` | `sg_read_install_manifest` 读取（用于先卸载旧版，REQ-INST-11） |
| 卸载 | `.secguard-install-manifest` | `sg_read_install_manifest` 读取 → 删除文件 → 删除 manifest |
| 验证 | `manifest.json`（包内） | 读取 `version` 与二进制版本比对 |

---

## 8. 权限合并/移除设计

### 8.1 权限项清单（7 项）

```python
REQUIRED_PERMS = [
    "Bash(secguard scan *)",
    "Bash(secguard index *)",
    "Bash(secguard plan *)",
    "Bash(secguard report *)",
    "Bash(secguard status *)",
    "Bash(secguard query *)",
    "Bash(secguard db *)",
]
```

### 8.2 sg_merge_permissions（REQ-CC-03 / AC-14）

用 python3 操作 JSON，幂等合并：

```python
import json, os, sys
settings_path = sys.argv[1]
required_perms = [...]  # 7 项

try:
    with open(settings_path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    settings = {}

settings.setdefault("permissions", {}).setdefault("allow", [])
settings["permissions"].setdefault("deny", [])  # 保留 deny（NFR-SEC-03）

existing = set(settings["permissions"]["allow"])
for perm in required_perms:
    if perm not in existing:
        settings["permissions"]["allow"].append(perm)
        existing.add(perm)

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
```

- 幂等：用集合去重，重复安装不重复添加（AC-14）。
- 安全：只 append 到 `allow`，**不覆盖**整个 settings.json，**不动** `deny` 列表（NFR-SEC-03）。

### 8.3 sg_remove_permissions（REQ-UNINST-07）

```python
import json, sys
settings_path = sys.argv[1]
required_perms = [...]  # 同上 7 项

try:
    with open(settings_path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(0)  # 文件不存在视为已移除，幂等不报错

allow = settings.get("permissions", {}).get("allow", [])
settings["permissions"]["allow"] = [p for p in allow if p not in required_perms]

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
```

- 仅移除 secguard 相关 7 项，保留其它权限项（REQ-INST-12 / REQ-UNINST-04）。
- 幂等：多次执行不报错。

### 8.4 sg_check_permissions_merged（供 --verify）

```python
# 返回 0 若 7 项全在 allow 中，否则非 0
```

### 8.5 可移植性（NFR-PORT-02）

全部用 python3 处理 JSON，避免 `sed -i` 在 macOS（BSD sed）与 Linux（GNU sed）的差异。

---

## 9. 版本解析设计

### 9.1 三级回退（REQ-VER-01~04）

```text
resolve_version(explicit):
  1. if explicit 非空: return explicit          # --version 覆盖（REQ-VER-04）
  2. if VERSION 文件存在且非空: return 其内容去空白  # REQ-VER-01
  3. if 当前在 git 仓库内:
       v = git describe --tags --always --dirty
       if v 非空: return v                       # REQ-VER-02
  4. return "0.0.0-dev"                          # REQ-VER-03
```

### 9.2 VERSION 文件格式

- 根目录 `VERSION`，单行，如 `1.2.0`。
- 读取时 `tr -d '[:space:]'` 去首尾空白与换行。
- 打包时将版本写入包内 `VERSION` 文件与 `manifest.json`（REQ-VER-05）。

### 9.3 git describe 语义

- `--tags`：使用所有标签（非仅 annotated）。
- `--always`：无标签时回退到短 commit hash。
- `--dirty`：工作区有未提交改动时追加 `-dirty`。

---

## 10. 接口设计

### 10.1 build.sh CLI（REQ-BUILD-01~05 / §4.1 of spec）

```
./build.sh [--test] [--install] [--package|--dist] [--version <v>]
           [--os <os>] [--arch <arch>] [--target <t>] [--help|-h]
```

| 参数 | 说明 | 默认 |
|------|------|------|
| `--test` | 构建前运行 `go test ./...` | 否 |
| `--install` | 安装二进制到 `~/.local/bin` | 否 |
| `--package` / `--dist` | 执行发行打包，产物到 `dist/` | 否 |
| `--version` | 显式版本号（透传给 `resolve_version`） | 空 |
| `--os` | 限定目标 OS（darwin/linux） | 全部 |
| `--arch` | 限定目标架构（amd64/arm64） | 全部 |
| `--target` | 限定包类型（master/opencode/claude-code/all） | all |
| `--help` | 显示用法 | — |

**退出码**：`0` 成功；`1` 失败（测试失败/构建失败/参数错误）。

**向后兼容**：无 `--package` 时，`--test`/`--install`/`--help` 行为与改造前完全一致（AC-11）。

### 10.2 install.sh CLI（统一包，REQ-INST-01~15 / §4.2 of spec）

```
./install.sh [--target <opencode|claude-code|all>] [--prefix <path>]
             [--bin-dir <path>] [--no-binary] [--uninstall] [--verify]
             [--yes|-y] [--help|-h]
```

| 参数 | 说明 | 默认 |
|------|------|------|
| `--target` | 安装/卸载/验证目标平台 | all |
| `--prefix` | 覆盖默认安装根 | OC: `~/.config/opencode`，CC: `~/.claude` |
| `--bin-dir` | 覆盖二进制安装目录 | `/usr/local/bin`，无写权限回退 `~/.local/bin` |
| `--no-binary` | 跳过二进制安装 | 否 |
| `--uninstall` | 执行卸载（调用 `sg_uninstall_platform`） | 否 |
| `--verify` | 执行安装验证（调用 `sg_verify_platform`），不安装不卸载 | 否 |
| `--yes`/`-y` | 跳过交互确认 | 否 |
| `--help` | 显示用法 | — |

**互斥**：`--uninstall` 与 `--verify` 不可同时指定；同时指定时报错退出 1。

**退出码**：`0` 成功/验证全通过；`1` 失败/验证有项未通过；`2` 参数错误。

**交互**：未指定 `--target` 且为交互终端时提示选择（REQ-INST-13）。

### 10.3 uninstall.sh CLI（统一包与专用包，§4.3 of spec）

```
./uninstall.sh [--target <opencode|claude-code|all>] [--prefix <path>]
               [--bin-dir <path>] [--yes|-y] [--help|-h]
```

| 参数 | 说明 | 默认 |
|------|------|------|
| `--target` | 卸载目标平台（仅删除指定平台文件） | all |
| `--prefix` | 覆盖默认安装根（定位 manifest） | 同 install.sh |
| `--bin-dir` | 覆盖二进制目录（定位已安装二进制） | 同 install.sh |
| `--yes`/`-y` | 跳过删除确认 | 否 |
| `--help` | 显示用法 | — |

**专用包内 `uninstall.sh`**：无 `--target` 参数（仅卸载该专用平台），其余相同。

**退出码**：`0` 成功；`1` 失败（manifest 缺失且无法启发式清理）；`2` 参数错误。

**等价性**（REQ-UNINST-08 / AC-18）：`uninstall.sh --target X` ≡ `install.sh --uninstall --target X`，共享 `sg_uninstall_platform`。

### 10.4 专用 install.sh CLI（REQ-INST-OC-01 / REQ-INST-CC-01）

OpenCode 专用 `install.sh`：无 `--target` 参数（仅安装 OpenCode），接受 `--prefix`/`--bin-dir`/`--no-binary`/`--uninstall`/`--verify`/`--yes`。

ClaudeCode 专用 `install.sh`：无 `--target` 参数（仅安装 ClaudeCode），接受相同参数，安装时执行 `sg_merge_permissions`。

---

## 11. zip 包结构设计

### 11.1 统一包 `secguard-<version>.zip`（REQ-MASTER-02 / §4.4 of spec）

```text
secguard-<version>/
  install.sh                              # 自包含，sg_* 已内联注入
  uninstall.sh                            # 自包含，独立卸载入口
  VERSION
  manifest.json
  README.md
  LICENSE                                 # 若根目录存在
  secguard-darwin-amd64
  secguard-darwin-arm64
  secguard-linux-amd64
  secguard-linux-arm64
  shared/
    agent-body.md
    command-instructions.md
    skills/
      null-deref/SKILL.md
      buffer-overflow/SKILL.md
      ... (共 14 个)
  opencode/
    extension.json                        # version 字段已同步
    opencode.json
    commands/secguard.md                 # 已展开 {{include}}
    agents/security-auditor.md            # 已展开
    tools/secguard_*.ts
    plugins/secguard-context.ts
  claude-code/
    .claude-plugin/plugin.json            # version 字段已同步
    .claude/
      settings.json
      commands/secguard.md               # 已展开
      agents/security-auditor.md          # 已展开
    hooks/hooks.json
```

### 11.2 OpenCode 专用包 `secguard-extension-opencode-<version>.zip`（REQ-OC-02）

根目录即 extension（无顶层包裹目录）：

```text
extension.json
opencode.json
install.sh                                # OpenCode 专用，自包含
uninstall.sh                              # OpenCode 专用，自包含
VERSION
manifest.json
commands/secguard.md                     # 已展开
agents/security-auditor.md                # 已展开
tools/secguard_*.ts
plugins/secguard-context.ts
skills/
  null-deref/SKILL.md
  ... (共 14 个)
```

### 11.3 ClaudeCode 专用包 `secguard-extension-claude-code-<version>.zip`（REQ-CC-02）

根目录即 plugin：

```text
.claude-plugin/plugin.json               # version 字段已同步
install.sh                                # ClaudeCode 专用，自包含
uninstall.sh                              # ClaudeCode 专用，自包含
VERSION
manifest.json
commands/secguard.md                     # 已展开
agents/security-auditor.md                # 已展开
hooks/hooks.json
skills/
  null-deref/SKILL.md
  ... (共 14 个)
bin/
  secguard-darwin-amd64
  secguard-darwin-arm64
  secguard-linux-amd64
  secguard-linux-arm64
```

### 11.4 排除规则（REQ-MASTER-04 / AC-10 / NFR-SEC-01）

打包时排除：`.gocache`、`.gotmp`、`*.db`、`sgre.db`、`.DS_Store`、`__pycache__`、`.git`、`.env`、`credentials.json`、`*.key`、`*.pem`。

实现：`zip -X -r ... -x "*.gocache*" -x "*.gotmp*" -x "*.db" -x "*.DS_Store" -x "*__pycache__*" -x "*.env" -x "*credentials*" -x "*.key" -x "*.pem"`

### 11.5 可重复构建（NFR-REL-01）

- `go build -trimpath`：去除构建路径。
- `zip -X`：不存额外文件属性时间戳。
- `manifest.json` 的 `build_date` 取 `VERSION` 文件 mtime（固定值），非当前时间。
- `extension.json`/`plugin.json` 的 `version` 字段由版本决定，确定性。

---

## 12. 错误处理与回退

| 场景 | 处理 | 关联需求 |
|------|------|----------|
| `VERSION` 文件不存在 | 回退 git describe，再回退 `0.0.0-dev` | REQ-VER-02/03 |
| git 非仓库 | 回退 `0.0.0-dev` | REQ-VER-03 |
| CGO 交叉编译工具链缺失 | 警告并跳过该目标；全部失败则回退本机构建 | REQ-BIN-04 |
| 本机构建也失败 | exit 1，中止打包 | NFR-REL-02 |
| `go test` 失败（--test） | exit 1，中止打包 | REQ-BIN-05 |
| 包内无匹配当前平台二进制 | stderr 列出可用目标，exit 1 | REQ-INST-06 |
| `bin-dir` 无写权限 | 回退 `~/.local/bin` | REQ-INST-03 |
| 重复安装同版本 | 覆盖文件，不报错（幂等） | REQ-INST-10 / AC-04 |
| 安装不同版本 | 先按 manifest 卸载旧版，再安装新版 | REQ-INST-11 |
| manifest 缺失/损坏 | 警告，回退启发式清理（按约定路径） | 风险-4 / REQ-UNINST-03 |
| `secguard --version` 执行失败（动态库缺失） | verify 该项 ✗，记录错误，不整体崩溃 | 风险-5 / REQ-VERIFY-02 |
| python3 不存在 | 权限合并/JSON 操作失败，警告但安装继续（权限可后补） | NFR-PORT-02 |
| `zip` 时间戳差异 | 用 `zip -X` 规避 | 风险-1 / NFR-REL-01 |
| 模板中残留 `source .../lib.sh` | 打包后静态检查失败，打包中止 | REQ-LIB-04 / AC-16 |
| 注入标记缺失 | `inject_into` 断言失败，打包中止 | §5.2 |

---

## 13. 与现有脚本的兼容性

### 13.1 build.sh 向后兼容（AC-11）

- 无 `--package`/`--dist` 参数时，`build.sh` 执行原有逻辑：`go build -o bin/secguard ./cmd/secguard`，`--test`/`--install`/`--help` 行为不变。
- 新增参数仅在 `--package` 时生效，透传给 `release/build-packages.sh`。
- 实现方式：在现有参数解析循环中新增 `--package`/`--version`/`--os`/`--arch`/`--target` 分支，设置 `DO_PACKAGE=true` 及相应变量；脚本末尾 `if [ "$DO_PACKAGE" = true ]; then exec release/build-packages.sh ...; fi`，在原有构建逻辑之后。

### 13.2 deploy.sh 改造（REQ-LIB-02 / NFR-MAINT-01 / AC-15）

- 移除 `deploy.sh` 内联的 `expand_includes()` 函数（第 103-122 行）。
- 在脚本头部加入：`source "$SCRIPT_DIR/release/lib.sh"`。
- `lib.sh` 中 `expand_includes` 包装 `sg_expand_includes`，签名兼容（`deploy.sh` 调用 `expand_includes "$f" "$out"`，`lib.sh` 中 `expand_includes() { sg_expand_includes "$1" "$2" "$SHARED_DIR"; }`，或调整 `deploy.sh` 调用传 `$SHARED_DIR`）。
- 其余 `deploy.sh` 行为（`build_binary`、`install_opencode`、`install_claude_code`、`merge_claude_permissions`、`sync_project_local`、验证）不变，与发行包安装并存。
- `merge_claude_permissions` 可保留在 `deploy.sh`（开发模式专用），或也迁入 `lib.sh` 可注入区复用 `sg_merge_permissions`。推荐后者以进一步 DRY。

### 13.3 extension/install.sh 处置（已删除）

- 删除该文件（其 `expand_includes` 重复实现移除）。
- 若开发者需本地试运行安装，使用 `release/build-packages.sh` 生成的注入后副本，或直接运行 `deploy.sh`。

### 13.4 现有 dist/ 产物

- 现有 `secguard-v0.1.0.zip` 等旧产物可保留或清理；新打包产物命名为 `secguard-<version>.zip`（无 `v` 前缀，与 spec 一致）。若需保留 `v` 前缀兼容，可在 `build-packages.sh` 中统一为 `secguard-<version>.zip`（spec REQ-MASTER-01 即此格式）。

---

## 14. 验收标准映射

| AC ID | 验收标准 | 保证设计点 |
|-------|---------|------------|
| AC-01 | `./build.sh --package` 后 `dist/` 有 3 zip + 3 sha256 | §3.1 步骤 11-14；`build_target` ×4 + 三包组装 + `sha256_file` |
| AC-02 | 统一包 `install.sh --target all` 干净环境成功安装 | §3.2 安装流程；路径对齐 §1.3；`sg_select_binary` |
| AC-03 | `install.sh --uninstall` 删除所有已安装文件 | §3.3 卸载流程；`sg_uninstall_platform` 读 manifest 删除 |
| AC-04 | 重复 `install.sh --target all` 幂等不报错 | §1.3 幂等原则；文件覆盖；权限集合去重 §8.2 |
| AC-05 | OpenCode 专用包可被直接加载 | §11.2 包结构根目录即 extension；`extension.json` version 同步 |
| AC-06 | ClaudeCode 专用包可被作为 plugin 发现 | §11.3 包结构；`.claude-plugin/plugin.json` |
| AC-07 | 含全部 14 skills | §3.1 步骤 7 glob 自动发现；`manifest.json` skills 列表；NFR-MAINT-02 |
| AC-08 | manifest.json version 与 zip 文件名一致 | §7.1；`resolve_version` 单一来源贯穿命名与 manifest |
| AC-09 | `.sha256` 校验通过 | `sha256_file` 生成 `<hash>  <filename>` 格式 |
| AC-10 | 包内无 .gocache/.gotmp/*.db/.DS_Store | §11.4 排除规则 |
| AC-11 | `./build.sh` 无 `--package` 行为不变 | §13.1 向后兼容 |
| AC-12 | macOS arm64 自动选择 darwin-arm64 | `sg_detect_os`/`sg_detect_arch`/`sg_select_binary` §4.2 |
| AC-13 | 安装路径与 deploy.sh 一致 | §1.3 路径一致；`extensions/zhuque-secguard/`、`skills/zhuque-secguard/` |
| AC-14 | ClaudeCode 安装后 settings.json 含 7 项权限，重复不重复添加 | §8.2 `sg_merge_permissions` 集合去重 |
| AC-15 | lib.sh 存在且 build-packages.sh/deploy.sh source 引用 | §2.1.1 lib.sh；§13.2 deploy.sh 改造 |
| AC-16 | zip 内 install.sh 不含 source lib.sh，可独立运行 | §5.4 自包含保证；静态检查 |
| AC-17 | 修改 lib.sh 后重新打包自动包含新实现 | §5.5 单一来源保证；`extract_inject_block` |
| AC-18 | uninstall.sh 存在且等价 install.sh --uninstall | §3.3；`sg_uninstall_platform` 共享；REQ-UNINST-08 |
| AC-19 | 跨版本卸载，仅删指定平台 | `sg_uninstall_platform` 读 manifest.files 按 target 过滤；§7.2 跨版本 |
| AC-20 | 卸载前展示清单，--yes 跳过，清理空目录不删用户文件 | `sg_confirm_action`；§3.3 步骤 6/9；REQ-INST-12 |
| AC-21 | --verify 全 ✓ 退出 0；删一个 skill 后 ✗ 退出非 0 | §3.4 `sg_verify_platform`；逐项检测 |
| AC-22 | --verify 覆盖二进制/关键文件/路径/权限 | §3.4 步骤 4-6；REQ-VERIFY-02~05 |

---

## 附录 A：lib.sh 可注入区结构示意

```bash
# release/lib.sh
# 构建侧共享函数库。构建脚本 source 本文件复用；
# zip 内 install.sh/uninstall.sh 不 source 本文件，所需函数由打包时内联注入。

# ── 可注入区（打包时提取，注入到 zip 内脚本）──────────────────────
# @@SG_INJECT_START@@

sg_expand_includes() {
    local input_file="$1" output_file="$2" shared_dir="$3"
    cp "$input_file" "$output_file"
    for shared_file in "$shared_dir"/*.md; do
        [ -f "$shared_file" ] || continue
        local shared_name; shared_name=$(basename "$shared_file")
        local shared_rel="shared/$shared_name"
        if grep -q "{{include $shared_rel}}" "$output_file" 2>&1; then
            python3 -c "
with open('$output_file','r') as f: c=f.read()
with open('$shared_file','r') as f: inc=f.read()
with open('$output_file','w') as f: f.write(c.replace('{{include $shared_rel}}',inc))
"
        fi
    done
}

sg_select_binary() { ... }       # §4.2
sg_detect_os() { ... }
sg_detect_arch() { ... }
sg_write_install_manifest() { ... }   # python3 写 JSON
sg_read_install_manifest() { ... }
sg_merge_permissions() { ... }   # §8.2
sg_remove_permissions() { ... }  # §8.3
sg_check_permissions_merged() { ... }
sg_uninstall_platform() { ... }  # §3.3 核心卸载
sg_verify_platform() { ... }     # §3.4 核心验证
sg_confirm_action() { ... }

# @@SG_INJECT_END@@
# ── 可注入区结束 ────────────────────────────────────────────────

# ── 构建侧专用函数（不注入）─────────────────────────────────────
resolve_version() { ... }        # §9
build_target() { ... }           # §6
sha256_file() { ... }
write_manifest() { ... }         # §7.1
expand_includes() { sg_expand_includes "$1" "$2" "$3"; }  # 构建侧别名
extract_inject_block() { ... }   # §5.2
inject_into() { ... }            # §5.2
```

## 附录 B：install.sh.tmpl 结构示意

```bash
#!/bin/bash
set -euo pipefail

# @@SG_LIB_INJECT@@

PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_VERSION="$(cat "$PKG_DIR/VERSION" 2>/dev/null || echo unknown)"

# ── 参数解析 ──
TARGET="all"; PREFIX=""; BIN_DIR=""; NO_BINARY=false; UNINSTALL=false; VERIFY=false; YES=false
while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="$2"; shift 2 ;;
        --prefix) PREFIX="$2"; shift 2 ;;
        --bin-dir) BIN_DIR="$2"; shift 2 ;;
        --no-binary) NO_BINARY=true; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --verify) VERIFY=true; shift ;;
        --yes|-y) YES=true; shift ;;
        --help|-h) usage; exit 0 ;;
        *) echo "Unknown: $1"; exit 2 ;;
    esac
done

# 互斥检查
if [ "$UNINSTALL" = true ] && [ "$VERIFY" = true ]; then
    echo "ERROR: --uninstall and --verify are mutually exclusive"; exit 2
fi

# ── 路径解析 ──
OC_PREFIX="${PREFIX:-$HOME/.config/opencode}"
CC_PREFIX="${PREFIX:-$HOME/.claude}"
OC_TARGET_DIR="$OC_PREFIX/extensions/zhuque-secguard"
CC_TARGET_DIR="$CC_PREFIX/skills/zhuque-secguard"
if [ -z "$BIN_DIR" ]; then
    if [ -w /usr/local/bin ]; then BIN_DIR="/usr/local/bin"
    else BIN_DIR="$HOME/.local/bin"; fi
fi

# ── 分发 ──
if [ "$VERIFY" = true ]; then
    sg_verify_platform "$TARGET" "$OC_PREFIX" "$BIN_DIR" "$PKG_VERSION"
    exit $?
fi
if [ "$UNINSTALL" = true ]; then
    # 对每个平台调用 sg_uninstall_platform
    ...
    exit 0
fi
# ── 安装 ──
# 先卸载旧版本（若 manifest 存在且版本不同）
...
# 安装 opencode / claude-code / binary
...
# 写 manifest
sg_write_install_manifest ...
```

## 附录 C：关键设计决策摘要

1. **双区 lib.sh + 标记注入**：`lib.sh` 分构建专用区与可注入区（`@@SG_INJECT_START/END@@`），打包时 `extract_inject_block` 提取可注入区，`inject_into` 替换模板占位标记 `@@SG_LIB_INJECT@@`。实现"构建侧 source 共享 + 安装侧自包含"，单一来源，`sg_` 前缀防冲突。

2. **双 manifest**：包内 `manifest.json`（描述包内容，可重复构建）+ 安装后 `.secguard-install-manifest`（记录绝对路径，供跨版本卸载）。manifest 缺失时启发式清理降级。

3. **路径对齐 deploy.sh**：发行包安装路径与开发部署路径完全一致（`extensions/zhuque-secguard/`、`skills/zhuque-secguard/`），修复现有 `release/install.sh` 装装到根目录的 bug。

4. **CGO 跨平台回退**：逐目标构建，失败警告跳过，全失败回退本机，不中断整体打包（NFR-REL-02）。

5. **权限操作用 python3**：幂等合并/移除，保留 deny 与其它权限，规避 sed 跨平台差异（NFR-PORT-02/NFR-SEC-03）。

6. **install.sh 单主入口 + uninstall.sh 独立入口**：`--uninstall`/`--verify` 子模式收敛入口；`uninstall.sh` 满足高频独立卸载直觉，二者共享 `sg_uninstall_platform`。

7. **可重复构建**：`go build -trimpath` + `zip -X` + manifest build_date 取 VERSION mtime。

8. **glob 自动发现 skills**：新增 skill 自动打包，无需改脚本（NFR-MAINT-02）。