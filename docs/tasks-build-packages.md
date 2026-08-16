# SecGuard 构建打包与发行 — 实现任务清单

| 字段 | 值 |
|------|-----|
| 文档标题 | SecGuard 构建打包与发行实现任务清单 |
| 创建日期 | 2026-08-11 |
| 关联需求规格 | `docs/spec-build-packages.md` v1.2 |
| 关联技术设计 | `docs/design-build-packages.md` v1.0 |
| 状态 | 待执行 |

---

## 任务概览

| ID | 标题 | 依赖 | 版本 |
|----|------|------|------|
| T1 | 创建 VERSION 文件 | — | 第一版本 |
| T2 | 实现 lib.sh 可注入区（sg_* 函数） | — | 第一版本 |
| T3 | 实现 lib.sh 构建侧专用函数 | T2 | 第一版本 |
| T4 | 创建统一包 install.sh.tmpl 模板 | T2 | 第一版本 |
| T5 | 创建统一包 uninstall.sh 模板 | T2 | 第一版本 |
| T6 | 创建 OpenCode 专用 install/uninstall 模板 | T2 | 第一版本 |
| T7 | 创建 ClaudeCode 专用 install/uninstall 模板 | T2 | 第一版本 |
| T8 | 重构 build-packages.sh 为打包核心 | T1, T3, T4, T5, T6, T7 | 第一版本 |
| T9 | 扩展根目录 build.sh 集成 --package | T8 | 第一版本 |
| T10 | 重构 deploy.sh 复用 lib.sh | T3 | 第一版本 |
| T11 | 删除 extension/install.sh ✅ | T10 | 第一版本 |
| T12 | 端到端集成验证 | T1–T11 | 第一版本 |
| T13 | 可重复构建增强（固定时间戳） | T12 | 后续优化 |
| T14 | 启发式清理与降级增强 | T12 | 后续优化 |

> **第一版本目标**：可端到端工作的打包流程——三包能生成、install.sh 能装、uninstall.sh 能卸、--verify 能验。跨平台 CGO 交叉编译实现"本机 + 尽力跨平台，失败回退"。

---

## 1. 基础设施

### T1：创建 VERSION 文件

- **涉及文件**：`VERSION`（根目录新建）
- **依赖**：无
- **版本**：第一版本必须
- **实现步骤**：
  1. 在项目根目录 `/Users/kongan/workbench/github/secguard-clang/` 创建 `VERSION` 文件
  2. 内容为单行版本号，如 `1.2.0`（无前导 `v`，无尾部换行外的空白）
  3. 此文件作为 `resolve_version` 的第二优先级来源（REQ-VER-01），并被打入发行包顶层
- **验证方式**：
  - `[ -f VERSION ] && cat VERSION` 输出 `1.2.0`
  - `tr -d '[:space:]' < VERSION` 输出非空

---

## 2. 共享函数库 lib.sh

### T2：实现 lib.sh 可注入区（sg_* 函数）

- **涉及文件**：`release/lib.sh`（新建）
- **依赖**：无
- **版本**：第一版本必须
- **实现步骤**：
  1. 创建 `release/lib.sh`，文件头注释说明：构建侧 source 复用；zip 内脚本不 source，函数由打包时内联注入
  2. 写入可注入区起始标记：`# @@SG_INJECT_START@@`
  3. 实现以下 `sg_` 前缀函数（全部位于标记区间内，不得引用包外路径或 `source` 外部文件）：
     - `sg_expand_includes(input_file, output_file, shared_dir)`：模板展开，将 `{{include shared/<name>}}` 替换为对应文件内容；用 python3 处理多行替换（避免 sed 跨平台差异）；同时展开 `skills/*/SKILL.md` 引用
     - `sg_detect_os()`：`uname -s` 映射（Darwin→darwin，Linux→linux），stdout 输出
     - `sg_detect_arch()`：`uname -m` 映射（x86_64→amd64，aarch64/arm64→arm64），stdout 输出
     - `sg_select_binary(pkg_dir, os, arch)`：查找 `secguard-<os>-<arch>`，找到则 stdout 输出路径返回 0；未找到则 stderr 列出包内所有 `secguard-*` 候选并返回 1
     - `sg_write_install_manifest(manifest_path, version, target, bin_path, files_csv)`：用 python3 写出 `.secguard-install-manifest` JSON（schema 见 design §7.2：version、install_date、target、bin_path、files 绝对路径列表）
     - `sg_read_install_manifest(manifest_path)`：读取并校验 JSON 合法性，stdout 输出 JSON 内容；不存在/损坏时返回非 0
     - `sg_merge_permissions(settings_path)`：用 python3 将 7 项 `Bash(secguard *)` 权限幂等合并进 `permissions.allow`，保留 `deny` 列表与其它权限项（design §8.2 提供完整 python3 实现）
     - `sg_remove_permissions(settings_path)`：从 `permissions.allow` 移除 7 项 secguard 权限，保留其它项；文件不存在时静默返回 0（幂等）
     - `sg_check_permissions_merged(settings_path)`：检测 7 项是否全在 `allow` 中，全在返回 0，缺失返回非 0
     - `sg_uninstall_platform(platform, prefix, bin_dir, manifest_path, yes)`：核心卸载逻辑——读取 manifest → 按 platform 过滤待删除文件 → 交互确认（若非 yes 且为 tty）→ 逐个 `rm -f` → 若 platform 含 claude-code 则调用 `sg_remove_permissions` → 自底向上清理空目录（rmdir 空的 zhuque-secguard/ 及其父目录仅当空）→ 若所有文件已删则 rm manifest
     - `sg_verify_platform(platform, prefix, bin_dir, pkg_version)`：核心验证逻辑——逐项检测（二进制存在/可执行/版本匹配；extension.json 或 plugin.json 存在；commands/secguard.md、agents/security-auditor.md、14 个 skills/*/SKILL.md 存在；平台发现路径正确；ClaudeCode 权限已合并），每项标注 ✓/✗，全通过返回 0 否则返回 1
     - `sg_confirm_action(prompt)`：交互确认，非 tty 自动返回 0，tty 时读取用户输入 y/yes 返回 0 否则非 0
  4. 写入可注入区结束标记：`# @@SG_INJECT_END@@`
  5. 权限项清单（7 项）定义为常量数组，供 merge/remove/check 共用：
     - `Bash(secguard scan *)`、`Bash(secguard index *)`、`Bash(secguard plan *)`、`Bash(secguard report *)`、`Bash(secguard status *)`、`Bash(secguard query *)`、`Bash(secguard db *)`
  6. 所有 JSON 操作用 python3 heredoc，不依赖 `jq`
- **验证方式**：
  - `bash -n release/lib.sh` 语法检查通过
  - `grep -c '^sg_' release/lib.sh` ≥ 12（至少 12 个 sg_ 函数）
  - `awk '/@@SG_INJECT_START@@/{f=1} /@@SG_INJECT_END@@/{f=0} f' release/lib.sh | grep -c 'sg_'` ≥ 12（全部在标记区间内）
  - 手动 source 后调用 `sg_detect_os`、`sg_detect_arch` 输出当前平台

---

### T3：实现 lib.sh 构建侧专用函数

- **涉及文件**：`release/lib.sh`（续写，在 `@@SG_INJECT_END@@` 之后）
- **依赖**：T2
- **版本**：第一版本必须
- **实现步骤**：
  1. 在 `release/lib.sh` 的 `# @@SG_INJECT_END@@` 之后追加构建侧专用函数区（不注入 zip）
  2. 定义全局路径变量（文件顶部或函数内计算）：`PROJECT_ROOT`、`SGRE_DIR=$PROJECT_ROOT/sgre`、`DIST_DIR=$PROJECT_ROOT/dist`、`EXTENSION_DIR=$PROJECT_ROOT/extension`、`LIB_SH` 自身路径
  3. 实现以下函数：
     - `resolve_version(explicit)`：三级回退——`$1` 非空用之；否则读 `VERSION` 文件去空白；否则 `git describe --tags --always --dirty`；否则 `0.0.0-dev`（design §9.1 伪代码）
     - `build_target(goos, goarch, version)`：设置 `GOOS`/`GOARCH`/`CGO_ENABLED=1`/`GOFLAGS=-mod=mod`/`GONOSUMDB=*`/`GOCACHE=$SGRE_DIR/.gocache`/`TMPDIR=$SGRE_DIR/.gotmp`，在 `sgre/` 下 `go build -trimpath -o $DIST_DIR/secguard-<os>-<arch> ./cmd/secguard`，成功 stdout 输出二进制绝对路径，失败返回非 0
     - `sha256_file(file_path)`：`shasum -a 256 "$1" | cut -d' ' -f1`（macOS/Linux 兼容）
     - `write_manifest(pkg_root, version, targets_csv, skills_csv)`：用 python3 生成 `manifest.json`（schema：version、build_date、go_version、targets、skills、files 相对路径→sha256）；`build_date` 第一版本取当前 UTC 时间（T13 优化为 VERSION mtime）；`go_version` 解析 `go version` 输出
     - `expand_includes(input_file, output_file, shared_dir)`：构建侧别名，直接委托 `sg_expand_includes "$1" "$2" "$3"`（DRY，design §4.1）
     - `extract_inject_block(lib_sh_path)`：用 awk 提取 `# @@SG_INJECT_START@@` 与 `# @@SG_INJECT_END@@` 之间的内容（含 sg_* 函数定义），stdout 输出（design §5.2）
     - `inject_into(template_path, inject_block)`：用 python3 将 `$inject_block` 替换模板中的 `# @@SG_LIB_INJECT@@` 占位标记，stdout 输出注入后完整脚本；断言占位标记存在否则失败（design §5.2）
  4. 文件末尾不加任何执行逻辑（纯函数库，供 source）
- **验证方式**：
  - `bash -n release/lib.sh` 语法通过
  - `source release/lib.sh && resolve_version "9.9.9"` 输出 `9.9.9`
  - `source release/lib.sh && resolve_version ""` 输出 `1.2.0`（依赖 T1）
  - `source release/lib.sh && extract_inject_block release/lib.sh | grep -c 'sg_'` ≥ 12

---

## 3. 安装/卸载脚本模板

### T4：创建统一包 install.sh.tmpl 模板

- **涉及文件**：`release/install.sh.tmpl`（新建，取代现有 `release/install.sh`）
- **依赖**：T2（需知可用 sg_* 函数签名）
- **版本**：第一版本必须
- **实现步骤**：
  1. 创建 `release/install.sh.tmpl`，shebang `#!/bin/bash`，`set -euo pipefail`
  2. 在 shebang 之后、任何逻辑之前写入占位标记：`# @@SG_LIB_INJECT@@`（打包时由 `inject_into` 替换为 sg_* 函数定义）
  3. **禁止**出现任何 `source .../lib.sh` 语句（REQ-LIB-04）
  4. 定义 `PKG_DIR="$(cd "$(dirname "$0")" && pwd)"`、`PKG_VERSION="$(cat "$PKG_DIR/VERSION" 2>/dev/null || echo unknown)"`
  5. 参数解析循环（design 附录 B）：`--target`（默认 all）、`--prefix`、`--bin-dir`、`--no-binary`、`--uninstall`、`--verify`、`--yes`/`-y`、`--help`/`-h`；未知参数 exit 2
  6. 互斥检查：`--uninstall` 与 `--verify` 同时指定时报错 exit 2
  7. 路径解析：
     - `OC_PREFIX="${PREFIX:-$HOME/.config/opencode}"`
     - `CC_PREFIX="${PREFIX:-$HOME/.claude}"`
     - `OC_TARGET_DIR="$OC_PREFIX/extensions/zhuque-secguard"`（与 deploy.sh 一致，REQ-INST-07）
     - `CC_TARGET_DIR="$CC_PREFIX/skills/zhuque-secguard"`（REQ-INST-08）
     - `BIN_DIR` 默认 `/usr/local/bin`，无写权限时回退 `$HOME/.local/bin`（REQ-INST-03）
  8. 分发逻辑：
     - 若 `--verify`：调用 `sg_verify_platform "$TARGET" "$OC_PREFIX" "$BIN_DIR" "$PKG_VERSION"`，exit 其返回码
     - 若 `--uninstall`：对每个目标平台调用 `sg_uninstall_platform`，exit 0
     - 否则执行安装：
       a. 检测当前平台 `cur_os=$(sg_detect_os)`、`cur_arch=$(sg_detect_arch)`
       b. 若存在旧 manifest 且版本不同：先调用 `sg_uninstall_platform` 卸载旧版（REQ-INST-11）
       c. 若 TARGET 含 opencode：`install_opencode()`——mkdir 目标目录结构，复制 extension.json、opencode.json、commands/*.md、agents/*.md、tools/*.ts、plugins/*.ts、skills/*/SKILL.md（glob 自动 14 个），记录已安装文件到 `installed_files[]`
       d. 若 TARGET 含 claude-code：`install_claude_code()`——mkdir 目标目录结构，复制 .claude-plugin/plugin.json、hooks/hooks.json、commands/*.md、agents/*.md、skills/*/SKILL.md，调用 `sg_merge_permissions "$CC_PREFIX/settings.json"`，记录已安装文件
       e. 若非 `--no-binary`：`bin=$(sg_select_binary "$PKG_DIR" "$cur_os" "$cur_arch")`，失败则 exit 1；`cp "$bin" "$BIN_DIR/secguard"`，`chmod +x`，记录到 installed_files[]
       f. 调用 `sg_write_install_manifest` 写入安装清单（REQ-INST-09）
       g. 打印安装摘要
  9. `--help` 输出用法（参数表）
- **验证方式**：
  - `bash -n release/install.sh.tmpl` 语法通过
  - `grep 'source.*lib\.sh' release/install.sh.tmpl` 无匹配（自包含保证）
  - `grep '@@SG_LIB_INJECT@@' release/install.sh.tmpl` 有且仅有一处匹配

---

### T5：创建统一包 uninstall.sh 模板

- **涉及文件**：`release/uninstall.sh`（新建模板，含占位标记）
- **依赖**：T2
- **版本**：第一版本必须
- **实现步骤**：
  1. 创建 `release/uninstall.sh`，shebang `#!/bin/bash`，`set -euo pipefail`
  2. 写入占位标记 `# @@SG_LIB_INJECT@@`
  3. **禁止** `source .../lib.sh`
  4. 定义 `PKG_DIR`、`PKG_VERSION`（同 T4）
  5. 参数解析：`--target`（默认 all）、`--prefix`、`--bin-dir`、`--yes`/`-y`、`--help`/`-h`；无 `--uninstall`/`--verify`（此脚本专司卸载）
  6. 路径解析（同 T4，用于定位 manifest）
  7. 主逻辑：定位 manifest（`$OC_PREFIX/.secguard-install-manifest` 或 `$CC_PREFIX/.secguard-install-manifest`），对每个目标平台调用 `sg_uninstall_platform "$platform" "$prefix" "$BIN_DIR" "$manifest_path" "$YES"`（REQ-UNINST-08 等价于 install.sh --uninstall）
  8. manifest 均不存在时：警告并回退启发式清理——按约定路径删除 `extensions/zhuque-secguard/`、`skills/zhuque-secguard/`、`<bin-dir>/secguard`（基础版，T14 增强）
  9. `--help` 输出用法
- **验证方式**：
  - `bash -n release/uninstall.sh` 语法通过
  - `grep 'source.*lib\.sh' release/uninstall.sh` 无匹配
  - `grep '@@SG_LIB_INJECT@@' release/uninstall.sh` 有且仅有一处匹配

---

### T6：创建 OpenCode 专用 install/uninstall 模板

- **涉及文件**：
  - `release/install-opencode.sh.tmpl`（新建，重构现有 `install-opencode.sh`）
  - `release/uninstall-opencode.sh`（新建模板）
- **依赖**：T2
- **版本**：第一版本必须
- **实现步骤**：
  1. **install-opencode.sh.tmpl**：
     - shebang + `set -euo pipefail` + 占位标记 `# @@SG_LIB_INJECT@@`
     - 无 `--target` 参数（仅安装 OpenCode，REQ-INST-OC-01）
     - 接受 `--prefix`、`--bin-dir`、`--no-binary`、`--uninstall`、`--verify`、`--yes`/`-y`、`--help`
     - 安装路径：`OC_TARGET_DIR="${PREFIX:-$HOME/.config/opencode}/extensions/zhuque-secguard"`（与 deploy.sh 一致）
     - 包根即当前目录（PKG_DIR=$(dirname $0)），直接复制包内 extension.json、opencode.json、commands/、agents/、tools/、plugins/、skills/ 到 OC_TARGET_DIR
     - 二进制安装：OpenCode 专用包不含二进制（design §6.4），默认 `--no-binary` 行为；若用户指定安装二进制则从 PATH 检测或提示
     - `--uninstall`/`--verify` 分发到 `sg_uninstall_platform "opencode" ...` / `sg_verify_platform "opencode" ...`
  2. **uninstall-opencode.sh**：
     - 同 install-opencode 的卸载子模式，无 `--target`，调用 `sg_uninstall_platform "opencode" ...`
- **验证方式**：
  - `bash -n release/install-opencode.sh.tmpl` 与 `bash -n release/uninstall-opencode.sh` 语法通过
  - 两文件均含 `@@SG_LIB_INJECT@@` 且无 `source.*lib\.sh`

---

### T7：创建 ClaudeCode 专用 install/uninstall 模板

- **涉及文件**：
  - `release/install-claude-code.sh.tmpl`（新建，重构现有 `install-claude-code.sh`）
  - `release/uninstall-claude-code.sh`（新建模板）
- **依赖**：T2
- **版本**：第一版本必须
- **实现步骤**：
  1. **install-claude-code.sh.tmpl**：
     - shebang + `set -euo pipefail` + 占位标记 `# @@SG_LIB_INJECT@@`
     - 无 `--target` 参数（仅安装 ClaudeCode，REQ-INST-CC-01）
     - 接受 `--prefix`、`--bin-dir`、`--no-binary`、`--uninstall`、`--verify`、`--yes`/`-y`、`--help`
     - 安装路径：`CC_TARGET_DIR="${PREFIX:-$HOME/.claude}/skills/zhuque-secguard"`（与 deploy.sh 一致）
     - 复制 .claude-plugin/plugin.json、commands/、agents/、hooks/、skills/、bin/ 到 CC_TARGET_DIR
     - 调用 `sg_merge_permissions "$CC_PREFIX/settings.json"` 合并 7 项权限（REQ-CC-03）
     - 二进制安装：ClaudeCode 包含 bin/secguard-<os>-<arch>，用 `sg_select_binary` 选择匹配平台二进制复制为 `<bin-dir>/secguard`
     - `--uninstall`/`--verify` 分发
  2. **uninstall-claude-code.sh**：
     - 调用 `sg_uninstall_platform "claude-code" ...`，含权限移除（`sg_remove_permissions`）
- **验证方式**：
  - `bash -n` 两文件语法通过
  - 含 `@@SG_LIB_INJECT@@` 且无 `source.*lib\.sh`

---

## 4. 打包核心

### T8：重构 build-packages.sh 为打包核心

- **涉及文件**：`release/build-packages.sh`（重写）
- **依赖**：T1, T3, T4, T5, T6, T7
- **版本**：第一版本必须
- **实现步骤**：
  1. shebang `#!/bin/bash`，`set -euo pipefail`
  2. 计算路径：`SCRIPT_DIR`、`PROJECT_ROOT`、`SGRE_DIR`、`EXTENSION_DIR`、`DIST_DIR=$PROJECT_ROOT/dist`、`LIB_SH=$SCRIPT_DIR/lib.sh`
  3. `source "$LIB_SH"` 加载公共函数（REQ-LIB-02）
  4. 解析 CLI 参数：`--version`、`--os`、`--arch`、`--target`（master/opencode/claude-code/all，默认 all）、`--test`、`--help`
  5. `version=$(resolve_version "$EXPLICIT_VERSION")`，打印版本
  6. 若 `--test`：在 `sgre/` 下运行 `go test ./...`，失败 exit 1（REQ-BIN-05）
  7. 计算目标矩阵 `targets`：默认 `[(darwin,amd64),(darwin,arm64),(linux,amd64),(linux,arm64)]`；`--os`/`--arch` 过滤（REQ-BIN-01/02）
  8. 跨平台构建（design §6.2 回退策略）：
     - 对每个 `(goos, goarch)` 调用 `build_target`，成功记录路径，失败记录警告
     - 全部失败时回退本机目标 `build_target $(go env GOOS) $(go env GOARCH) $version`；本机也失败则 exit 1
     - 部分失败不中断（NFR-REL-02），manifest.targets 只记录成功目标
  9. `skills=$(ls $EXTENSION_DIR/shared/skills/*/SKILL.md | xargs -n1 dirname | xargs -n1 basename | sort)`（自动发现 14 个，NFR-MAINT-02）
  10. 对需要展开的文件调用 `expand_includes`（构建侧，source 自 lib.sh）：`opencode/commands/secguard.md`、`opencode/agents/security-auditor.md`、`claude-code/.claude/commands/secguard.md`、`claude-code/.claude/agents/security-auditor.md`
  11. 覆写 `extension/opencode/extension.json` 与 `extension/claude-code/.claude-plugin/plugin.json` 的 version 字段为 `$version`（DATA-03/04，用 python3）
  12. `inject_block=$(extract_inject_block "$LIB_SH")` 提取可注入区
  13. **组装统一包**（若 target 含 master/all）：
      - 创建临时目录 `$DIST_DIR/.tmp-master/secguard-$version/`
      - 复制 4 个二进制 `secguard-<os>-<arch>`（成功的目标）
      - 复制 `shared/`（agent-body.md、command-instructions.md、skills/*/SKILL.md）
      - 复制 `opencode/`（已展开）、`claude-code/`（已展开）
      - `inject_into "$SCRIPT_DIR/install.sh.tmpl" "$inject_block" > "$MASTER_ROOT/install.sh"` && `chmod +x`
      - `inject_into "$SCRIPT_DIR/uninstall.sh" "$inject_block" > "$MASTER_ROOT/uninstall.sh"` && `chmod +x`
      - 写入 `VERSION`、`manifest.json`（`write_manifest`）、`README.md`、`LICENSE`（若根目录存在）
      - 静态检查：`grep -n 'source.*lib\.sh' "$MASTER_ROOT/install.sh" "$MASTER_ROOT/uninstall.sh"` 必须无匹配否则 exit 1（REQ-LIB-04）
      - `cd .tmp-master && zip -X -r "$DIST_DIR/secguard-$version.zip" "secguard-$version" -x 排除规则`（design §11.4）
  14. **组装 OpenCode 专用包**（若 target 含 opencode/all）：
      - 创建临时目录 `$DIST_DIR/.tmp-oc-ext/`（根目录即 extension，无顶层包裹）
      - 复制 extension.json、opencode.json、commands/、agents/、tools/、plugins/、skills/（已展开）
      - 注入 install.sh / uninstall.sh（专用模板）
      - 写入 VERSION、manifest.json
      - 静态检查 + `zip -X -r secguard-extension-opencode-$version.zip .`
  15. **组装 ClaudeCode 专用包**（若 target 含 claude-code/all）：
      - 创建临时目录 `$DIST_DIR/.tmp-cc-ext/`
      - 复制 .claude-plugin/、commands/、agents/、hooks/、skills/、bin/（含多平台二进制）
      - 注入 install.sh / uninstall.sh（专用模板）
      - 写入 VERSION、manifest.json
      - 静态检查 + `zip -X -r secguard-extension-claude-code-$version.zip .`
  16. 对每个 zip 生成 `.sha256`：`shasum -a 256 <zip> > <zip>.sha256`（REQ-SUM-01）
  17. 清理临时目录、二进制中间产物
  18. 打印产物列表（路径、大小、sha256，REQ-BUILD-05）
  19. 排除规则（design §11.4）：`-x "*.gocache*" -x "*.gotmp*" -x "*.db" -x "*.DS_Store" -x "*__pycache__*" -x "*.env" -x "*credentials*" -x "*.key" -x "*.pem"`
- **验证方式**：
  - `bash -n release/build-packages.sh` 语法通过
  - `cd sgre && go build ./...` 通过（确保 build_target 目标正确）
  - 执行 `release/build-packages.sh --target master --os darwin --arch arm64` 后 `dist/secguard-<version>.zip` 存在且 `dist/secguard-<version>.zip.sha256` 存在
  - 解压统一包后 `install.sh` 内含 `sg_select_binary` 函数定义（注入成功）、无 `source.*lib\.sh`
  - `shasum -c dist/secguard-*.sha256` 校验通过

---

## 5. 入口集成

### T9：扩展根目录 build.sh 集成 --package

- **涉及文件**：`build.sh`（根目录，修改）
- **依赖**：T8
- **版本**：第一版本必须
- **实现步骤**：
  1. 读取现有 `build.sh`，保留原有 `--test`、`--install`、`--help` 行为完全不变（AC-11）
  2. 在参数解析循环中新增分支：`--package`/`--dist`（设置 `DO_PACKAGE=true`）、`--version`（捕获到 `EXPLICIT_VERSION`）、`--os`（捕获到 `OS_FILTER`）、`--arch`（捕获到 `ARCH_FILTER`）、`--target`（捕获到 `TARGET_FILTER`）
  3. 在原有构建逻辑之后（或之前，但须保证无 `--package` 时不影响原逻辑）加入：
     ```bash
     if [ "$DO_PACKAGE" = true ]; then
         exec "$SCRIPT_DIR/release/build-packages.sh" \
             ${EXPLICIT_VERSION:+--version "$EXPLICIT_VERSION"} \
             ${OS_FILTER:+--os "$OS_FILTER"} \
             ${ARCH_FILTER:+--arch "$ARCH_FILTER"} \
             ${TARGET_FILTER:+--target "$TARGET_FILTER"} \
             ${DO_TEST:+--test}
     fi
     ```
  4. 更新 `--help` 输出，加入新参数说明（design §10.1 参数表）
  5. 退出码：透传 build-packages.sh 的退出码
- **验证方式**：
  - `bash -n build.sh` 语法通过
  - `./build.sh --help` 输出包含 `--package` 说明
  - `./build.sh`（无参数）行为与改造前一致：生成 `bin/secguard`（AC-11）
  - `./build.sh --package --target master --os darwin --arch arm64` 触发打包流程

---

### T10：重构 deploy.sh 复用 lib.sh

- **涉及文件**：`deploy.sh`（根目录，修改）
- **依赖**：T3
- **版本**：第一版本必须
- **实现步骤**：
  1. 读取现有 `deploy.sh`，定位内联 `expand_includes()` 函数定义（约第 103-122 行）
  2. 移除该内联函数定义
  3. 在脚本头部（路径变量定义之后）加入：`source "$SCRIPT_DIR/release/lib.sh"`
  4. 检查 `deploy.sh` 中对 `expand_includes` 的调用签名：若原调用为 `expand_includes "$f" "$out"`（两参），需改为 `expand_includes "$f" "$out" "$SHARED_DIR"`（三参，与 lib.sh 签名一致）；或调整 lib.sh 中 `expand_includes` 包装为兼容两参（默认 SHARED_DIR）—— 推荐前者更显式
  5. 可选：将 `deploy.sh` 内联的 `merge_claude_permissions` 也改为调用 `sg_merge_permissions`（进一步 DRY，design §13.2 推荐）
  6. 其余 `deploy.sh` 行为（`build_binary`、`install_opencode`、`install_claude_code`、`sync_project_local`、验证）不变
- **验证方式**：
  - `bash -n deploy.sh` 语法通过
  - `grep -c 'expand_includes()' deploy.sh` == 0（无内联定义）
  - `grep 'source.*lib\.sh' deploy.sh` 有匹配
  - `./deploy.sh --help` 或 dry-run 行为正常（不因移除函数而报错）

---

### T11：删除 extension/install.sh（已完成）

- **涉及文件**：`extension/install.sh`（已删除）
- **依赖**：T10
- **版本**：第一版本必须
- **实现步骤**：
  1. 确认 `extension/install.sh` 的 `expand_includes` 重复实现已由 `lib.sh` 统一提供
  2. 确认无其它脚本/文档引用 `extension/install.sh`（用 grep 检查）
  3. 删除该文件
  4. 若有引用，更新引用指向 `release/install.sh.tmpl`（注入后副本）或 `deploy.sh`
- **验证方式**：
  - `[ ! -f extension/install.sh ]` 为真
  - `grep -r 'extension/install.sh' --include='*.sh' --include='*.md' .` 无引用（或引用已更新）

---

## 6. 验证

### T12：端到端集成验证

- **涉及文件**：无新文件，全流程验证
- **依赖**：T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11
- **版本**：第一版本必须
- **实现步骤**：
  1. **清理环境**：`rm -rf dist/ bin/secguard`；清理 `~/.config/opencode/extensions/zhuque-secguard/`、`~/.claude/skills/zhuque-secguard/`、`~/.local/bin/secguard`（若存在）
  2. **执行打包**：`./build.sh --package`（默认全平台、全包类型）
  3. **验证 AC-01**：`dist/` 存在 3 个 zip + 3 个 sha256 文件
  4. **验证 AC-07**：解压统一包，`shared/skills/` 下有 14 个 skill 目录
  5. **验证 AC-08**：`manifest.json` 的 `version` 字段与 zip 文件名版本一致
  6. **验证 AC-09**：`cd dist && shasum -c secguard-*.sha256` 全部通过
  7. **验证 AC-10**：解压统一包，`find . -name '*.gocache*' -o -name '*.db' -o -name '.DS_Store'` 无结果
  8. **验证 AC-11**：`./build.sh`（无 `--package`）仍生成 `bin/secguard`，行为不变
  9. **验证 AC-12**：在 macOS arm64 上解压统一包，`./install.sh --target all` 自动选择 `secguard-darwin-arm64` 二进制
  10. **验证 AC-02**：`./install.sh --target all` 在干净环境成功安装，`secguard --version` 可执行
  11. **验证 AC-13**：检查安装路径 `~/.config/opencode/extensions/zhuque-secguard/` 与 `~/.claude/skills/zhuque-secguard/` 存在且含关键文件
  12. **验证 AC-14**：`cat ~/.claude/settings.json` 含 7 项 secguard 权限；重复执行 `./install.sh --target claude-code` 后权限项数仍为 7（幂等）
  13. **验证 AC-04**：重复执行 `./install.sh --target all` 不产生错误，文件不变
  14. **验证 AC-21**：`./install.sh --verify` 输出全 ✓ 且退出码 0；手动删除一个 skill 后 `./install.sh --verify` 该项 ✗ 且退出码非 0
  15. **验证 AC-03**：`./uninstall.sh --target all --yes` 删除所有已安装文件，`secguard` 命令不再可用，`~/.config/opencode/extensions/zhuque-secguard/` 与 `~/.claude/skills/zhuque-secguard/` 不存在或为空
  16. **验证 AC-18**：重新安装后 `./uninstall.sh --target all --yes` 与 `./install.sh --uninstall --target all --yes` 效果一致
  17. **验证 AC-05**：解压 OpenCode 专用包，目录结构可被 OpenCode 直接作为 extension 加载（extension.json 在根目录）
  18. **验证 AC-06**：解压 ClaudeCode 专用包，`.claude-plugin/plugin.json` 在根目录，可被 ClaudeCode 发现
  19. **验证 AC-15**：`release/lib.sh` 存在且定义 `expand_includes`；`grep 'source.*lib\.sh' release/build-packages.sh deploy.sh` 均有匹配
  20. **验证 AC-16**：`grep 'source.*lib\.sh'` 在 zip 内 install.sh、uninstall.sh 均无匹配
  21. **记录结果**：将每项 AC 的通过/失败状态记录到验证报告（可临时写入 `docs/verification-report.md`，验证通过后可删除）
- **验证方式**：
  - 上述 21 项 AC 检查全部通过
  - 若某项失败，记录失败详情与根因，反馈至对应任务修复后重新验证

---

## 7. 后续优化

### T13：可重复构建增强（固定时间戳）

- **涉及文件**：`release/lib.sh`（`write_manifest` 函数）、`release/build-packages.sh`
- **依赖**：T12
- **版本**：后续优化
- **实现步骤**：
  1. `write_manifest` 中 `build_date` 改为取 `VERSION` 文件 mtime（`stat -f %m VERSION` macOS / `stat -c %Y VERSION` Linux），UTC ISO8601 格式化；无 VERSION 时取固定值如 `1970-01-01T00:00:00Z`
  2. 确认 `go build -trimpath` 已生效（T8 已包含）
  3. 确认 `zip -X` 已生效（T8 已包含）
  4. 验证：相同输入两次打包，`shasum -a 256` 两次产物字节相同
- **验证方式**：
  - `./build.sh --package` 两次，`diff <(shasum -a 256 dist/secguard-*.zip) <(shasum -a 256 dist/secguard-*.zip)` 无差异

---

### T14：启发式清理与降级增强

- **涉及文件**：`release/lib.sh`（`sg_uninstall_platform` 函数）
- **依赖**：T12
- **版本**：后续优化
- **实现步骤**：
  1. 增强 `sg_uninstall_platform` 的 manifest 缺失降级路径：
     - 当前基础版（T2 实现）按约定路径删除 `extensions/zhuque-secguard/`、`skills/zhuque-secguard/`、`<bin-dir>/secguard`
     - 增强版：先检测约定路径下是否存在 `VERSION`/`manifest.json` 推断已安装版本，提示用户确认；扫描 `~/.claude/settings.json` 是否有 secguard 权限项并清理
  2. 增加日志输出：启发式清理时打印每一步删除的路径，便于审计
  3. 增加 `--dry-run` 选项（可选）：仅展示将删除的文件不实际删除
- **验证方式**：
  - 手动删除 `.secguard-install-manifest` 后执行 `./uninstall.sh --target all --yes`，启发式清理成功且打印清理日志
  - `~/.claude/settings.json` 中 secguard 权限项被清理

---

## 任务依赖图

```text
T1 (VERSION) ────────────────────────────────┐
                                             │
T2 (lib.sh 可注入区) ──┬── T4 (install.tmpl) ─┤
                       ├── T5 (uninstall)   ─┤
                       ├── T6 (OC 模板)     ─┤
                       └── T7 (CC 模板)     ─┤
                                             │
T3 (lib.sh 构建侧) ─── T10 (deploy.sh) ── T11 (删除 ext/install.sh)
   │                          │
   └── T8 (build-packages.sh) ┤
                              │
T9 (build.sh --package) ──────┘
                              │
                  T12 (端到端验证)
                              │
                  T13 (可重复构建) ── 后续优化
                  T14 (启发式清理) ── 后续优化
```

---

## 实现顺序建议

1. **第一波（并行）**：T1、T2
2. **第二波（并行）**：T3、T4、T5、T6、T7（均依赖 T2，T3 依赖 T2）
3. **第三波**：T8（依赖 T1、T3、T4-T7）
4. **第四波（并行）**：T9、T10（T9 依赖 T8，T10 依赖 T3）
5. **第五波**：T11（依赖 T10）
6. **第六波**：T12（依赖全部）
7. **后续**：T13、T14（按需）