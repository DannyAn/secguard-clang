#!/bin/bash
set -euo pipefail

# build-packages.sh — SecGuard 发行包构建核心
# 用法：build-packages.sh [--version <v>] [--os <os>] [--arch <arch>] [--test] [--help]
# 产物：$PROJECT_ROOT/dist/secguard-<version>.zip（唯一发布资产）
#
# 目标矩阵（见 lib.sh build_target）：
#   - darwin/amd64 + darwin/arm64   macOS（Intel + Apple Silicon）
#   - linux/amd64                   x86_64 Linux（zig musl 静态链接）
#   - linux/arm64                   aarch64 Linux（zig musl 静态链接）
#   - windows/amd64                 x86_64 Windows（zig mingw 交叉编译）
# 任何目标构建失败都会中止（不再静默回退本机，避免发布缺平台的包）。

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SGRE_DIR="$PROJECT_ROOT/sgre"
EXTENSION_DIR="$PROJECT_ROOT/extension"
DIST_DIR="$PROJECT_ROOT/dist"
LIB_SH="$SCRIPT_DIR/lib.sh"

# 加载共享函数库
source "$LIB_SH"

# ── 参数解析 ──
EXPLICIT_VERSION=""
OS_FILTER=""
ARCH_FILTER=""
DO_TEST=false
ASSEMBLE_ONLY=false

usage() {
    cat <<EOF
SecGuard Package Builder
Usage: build-packages.sh [options]

Options:
  --version <v>                        Explicit version (overrides VERSION/git)
  --os <darwin|linux|windows>          Filter target OS
  --arch <amd64|arm64>                 Filter target arch
  --test                               Run tests before building
  --assemble-only                      Skip building; zip pre-built binaries in dist/
  --help, -h                           Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)  EXPLICIT_VERSION="$2"; shift 2 ;;
        --os)       OS_FILTER="$2"; shift 2 ;;
        --arch)     ARCH_FILTER="$2"; shift 2 ;;
        --test)     DO_TEST=true; shift ;;
        --assemble-only) ASSEMBLE_ONLY=true; shift ;;
        --help|-h)  usage; exit 0 ;;
        *)          echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

# ── 定位 zig（跨平台 C 编译器，linux/windows 交叉必需）──
ZIG="${ZIG:-}"
if [ -z "$ZIG" ]; then
    if [ -x "$PROJECT_ROOT/.tools/zig/zig" ]; then
        export ZIG="$PROJECT_ROOT/.tools/zig/zig"
        export PATH="$PROJECT_ROOT/.tools/zig:$PATH"
    elif command -v zig >/dev/null 2>&1; then
        export ZIG="$(command -v zig)"
    fi
fi
mkdir -p "$SGRE_DIR/.zig-cache/global" "$SGRE_DIR/.zig-cache/local"

# ── 版本解析 ──
version=$(resolve_version "$EXPLICIT_VERSION")
echo "SecGuard v$version — Building distribution packages"
echo "Project root: $PROJECT_ROOT"
if [ -n "$ZIG" ]; then
    echo "zig: $ZIG ($($ZIG version 2>/dev/null || echo unknown))"
else
    echo "zig: NOT FOUND (linux/windows 目标将失败)"
fi
echo ""

# ── 扩展一致性校验：turn budget 必须是单一事实源 ──
"$SCRIPT_DIR/check-extension-consistency.py"

# ── 测试 ──
if [ "$DO_TEST" = true ]; then
    echo "[test] Running go test ./..."
    (cd "$SGRE_DIR" && go test ./... 2>&1)
    echo "[test] All tests passed."
    echo ""
fi

# ── 目标矩阵 ──
all_targets=("darwin amd64" "darwin arm64" "linux amd64" "linux arm64" "windows amd64")
targets=()
for t in "${all_targets[@]}"; do
    read -r os arch <<< "$t"
    if [ -n "$OS_FILTER" ] && [ "$os" != "$OS_FILTER" ]; then continue; fi
    if [ -n "$ARCH_FILTER" ] && [ "$arch" != "$ARCH_FILTER" ]; then continue; fi
    targets+=("$os $arch")
done

if [ ${#targets[@]} -eq 0 ]; then
    echo "ERROR: No targets match filters (os=$OS_FILTER arch=$ARCH_FILTER)" >&2
    exit 1
fi

echo "[targets] ${targets[*]}"
echo ""

# ── 清理旧产物，避免不同版本/不同平台的 zip 混在 dist 里 ──
rm -f "$DIST_DIR"/secguard-*.zip "$DIST_DIR"/secguard-*.zip.sha256 \
      "$DIST_DIR"/secguard-*.sha256 "$DIST_DIR"/SHA256SUMS 2>/dev/null || true
# 非 assemble-only 模式下，一并清理残留的裸二进制
if [ "$ASSEMBLE_ONLY" != true ]; then
    rm -f "$DIST_DIR"/secguard-*-[a-z]* "$DIST_DIR"/secguard-*.exe 2>/dev/null || true
fi
mkdir -p "$DIST_DIR"

# ── 收集二进制（构建或复用 dist 中预构建产物）──
built_binaries=()

for t in "${targets[@]}"; do
    read -r os arch <<< "$t"
    if [ "$ASSEMBLE_ONLY" = true ]; then
        echo "[assemble] $os/$arch ..."
        bin_path="$DIST_DIR/secguard-${os}-${arch}"
        if [ ! -f "$bin_path" ]; then
            bin_path="$DIST_DIR/secguard-${os}-${arch}.exe"
        fi
        if [ -f "$bin_path" ]; then
            built_binaries+=("$bin_path")
            echo "  OK → $(basename "$bin_path")"
        else
            echo "  FAIL: pre-built binary not found for $os/$arch in $DIST_DIR" >&2
            exit 1
        fi
        continue
    fi
    echo "[build] $os/$arch ..."
    # 只捕获 stdout（build_target 在 stdout 回显产物路径）；stderr 直接透传到终端
    if bin_path=$(build_target "$os" "$arch" "$version"); then
        if [ -f "$bin_path" ] && [ -x "$bin_path" ]; then
            built_binaries+=("$bin_path")
            echo "  OK → $(basename "$bin_path")"
        else
            echo "  FAIL: binary not found at expected path ($bin_path)" >&2
            exit 1
        fi
    else
        echo "  FAIL (cross-compile failed, see errors above)" >&2
        exit 1
    fi
done

echo ""

# ── 自动发现 skills ──
skills=()
for skill_dir in "$EXTENSION_DIR"/shared/skills/*/; do
    [ -d "$skill_dir" ] || continue
    skills+=("$(basename "$skill_dir")")
done
skills_csv=$(IFS=,; echo "${skills[*]}")
echo "[skills] ${#skills[@]} skills: ${skills[*]}"
echo ""

# ── 准备注入块 ──
INJECT_FILE="$DIST_DIR/.inject_block"
extract_inject_block "$LIB_SH" > "$INJECT_FILE"
echo "[inject] Extracted $(grep -c '^sg_' "$INJECT_FILE") functions from lib.sh"
echo ""

# ── 辅助函数：覆写 JSON version 字段 ──
set_json_version() {
    local file="$1"
    local ver="$2"
    python3 -c "
import json
with open('''$file''', 'r') as f:
    d = json.load(f)
d['version'] = '''$ver'''
with open('''$file''', 'w') as f:
    json.dump(d, f, indent=2)
    f.write('\n')
"
}

# ── 排除规则 ──
ZIP_EXCLUDE=(-x "*.gocache*" -x "*.gotmp*" -x "*.db" -x "*.DS_Store" -x "*__pycache__*" -x "*.env" -x "*credentials*" -x "*.key" -x "*.pem")

# ── 组装统一包（唯一发布资产）──
build_master() {
    echo "[master] Building secguard-${version}.zip ..."
    local tmp="$DIST_DIR/.tmp-master"
    local root="$tmp/secguard-${version}"
    rm -rf "$tmp"
    mkdir -p "$root"

    # 二进制（含 windows .exe）
    local bin
    for bin in "${built_binaries[@]}"; do
        cp "$bin" "$root/"
    done

    # shared
    mkdir -p "$root/shared/skills"
    cp "$EXTENSION_DIR/shared/agent-body.md" "$root/shared/" 2>/dev/null || true
    cp "$EXTENSION_DIR/shared/command-instructions.md" "$root/shared/" 2>/dev/null || true
    cp -r "$EXTENSION_DIR/shared/skills"/* "$root/shared/skills/"

    # opencode（插件机制：package.json + index.ts，展开模板）
    mkdir -p "$root/opencode"/{commands,agents,tools}
    cp "$EXTENSION_DIR/opencode/package.json" "$root/opencode/"
    set_json_version "$root/opencode/package.json" "$version"
    cp "$EXTENSION_DIR/opencode/index.ts" "$root/opencode/"
    expand_includes "$EXTENSION_DIR/opencode/commands/secguard.md" "$root/opencode/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/diff.md" "$root/opencode/commands/diff.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/pr.md" "$root/opencode/commands/pr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/mr.md" "$root/opencode/commands/mr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/metrics.md" "$root/opencode/commands/metrics.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/agents/security-auditor.md" "$root/opencode/agents/security-auditor.md" "$EXTENSION_DIR/shared"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$root/opencode/tools/" 2>/dev/null || true

    # opencode-nga（OpenCode 开源分支：manifest 改名 codeagent-extension.json，
    # 其余文件与 opencode 完全一致；.codeagent-extension-install.json 的 source 在
    # install 时按实际安装目录替换）
    mkdir -p "$root/opencode-nga"/{commands,agents,tools,plugins}
    cp "$EXTENSION_DIR/opencode-nga/codeagent-extension.json" "$root/opencode-nga/"
    set_json_version "$root/opencode-nga/codeagent-extension.json" "$version"
    cp "$EXTENSION_DIR/opencode-nga/.codeagent-extension-install.json" "$root/opencode-nga/"
    cp "$EXTENSION_DIR/opencode-nga/opencode.json" "$root/opencode-nga/"
    cp "$EXTENSION_DIR/opencode-nga/index.ts" "$root/opencode-nga/"
    cp "$EXTENSION_DIR/opencode-nga/package.json" "$root/opencode-nga/"
    set_json_version "$root/opencode-nga/package.json" "$version"
    expand_includes "$EXTENSION_DIR/opencode/commands/secguard.md" "$root/opencode-nga/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/diff.md" "$root/opencode-nga/commands/diff.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/pr.md" "$root/opencode-nga/commands/pr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/mr.md" "$root/opencode-nga/commands/mr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/commands/metrics.md" "$root/opencode-nga/commands/metrics.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/agents/security-auditor.md" "$root/opencode-nga/agents/security-auditor.md" "$EXTENSION_DIR/shared"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$root/opencode-nga/tools/" 2>/dev/null || true
    cp "$EXTENSION_DIR/opencode-nga/plugins/"*.ts "$root/opencode-nga/plugins/" 2>/dev/null || true

    # claude-code（官方插件方式，安装到 ~/.claude/plugins/，非 skills/）
    mkdir -p "$root/claude-code/.claude-plugin" "$root/claude-code/.claude/commands" "$root/claude-code/.claude/agents" "$root/claude-code/hooks"
    cp "$EXTENSION_DIR/claude-code/.claude-plugin/plugin.json" "$root/claude-code/.claude-plugin/"
    set_json_version "$root/claude-code/.claude-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-code/hooks/hooks.json" "$root/claude-code/hooks/"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/secguard.md" "$root/claude-code/.claude/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/diff.md" "$root/claude-code/.claude/commands/diff.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/pr.md" "$root/claude-code/.claude/commands/pr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/mr.md" "$root/claude-code/.claude/commands/mr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/metrics.md" "$root/claude-code/.claude/commands/metrics.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/agents/security-auditor.md" "$root/claude-code/.claude/agents/security-auditor.md" "$EXTENSION_DIR/shared"

    # claude-cac（Claude Code 开源分支：~/.cac/，manifest 改名 .cac-plugin/plugin.json）
    mkdir -p "$root/claude-cac/.cac-plugin" "$root/claude-cac/.cac/commands" "$root/claude-cac/.cac/agents" "$root/claude-cac/hooks"
    cp "$EXTENSION_DIR/claude-cac/.cac-plugin/plugin.json" "$root/claude-cac/.cac-plugin/"
    set_json_version "$root/claude-cac/.cac-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-cac/hooks/hooks.json" "$root/claude-cac/hooks/"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/secguard.md" "$root/claude-cac/.cac/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/diff.md" "$root/claude-cac/.cac/commands/diff.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/pr.md" "$root/claude-cac/.cac/commands/pr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/mr.md" "$root/claude-cac/.cac/commands/mr.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/metrics.md" "$root/claude-cac/.cac/commands/metrics.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/agents/security-auditor.md" "$root/claude-cac/.cac/agents/security-auditor.md" "$EXTENSION_DIR/shared"

    # install.sh / uninstall.sh（注入）
    inject_into "$SCRIPT_DIR/install.sh.tmpl" "$INJECT_FILE" > "$root/install.sh"
    inject_into "$SCRIPT_DIR/uninstall.sh" "$INJECT_FILE" > "$root/uninstall.sh"
    chmod +x "$root/install.sh" "$root/uninstall.sh"

    # 静态检查（仅检查非注释行）
    if grep -rn 'source.*lib\.sh' "$root/install.sh" "$root/uninstall.sh" 2>/dev/null | grep -v ':#'; then
        echo "ERROR: install.sh/uninstall.sh contain forbidden source lib.sh" >&2
        exit 1
    fi

    # VERSION, manifest, README, LICENSE
    echo "$version" > "$root/VERSION"
    local targets_csv=""
    for bin in "${built_binaries[@]}"; do
        local bn pair
        bn=$(basename "$bin")
        bn=${bn%.exe}                 # secguard-windows-amd64.exe -> secguard-windows-amd64
        pair=$(echo "$bn" | sed 's/^secguard-//; s/-/\//')  # secguard-darwin-arm64 -> darwin/arm64
        targets_csv="${targets_csv:+$targets_csv,}$pair"
    done
    write_manifest "$root" "$version" "$targets_csv" "$skills_csv"
    [ -f "$PROJECT_ROOT/README.md" ] && cp "$PROJECT_ROOT/README.md" "$root/" 2>/dev/null || true
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$root/" 2>/dev/null || true

    # zip
    (cd "$tmp" && zip -X -r "$DIST_DIR/secguard-${version}.zip" "secguard-${version}" "${ZIP_EXCLUDE[@]}") >/dev/null 2>&1
    rm -rf "$tmp"
    echo "  → dist/secguard-${version}.zip"
}

# ── 插件包（AI Agent Market 发布用）──
# 每个平台一个自包含插件目录：平台文件（展开）+ skills + bin/（5 架构二进制 + shim）。
# 布局遵循各平台 Market 的"顶层 commands/agents/skills/hooks"规范，而非 install.sh
# 里 master zip 的 .claude/、.cac/ 包装结构——market 安装是宿主把目录复制进缓存，
# 不带我们的 install.sh，所以必须"出厂即自包含"。

copy_skills_to() {
    local dest="$1"
    mkdir -p "$dest"
    local skill_dir skill_name
    for skill_dir in "$EXTENSION_DIR"/shared/skills/*/; do
        [ -d "$skill_dir" ] || continue
        skill_name=$(basename "$skill_dir")
        mkdir -p "$dest/$skill_name"
        cp "$skill_dir/SKILL.md" "$dest/$skill_name/SKILL.md"
    done
}

# 展开 src_dir 下所有 .md 到 dest_dir（处理 {{include}}）
expand_md_dir() {
    local src_dir="$1"
    local dest_dir="$2"
    mkdir -p "$dest_dir"
    local f
    for f in "$src_dir"/*.md; do
        [ -f "$f" ] || continue
        expand_includes "$f" "$dest_dir/$(basename "$f")" "$EXTENSION_DIR/shared"
    done
}

# 拷贝 5 架构二进制 + 注入调度 shim 到插件目录的 bin/
install_plugin_bin() {
    local plugin_dir="$1"
    mkdir -p "$plugin_dir/bin"
    local bin
    for bin in "${built_binaries[@]}"; do
        cp "$bin" "$plugin_dir/bin/"
    done
    cp "$SCRIPT_DIR/shim-secguard.sh" "$plugin_dir/bin/secguard"
    chmod +x "$plugin_dir/bin/secguard"
    cp "$SCRIPT_DIR/shim-secguard.cmd" "$plugin_dir/bin/secguard.cmd"
}

build_plugin_opencode() {
    local out="$1"
    mkdir -p "$out"/{commands,agents,tools}
    cp "$EXTENSION_DIR/opencode/package.json" "$out/"
    set_json_version "$out/package.json" "$version"
    cp "$EXTENSION_DIR/opencode/index.ts" "$out/"
    expand_md_dir "$EXTENSION_DIR/opencode/commands" "$out/commands"
    expand_md_dir "$EXTENSION_DIR/opencode/agents" "$out/agents"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$out/tools/"
    copy_skills_to "$out/skills"
    install_plugin_bin "$out"
}

build_plugin_opencode_nga() {
    local out="$1"
    mkdir -p "$out"/{commands,agents,tools,plugins}
    cp "$EXTENSION_DIR/opencode-nga/codeagent-extension.json" "$out/"
    set_json_version "$out/codeagent-extension.json" "$version"
    # .codeagent-extension-install.json 是"安装来源"元数据；保留模板，安装方（install.sh/市场宿主）
    # 把 {{OC_TARGET_DIR}} 替换为实际目录。与 master zip 的 opencode-nga 布局保持一致。
    cp "$EXTENSION_DIR/opencode-nga/.codeagent-extension-install.json" "$out/"
    cp "$EXTENSION_DIR/opencode-nga/opencode.json" "$out/"
    cp "$EXTENSION_DIR/opencode-nga/index.ts" "$out/"
    cp "$EXTENSION_DIR/opencode-nga/package.json" "$out/"
    set_json_version "$out/package.json" "$version"
    # commands/agents/tools 与 opencode 同源（见 build_master 的既有约定）
    expand_md_dir "$EXTENSION_DIR/opencode/commands" "$out/commands"
    expand_md_dir "$EXTENSION_DIR/opencode/agents" "$out/agents"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$out/tools/"
    cp "$EXTENSION_DIR/opencode-nga/plugins/"*.ts "$out/plugins/"
    copy_skills_to "$out/skills"
    install_plugin_bin "$out"
}

build_plugin_claude_code() {
    local out="$1"
    mkdir -p "$out"/{.claude-plugin,commands,agents,hooks}
    cp "$EXTENSION_DIR/claude-code/.claude-plugin/plugin.json" "$out/.claude-plugin/"
    set_json_version "$out/.claude-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-code/hooks/hooks.json" "$out/hooks/"
    # market 用顶层 commands/agents（非 .claude/ 包装）
    expand_md_dir "$EXTENSION_DIR/claude-code/.claude/commands" "$out/commands"
    expand_md_dir "$EXTENSION_DIR/claude-code/.claude/agents" "$out/agents"
    copy_skills_to "$out/skills"
    install_plugin_bin "$out"
}

build_plugin_claude_cac() {
    local out="$1"
    mkdir -p "$out"/{.cac-plugin,commands,agents,hooks}
    cp "$EXTENSION_DIR/claude-cac/.cac-plugin/plugin.json" "$out/.cac-plugin/"
    set_json_version "$out/.cac-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-cac/hooks/hooks.json" "$out/hooks/"
    sg_write_codeagent_extension "$out" "$version"
    expand_md_dir "$EXTENSION_DIR/claude-cac/.cac/commands" "$out/commands"
    expand_md_dir "$EXTENSION_DIR/claude-cac/.cac/agents" "$out/agents"
    copy_skills_to "$out/skills"
    install_plugin_bin "$out"
}

write_bundle_manifest() {
    local root="$1"
    python3 -c "
import json, hashlib, os, datetime
root = '''$root'''
version = '''$version'''
plugins = []
for fn in sorted(os.listdir(root)):
    if not fn.endswith('.zip'):
        continue
    with open(os.path.join(root, fn), 'rb') as f:
        h = hashlib.sha256(f.read()).hexdigest()
    plugins.append({'name': fn[:-4], 'file': fn, 'sha256': h})
manifest = {
    'version': version,
    'build_date': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
    'plugins': plugins,
}
with open(os.path.join(root, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
"
}

validate_plugin_dir() {
    local plugin_dir="$1"
    local label="$2"
    local missing=()
    case "$label" in
        opencode)      [ -f "$plugin_dir/package.json" ] || missing+=("package.json") ;;
        opencode-nga)  [ -f "$plugin_dir/codeagent-extension.json" ] || missing+=("codeagent-extension.json") ;;
        claude-code)   [ -f "$plugin_dir/.claude-plugin/plugin.json" ] || missing+=(".claude-plugin/plugin.json") ;;
        claude-cac)    [ -f "$plugin_dir/.cac-plugin/plugin.json" ] || missing+=(".cac-plugin/plugin.json")
                       [ -f "$plugin_dir/codeagent-extension.json" ] || missing+=("codeagent-extension.json") ;;
    esac
    [ -f "$plugin_dir/commands/secguard.md" ] || missing+=("commands/secguard.md")
    [ -f "$plugin_dir/agents/security-auditor.md" ] || missing+=("agents/security-auditor.md")
    [ -f "$plugin_dir/bin/secguard" ] || missing+=("bin/secguard")
    [ -f "$plugin_dir/bin/secguard.cmd" ] || missing+=("bin/secguard.cmd")
    local skill_count bin bn
    skill_count=$(find "$plugin_dir/skills" -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
    [ "$skill_count" -eq "${#skills[@]}" ] || { echo "  FAIL: $label skills=$skill_count expected=${#skills[@]}" >&2; return 1; }
    for bin in "${built_binaries[@]}"; do
        bn=$(basename "$bin")
        [ -f "$plugin_dir/bin/$bn" ] || missing+=("bin/$bn")
    done
    if [ ${#missing[@]} -gt 0 ]; then
        echo "  FAIL: $label missing: ${missing[*]}" >&2
        return 1
    fi
    echo "  OK: $label (${#skills[@]} skills, ${#built_binaries[@]} binaries)"
}

build_plugins() {
    echo ""
    echo "[plugins] Building per-platform plugin zips + aggregate bundle ..."
    local tmp="$DIST_DIR/.tmp-plugins"
    local work="$tmp/work"
    local zips="$tmp/zips"
    local root="$tmp/secguard-clang-plugins-${version}"
    rm -rf "$tmp"
    mkdir -p "$work" "$zips" "$root"

    # 逐平台 zip：zip 顶层统一用插件安装名 `secguard-clang`（Market 据此把插件装到
    # plugins/ 或 extensions/ 下），打进临时 zips/ 目录（随后并入聚合包，不单独发布）。
    local p label
    for label in opencode opencode-nga claude-code claude-cac; do
        p="$work/secguard-clang-${label}"
        case "$label" in
            opencode)      build_plugin_opencode "$p" ;;
            opencode-nga)  build_plugin_opencode_nga "$p" ;;
            claude-code)   build_plugin_claude_code "$p" ;;
            claude-cac)    build_plugin_claude_cac "$p" ;;
        esac
        validate_plugin_dir "$p" "$label" || exit 1
        echo "$version" > "$p/VERSION"
        rm -rf "$work/secguard-clang"
        mv "$p" "$work/secguard-clang"
        (cd "$work" && zip -X -r "$zips/secguard-clang-${label}-${version}.zip" "secguard-clang" "${ZIP_EXCLUDE[@]}") >/dev/null 2>&1
        echo "  → secguard-clang-${label}-${version}.zip"
    done

    # 聚合包：内含 4 个逐平台 zip（一次下载取全部平台），供用户解压后挑对应平台上传 Market。
    cp "$zips"/*.zip "$root/"
    echo "$version" > "$root/VERSION"
    cp "$SCRIPT_DIR/plugins-README.md" "$root/README.md"
    [ -f "$PROJECT_ROOT/LICENSE" ] && cp "$PROJECT_ROOT/LICENSE" "$root/" 2>/dev/null || true
    write_bundle_manifest "$root"

    (cd "$tmp" && zip -X -r "$DIST_DIR/secguard-clang-plugins-${version}.zip" "secguard-clang-plugins-${version}" "${ZIP_EXCLUDE[@]}") >/dev/null 2>&1
    rm -rf "$tmp"
    echo "  → dist/secguard-clang-plugins-${version}.zip"
}

# ── 执行打包 ──
build_master
build_plugins

# ── 生成校验和（写入相对文件名，便于下游校验）──
sg_sum() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}
echo ""
echo "[sha256] Generating checksums..."
ALL_ZIPS=("secguard-${version}.zip"
          "secguard-clang-plugins-${version}.zip")
( cd "$DIST_DIR" && \
  for z in "${ALL_ZIPS[@]}"; do sg_sum "$z" > "$z.sha256"; done && \
  sg_sum "${ALL_ZIPS[@]}" > SHA256SUMS )
echo "  → per-zip .sha256 + SHA256SUMS"

# ── 清理 ──
rm -f "$INJECT_FILE"
for bin in "${built_binaries[@]}"; do
    rm -f "$bin" 2>/dev/null || true
done
rm -rf "$DIST_DIR"/.tmp-* 2>/dev/null || true

# ── 产物列表 ──
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              Build Complete — v${version}                       ║"
echo "╠══════════════════════════════════════════════════════════╣"
for z in "${ALL_ZIPS[@]}"; do
    zsize=$(ls -lh "$DIST_DIR/$z" | awk '{print $5}')
    zhash=$(cut -d' ' -f1 "$DIST_DIR/$z.sha256" 2>/dev/null || echo "?")
    printf "║  %-52s %6s\n" "$z" "$zsize"
    printf "║    sha256: %s\n" "${zhash:0:16}..."
done
echo "╚══════════════════════════════════════════════════════════╝"
