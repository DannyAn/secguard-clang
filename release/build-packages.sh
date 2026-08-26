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

    # opencode（展开模板）
    mkdir -p "$root/opencode"/{commands,agents,tools,plugins}
    cp "$EXTENSION_DIR/opencode/extension.json" "$root/opencode/"
    set_json_version "$root/opencode/extension.json" "$version"
    cp "$EXTENSION_DIR/opencode/opencode.json" "$root/opencode/"
    expand_includes "$EXTENSION_DIR/opencode/commands/secguard.md" "$root/opencode/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/agents/security-auditor.md" "$root/opencode/agents/security-auditor.md" "$EXTENSION_DIR/shared"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$root/opencode/tools/" 2>/dev/null || true
    cp "$EXTENSION_DIR/opencode/plugins/"*.ts "$root/opencode/plugins/" 2>/dev/null || true

    # opencode-nga（OpenCode 开源分支：manifest 改名 codeagent-extension.json，
    # 其余文件与 opencode 完全一致；.codeagent-extension-install.json 的 source 在
    # install 时按实际安装目录替换）
    mkdir -p "$root/opencode-nga"/{commands,agents,tools,plugins}
    cp "$EXTENSION_DIR/opencode-nga/codeagent-extension.json" "$root/opencode-nga/"
    set_json_version "$root/opencode-nga/codeagent-extension.json" "$version"
    cp "$EXTENSION_DIR/opencode-nga/.codeagent-extension-install.json" "$root/opencode-nga/"
    cp "$EXTENSION_DIR/opencode/opencode.json" "$root/opencode-nga/"
    expand_includes "$EXTENSION_DIR/opencode/commands/secguard.md" "$root/opencode-nga/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/opencode/agents/security-auditor.md" "$root/opencode-nga/agents/security-auditor.md" "$EXTENSION_DIR/shared"
    cp "$EXTENSION_DIR/opencode/tools/"*.ts "$root/opencode-nga/tools/" 2>/dev/null || true
    cp "$EXTENSION_DIR/opencode/plugins/"*.ts "$root/opencode-nga/plugins/" 2>/dev/null || true

    # claude-code（官方插件方式，安装到 ~/.claude/plugins/，非 skills/）
    mkdir -p "$root/claude-code/.claude-plugin" "$root/claude-code/.claude/commands" "$root/claude-code/.claude/agents" "$root/claude-code/hooks"
    cp "$EXTENSION_DIR/claude-code/.claude-plugin/plugin.json" "$root/claude-code/.claude-plugin/"
    set_json_version "$root/claude-code/.claude-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-code/hooks/hooks.json" "$root/claude-code/hooks/"
    cp "$EXTENSION_DIR/claude-code/.claude/settings.json" "$root/claude-code/.claude/" 2>/dev/null || true
    expand_includes "$EXTENSION_DIR/claude-code/.claude/commands/secguard.md" "$root/claude-code/.claude/commands/secguard.md" "$EXTENSION_DIR/shared"
    expand_includes "$EXTENSION_DIR/claude-code/.claude/agents/security-auditor.md" "$root/claude-code/.claude/agents/security-auditor.md" "$EXTENSION_DIR/shared"

    # claude-cac（Claude Code 开源分支：~/.cac/，manifest 改名 .cac-plugin/plugin.json）
    mkdir -p "$root/claude-cac/.cac-plugin" "$root/claude-cac/.cac/commands" "$root/claude-cac/.cac/agents" "$root/claude-cac/hooks"
    cp "$EXTENSION_DIR/claude-cac/.cac-plugin/plugin.json" "$root/claude-cac/.cac-plugin/"
    set_json_version "$root/claude-cac/.cac-plugin/plugin.json" "$version"
    cp "$EXTENSION_DIR/claude-cac/hooks/hooks.json" "$root/claude-cac/hooks/"
    cp "$EXTENSION_DIR/claude-cac/.cac/settings.json" "$root/claude-cac/.cac/" 2>/dev/null || true
    expand_includes "$EXTENSION_DIR/claude-cac/.cac/commands/secguard.md" "$root/claude-cac/.cac/commands/secguard.md" "$EXTENSION_DIR/shared"
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

# ── 执行打包 ──
build_master

# ── 生成校验和（写入相对文件名，便于下游校验）──
echo ""
echo "[sha256] Generating checksums..."
ZIP_FILE="$DIST_DIR/secguard-${version}.zip"
ZIP_BASENAME="$(basename "$ZIP_FILE")"
if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$DIST_DIR" && sha256sum "$ZIP_BASENAME" > "$ZIP_BASENAME.sha256" && sha256sum "$ZIP_BASENAME" > SHA256SUMS )
else
    ( cd "$DIST_DIR" && shasum -a 256 "$ZIP_BASENAME" > "$ZIP_BASENAME.sha256" && shasum -a 256 "$ZIP_BASENAME" > SHA256SUMS )
fi
echo "  → secguard-${version}.zip.sha256"
echo "  → SHA256SUMS"

# ── 清理 ──
rm -f "$INJECT_FILE"
for bin in "${built_binaries[@]}"; do
    rm -f "$bin" 2>/dev/null || true
done
rm -rf "$DIST_DIR"/.tmp-* 2>/dev/null || true

# ── 产物列表 ──
size=$(ls -lh "$ZIP_FILE" | awk '{print $5}')
hash=$(cut -d' ' -f1 "$ZIP_FILE.sha256" 2>/dev/null || echo "?")
echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║              Build Complete — v${version}                       ║"
echo "╠══════════════════════════════════════════════════════════╣"
printf "║  %-52s %6s\n" "$(basename "$ZIP_FILE")" "$size"
printf "║    sha256: %s\n" "${hash:0:16}..."
echo "╚══════════════════════════════════════════════════════════╝"
