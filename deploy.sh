#!/bin/bash
set -euo pipefail

# deploy.sh — Quick build + deploy secguard-clang extension to user-level config dirs
# Usage: ./deploy.sh [opencode|claude-code|all] [--no-binary]
# Default (no args): builds binary + installs both platforms as extensions

PRODUCT="secguard-clang"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SGRE_DIR="$SCRIPT_DIR/sgre"
EXT_DIR="$SCRIPT_DIR/extension"
SHARED_DIR="$EXT_DIR/shared"
# 版本号：dev 部署用仓库根 VERSION 文件（与发布一致），缺失时回退 0.0.0
VERSION="$(head -1 "$SCRIPT_DIR/VERSION" 2>/dev/null | tr -d '[:space:]')"
[ -n "$VERSION" ] || VERSION="0.0.0"

# 加载共享函数库（expand_includes 等由 lib.sh 提供）
source "$SCRIPT_DIR/release/lib.sh"

OPENCODE_BASE="${OPENCODE_DIR:-$HOME/.config/opencode}"
CLAUDE_BASE="${CLAUDE_DIR:-$HOME/.claude}"
CAC_BASE="${CAC_DIR:-$HOME/.cac}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

OPENCODE_EXT_DIR="$OPENCODE_BASE/extensions/$PRODUCT"
OPENCODE_PLUGIN_DIR="$OPENCODE_BASE/plugins/$PRODUCT"
CLAUDE_PLUGIN_DIR="$CLAUDE_BASE/plugins/$PRODUCT"
CAC_PLUGIN_DIR="$CAC_BASE/plugins/$PRODUCT"

PLATFORM="all"
INSTALL_BINARY=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        opencode|opencode-nga|claude-code|claude-cac|all)
            PLATFORM="$1"; shift ;;
        --no-binary)
            INSTALL_BINARY=false; shift ;;
        --help|-h)
            echo "Usage: $0 [opencode|opencode-nga|claude-code|claude-cac|all] [--no-binary]"
            echo ""
            echo "Product: $PRODUCT"
            echo ""
            echo "Platforms:"
            echo "  opencode      Install extension to ~/.config/opencode/extensions/$PRODUCT/"
            echo "  opencode-nga  Install OpenCode fork extension (codeagent-extension.json) to the same dir"
            echo "  claude-code   Install official plugin to ~/.claude/plugins/$PRODUCT/"
            echo "  claude-cac    Install Claude Code fork plugin to ~/.cac/plugins/$PRODUCT/"
            echo "  all           Install all four (default)"
            echo ""
            echo "Options:"
            echo "  --no-binary  Skip binary build/install"
            echo ""
            echo "Env overrides:"
            echo "  OPENCODE_DIR  Default: ~/.config/opencode"
            echo "  CLAUDE_DIR    Default: ~/.claude"
            echo "  CAC_DIR       Default: ~/.cac"
            echo "  BIN_DIR       Default: ~/.local/bin"
            exit 0 ;;
        *)
            echo "Unknown option: $1 (use --help for usage)"; exit 1 ;;
    esac
done

echo "╔══════════════════════════════════════════════════════════╗"
echo "║       $PRODUCT — Quick Deploy (dev mode)              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "  Project root:  $SCRIPT_DIR"
echo "  Platform:      $PLATFORM"
echo "  Binary build:  $([ "$INSTALL_BINARY" = true ] && echo "yes" || echo "skipped")"
echo ""

# ── Build binary ──────────────────────────────────────────────
BINARY_OK=false

build_binary() {
    if [ "$INSTALL_BINARY" = false ]; then
        echo "[binary] Skipped (--no-binary)"
        return
    fi

    echo "[binary] Building secguard..."
    mkdir -p "$BIN_DIR"

    if ! command -v go 2>&1 | grep -q go; then
        echo "[binary] WARNING: Go not found — skipping binary build"
        return
    fi

    export PATH="/opt/homebrew/bin:$PATH"
    export CGO_ENABLED=1
    export GONOSUMDB='*'
    export GOFLAGS=-mod=mod
    export GOCACHE="$SGRE_DIR/.gocache"
    export TMPDIR="$SGRE_DIR/.gotmp"
    mkdir -p "$GOCACHE" "$TMPDIR"

    (
        cd "$SGRE_DIR"
        CGO_ENABLED=1 go build -o "$BIN_DIR/secguard" ./cmd/secguard 2>&1
    ) && {
        chmod +x "$BIN_DIR/secguard"
        BINARY_OK=true
        echo "[binary] OK → $BIN_DIR/secguard"
    } || {
        echo "[binary] WARNING: Build failed (missing deps?)."
        echo "         Install deps: go get modernc.org/sqlite@latest && go mod tidy"
        echo "         Extension files will still be deployed."
    }
    echo ""
}

# ── Template expansion (provided by lib.sh: expand_includes) ──

# ── Install skills (shared) ───────────────────────────────────
install_skills() {
    local target_skills_dir="$1"
    for skill_dir in "$SHARED_DIR/skills"/*/; do
        [ -d "$skill_dir" ] || continue
        local skill_name
        skill_name=$(basename "$skill_dir")
        mkdir -p "$target_skills_dir/$skill_name"
        cp "$skill_dir/SKILL.md" "$target_skills_dir/$skill_name/"
    done
}

# ── 覆写 plugin.json 的 version 字段（与发布时 set_json_version 一致）──
stamp_json_version() {
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

# ── Install OpenCode plugin ───────────────────────────────────
install_opencode() {
    echo "[opencode] Plugin dir: $OPENCODE_PLUGIN_DIR"
    mkdir -p "$OPENCODE_PLUGIN_DIR"/{commands,agents,tools,skills}

    cp "$EXT_DIR/opencode/package.json" "$OPENCODE_PLUGIN_DIR/"
    stamp_json_version "$OPENCODE_PLUGIN_DIR/package.json" "$VERSION"
    cp "$EXT_DIR/opencode/index.ts" "$OPENCODE_PLUGIN_DIR/"

    for f in "$EXT_DIR/opencode/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_PLUGIN_DIR/commands/$(basename "$f")" "$SHARED_DIR"
    done
    for f in "$EXT_DIR/opencode/agents"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_PLUGIN_DIR/agents/$(basename "$f")" "$SHARED_DIR"
    done

    cp "$EXT_DIR/opencode/tools/"*.ts "$OPENCODE_PLUGIN_DIR/tools/" 2>&1 || true

    install_skills "$OPENCODE_PLUGIN_DIR/skills"

    sg_register_opencode_plugin "$OPENCODE_BASE" "$PRODUCT"

    # 清理旧版 opencode extension 的遗留清单（extension.json，已由 package.json 取代）。
    # 注意：extensions/ 目录现归 opencode-nga 独占，只删旧清单文件、不整目录删除。
    rm -f "$OPENCODE_EXT_DIR/extension.json"
    rm -f "$OPENCODE_BASE/.secguard-install-manifest" "$OPENCODE_BASE/.secguard-install-manifest-nga"

    echo "[opencode] Done"
    echo ""
}

# ── Install OpenCode-NGA extension ───────────────────────────
install_opencode_nga() {
    echo "[opencode-nga] Extension dir: $OPENCODE_EXT_DIR"
    # 清理 <=0.4.4 的旧清单名（code-extension*.json），避免扩展目录里出现两套清单。
    rm -f "$OPENCODE_EXT_DIR/code-extension.json" "$OPENCODE_EXT_DIR/code-extension-install.json"
    mkdir -p "$OPENCODE_EXT_DIR"/{commands,agents,tools,plugins,skills}

    cp "$EXT_DIR/opencode-nga/codeagent-extension.json" "$OPENCODE_EXT_DIR/"
    stamp_json_version "$OPENCODE_EXT_DIR/codeagent-extension.json" "$VERSION"
    # 用 python3 做字面替换，避免 sed 把路径里的 `&`/`|` 当特殊字符。
    python3 -c "
src = '''$EXT_DIR/opencode-nga/.codeagent-extension-install.json'''
dst = '''$OPENCODE_EXT_DIR/.codeagent-extension-install.json'''
target = '''$OPENCODE_EXT_DIR'''
with open(src) as f:
    content = f.read()
with open(dst, 'w') as f:
    f.write(content.replace('{{OC_TARGET_DIR}}', target))
"
    cp "$EXT_DIR/opencode-nga/opencode.json" "$OPENCODE_EXT_DIR/"

    for f in "$EXT_DIR/opencode/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_EXT_DIR/commands/$(basename "$f")" "$SHARED_DIR"
    done
    for f in "$EXT_DIR/opencode/agents"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_EXT_DIR/agents/$(basename "$f")" "$SHARED_DIR"
    done

    cp "$EXT_DIR/opencode/tools/"*.ts "$OPENCODE_EXT_DIR/tools/" 2>&1 || true
    cp "$EXT_DIR/opencode-nga/plugins/"*.ts "$OPENCODE_EXT_DIR/plugins/" 2>&1 || true

    install_skills "$OPENCODE_EXT_DIR/skills"

    echo "[opencode-nga] Done"
    echo ""
}

# ── Register a Claude Code / Claude CAC plugin (marketplace-style) ──
# 官方 Claude Code 不会自动扫描 ~/.claude/plugins/<name>/，它靠
# plugins/installed_plugins.json（installPath 指向 cache 目录）+ settings.json 的
# enabledPlugins 来发现插件。仅把文件拷进 ~/.claude/plugins/ 是不会生效的（这正是
# deploy.sh claude-code 之前"装了但 / 里找不到命令"的根因）。此函数补齐注册步骤，
# 与 release/install.sh.tmpl 的 install_claude_code/install_claude_cac 保持一致。
register_claude_plugin() {
    local prefix="$1"       # ~/.claude 或 ~/.cac
    local plugin_dir="$2"   # ~/.claude/plugins/secguard-clang
    local version="$3"

    local cache_dir="$prefix/plugins/cache/local-secguard/$PRODUCT/$version"
    mkdir -p "$cache_dir"
    # 用 `/.` 而非 `/*`：`*` 不匹配点文件，会漏掉 .claude-plugin/（插件清单）。
    cp -r "$plugin_dir"/. "$cache_dir/" 2>/dev/null || true

    sg_write_codeagent_extension "$cache_dir" "$version"
    sg_write_codeagent_extension "$plugin_dir" "$version"

    sg_register_plugin "$prefix/plugins/installed_plugins.json" "$PRODUCT" "local-secguard" "$cache_dir" "$version"
    sg_enable_plugin "$prefix/settings.json" "$PRODUCT" "local-secguard"
    echo "[plugin] Registered $PRODUCT@local-secguard → $cache_dir"
}

# ── Install Claude Code plugin ────────────────────────────────
install_claude_code() {
    echo "[claude-code] Plugin dir: $CLAUDE_PLUGIN_DIR"
    mkdir -p "$CLAUDE_PLUGIN_DIR"/{.claude-plugin,commands,agents,hooks,skills,bin}

    cp "$EXT_DIR/claude-code/.claude-plugin/plugin.json" "$CLAUDE_PLUGIN_DIR/.claude-plugin/"
    stamp_json_version "$CLAUDE_PLUGIN_DIR/.claude-plugin/plugin.json" "$VERSION"

    cp "$EXT_DIR/claude-code/hooks/hooks.json" "$CLAUDE_PLUGIN_DIR/hooks/"

    for f in "$EXT_DIR/claude-code/.claude/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$CLAUDE_PLUGIN_DIR/commands/$(basename "$f")" "$SHARED_DIR"
    done
    for f in "$EXT_DIR/claude-code/.claude/agents"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$CLAUDE_PLUGIN_DIR/agents/$(basename "$f")" "$SHARED_DIR"
    done

    install_skills "$CLAUDE_PLUGIN_DIR/skills"

    if [ "$BINARY_OK" = true ]; then
        cp "$BIN_DIR/secguard" "$CLAUDE_PLUGIN_DIR/bin/"
        chmod +x "$CLAUDE_PLUGIN_DIR/bin/secguard"
        echo "[claude-code] Binary → $CLAUDE_PLUGIN_DIR/bin/secguard"
    fi

    register_claude_plugin "$CLAUDE_BASE" "$CLAUDE_PLUGIN_DIR" "$VERSION"

    echo "[claude-code] Merging permissions into $CLAUDE_BASE/settings.json"
    merge_claude_permissions "$CLAUDE_BASE/settings.json"

    echo "[claude-code] Done"
    echo ""
}

# ── Install Claude CAC plugin (Claude Code 开源分支) ─────────
install_claude_cac() {
    echo "[claude-cac] Plugin dir: $CAC_PLUGIN_DIR"
    mkdir -p "$CAC_PLUGIN_DIR"/{.cac-plugin,commands,agents,hooks,skills,bin}

    cp "$EXT_DIR/claude-cac/.cac-plugin/plugin.json" "$CAC_PLUGIN_DIR/.cac-plugin/"
    stamp_json_version "$CAC_PLUGIN_DIR/.cac-plugin/plugin.json" "$VERSION"

    cp "$EXT_DIR/claude-cac/hooks/hooks.json" "$CAC_PLUGIN_DIR/hooks/"

    for f in "$EXT_DIR/claude-cac/.cac/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$CAC_PLUGIN_DIR/commands/$(basename "$f")" "$SHARED_DIR"
    done
    for f in "$EXT_DIR/claude-cac/.cac/agents"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$CAC_PLUGIN_DIR/agents/$(basename "$f")" "$SHARED_DIR"
    done

    install_skills "$CAC_PLUGIN_DIR/skills"

    if [ "$BINARY_OK" = true ]; then
        cp "$BIN_DIR/secguard" "$CAC_PLUGIN_DIR/bin/"
        chmod +x "$CAC_PLUGIN_DIR/bin/secguard"
        echo "[claude-cac] Binary → $CAC_PLUGIN_DIR/bin/secguard"
    fi

    register_claude_plugin "$CAC_BASE" "$CAC_PLUGIN_DIR" "$VERSION"

    echo "[claude-cac] Merging permissions into $CAC_BASE/settings.json"
    merge_claude_permissions "$CAC_BASE/settings.json"

    echo "[claude-cac] Done"
    echo ""
}

# ── Merge Claude Code / Claude CAC permissions ────────────────
merge_claude_permissions() {
    local settings_path="${1:-$CLAUDE_BASE/settings.json}"
    python3 -c "
import json, os, sys

settings_path = '''$settings_path'''
required_perms = [
    'Bash(secguard scan *)',
    'Bash(secguard index *)',
    'Bash(secguard plan *)',
    'Bash(secguard report *)',
    'Bash(secguard status *)',
    'Bash(secguard query *)',
    'Bash(secguard types *)',
    'Bash(secguard db *)',
    'Bash(secguard schema *)',
]

try:
    with open(settings_path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    settings = {}

if 'permissions' not in settings:
    settings['permissions'] = {}
if 'allow' not in settings['permissions']:
    settings['permissions']['allow'] = []
if 'deny' not in settings['permissions']:
    settings['permissions']['deny'] = []

existing = set(settings['permissions']['allow'])
added = []
for perm in required_perms:
    if perm not in existing:
        settings['permissions']['allow'].append(perm)
        existing.add(perm)
        added.append(perm)

with open(settings_path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')

if added:
    print(f'  Added {len(added)} permission(s): {added}')
else:
    print('  All permissions already present — no changes needed')
" 2>&1 || echo "  WARNING: Could not merge permissions (python3 failed)"
}

# ── Execute ───────────────────────────────────────────────────
build_binary

case "$PLATFORM" in
    opencode)
        install_opencode || true
        ;;
    opencode-nga)
        install_opencode_nga || true
        ;;
    claude-code)
        install_claude_code || true
        ;;
    claude-cac)
        install_claude_cac || true
        ;;
    all)
        install_opencode || true
        install_opencode_nga || true
        install_claude_code || true
        install_claude_cac || true
        ;;
esac

# ── Summary ───────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                   Deploy Summary                          ║"
echo "╠══════════════════════════════════════════════════════════╣"

if [ "$BINARY_OK" = true ]; then
    echo "║  Binary:  $BIN_DIR/secguard"
fi

case "$PLATFORM" in
    opencode|all)
        echo "║  OpenCode plugin:"
        echo "║    $OPENCODE_PLUGIN_DIR/"
        echo "║      package.json, index.ts"
        echo "║      commands/secguard.md (→ /secguard-clang/secguard)"
        echo "║      agents/security-auditor.md"
        echo "║      tools/secguard_*.ts"
        echo "║      skills/*/SKILL.md"
        echo "║  OpenCode config:"
        echo "║    $OPENCODE_BASE/opencode.json (plugin: ./plugins/$PRODUCT)"
        ;;
esac

case "$PLATFORM" in
    opencode-nga|all)
        echo "║  OpenCode-NGA extension:"
        echo "║    $OPENCODE_EXT_DIR/"
        echo "║      codeagent-extension.json, .codeagent-extension-install.json"
        echo "║      opencode.json, commands/, agents/, tools/, plugins/, skills/"
        ;;
esac

case "$PLATFORM" in
    claude-code|all)
        echo "║  Claude Code plugin (official plugins-dir):"
        echo "║    $CLAUDE_PLUGIN_DIR/"
        echo "║      .claude-plugin/plugin.json"
        echo "║      commands/secguard.md"
        echo "║      agents/security-auditor.md"
        echo "║      hooks/hooks.json"
        echo "║      bin/secguard"
        echo "║      skills/*/SKILL.md"
        echo "║  Claude Code plugin registration:"
        echo "║    cache:     $CLAUDE_BASE/plugins/cache/local-secguard/$PRODUCT/$VERSION/"
        echo "║    registry:  $CLAUDE_BASE/plugins/installed_plugins.json"
        echo "║    enabled:   $CLAUDE_BASE/settings.json (enabledPlugins)"
        echo "║  Claude Code permissions:"
        echo "║    $CLAUDE_BASE/settings.json (merged)"
        ;;
esac

case "$PLATFORM" in
    claude-cac|all)
        echo "║  Claude CAC plugin (Claude Code 开源分支):"
        echo "║    $CAC_PLUGIN_DIR/"
        echo "║      .cac-plugin/plugin.json"
        echo "║      commands/secguard.md"
        echo "║      agents/security-auditor.md"
        echo "║      hooks/hooks.json"
        echo "║      bin/secguard"
        echo "║      skills/*/SKILL.md"
        echo "║  Claude CAC plugin registration:"
        echo "║    cache:     $CAC_BASE/plugins/cache/local-secguard/$PRODUCT/$VERSION/"
        echo "║    registry:  $CAC_BASE/plugins/installed_plugins.json"
        echo "║    enabled:   $CAC_BASE/settings.json (enabledPlugins)"
        echo "║  Claude CAC permissions:"
        echo "║    $CAC_BASE/settings.json (merged)"
        ;;
esac

echo "╠══════════════════════════════════════════════════════════╣"
echo "║  OpenCode:   /$PRODUCT/secguard [path]"
echo "║  Claude Code:/$PRODUCT:secguard [path]"
echo "║  Skills:   null-deref, buffer-overflow, memory-leak, injection, resource-leak, uninit, use-after-free, double-free, format-string"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""

# ── Verify deployed files exist ───────────────────────────────
echo "Verification — checking deployed files:"
all_ok=true

check_file() {
    if [ -f "$1" ]; then
        echo "  OK   $1"
    else
        echo "  MISS $1"
        all_ok=false
    fi
}

check_dir() {
    if [ -d "$1" ]; then
        echo "  OK   $1/"
    else
        echo "  MISS $1/"
        all_ok=false
    fi
}

if [ "$BINARY_OK" = true ]; then
    check_file "$BIN_DIR/secguard"
fi

case "$PLATFORM" in
    opencode|all)
        echo ""
        echo "  OpenCode plugin ($OPENCODE_PLUGIN_DIR):"
        check_file "$OPENCODE_PLUGIN_DIR/package.json"
        check_file "$OPENCODE_PLUGIN_DIR/index.ts"
        check_file "$OPENCODE_PLUGIN_DIR/commands/secguard.md"
        check_file "$OPENCODE_PLUGIN_DIR/commands/diff.md"
        check_file "$OPENCODE_PLUGIN_DIR/agents/security-auditor.md"
        check_file "$OPENCODE_PLUGIN_DIR/tools/secguard_scan.ts"
        check_file "$OPENCODE_PLUGIN_DIR/tools/secguard_db.ts"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/null-deref"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/buffer-overflow"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/memory-leak"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/injection"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/resource-leak"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/uninit"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/use-after-free"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/double-free"
        check_dir  "$OPENCODE_PLUGIN_DIR/skills/format-string"
        ;;
esac

case "$PLATFORM" in
    opencode-nga|all)
        echo ""
        echo "  OpenCode-NGA extension ($OPENCODE_EXT_DIR):"
        check_file "$OPENCODE_EXT_DIR/codeagent-extension.json"
        check_file "$OPENCODE_EXT_DIR/.codeagent-extension-install.json"
        check_file "$OPENCODE_EXT_DIR/opencode.json"
        check_file "$OPENCODE_EXT_DIR/commands/secguard.md"
        check_file "$OPENCODE_EXT_DIR/agents/security-auditor.md"
        check_file "$OPENCODE_EXT_DIR/plugins/secguard-context.ts"
        check_file "$OPENCODE_EXT_DIR/tools/secguard_scan.ts"
        check_file "$OPENCODE_EXT_DIR/tools/secguard_db.ts"
        check_dir  "$OPENCODE_EXT_DIR/skills/null-deref"
        check_dir  "$OPENCODE_EXT_DIR/skills/buffer-overflow"
        ;;
esac

case "$PLATFORM" in
    claude-code|all)
        echo ""
        echo "  Claude Code plugin ($CLAUDE_PLUGIN_DIR):"
        check_file "$CLAUDE_PLUGIN_DIR/.claude-plugin/plugin.json"
        check_file "$CLAUDE_PLUGIN_DIR/commands/secguard.md"
        check_file "$CLAUDE_PLUGIN_DIR/agents/security-auditor.md"
        check_file "$CLAUDE_PLUGIN_DIR/hooks/hooks.json"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/null-deref"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/buffer-overflow"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/memory-leak"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/injection"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/resource-leak"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/uninit"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/use-after-free"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/double-free"
        check_dir  "$CLAUDE_PLUGIN_DIR/skills/format-string"
        if [ "$BINARY_OK" = true ]; then
            check_file "$CLAUDE_PLUGIN_DIR/bin/secguard"
        fi
        echo ""

        echo "  Claude Code settings:"
        check_file "$CLAUDE_BASE/settings.json"
        ;;
esac

case "$PLATFORM" in
    claude-cac|all)
        echo ""
        echo "  Claude CAC plugin ($CAC_PLUGIN_DIR):"
        check_file "$CAC_PLUGIN_DIR/.cac-plugin/plugin.json"
        check_file "$CAC_PLUGIN_DIR/commands/secguard.md"
        check_file "$CAC_PLUGIN_DIR/agents/security-auditor.md"
        check_file "$CAC_PLUGIN_DIR/hooks/hooks.json"
        check_dir  "$CAC_PLUGIN_DIR/skills/null-deref"
        check_dir  "$CAC_PLUGIN_DIR/skills/buffer-overflow"
        if [ "$BINARY_OK" = true ]; then
            check_file "$CAC_PLUGIN_DIR/bin/secguard"
        fi
        echo ""
        echo "  Claude CAC settings:"
        check_file "$CAC_BASE/settings.json"
        ;;
esac

echo ""

if [ "$all_ok" = true ]; then
    echo "All files deployed successfully."
else
    echo "WARNING: Some files are missing — check output above."
fi
