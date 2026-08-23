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

# 加载共享函数库（expand_includes 等由 lib.sh 提供）
source "$SCRIPT_DIR/release/lib.sh"

OPENCODE_BASE="${OPENCODE_DIR:-$HOME/.config/opencode}"
CLAUDE_BASE="${CLAUDE_DIR:-$HOME/.claude}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"

OPENCODE_EXT_DIR="$OPENCODE_BASE/extensions/$PRODUCT"
CLAUDE_PLUGIN_DIR="$CLAUDE_BASE/skills/$PRODUCT"

PLATFORM="all"
INSTALL_BINARY=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        opencode|claude-code|all)
            PLATFORM="$1"; shift ;;
        --no-binary)
            INSTALL_BINARY=false; shift ;;
        --help|-h)
            echo "Usage: $0 [opencode|claude-code|all] [--no-binary]"
            echo ""
            echo "Product: $PRODUCT"
            echo ""
            echo "Platforms:"
            echo "  opencode     Install extension to ~/.config/opencode/extensions/$PRODUCT/"
            echo "  claude-code  Install plugin to ~/.claude/skills/$PRODUCT/ (skills-dir plugin)"
            echo "  all          Install both (default)"
            echo ""
            echo "Options:"
            echo "  --no-binary  Skip binary build/install"
            echo ""
            echo "Env overrides:"
            echo "  OPENCODE_DIR  Default: ~/.config/opencode"
            echo "  CLAUDE_DIR    Default: ~/.claude"
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

# ── Install OpenCode extension ────────────────────────────────
install_opencode() {
    echo "[opencode] Extension dir: $OPENCODE_EXT_DIR"
    mkdir -p "$OPENCODE_EXT_DIR"/{commands,agents,tools,plugins,skills}

    cp "$EXT_DIR/opencode/extension.json" "$OPENCODE_EXT_DIR/"
    cp "$EXT_DIR/opencode/opencode.json" "$OPENCODE_EXT_DIR/"

    for f in "$EXT_DIR/opencode/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_EXT_DIR/commands/$(basename "$f")" "$SHARED_DIR"
    done
    for f in "$EXT_DIR/opencode/agents"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_EXT_DIR/agents/$(basename "$f")" "$SHARED_DIR"
    done

    cp "$EXT_DIR/opencode/tools/"*.ts "$OPENCODE_EXT_DIR/tools/" 2>&1 || true
    cp "$EXT_DIR/opencode/plugins/"*.ts "$OPENCODE_EXT_DIR/plugins/" 2>&1 || true

    install_skills "$OPENCODE_EXT_DIR/skills"

    echo "[opencode] Global command: $OPENCODE_BASE/commands/"
    mkdir -p "$OPENCODE_BASE/commands"
    for f in "$EXT_DIR/opencode/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$OPENCODE_BASE/commands/$(basename "$f")" "$SHARED_DIR"
    done

    echo "[opencode] Done"
    echo ""
}

# ── Install Claude Code plugin ────────────────────────────────
install_claude_code() {
    echo "[claude-code] Plugin dir: $CLAUDE_PLUGIN_DIR"
    mkdir -p "$CLAUDE_PLUGIN_DIR"/{.claude-plugin,commands,agents,hooks,skills,bin}

    cp "$EXT_DIR/claude-code/.claude-plugin/plugin.json" "$CLAUDE_PLUGIN_DIR/.claude-plugin/"

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

    echo "[claude-code] Global command: $CLAUDE_BASE/commands/"
    mkdir -p "$CLAUDE_BASE/commands"
    for f in "$EXT_DIR/claude-code/.claude/commands"/*.md; do
        [ -f "$f" ] && expand_includes "$f" "$CLAUDE_BASE/commands/$(basename "$f")" "$SHARED_DIR"
    done

    echo "[claude-code] Merging permissions into $CLAUDE_BASE/settings.json"
    merge_claude_permissions

    echo "[claude-code] Done"
    echo ""
}

# ── Merge Claude Code permissions ─────────────────────────────
merge_claude_permissions() {
    python3 -c "
import json, os, sys

settings_path = '$CLAUDE_BASE/settings.json'
required_perms = [
    'Bash(secguard scan *)',
    'Bash(secguard index *)',
    'Bash(secguard plan *)',
    'Bash(secguard report *)',
    'Bash(secguard status *)',
    'Bash(secguard query *)',
    'Bash(secguard db *)',
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
    claude-code)
        install_claude_code || true
        ;;
    all)
        install_opencode || true
        install_claude_code || true
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
        echo "║  OpenCode extension:"
        echo "║    $OPENCODE_EXT_DIR/"
        echo "║      extension.json, opencode.json"
        echo "║      commands/secguard.md"
        echo "║      agents/security-auditor.md"
        echo "║      tools/secguard_*.ts"
        echo "║      plugins/secguard-context.ts"
        echo "║      skills/*/SKILL.md"
        echo "║  OpenCode global command:"
        echo "║    $OPENCODE_BASE/commands/secguard.md"
        ;;
esac

case "$PLATFORM" in
    claude-code|all)
        echo "║  Claude Code plugin (skills-dir, auto-loaded):"
        echo "║    $CLAUDE_PLUGIN_DIR/"
        echo "║      .claude-plugin/plugin.json"
        echo "║      commands/secguard.md"
        echo "║      agents/security-auditor.md"
        echo "║      hooks/hooks.json"
        echo "║      bin/secguard"
        echo "║      skills/*/SKILL.md"
        echo "║  Claude Code global command:"
        echo "║    $CLAUDE_BASE/commands/secguard.md"
        echo "║  Claude Code permissions:"
        echo "║    $CLAUDE_BASE/settings.json (merged)"
        ;;
esac

echo "╠══════════════════════════════════════════════════════════╣"
echo "║  Command:  /secguard [path]  or  /$PRODUCT:secguard [path]"
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
        echo "  OpenCode extension ($OPENCODE_EXT_DIR):"
        check_file "$OPENCODE_EXT_DIR/extension.json"
        check_file "$OPENCODE_EXT_DIR/opencode.json"
        check_file "$OPENCODE_EXT_DIR/commands/secguard.md"
        check_file "$OPENCODE_EXT_DIR/agents/security-auditor.md"
        check_file "$OPENCODE_EXT_DIR/plugins/secguard-context.ts"
        check_file "$OPENCODE_EXT_DIR/tools/secguard_scan.ts"
        check_file "$OPENCODE_EXT_DIR/tools/secguard_db.ts"
        check_dir  "$OPENCODE_EXT_DIR/skills/null-deref"
        check_dir  "$OPENCODE_EXT_DIR/skills/buffer-overflow"
        check_dir  "$OPENCODE_EXT_DIR/skills/memory-leak"
        check_dir  "$OPENCODE_EXT_DIR/skills/injection"
        check_dir  "$OPENCODE_EXT_DIR/skills/resource-leak"
        check_dir  "$OPENCODE_EXT_DIR/skills/uninit"
        check_dir  "$OPENCODE_EXT_DIR/skills/use-after-free"
        check_dir  "$OPENCODE_EXT_DIR/skills/double-free"
        check_dir  "$OPENCODE_EXT_DIR/skills/format-string"
        echo ""
        echo "  OpenCode global command:"
        check_file "$OPENCODE_BASE/commands/secguard.md"
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
        echo "  Claude Code global command:"
        check_file "$CLAUDE_BASE/commands/secguard.md"
        echo ""
        echo "  Claude Code settings:"
        check_file "$CLAUDE_BASE/settings.json"
        ;;
esac

echo ""

if [ "$all_ok" = true ]; then
    echo "All files deployed successfully."
else
    echo "WARNING: Some files are missing — check output above."
fi
