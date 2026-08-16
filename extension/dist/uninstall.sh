#!/bin/bash
set -euo pipefail

# uninstall.sh — SecGuard 独立卸载脚本（统一包模板）
# 打包时占位标记会被替换为 sg_* 函数定义（内联注入）
# 此脚本自包含，无外部依赖

# @@SG_LIB_INJECT@@

PKG_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG_VERSION="$(cat "$PKG_DIR/VERSION" 2>/dev/null || echo unknown)"

TARGET="all"
PREFIX=""
BIN_DIR=""
YES=false

usage() {
    cat <<EOF
SecGuard v${PKG_VERSION} Uninstaller
Usage: uninstall.sh [options]

Options:
  --target <opencode|claude-code|all>  Target platform (default: all)
  --prefix <path>                      Override install root
  --bin-dir <path>                     Binary install dir (default: /usr/local/bin)
  --yes, -y                            Skip confirmation prompts
  --help, -h                           Show this help

Environment overrides:
  OPENCODE_DIR   Default: ~/.config/opencode
  CLAUDE_DIR     Default: ~/.claude
  BIN_DIR        Default: /usr/local/bin
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --target)    TARGET="$2"; shift 2 ;;
        --target=*)  TARGET="${1#--target=}"; shift ;;
        --prefix)    PREFIX="$2"; shift 2 ;;
        --prefix=*)  PREFIX="${1#--prefix=}"; shift ;;
        --bin-dir)   BIN_DIR="$2"; shift 2 ;;
        --bin-dir=*) BIN_DIR="${1#--bin-dir=}"; shift ;;
        --yes|-y)    YES=true; shift ;;
        --help|-h)   usage; exit 0 ;;
        *)           echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
done

OC_PREFIX="${PREFIX:-${OPENCODE_DIR:-$HOME/.config/opencode}}"
CC_PREFIX="${PREFIX:-${CLAUDE_DIR:-$HOME/.claude}}"
[ -z "$BIN_DIR" ] && BIN_DIR="${BIN_DIR_ENV:-/usr/local/bin}"
OC_MANIFEST="$OC_PREFIX/.secguard-install-manifest"
CC_MANIFEST="$CC_PREFIX/.secguard-install-manifest"

yes_flag="false"
[ "$YES" = true ] && yes_flag="true"

echo "SecGuard v${PKG_VERSION} — Uninstalling (target: $TARGET)"
echo "========================================================"

case "$TARGET" in
    opencode)
        sg_uninstall_platform "opencode" "$OC_PREFIX" "$BIN_DIR" "$OC_MANIFEST" "$yes_flag"
        ;;
    claude-code)
        sg_uninstall_platform "claude-code" "$CC_PREFIX" "$BIN_DIR" "$CC_MANIFEST" "$yes_flag"
        ;;
    all)
        sg_uninstall_platform "opencode" "$OC_PREFIX" "$BIN_DIR" "$OC_MANIFEST" "$yes_flag"
        echo ""
        sg_uninstall_platform "claude-code" "$CC_PREFIX" "$BIN_DIR" "$CC_MANIFEST" "$yes_flag"
        ;;
    *) echo "Unknown target: $TARGET" >&2; exit 2 ;;
esac

echo ""
echo "Uninstall complete."