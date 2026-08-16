#!/bin/bash
set -euo pipefail

# build.sh — Build secguard binary and/or distribution packages
# Usage: ./build.sh [options]
#   --test       Run tests before building
#   --install    Install binary to ~/.local/bin (default: ./bin/secguard)
#   --package    Build distribution package (single zip) to ./dist/
#   --version <v>  Explicit version (for --package)
#   --os <os>    Filter target OS for --package (darwin|linux|windows)
#   --arch <a>   Filter target arch for --package (amd64|arm64)
#   --help       Show usage

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SGRE_DIR="$SCRIPT_DIR/sgre"
BIN_DIR="$SCRIPT_DIR/bin"
INSTALL_DIR="$HOME/.local/bin"
OUTPUT="$BIN_DIR/secguard"
RUN_TEST=false
DO_INSTALL=false
DO_PACKAGE=false
EXPLICIT_VERSION=""
OS_FILTER=""
ARCH_FILTER=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --test)    RUN_TEST=true; shift ;;
        --install) DO_INSTALL=true; shift ;;
        --package|--dist) DO_PACKAGE=true; shift ;;
        --version) EXPLICIT_VERSION="$2"; shift 2 ;;
        --os)      OS_FILTER="$2"; shift 2 ;;
        --arch)    ARCH_FILTER="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --test         Run tests before building"
            echo "  --install      Install binary to $INSTALL_DIR (default: $OUTPUT)"
            echo "  --package      Build distribution package (single zip) to ./dist/"
            echo "  --version <v>  Explicit version (for --package)"
            echo "  --os <os>      Filter target OS (darwin|linux|windows) for --package"
            echo "  --arch <a>     Filter target arch (amd64|arm64) for --package"
            exit 0 ;;
        *) echo "Unknown option: $1 (use --help)"; exit 1 ;;
    esac
done

# ── Package mode: delegate to build-packages.sh ──
if [ "$DO_PACKAGE" = true ]; then
    pkg_args=()
    [ -n "$EXPLICIT_VERSION" ] && pkg_args+=(--version "$EXPLICIT_VERSION")
    [ -n "$OS_FILTER" ] && pkg_args+=(--os "$OS_FILTER")
    [ -n "$ARCH_FILTER" ] && pkg_args+=(--arch "$ARCH_FILTER")
    [ "$RUN_TEST" = true ] && pkg_args+=(--test)
    exec "$SCRIPT_DIR/extension/dist/build-packages.sh" ${pkg_args[@]+"${pkg_args[@]}"}
fi

# ── Default: build binary only (original behavior) ──
export PATH="/opt/homebrew/bin:$PATH"
export CGO_ENABLED=1
export GONOSUMDB='*'
export GOFLAGS=-mod=mod
export GOCACHE="$SGRE_DIR/.gocache"
export TMPDIR="$SGRE_DIR/.gotmp"

mkdir -p "$GOCACHE" "$TMPDIR" "$BIN_DIR"

echo "Building secguard..."
echo "  Source:  $SGRE_DIR"
echo "  Output:  $OUTPUT"
echo ""

if [ "$RUN_TEST" = true ]; then
    echo "Running tests..."
    (cd "$SGRE_DIR" && go test ./... 2>&1)
    echo "Tests passed."
    echo ""
fi

cd "$SGRE_DIR"
go build -o "$OUTPUT" ./cmd/secguard
chmod +x "$OUTPUT"

echo "Build OK: $OUTPUT"

if [ "$DO_INSTALL" = true ]; then
    mkdir -p "$INSTALL_DIR"
    cp "$OUTPUT" "$INSTALL_DIR/secguard"
    chmod +x "$INSTALL_DIR/secguard"
    echo "Installed: $INSTALL_DIR/secguard"
fi
