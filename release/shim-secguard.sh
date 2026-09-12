#!/bin/sh
# bin/secguard — SecGuard plugin 的二进制统一入口（调度 shim）。
#
# 它按 os/arch 选型并 exec 对应的 secguard-<os>-<arch>[.exe]。
# 注意：它不是任何单一架构的二进制本体；5 个架构二进制始终以
# secguard-<os>-<arch> 命名并列存在。严禁用某个架构的二进制覆盖本文件。
PLUGIN_BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "$(uname -s)" in
    Darwin) OS=darwin ;;
    Linux)  OS=linux ;;
    MINGW*|MSYS*|CYGWIN*) OS=windows ;;
    *)      OS=$(uname -s | tr 'A-Z' 'a-z') ;;
esac

case "$(uname -m)" in
    x86_64)         ARCH=amd64 ;;
    aarch64|arm64)  ARCH=arm64 ;;
    *)              ARCH=$(uname -m) ;;
esac

BIN="$PLUGIN_BIN_DIR/secguard-${OS}-${ARCH}"
[ "$OS" = "windows" ] && BIN="$PLUGIN_BIN_DIR/secguard-${OS}-${ARCH}.exe"

exec "$BIN" "$@"
