#!/usr/bin/env bash
# 从 CHANGELOG.md 提取单个版本的发布说明（从 `## [v]` 到下一个 `## [` 之前）。
# 用法：release-notes.sh <version> [changelog] [output]
# 若未找到该版本小节（说明版本号与 CHANGELOG 不一致），回退到完整 CHANGELOG。
set -euo pipefail

version="$1"
changelog="${2:-CHANGELOG.md}"
output="${3:-release-notes.md}"

awk -v v="$version" '
  BEGIN { heading = "^## \\[" v "\\]" }
  $0 ~ heading { in_section = 1 }
  in_section && $0 !~ heading && /^## \[/ { exit }
  in_section { print }
' "$changelog" > "$output"

[ -s "$output" ] || cp "$changelog" "$output"
