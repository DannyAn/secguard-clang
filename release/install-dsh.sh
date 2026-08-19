#!/usr/bin/env bash
# Install the SecGuard DeepSeek Harness (DSH) agent preset.
#
# Copies the DSH thin wrapper (extension/deepseek-harness/) plus the shared
# skills (extension/shared/skills/) into the user's DSH agent-preset root:
#   ${DSH_HOME:-$HOME/.dsh}/.agent-presets/secguard/
#
# The preset becomes selectable as "SecGuard 安全审计" in DSH. Re-run any time
# the source skills or composition change to refresh the installed copy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DSH_HOME="${DSH_HOME:-$HOME/.dsh}"
DEST="$DSH_HOME/.agent-presets/secguard"

echo "SecGuard DSH install:"
echo "  source : $REPO_ROOT/extension/deepseek-harness + extension/shared/skills"
echo "  dest   : $DEST"

mkdir -p "$DEST"
cp "$REPO_ROOT/extension/deepseek-harness/preset.yml" "$DEST/preset.yml"
cp "$REPO_ROOT/extension/deepseek-harness/agent.cordis.yml" "$DEST/agent.cordis.yml"

rm -rf "$DEST/skills"
cp -R "$REPO_ROOT/extension/shared/skills" "$DEST/skills"

echo "Installed $(find "$DEST/skills" -name SKILL.md | wc -l | tr -d ' ') SecGuard skills."
echo
echo "Select the 'SecGuard 安全审计' preset in DSH, then ask it to:"
echo '  secguard scan <path>   全量扫描'
echo '  看看有没有 buffer-overflow, null-deref 问题   过滤扫描'
echo
echo "Note: the secguard binary must be on PATH (see README for install)."
