#!/usr/bin/env python3
"""Verify cross-platform consistency of the SecGuard extension (single source of truth).

Two drift classes are checked:

1. Turn budget — the shared batch-capacity model (shared/command-instructions.md
   `MAXTURNS`) sizes subagent batches from the turn cap; every platform's agent
   must declare the SAME cap in its native field:
     - Claude Code   : maxTurns  (claude-code/.claude/agents/security-auditor.md)
     - Claude CAC    : maxTurns  (claude-cac/.cac/agents/security-auditor.md)
     - OpenCode      : steps     (opencode/agents/security-auditor.md)
     - OpenCode-NGA  : steps     (opencode-nga/opencode.json)
   The OpenCode plugin (opencode/index.ts) must NOT hardcode `steps` — it reads
   them from the frontmatter.

2. Tool registration — the 8 `secguard_*` tools must agree across:
     - opencode/index.ts `SECGUARD_TOOLS` array
     - opencode/tools/*.ts filenames
     - opencode-nga/opencode.json `permission` keys (OpenCode-NGA relies on the
       old fork's extension loader registering tools/*.ts, so the permission list
       and the tool files must never drift apart)

Exits non-zero on any drift so the release build fails instead of shipping an
inconsistent extension.
"""

import json
import os
import re
import sys

EXT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "extension")


def fail(msg):
    print(f"EXTENSION CONSISTENCY CHECK FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def read(rel):
    with open(os.path.join(EXT, rel), encoding="utf-8") as f:
        return f.read()


def md_field(text, field):
    m = re.search(rf"^{field}:\s*(\d+)", text, re.M)
    return m.group(1) if m else None


def check_turn_budget():
    ci = read("shared/command-instructions.md")
    m = re.search(r"`MAXTURNS`\s*\|\s*(\d+)", ci)
    if not m:
        fail("MAXTURNS not found in shared/command-instructions.md")
    canonical = m.group(1)

    decls = {
        "claude-code maxTurns (.claude/agents/security-auditor.md)":
            md_field(read("claude-code/.claude/agents/security-auditor.md"), "maxTurns"),
        "claude-cac maxTurns (.cac/agents/security-auditor.md)":
            md_field(read("claude-cac/.cac/agents/security-auditor.md"), "maxTurns"),
        "opencode steps (agents/security-auditor.md)":
            md_field(read("opencode/agents/security-auditor.md"), "steps"),
    }

    try:
        nga = json.loads(read("opencode-nga/opencode.json"))
        decls["opencode-nga steps (opencode.json)"] = str(nga["agent"]["security-auditor"]["steps"])
    except (KeyError, json.JSONDecodeError) as e:
        fail(f"opencode-nga/opencode.json: {e}")

    for name, value in decls.items():
        if value != canonical:
            fail(f"{name} = {value}, expected {canonical}")

    idx = read("opencode/index.ts")
    if re.search(r"steps:\s*\d", idx):
        fail("opencode/index.ts hardcodes steps; read it from agents/security-auditor.md frontmatter")

    print(f"  turn budget: {canonical} turns across all platforms")


def check_tools():
    idx = read("opencode/index.ts")
    m = re.search(r"const SECGUARD_TOOLS = \[(.*?)\]", idx, re.S)
    if not m:
        fail("SECGUARD_TOOLS array not found in opencode/index.ts")
    index_tools = set(re.findall(r'"([^"]+)"', m.group(1)))

    tools_dir = os.path.join(EXT, "opencode", "tools")
    file_tools = {f[:-3] for f in os.listdir(tools_dir) if f.endswith(".ts")}

    try:
        nga = json.loads(read("opencode-nga/opencode.json"))
        nga_perms = {k for k in nga.get("permission", {}) if k.startswith("secguard_")}
    except json.JSONDecodeError as e:
        fail(f"opencode-nga/opencode.json: {e}")

    if index_tools != file_tools:
        only_idx = sorted(index_tools - file_tools)
        only_files = sorted(file_tools - index_tools)
        fail(f"SECGUARD_TOOLS != tools/*.ts: only-in-index={only_idx}, only-in-files={only_files}")

    if index_tools != nga_perms:
        only_idx = sorted(index_tools - nga_perms)
        only_nga = sorted(nga_perms - index_tools)
        fail(f"SECGUARD_TOOLS != opencode-nga permission keys: only-in-index={only_idx}, only-in-nga={only_nga}")

    print(f"  tools: {len(index_tools)} secguard_* tools consistent (index.ts == tools/*.ts == opencode-nga)")


def main():
    check_turn_budget()
    check_tools()
    print("Extension consistency check passed.")


if __name__ == "__main__":
    main()
