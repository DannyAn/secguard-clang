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

3. Subagent persistence surface — the security-auditor worker is a Bash-driver:
   it persists via `secguard report --write-json` (Bash), NOT via the `secguard_*`
   MCP tools. Those tools are orchestrator-only (granted at the top-level
   `permission` / index.ts config hook). Granting `secguard_*` to the subagent's
   own permission map breaks the OpenCode-NGA fork's config load — the v0.5.4
   regression. Guarded:
     - opencode/agents/security-auditor.md `permission.bash["secguard*"]` = allow
       and NO `secguard_*` key at the agent permission level
     - opencode-nga/opencode.json `agent.security-auditor.permission.bash["secguard*"]`
       = allow and NO `secguard_*` key there
     - claude-code + claude-cac `tools:` must include `Bash(secguard *)` + `Write`
       (the shell-only persistence surface); missing either = silent data loss

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


SHELL_TOOLS_REQUIRED = {"Bash(secguard *)", "Read", "Write", "Glob", "Grep", "Skill"}


def check_agent_permissions():
    # The secguard_* MCP tools are orchestrator-only (top-level permission /
    # index.ts config hook). The subagent persists via Bash. Granting secguard_*
    # to the subagent's own map breaks the OpenCode-NGA fork's config load.

    oc_agent = read("opencode/agents/security-auditor.md")
    oc_has_bash = re.search(r'^\s*"secguard\*":\s*allow', oc_agent, re.M) is not None
    oc_granted = sorted(set(re.findall(r'^\s*(secguard_\w+):\s*allow', oc_agent, re.M)))
    if not oc_has_bash:
        fail('opencode agents/security-auditor.md: permission.bash["secguard*"] must be allow (subagent persists via Bash)')
    if oc_granted:
        fail(f"opencode agents/security-auditor.md: must NOT grant {oc_granted} to the subagent — secguard_* tools are orchestrator-only")

    try:
        nga = json.loads(read("opencode-nga/opencode.json"))
        nga_perm = nga.get("agent", {}).get("security-auditor", {}).get("permission", {})
    except json.JSONDecodeError as e:
        fail(f"opencode-nga/opencode.json: {e}")
    nga_bash = nga_perm.get("bash", {})
    nga_has_bash = isinstance(nga_bash, dict) and nga_bash.get("secguard*") == "allow"
    nga_granted = sorted(k for k in nga_perm if k.startswith("secguard_") and nga_perm[k] == "allow")
    if not nga_has_bash:
        fail('opencode-nga agent.security-auditor.permission.bash["secguard*"] must be allow (subagent persists via Bash)')
    if nga_granted:
        fail(f"opencode-nga agent.security-auditor.permission: must NOT grant {nga_granted} to the subagent — secguard_* tools are orchestrator-only")

    for name, rel in [
        ("claude-code", "claude-code/.claude/agents/security-auditor.md"),
        ("claude-cac", "claude-cac/.cac/agents/security-auditor.md"),
    ]:
        text = read(rel)
        tm = re.search(r"^tools:\s*(.+)$", text, re.M)
        if not tm:
            fail(f"{name} agents/security-auditor.md: missing tools: field")
        tools = {t.strip() for t in tm.group(1).split(",") if t.strip()}
        missing = SHELL_TOOLS_REQUIRED - tools
        if missing:
            fail(f"{name} agents/security-auditor.md: tools missing {sorted(missing)}")

    print("  subagent persistence: Bash(secguard *) (opencode + opencode-nga), Bash(secguard *) + Write (claude-code + claude-cac)")


def main():
    check_turn_budget()
    check_tools()
    check_agent_permissions()
    print("Extension consistency check passed.")


if __name__ == "__main__":
    main()
