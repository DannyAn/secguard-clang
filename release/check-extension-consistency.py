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

3. Subagent persistence — the security-auditor worker has NO Bash on OpenCode-NGA,
   so it persists via the `secguard_report` MCP tool (granted `secguard_report` +
   `secguard_db` + `secguard_schema`). And the fork must register the 8 `secguard_*`
   tools via its `index.ts` entry point (`package.json` `main: index.ts` → `server.tool`)
   — the fork's extensions/ loader does NOT auto-discover tools/*.ts; without
   index.ts + package.json the tools are never exposed (the v0.5.4 "no secguard_*
   tools" smoke failure). Guarded:
     - opencode-nga/package.json `main` = index.ts, and opencode-nga/index.ts
       `tool: { ... }` registers all 8 tools
     - opencode/agents/security-auditor.md + opencode-nga agent permission allow
       `secguard_report`/`secguard_db`/`secguard_schema`
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

# The subagent persists via MCP on OpenCode hosts (no Bash there); these are the
# tools the agent-body.md write/review/id-lookup flow actually calls.
SUBAGENT_PERSIST_TOOLS = {"secguard_report", "secguard_db", "secguard_schema"}


def _secguard_tool_names():
    idx = read("opencode/index.ts")
    m = re.search(r"const SECGUARD_TOOLS = \[(.*?)\]", idx, re.S)
    if not m:
        fail("SECGUARD_TOOLS array not found in opencode/index.ts")
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def check_agent_permissions():
    secguard_tools = _secguard_tool_names()

    # The fork loads plugins/secguard-context.ts (referenced by opencode.json
    # `plugin: ["secguard-context"]`); its v1 `Hooks.tool` is where the 8
    # secguard_* tools MUST be registered. The fork does NOT auto-discover
    # tools/*.ts and does NOT load the v2 {id,server} index.ts default export
    # (that's upstream OpenCode only). Keep index.ts registered too as the
    # upstream-compatible entry point.
    nga_plugin = read("opencode-nga/plugins/secguard-context.ts")
    tool_block = re.search(r"tool:\s*\{([^}]*)\}", nga_plugin, re.S)
    if not tool_block:
        fail("opencode-nga/plugins/secguard-context.ts: missing `tool: { ... }` registration")
    registered = set(re.findall(r"(secguard_\w+)", tool_block.group(1)))
    if registered != secguard_tools:
        fail(f"opencode-nga/plugins/secguard-context.ts tool hook: registered {sorted(registered)}, expected {sorted(secguard_tools)}")

    nga_pkg = json.loads(read("opencode-nga/package.json"))
    if nga_pkg.get("main") != "index.ts":
        fail(f"opencode-nga/package.json: main must be index.ts, got {nga_pkg.get('main')}")
    nga_index = read("opencode-nga/index.ts")
    idx_block = re.search(r"tool:\s*\{([^}]*)\}", nga_index, re.S)
    if not idx_block:
        fail("opencode-nga/index.ts: missing `tool: { ... }` registration")
    idx_registered = set(re.findall(r"(secguard_\w+)", idx_block.group(1)))
    if idx_registered != secguard_tools:
        fail(f"opencode-nga/index.ts tool hook: registered {sorted(idx_registered)}, expected {sorted(secguard_tools)}")

    # OpenCode / OpenCode-NGA subagent: no Bash, so it must be granted the
    # persistence MCP tools (secguard_report + db/schema).
    oc_agent = read("opencode/agents/security-auditor.md")
    oc_granted = {m.group(1) for m in re.finditer(r"^\s*(secguard_\w+):\s*allow", oc_agent, re.M)}
    if SUBAGENT_PERSIST_TOOLS - oc_granted:
        fail(f"opencode agents/security-auditor.md: subagent missing {sorted(SUBAGENT_PERSIST_TOOLS - oc_granted)}")

    try:
        nga = json.loads(read("opencode-nga/opencode.json"))
        nga_perm = nga.get("agent", {}).get("security-auditor", {}).get("permission", {})
    except json.JSONDecodeError as e:
        fail(f"opencode-nga/opencode.json: {e}")
    nga_granted = {k for k, v in nga_perm.items() if k.startswith("secguard_") and v == "allow"}
    if SUBAGENT_PERSIST_TOOLS - nga_granted:
        fail(f"opencode-nga agent.security-auditor.permission: subagent missing {sorted(SUBAGENT_PERSIST_TOOLS - nga_granted)}")

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

    print("  subagent persistence: secguard_report MCP (opencode + opencode-nga), Bash(secguard *) + Write (claude-code + claude-cac)")


def main():
    check_turn_budget()
    check_tools()
    check_agent_permissions()
    print("Extension consistency check passed.")


if __name__ == "__main__":
    main()
