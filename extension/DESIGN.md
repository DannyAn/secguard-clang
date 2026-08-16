# SecGuard AI Agent Extension — E2E Design

## Multi-Agent Architecture

SecGuard supports multiple AI Agent platforms through a shared-core + platform-specific design:

```
extension/
  shared/                          # Platform-agnostic content — SINGLE SOURCE OF TRUTH
    skills/                        # Agent Skills spec (agentskills.io) — same for all
      null-deref/SKILL.md
      buffer-overflow/SKILL.md
      memory-leak/SKILL.md
      injection/SKILL.md
    agent-body.md                  # Shared agent prompt (role, workflow, rules, output format)
    command-instructions.md        # Shared command workflow instructions
  opencode/                        # OpenCode-specific (thin frontmatter wrappers)
    opencode.json                  # Config: agent, permissions, plugin
    commands/secguard.md           # Frontmatter + {{include shared/command-instructions.md}}
    agents/security-auditor.md     # Frontmatter + {{include shared/agent-body.md}}
    tools/secguard_scan.ts         # TypeScript tool wrappers (Bun.$ → CLI)
    tools/secguard_index.ts
    tools/secguard_plan.ts
    tools/secguard_report.ts
    tools/secguard_status.ts
    plugins/secguard-context.ts    # Plugin: auto-db-discovery, stale hints
  claude-code/                     # Claude Code-specific (thin frontmatter wrappers)
    .claude/
      settings.json                # Permissions: pre-approve Bash(secguard *)
      commands/secguard.md         # Frontmatter + {{include shared/command-instructions.md}}
      agents/security-auditor.md   # Frontmatter + {{include shared/agent-body.md}}
  install.sh                       # Installer: expands {{include}} + copies skills
```

## What's Shared vs. Platform-Specific

| Component | Shared? | Why |
|-----------|---------|-----|
| **Skills** (SKILL.md) | **Shared** | Both follow Agent Skills spec (agentskills.io). Identical format. |
| **Agent body** (role, workflow, rules, output) | **Shared** | Platform-agnostic instructions. Extracted to `shared/agent-body.md`. |
| **Command instructions** (workflow steps) | **Shared** | Platform-agnostic steps. Extracted to `shared/command-instructions.md`. |
| **Design doc** | **Shared** | Architecture is platform-agnostic. |
| **Command frontmatter** | **Separate** | Different fields (`agent:` vs `allowed-tools:`). Thin wrapper. |
| **Agent frontmatter** | **Separate** | Different permission models. Thin wrapper. |
| **Tools** | **Separate** | OpenCode: TypeScript + Bun.$; Claude Code: Bash + permissions. |
| **Config** | **Separate** | OpenCode: opencode.json; Claude Code: settings.json. |
| **Plugin/Hooks** | **Separate** | OpenCode: TS plugins; Claude Code: JSON hooks. |

### Template Expansion

Platform-specific files use `{{include shared/...}}` directives. The `install.sh` script expands these at install time:

```
Source template:                    Installed file:
opencode/agents/security-auditor.md → .opencode/agents/security-auditor.md
  ---                                 ---
  mode: subagent                      mode: subagent
  ---                                 ---
  {{include shared/agent-body.md}}    You are a security auditor...
                                      ## Your Role
                                      ## Workflow
                                      ## Classification Rules
                                      ## Output Format
```

**Benefit**: Changing a classification rule or workflow step requires editing **one file** (`shared/agent-body.md`), not two. No shotgun surgery.

## E2E Flow (Platform-Agnostic)

```
Developer types /secguard [path]
  │
  ▼
Command expands (path, status check)
  │
  ▼
security-auditor subagent activated
  │
  ├─ 1. Invoke secguard CLI (scan/index/plan)
  │     ├─ OpenCode: secguard_scan tool → Bun.$`secguard scan <path>`
  │     └─ Claude Code: Bash(secguard scan <path>)
  │
  │     secguard CLI internally:
  │       ├─ Index codebase (tree-sitter → SQLite sgre.db)
  │       ├─ Build call graph + data flow graph
  │       ├─ Run all detectors (null-source, deref, buffer-overflow, ...)
  │       ├─ Run convergence pipeline for each vuln type
  │       └─ Return JSON: { evidence_packages, index_summary }
  │
  ├─ 2. Load skills (lazy, on-demand)
  │     └─ skill("null-deref") → SKILL.md loaded into context
  │
  ├─ 3. Reason over evidence packages
  │     ├─ Classify: confirmed / suspected / false-positive
  │     ├─ Cross-reference with source code (Read tool)
  │     └─ Produce structured findings
  │
  └─ 4. Present findings to developer
        ├─ Summary table (severity, confidence, location)
        ├─ Detailed evidence for each finding
        └─ Suggested fixes
```

## Platform Comparison

| Aspect | OpenCode | Claude Code |
|--------|----------|-------------|
| **Command trigger** | `/secguard` (commands/secguard.md) | `/secguard` (commands/secguard.md) |
| **Subagent** | `security-auditor.md` (mode: subagent) | `security-auditor.md` (Agent tool) |
| **CLI invocation** | Custom TypeScript tools (Bun.$) | Bash tool (pre-approved) |
| **Permissions** | `permission: { edit: deny, bash: deny }` | `permissions.allow: ["Bash(secguard *)"]` |
| **Skills** | `.opencode/skills/` (shared) | `.claude/skills/` (shared) |
| **Context** | `context.worktree` | `${CLAUDE_PROJECT_DIR}` |
| **Result format** | Tool returns JSON string | Bash stdout (JSON) |
| **Stale hint** | Plugin `event` hook | `PostToolUse` hook on Edit|Write |

## Installation

```bash
# Install for both platforms (build binary + install both)
./deploy.sh all

# Install for specific platform only
./deploy.sh opencode
./deploy.sh claude-code

# Build binary only (no install)
./build.sh
```

The installer copies shared skills into both `.opencode/skills/` and `.claude/skills/`, then copies platform-specific files into their respective directories.

## Data Flow Contract (Same for Both Platforms)

```json
{
  "evidence_packages": [
    {
      "vulnerability_type": "null-deref",
      "summary": { "seed_count": 42, "final_count": 3, "convergence_rate": "92.8%" },
      "candidates": [
        {
          "type": "NULL_DEREFERENCE",
          "target": { "function": "process_data", "line": 42, "variable": "ptr" },
          "evidence": [
            { "type": "nullable_source", "detail": "variable ptr has NULL_VALUE source (malloc)" },
            { "type": "call_path", "detail": "function process_data is reachable from entry" },
            { "type": "data_flow", "detail": "NULL value propagates to dereference at line 42" }
          ]
        }
      ]
    }
  ],
  "index_summary": { "files_indexed": 15, "functions_indexed": 87 }
}
```

## Permission Model

### OpenCode
```json
{
  "permission": {
    "edit": "deny", "bash": "deny",
    "secguard_scan": "allow", "secguard_index": "allow",
    "secguard_plan": "allow", "secguard_report": "allow",
    "secguard_status": "allow", "read": "allow", "skill": "allow"
  }
}
```

### Claude Code
```json
{
  "permissions": {
    "allow": [
      "Bash(secguard scan *)", "Bash(secguard index *)",
      "Bash(secguard plan *)", "Bash(secguard report *)",
      "Bash(secguard status *)", "Bash(secguard query *)"
    ]
  }
}
```

Both models ensure the security-auditor agent can only:
- Call secguard CLI commands (safe, read-only on codebase)
- Read source files (for cross-referencing)
- Load skills (for vulnerability knowledge)
- NOT edit code or run arbitrary commands
