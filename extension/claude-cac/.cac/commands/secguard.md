---
description: Run SecGuard security analysis on the codebase
argument-hint: [path]
allowed-tools: Bash(secguard *), Read, Write, Edit, Glob, Grep, TodoWrite, Skill, Task, Agent
---
Current index status:
!`PATH="${CLAUDE_PLUGIN_ROOT:+${CLAUDE_PLUGIN_ROOT}/bin:}${PATH}" secguard status 2>&1 || echo '{"indexed": false, "message": "No index found — will create fresh index"}'`

> **Host: CodeAgentCLI (claude-cac).** This host registers plugin agents under
> their plugin namespace: dispatch security-auditor subagents with
> `subagent_type: "secguard-clang:security-auditor"` (NOT the bare name). If a
> dispatch still returns `Agent type ... not found`, follow rule F10 below: read
> the error's `Available agents:` list and re-dispatch with the exact
> `...:security-auditor` entry.

{{include shared/command-instructions.md}}
