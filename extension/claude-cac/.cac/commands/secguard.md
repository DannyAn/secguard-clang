---
description: Run SecGuard security analysis on the codebase
argument-hint: [path]
allowed-tools: Bash(secguard *), Read, Write, Edit, Glob, Grep, TodoWrite, Skill, Task, Agent
---
Current index status:
!`PATH="${CLAUDE_PLUGIN_ROOT:+${CLAUDE_PLUGIN_ROOT}/bin:}${PATH}" secguard status 2>&1 || echo '{"indexed": false, "message": "No index found — will create fresh index"}'`

{{include shared/command-instructions.md}}
