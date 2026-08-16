---
description: Run SecGuard security analysis on the codebase
argument-hint: [path]
allowed-tools: Bash(secguard *), Read, Glob, Grep, Agent
---
Current index status:
!`secguard status 2>&1 || echo '{"indexed": false, "message": "No index found — will create fresh index"}'`

{{include shared/command-instructions.md}}
