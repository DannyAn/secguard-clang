---
description: SecGuard security auditor — analyzes code for vulnerabilities using converged evidence packages
mode: subagent

temperature: 0.1
steps: 30
permission:
  edit: deny
  bash: deny
  read: allow
  grep: allow
  glob: allow
  skill: allow
---
{{include shared/agent-body.md}}
