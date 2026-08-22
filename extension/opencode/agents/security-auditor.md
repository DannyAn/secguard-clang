---
description: SecGuard security auditor — analyzes code for vulnerabilities using converged evidence packages
mode: all

temperature: 0.1
steps: 200
permission:
  edit: allow
  bash:
    "*": deny
    "secguard*": allow
  read: allow
  grep: allow
  glob: allow
  skill: allow
---
{{include shared/agent-body.md}}
