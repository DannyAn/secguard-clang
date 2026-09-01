---
description: SecGuard security auditor — analyzes code for vulnerabilities using converged evidence packages
mode: all

temperature: 0.1
steps: 30
permission:
  edit: allow
  bash:
    "secguard*": allow
    "echo*": allow
    "*": deny
  read: allow
  grep: allow
  glob: allow
  external_directory: allow
  skill: allow
  secguard_report: allow
  secguard_db: allow
  secguard_schema: allow
---
{{include shared/agent-body.md}}
