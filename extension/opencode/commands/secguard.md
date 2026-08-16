---
description: Run SecGuard security analysis on the codebase
---
Current index status:
!`secguard status --db .codeagent/zhuque-secguard/.sgre/sgre.db 2>&1 || echo '{"indexed": false, "message": "No index found — will create fresh index"}'`

{{include shared/command-instructions.md}}
