---
description: Show SecGuard scan performance and convergence metrics
allowed-tools: Bash(secguard *), Read
---
Show the user the latest scan's performance/convergence metrics (wall-clock and per-phase timings, raw→converged candidate reduction, report/AI-input volume, estimated tokens). Run the read-only metrics command and summarize the result as a short table:

!`secguard metrics 2>&1 || echo '{"error":"no scan metrics found — run /secguard first"}'`
