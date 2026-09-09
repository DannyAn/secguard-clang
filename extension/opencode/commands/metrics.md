---
description: Show SecGuard scan performance and convergence metrics
---
Show the user the latest scan's performance/convergence metrics (wall-clock and per-phase timings, raw→converged candidate reduction, report/AI-input volume, estimated tokens). Call the `secguard_metrics` tool and summarize the result as a short table. The `duration_sec`/`duration_ms` figure is the **自动分析** wall-clock (index+graph+detectors+convergence+auto-confirm) and does NOT include the AI Agent 研判 stage — say "自动分析耗时", never "扫描耗时" alone. Note "流水线/convergence" is a candidate-count concept (raw → 层层过滤 → converged), not a time label. If no metrics are recorded yet, tell the user to run `/secguard` first.
