# 分类阶段的上下文膨胀与并行化

## 背景

一次扫描分两段，瓶颈完全不同：

| 阶段 | 执行者 | 是否并行 | 上下文压力 |
|------|--------|----------|------------|
| index + graph + detect + plan（20 类型收敛） | `secguard` 二进制 | **已并行**（graph builder 与 plan 类型都用 goroutine，见 `cli/scan.go`） | 无（二进制内部，不占 agent 上下文） |
| 分类 + 落库（AI 逐类型循环） | AI agent | **串行** | **高**（20 个 skill + report.md + 源码 + 写 finding 的 bash 脚本） |

23 个源文件 / 97 候选的实测：扫描 ~1–2 分钟，AI 分类 ~15 分钟。瓶颈全在分类段。

## 三个问题与对策

### 1. 上下文膨胀

根因不是「候选多」，而是 agent 把本可避免的大块内容塞进了上下文：

- **通读全部源文件**（日志里先读 5 + 再读 16，把 23 个文件全读了）。指令要求「每类型 ≤5 个文件、优先用 candidate 证据文件」，但 agent 没遵守。680 文件时这不可行。
- **逐条写 finding 的 bash 脚本**（`/tmp/secguard_write_*.sh`，105/33/60/123 行）被 Write 工具回显进上下文，是最大的浪费源。

对策：

1. **批量写**：新增 `secguard report --write-json`（见下），一次命令写一整类，彻底去掉 bash 脚本。
2. **证据文件优先**：candidate `NNN_*.md` 已内嵌 location + evidence + pipeline assessment + 修复建议，绝大多数候选无需再读源码；只对「模糊候选」读源文件，且 ≤5 个/类型。
3. **并行 + 隔离上下文**：见下，每个 subagent 只看到自己那批类型的 report 切片。

### 2. 并行执行

扫描段已并行，缺的是分类段。两平台机制不同：

- **Claude Code**：内置 `Task` 工具派生子 agent，多个 `Task` 并发跑（官方：[Run agents in parallel](https://code.claude.com/docs/en/agents)）。每个子 agent 有独立上下文，跑完返回结果。
- **OpenCode**：`task` 工具派发 `security-auditor` 子 agent（`extension/opencode/agents/security-auditor.md`，已在 `opencode.json` 注册同名 agent 并授权 `secguard_*` 工具）。子 agent 的 `permission` 已显式 allow `secguard_*`，可直接分类 + 落库。

设计（平台无关的编排骨架）：

```
main agent
  ├─ 读 report.md → 按类型分组，切成 N 批（如每批 4~5 个类型）
  ├─ 并发派发 N 个 subagent，每个 subagent：
  │     1. 只加载本批类型的 skill
  │     2. 只读本批候选的 report 切片 + candidate 证据文件
  │     3. 分类 + A5
  │     4. 每类型一次批量写（Claude Code：`secguard report --write-json`；OpenCode：`secguard_report` 工具，内部已走 `--write-json` 单子进程，不再逐条 `--write`）
  │     5. 返回本批 confirmed/suspected/dismissed 计数 + 关键 finding id
  └─ 全部收齐后：`secguard report --audit` 一次 → 汇总最终报告
```

要点：

- **并发写安全**：`--write-json` 底层是幂等 upsert（见下），不同 subagent 写不同 (type, file, line) 不冲突；同一位置重复写也只是 update。
- **token 换墙钟**：并行会让总 token 上升（N 份上下文），但墙钟从「15 分钟 × 规模」降到「单批 ≈ 几分钟」。对 680 文件这种规模，值得。
- **不要过度并行**：类型之间要共享 `--db` 与 scan_id，但写入幂等、无锁冲突，故按类型切分是安全粒度的上限（20 个类型最多 20 个 subagent；再细无益）。

### 3. 680 文件规模

- 扫描段：index/graph/detect/plan 随规模近线性，且已并行，680 文件预计 5–10 分钟，可接受。
- 分类段：候选数随规模增长（可能 1000–3000 条）。**必须**：证据文件优先（不读全树）+ 类型级并行 + `--write-json` 批量写。三者齐了，墙钟可控、单上下文不爆。
- 风险点：`report.md` 单文件会随候选数变大。680 文件时若 report.md 超过几十 KB，主 agent 应**按类型分发**：每个 subagent 只读自己那批类型在 report.md 中的切片 + `candidates/<type>/` 证据文件，而不是一次性把全量 report.md 灌进单个上下文。`secguard_scan` 已为每个类型收敛过，subagent **不要**再跑 `secguard_plan`（那是重复收敛，不增加证据）。

## 已落地的代码改动

1. **幂等写入**：`db.UpsertFinding`（按 scan_id+rule_id+file+line+function 去重，重复写返回原 id、更新内容，不产生重复行）。`secguard report --write` 改用它。修掉了日志里「重跑脚本产生 15 条重复 finding、被迫手改 sqlite3」的问题。

2. **批量写**：`secguard report --write-json <file|->`，一次命令读一个 JSON 数组、逐条 upsert、返回 written 列表。Claude Code（无 MCP 工具）场景用它替代 bash 循环。

3. **前端说明**：`command-instructions.md` 增加平台分支（OpenCode 用 MCP 工具 / Claude Code 用 `secguard <verb>`）、批量写示例、以及「不要重跑写来验证、不要直接 sqlite3」的硬规则。
