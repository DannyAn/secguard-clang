# kimi3.1 方案检视与改建建议 —— extensions + sgre 联动（超大仓库扫描）

- **基线**：commit `c6a8e92`（v0.12.4），检视时工作区干净。
- **检视方式**：只读源码检视，三路并行（引擎层 / 编排层 / 端到端联动契约），全部 CRITICAL 项已由主检视回源复核 file:line。未以 `docs/` 历史文档或 `.claude/`、`.opencode/` 等生成副本为依据。
- **目标读者**：接手修正/重构的 AI Agent。每项均给出【问题与证据】【超大仓库影响】【修复方法】（CRITICAL/MAJOR 给到函数级/SQL/伪代码与验证方式），按编号取项即可，不必重新全面扫描。
- **规模**：去重后 **68 项**（CRITICAL 12 / MAJOR 36 / MINOR 20）。
- **验证基线**：`release/check-extension-consistency.py` 实测通过——它对下文全部漂移放行，本身即是问题 G-01。
- **DB 前提**：本项目 DB 每次全新创建、无 migration，所有 schema 修改直接改 `sgre/internal/db/schema.go` 即可，禁止引入迁移方案。

---

## 0. 总体判断

当前联动方案在"中小仓库、单批次、单子代理"路径上能跑通，但其**结算状态机、写回契约、容量模型**在超大仓库（数千文件、单类型数千候选、50+ range、多子代理并发）下存在**系统性断裂**，而非零散 bug：

1. **完成判定不可信**：任意一个 range 的 settlement 就把整个 vuln type 置 `done`（S-01），`--complete-type` 把该类型全部在途 claim 伪结算（S-02），audit 把未分类候选伪装成 dismissed 且 unclassified 恒 0（S-03）。三者叠加 = **候选可以大面积丢失而最终报告显示"完整"**。
2. **写回契约自我矛盾**：编排文档要求 worker 写 fenced JSON，CLI 只能解析裸 JSON（C-01）；dismissed 是否持久化在指令内部有 4 处互相矛盾的说法（C-02）；候选身份键在 scan_stats / findings / candidate_verdicts 三处不一致（C-03）。
3. **断点续扫复用的是"可能陈旧且自相矛盾的证据"**：E-01/E-02/E-03。大仓库越依赖 reuse 提速，假阴性越不可自愈。
4. **大仓库资源模型失守**：P-01（全仓库 AST pin）、P-03（锁内 cgo parse）、P-04/P-05（全量重吸收/全表物化）。
5. **MCP 与 Bash 两条宿主路径契约漂移**：M-01～M-09；DSH 完成条件数学不可达（O-11）。

**修复总纲**：先修"完成判定 + 写回契约"（S/C 组，结果正确性底线）；再修"续扫复用"（E 组，检测正确性底线）；然后编排一致性（O 组）与 MCP 对齐（M 组）；性能组（P 组）与前面有耦合（P-04 依赖 S-06 range 结构化、P-05 依赖 C-03 身份统一），按 §10 批次执行。

> **模型分歧说明（修 C 组前必读）**：`report.go:1555` 注释与 `unclassifiedCandidates` 体现的是"dismissed 不持久化"旧模型；而 `candidate_verdicts` 表 + `UpsertCandidateVerdict` 写路径已在代码中存在并被 `--write-json` 调用。两套模型并存正是 C-02/C-03/S-03 的总根因。本文档统一采用**后者（dismissed 落 candidate_verdicts，仅作进度台账，不进 findings、不进 SARIF、不暴露为漏洞）**作为修复基线——它是当前代码实际写路径，且是断点续扫精确恢复的必要条件；若维护者决定回到"完全不存"，则必须同步删除 candidate_verdicts 写路径并改为"range 级位图台账"，二选一，不允许并存。

---

## 1. 端到端时序与断裂点地图

```
secguard scan ──► index → graph → detectors → plan → candidates(md/json/sarif) + scan_stats(pending)
                                                          │
status --per-type ◄── settlement_stats / scan_stats        │ per-type 候选文件 + _index 分片(90KB)
      │ claim --claim-type/--claim-range/--claim-holder    ▼
      ▼                                            子代理读 candidates → 研判
 settlement_stats(dispatched)                                 │ report --write-json（confirmed→findings UPSERT，
      │                                                       │            dismissed→candidate_verdicts）
      │                                            <subagent_id>-report.json / -chunk-k.json（.tmp）
      ▼                                                       ▼
 status --reports 吸收 settlement ──► MarkAIStageDone（★S-01 在此提前 done）
      │
 report --complete-type（★S-02 批量伪结算 claim）
      ▼
 report --audit ──► 终态 SARIF/report/findings（★S-03 假 dismissed、无终态门禁、★S-04 快照竞争删文件）
```

---

## 2. S 组：结算与生命周期状态机（最高优先级）

### S-01 CRITICAL 任意一个 range 结算即把整个 vuln type 标为 done
- **位置**：`sgre/internal/cli/settlement.go:123-153`、`settlement.go:404-431`
- **问题与证据**（已回源确认）：`persistSettlementReports` 在 `for _, pt := range rep.Processed` 中，只要 `known[pt.Type]` 且报告级 `needs_context` 为空，就直接 `tx.MarkAIStageDone(ctx, rep.ScanID, pt.Type)`——不看 `pt.Range` 是 `1-40` 还是全集，不看同类型其他 range。`enrichPerTypeStatus` 随后见 `TerminalState=="done"` 强制 `Remaining=0` 并隐藏全部 `in_flight_ranges`。
- **超大仓库影响**：1980 候选拆 50 批，第一批完成即全类型 done；协议规定 done 类型不得重派 → 其余 ~1940 候选永久跳过，SARIF 静默缺发现。
- **修复方法**：
  1. 删除 `settlement.go:146-153` 的无条件 `MarkAIStageDone` 循环，改为每个报告吸收后调用统一的派生函数：
  ```go
  // settlement.go 新增，供吸收/complete-type/status/audit 四处共用
  func deriveTypeTerminalState(ctx context.Context, tx db.Store, scanID, vulnType string) (string, error) {
      st, err := tx.GetScanStat(ctx, scanID, vulnType) // candidate_count=needsReview 总数
      ranges, err := tx.ListSettlementRanges(ctx, scanID, vulnType) // 依赖 S-06 结构化区间
      covered := unionRanges(ranges, "done")            // 排序+扫描求并集
      if hasNeedsContext(ranges) || hasActiveClaims(ranges) { return "in-progress", nil }
      if covered.equals(interval{1, st.FinalCount}) { return "done", nil }
      return "in-progress", nil
  }
  ```
  2. 仅当派生结果为 done 才 `MarkAIStageDone`，且与 range 结算在同一 `WithImmediateTx`。
  3. `enrichPerTypeStatus` 改为调用同一派生函数计算 Remaining（`Remaining = candidate_count - coveredCandidates`），不再信任单一 done 位。
- **验证**：构造单类型 200 候选拆 5 批，只吸收第 1 批的 settlement 文件 → `status --per-type` 必须显示 remaining≈160、terminal_state≠done、`in_flight_ranges` 保留；转正为 `settlement_test.go` pinned 用例。

### S-02 CRITICAL `--complete-type` 把该类型所有活跃 claim 一次性伪结算为 done
- **位置**：`sgre/internal/cli/report.go:843-902`、`sgre/internal/db/crud_settlement.go:187-207`、`extension/shared/command-instructions.md:482-486`
- **问题与证据**：`SettleDispatchedClaims` 执行 `UPDATE settlement_stats SET status='done' WHERE scan_id=? AND vuln_type=? AND status='dispatched'`，无 range/holder/完成证明；编排指令要求每吸收一个有效 range 报告就调 `--complete-type`。且 `MarkAIStageDone` 与批量关 claim 不在同一事务。
- **超大仓库影响**：一个快速 range 收尾即把同类型其他在途 claim 全置 done；空 claim（written=dismissed=0）随后被 `already_covered_ranges` 当覆盖记录 → 漏分派/重复分派/中断后真实进度不可知。
- **修复方法**：
  1. 完成语义下沉到 range：新增 `secguard report --complete-range --vuln-type T --range R --claim-holder H`，SQL 改为 CAS：
  ```sql
  UPDATE settlement_stats SET status='done', finished_at=?
   WHERE scan_id=? AND vuln_type=? AND range_str=? AND subagent_id=? AND status='dispatched';
  -- 影响行数=0 时返回错误（holder 不匹配或已结算），不得静默成功
  ```
  2. `--complete-type` 保留为薄封装：先调 S-01 的 `deriveTypeTerminalState`，仅当派生 done 才置类型完成，且**不再触碰任何 claim 行**（claim 只能由对应 holder 的 complete-range 或 S-05 的 fail/release 关闭）。
  3. 类型完成与最后一个 range 的结算放同一 `WithImmediateTx`。
  4. `command-instructions.md:482-486` 改为"每批结束调 `--complete-range`；类型完成由引擎派生，worker/orchestrator 不得直接置 done"。
- **验证**：同类型 2 个并发 range（holder A/B），A 完成后 B 的 claim 必须仍 dispatched、且 A 的 complete-range 不能关闭 B。

### S-03 CRITICAL audit 将未分类候选伪装成 dismissed，`unclassified` 恒 0，且无终态门禁
- **位置**：`sgre/internal/cli/report.go:1553-1562`、`report.go:1943-1949`、`report.go:1150-1229`
- **问题与证据**（已回源确认）：`ov.AIDismissed = ov.Candidates - ov.AIConfirmed`（未开始的候选也被算成 dismissed）；`unclassifiedCandidates()` 硬编码 `return 0`；扫描刚结束、全类型 pending 时 `report --audit` 即可生成终态产物。
- **超大仓库影响**：只完成第一批，summary 也显示"其余全部已排除、未分类 0"，**掩盖** S-01/S-02 的候选丢失。
- **修复方法**：
  1. `buildScanOverview` 改为从台账聚合：`ov.AIDismissed = COUNT(candidate_verdicts WHERE scan_id=? AND verdict='dismissed')`；按类型同样口径填 `vulnAuditEntry.Dismissed`。
  2. 实现真正的 unclassified：`unclassified = candidate_count - ai_confirmed - ai_dismissed`（按类型独立计算，<0 时置 0 并输出 warning——负值本身就是 C-03 身份键错位的信号）。
  3. audit 入口加终态门禁：
  ```go
  // runReportCmd --audit 分支，重渲染之前
  states := perTypeTerminalStates(store, scanID) // 复用 S-01 派生
  if !allowPartial {
      for t, s := range states {
          if s != "done" { return fmt.Errorf("type %s is %s; use --allow-partial for a partial report", t, s) }
      }
      if activeClaimsExist(store, scanID) { return errors.New("active claims in flight") }
  }
  ```
  4. `--allow-partial` 产物在 SARIF (`runs[].properties.partial=true`)、report.md 头部、findings 目录 README 三处打 partial 标。
- **验证**：扫描后不写任何 AI 结果直接 audit → 必须非零退出；`--allow-partial` 时 `unclassified==candidate_count`、`dismissed_total==0`。

### S-04 MAJOR audit 快照竞争会删除并发 worker 新写入的 finding 文件
- **位置**：`sgre/internal/cli/report.go:1376-1383`、`sgre/internal/report/findings.go:671-699`
- **问题与证据**：audit 在一次 findings 查询快照后重建 SARIF/report/findings 目录；worker 在快照后写入的新 finding 不在旧 `keep` 集合中，`ReconcileFindings` 删除其 markdown。
- **修复方法**：
  1. 引入代际：`write-json`/`--write` 的写事务内 `SetMeta("findings_generation", gen+1)`（与 finding 插入同事务）。
  2. audit 流程：`gen0=读代际 → 快照查询 → 重渲染 → ReconcileFindings 前再读 gen1`；`gen1!=gen0` 则丢弃本次渲染并重试（最多 3 次）或报错退出，**不得继续清扫**。
  3. `ReconcileFindings` 增加保护：只删除"文件名对应 finding 在快照中不存在 且 文件 mtime < 快照开始时间"的文件——新写入文件 mtime 必晚于快照，天然豁免。
- **验证**：一个 goroutine 循环 write-json、另一个并发 audit 100 次，结束后 DB findings 数与 findings 目录 md 文件数一致。

### S-05 MAJOR claim 无 release/fail 闭环、无心跳续租、无 holder fencing
- **位置**：`sgre/internal/cli/scan.go:1041-1073`、`sgre/internal/db/crud_settlement.go:43-71`、`sgre/internal/cli/settlement.go:36-46`、`extension/shared/command-instructions.md:227-236,488-507`
- **问题与证据**：(1) CLI 只有 claim/reclaim，无按 holder 释放/标失败入口（DB 层 `MarkSettlementStatus` 存在但分派路径不可达）；(2) lease 只在创建/接管时写 `created_at`，chunk 心跳与 finding 写入均不续租，30 分钟 TTL 对仍在运行的 heavy batch 可被接管 → 双活 worker，旧 holder 报告按 mtime 覆盖新 holder；(3) F11b 10 分钟 reclaim、15 分钟 stall、30 分钟 TTL 三阈值冲突。
- **修复方法**：
  1. schema：`settlement_stats` 增加 `heartbeat_at INTEGER`（创建时=created_at）。
  2. 新增 CLI：`secguard status --release-claim --claim-type T --claim-range R --claim-holder H`（→status='released'）与 `--fail-claim ... --reason R`（→status='failed'）；spawn 失败/worker 明确失败/orchestrator 取消时必须调用；F13 的 `held` 语义改为"稍后重查"，不得当完成。
  3. 续租：两个已有写路径里加 `tx.RenewSettlementLease(scanID,holder)`（`UPDATE settlement_stats SET heartbeat_at=? WHERE subagent_id=? AND status='dispatched'`）——(a) `write-json` 事务内按输入的 holder 续租；(b) `status --reports` 吸收到该 holder 的 chunk/report 文件时续租。
  4. stale 判定改心跳：`stale = now - heartbeat_at > STALL_TTL`（唯一阈值，建议 15min）；`--reclaim` 只允许接管 stale 行，SQL 带 `AND heartbeat_at < ?`；删除 F11b 的 10 分钟条款，文档只保留一个阈值。
  5. fencing：settlement 吸收的 UPDATE 全部带 `AND subagent_id=? AND status='dispatched'`；迟到 holder 的报告写入 `late_reports` 日志字段但不改状态。
- **验证**：holder A 每 5s 写一个 chunk 持续 40 分钟，期间 B 的 claim 必须返回 held；kill A 停止心跳 15 分钟后 B 才能接管；A 恢复后提交的报告不得覆盖 B 的结算行。

### S-06 MAJOR range 是不透明字符串：无法防重叠 claim、无法证明覆盖无空洞
- **位置**：`sgre/internal/cli/settlement.go:55-61,377-423`、`sgre/internal/db/crud_settlement.go:59-71`、`sgre/internal/cli/reports.go:257-275`
- **问题与证据**：`normalizeSettlementRange` 仅 trim；`01-100`/`1 - 100` 是不同 claim；`1-40` 与 `1-100` 可同时持有；`all` 与部分 range 并行；`already_covered_ranges` 无区间运算。claim 不校验 scan_id 存在 → 孤儿数据并污染 r_type 样本。
- **修复方法**：
  1. schema：`settlement_stats` 增加 `range_start INTEGER, range_end INTEGER`（`all` 在 claim 时展开为 `[1, candidate_count]`，candidate_count 从 scan_stats 读）；保留 range_str 仅作展示。
  2. claim 事务内重叠检测：
  ```sql
  SELECT 1 FROM settlement_stats
   WHERE scan_id=? AND vuln_type=? AND status IN ('dispatched','done')
     AND range_start <= ? AND range_end >= ? LIMIT 1;  -- ? = 新区间 end/start
  -- 命中则返回 held（附冲突区间与 holder），不得新建
  ```
  3. `already_covered_ranges` 改为对 done 区间排序求并集输出；新增 `uncovered_ranges`（全集减并集）供 O-01 精确重派。
  4. claim 与 settlement 吸收入口先 `GetScanStat(scan_id,type)`，不存在直接报错。
- **验证**：`1-40` 与 `35-80` 不能同时 claim 成功；完成 `1-40,41-80` 后 uncovered 为空；`all` 与 `1-10` 互斥。

### S-07 MAJOR `needs_context`/`failed_types` 缺 type/range 维度，多类型批次集体卡死或静默丢失
- **位置**：`sgre/internal/cli/settlement.go:111-153`、`sgre/internal/cli/reports.go:17-28,102-135`、`extension/shared/agent-body.md:678-684,722-727`、`sgre/internal/db/crud_scan_stats.go:183-217`
- **问题与证据**：(1) `needs_context` 是报告级数组（仅 candidate/reason），多类型报告时数组非空就跳过**所有** processed type 的 `MarkAIStageDone`，但各 range 已以默认 `status='done'` 落库进入 covered 集合 → 状态自相矛盾；(2) `failed_types` 被解析但吸收逻辑完全不读 `rep.Failed`；全仓没有 `ai_stage_status='failed'` 写入入口。
- **修复方法**：
  1. 报告 schema v2：`processed_types[]` 条目内嵌 `needs_context:[{candidate_id,reason}]` 与 `status:"done|partial|failed"`；报告级 `failed_types[]` 条目补 `range`。`format_version:2`，解析端保留 v1 兼容（v1 多类型报告含 needs_context 时一律按 partial 处理，不再猜）。
  2. 吸收逻辑按条目独立：done 条目才进入覆盖并集；partial 条目 settlement 行 status='partial'（不进 covered）；failed 条目写 status='failed' 并关闭当前 holder claim。
  3. `scan_stats` 新增 `MarkAIStageFailed(scanID,type,reason)`，在"该类型全部 range 均 failed 或 orchestrator 终止"时调用；audit 展示 failed 并计入 unclassified。
- **验证**：四类型批次中 1 个候选 needs_context → 其余三类型正常 done；failed-only 报告后 `status --per-type` 显示 failed 而非 pending。

### S-08 MAJOR 显式复用同一 scan_id/output-dir 重扫，旧 findings/verdicts/claims/settlements 全部保留
- **位置**：`sgre/internal/cli/scan.go:141-152`、`sgre/internal/db/crud_scan_stats.go:15-22`、`sgre/internal/report/protocol.go:143-153`
- **问题与证据**：`--output-dir` 允许与旧 scan_id 同名；重扫仅重置 `ai_stage_status=pending` 与 scan_runs，DB 中该 scan_id 的旧 findings、candidate_verdicts、settlement_stats 不清理 → 旧 covered ranges 让新候选被跳过、已修复缺陷继续进 SARIF。
- **修复方法**：
  1. scan 启动检测 output-dir 对应 scan_id 已存在于 scan_runs：默认**报错退出**，提示二选一：`--new-scan-id`（生成新 ID，旧数据原样保留）或 `--resume`。
  2. `--resume` 校验输入指纹（文件 checksum 集 + config checksum + 工具版本，复用 E-03 指纹）完全一致才允许继续；不一致按"重扫"处理：单事务 `DELETE FROM findings/candidate_verdicts/settlement_stats/scan_incomplete_tasks WHERE scan_id=?` 并清 `.tmp` 下该 scan 的 settlement 文件。
  3. 在 `BeginScanRun` 记录 `generation` 自增，audit 输出携带 generation，杜绝两代混淆。
- **验证**：同 output-dir 重扫后 `already_covered_ranges` 为空、旧 confirmed 不出现在新 SARIF。

### S-09 MINOR stale-running 清理无存活判据，并发扫描互相标 failed
- **位置**：`sgre/internal/db/crud_scan_runs.go:131-165`、`sgre/internal/cli/scan.go:183-195`
- **修复方法**：scan_runs 增加 `pid INTEGER, heartbeat_at INTEGER`；扫描主循环每 30s 更新心跳（各阶段已有 ticker 处挂载即可）；`MarkStaleRunningAsFailed` 改为仅清理 `heartbeat_at < now-10min` 且 `pid 不存在`（`syscall.Kill(pid,0)` 探测，Unix；Windows 用 OpenProcess）的行；成功收尾删除自己目录 `.failed`。若决定不支持并发扫描，则改为启动时 DB 互斥锁直接拒绝第二个扫描并明确报错——两种取其一，推荐前者（大仓库长扫描场景下用户并行操作常见）。

### S-10 MINOR executor（classify --mode executor）不写 scan_runs，PlanErrors 整体丢弃
- **位置**：`sgre/internal/cli/classify.go:70-104,128-147,173-175`
- **修复方法**：把 scan.go 中的生命周期段（BeginScanRun/stale sweep/SetScanRunCompletionState/suppression/scope）抽成 `scanLifecycle` 小结构供 scan 与 classify 共用；classify 输出 JSON 增加 `plan_errors` 并写 `scan_incomplete_tasks`；`Missing` 改为 `batches[bi].RangeEnd-batches[bi].RangeStart`（或按 `len(res.MissingSeqs)+len(p.Expected)` 精确值）；`MarkAIStageDone` 的 err 写入输出并计入该类型失败，删除 `_ = err`。

---

## 3. C 组：写回契约与计数口径

### C-01 CRITICAL 编排要求写 fenced JSON，CLI 只能解析裸 JSON
- **位置**：`extension/shared/agent-body.md:664-671,737-779` vs `sgre/internal/cli/reports.go:98-145`
- **问题与证据**（已回源确认）：agent-body 原文"write the SAME fenced JSON to `<tmpdir>/<subagent_id>-report.json`"，chunk 同；`listSubagentReports` 对文件内容直接 `json.Unmarshal`（reports.go:121），```json fence 必解析失败 → `valid:false` → 不吸收。
- **超大仓库影响**：严格按指令写出的 final/checkpoint/chunk 全部不吸收 → claim 等 TTL、重复分派、心跳与 r_type 样本失效。属"照文档做就必坏"的契约错误。
- **修复方法**：
  1. 改文档（主修复）：agent-body.md 三处（final report :737-742、per-type checkpoint :755-763、chunk :764-779）统一为"**文件内容是裸 JSON object**（不含 markdown fence）；fenced block 仅用于最终聊天消息"。 Structured Report Protocol 一节加注说明两种载体。
  2. 解析端短期兼容（防旧 worker）：`listSubagentReports` 在 Unmarshal 前调用 `stripJSONFence(data)`（trim 后以 ``` 开头则剥首末行），兼容期一个版本后删除。
  3. 写盘原子化：worker 指令改为"先写 `<name>.json.tmp` 再 rename 为 `<name>.json`"，消除 `unparseable report (partial write)` 这一整类心跳误报。
  4. 新增 `sgre/internal/cli/settlement_report_format_test.go`：分别写入裸 JSON、fenced JSON、tmp+rename 中途三种形态，断言吸收行为。
- **验证**：按 agent-body 原文逐字生成 `<subagent_id>-report.json` 后跑 `status --reports`，必须 `valid:true` 且被 `persistSettlementReports` 吸收。

### C-02 CRITICAL dismissed 是否持久化，指令内部 4 处互相矛盾
- **位置**：`extension/shared/command-instructions.md:44-52,382-384,450-458,718-721,745-747`、`extension/shared/agent-body.md:181-184,475-518,513-516,607-613,706-710`
- **问题与证据**：一处"confirmed+dismissed 必须同批写入 candidate_verdicts"；一处"零 confirmed 完全跳过 --write-json"；parallel 模板"没有 confirmed 就跳过 write、dismissed 不持久化"；Structured Report 注释残留"dismissed 不在 DB、只留 transcript"。顺序路径明确"只写 confirmed"。
- **超大仓库影响**：全 dismissed range 按指令可不写任何台账 → 中断恢复无法区分"全部判驳"与"从未运行" → 整批重做、remaining 失真。
- **修复方法**（按 §0 模型分歧说明，统一为"dismissed 落 candidate_verdicts 台账"）：
  1. 在 agent-body.md 的 Write discipline 一节写**唯一契约**："每个候选必须有且仅有一条终态记录：confirmed→`findings`；dismissed→`candidate_verdicts`。zero-confirmed 批次也必须调用 `--write-json`（payload 只含 dismissed 行，`findings_written=0` 是正常结果）。只有 range 内候选数为 0 才允许跳过写入。"
  2. 全局删除/改写其余 4 处旧表述（含 Structured Report Protocol 注释中"dismissed 不在 DB"字样）；顺序路径与 parallel 模板共用同一段文字，禁止复制变体。
  3. `release/check-extension-consistency.py` 增加禁词断言：`agent-body.md`/`command-instructions.md` 不得出现"dismissed 不持久化"/"dismissed are never persisted"/"skip.*write.*zero.*confirmed"等模式（英文同义句一并列出）。
- **验证**：全 dismissed range 执行后 `SELECT COUNT(*) FROM candidate_verdicts WHERE scan_id=?` 等于该 range 候选数；一致性脚本对故意回写旧措辞的 PR 必须失败。

### C-03 CRITICAL 候选身份键三处不一致：scan_stats / findings / candidate_verdicts
- **位置**：`sgre/internal/db/schema.go:324-340`、`sgre/internal/db/crud_candidate_verdicts.go:11-23`、`sgre/internal/db/crud_findings.go:88-115`、`sgre/internal/cli/scan.go:756-770`
- **问题与证据**：candidate_count 按 `(file,line,variable)` 去重；findings UPSERT 键 `(scan_id,rule_id,file,line,variable)`；candidate_verdicts 唯一键却是 `(scan,type,file,line,function)`——无 variable、无 rule_id、多 function。
- **超大仓库影响**：同行两变量 dismissed 只留一条 → remaining 恒>0 反复重派；重试漏 function 生成第二条 → dismissed 虚增提前 remaining=0；同 type 不同 category 同行候选互相覆盖。
- **修复方法**（引入 candidate_id，C 组其余多项的前置）：
  1. planner 输出：`planner.Candidate` 增加 `ID string`，在 plan 阶段由规范身份计算：
  ```go
  func candidateID(scanID, vulnType, ruleID, normFile string, line int, variable string) string {
      h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s|%d|%s",
          scanID, vulnType, strings.ToUpper(ruleID), normFile, line, variable)))
      return hex.EncodeToString(h[:8]) // 64bit，碰撞概率可忽略；冲突时 UPSERT 同键即同候选
  }
  ```
  2. schema（全新建库，直接改）：`findings`、`candidate_verdicts` 均加 `candidate_id TEXT`；candidate_verdicts 唯一键改 `UNIQUE(scan_id,candidate_id)`；findings 现有唯一键保留并额外要求 candidate_id 与之一致（写路径单点计算保证）。
  3. 输出：candidates md 每候选头部、`_index.md` 每行、candidates SARIF 每个 result 的 properties 均输出 `candidate_id`（与 C-08 的 rule_id/vuln_type/category 同批落地）。
  4. 写回：`--write-json` 输入允许仅带 `candidate_id + status + 研判字段`，CLI 用 candidate_id 反查本次扫描的候选快照表（plan 落地时写入 `candidates` 表）回填 rule_id/file/line/variable/function/vuln_type；同时保留旧字段输入做一致性校验，不一致即报错。
  5. `distinctFindingLocations` 与 auto-confirm 计数也改用同一身份函数。
- **验证**：同行两变量候选分别 dismissed → verdicts 两行；重试省略 function/variable → 命中同一 candidate_id UPSERT 不新增；remaining 归零。

### C-04 MAJOR `--write-json` 对 UPSERT 键字段缺规范化，静默重复行/元数据倒退
- **位置**：`sgre/internal/cli/report.go:239-258,643-653,719-751`、`sgre/internal/db/crud_findings.go:95-99,139-156`
- **问题与证据**：rule_id 校验用 cweNorm 但落库原始串（`CWE-476`/`cwe-476` 两行）；variable 是键却非必填，重试漏写变 `""` 插第二行；function 不在键中，重试漏写被 DO UPDATE 覆盖为空；file 多后缀匹配静默选最短路径。
- **修复方法**：
  1. 新增 `normalizeFindingInput(in *findingInput) error` 在写库前统一执行：`in.RuleID = strings.ToUpper(strings.TrimSpace(in.RuleID))`；`in.File` 必须经 `resolveFindingFilePath` 唯一解析（多匹配→返回 ambiguity 错误并列出候选路径）；需要 variable 的类型（按 planner registry 标注）强制非空。
  2. UPSERT 的 DO UPDATE 对可空缺元数据防倒退：
  ```sql
  function = CASE WHEN excluded.function = '' THEN findings.function ELSE excluded.function END
  ```
  variable 同理（空串不覆盖已有值），但因 C-03 后 variable 由 candidate_id 回填，正常路径不会再为空。
  3. 上述规范化函数同时用于 `--write` 单条路径。
- **验证**：先写 `CWE-476` 再写 `cwe-476` 同行候选 → `duplicates=1` 而非新增；重试省略 function → DB 中 function 保持原值。

### C-05 MAJOR 截断/非法 JSON 被静默 salvage 为成功批次，尾部 finding 无告警丢失
- **位置**：`sgre/internal/cli/report.go:2020-2037,2077-2093,815-840`、`sgre/internal/cli/contract_test.go:783-812`
- **问题与证据**：严格解析失败后 salvage 提取前缀完整对象即返回成功，无 salvaged 标记、无 warning、envelope 内嵌 scan_id 被丢弃（走 latest 继承可能写错扫描）；嵌套对象也被当独立 finding 提取；现有测试只验证前缀保留。
- **修复方法**：
  1. `parseWriteJSONInput` 返回 `(findings, meta, error)`，meta 含 `Salvaged bool, Recovered int, DroppedEstimate int, EnvelopeScanID string`；salvage 时保留 envelope scan_id。
  2. runWriteJSON 在 Salvaged=true 时：响应 `status:"partial", truncated:true, salvaged_count:Recovered`，进程**非零退出**；该批次不得触发 complete-range（S-02 的 CAS 前置条件检查输入标志）。
  3. 默认关闭自动 salvage：严格解析失败即报错，仅 `--allow-truncated-salvage` 时走上述 partial 路径。
  4. `salvageFindingObjects` 跟踪 JSON 深度，只接受顶层数组元素，不提取嵌套对象。
  5. 更新 `contract_test.go:783-812`：增加 truncated 标记与非零退出断言。
- **验证**：200 行 payload 截断为前 120 行 → exit≠0、输出 truncated:true、DB 行数=salvaged_count 且 status/audit 中该 range 不标 done。

### C-06 MAJOR dismissed 写回 best-effort：写失败仅 warning 仍返回成功，单条 --write 路径完全不写台账
- **位置**：`sgre/internal/cli/report.go:678-716,494-513,754-804`、`sgre/internal/db/crud_candidate_verdicts.go:11-23`
- **问题与证据**：dismissed 在 confirmed 的 `WithImmediateTx` 之外逐条 autocommit（数千 dismissed=数千次写锁）；`UpsertCandidateVerdict` 失败仅 stderr warning 后 continue，`skippedDismissed` 提前自增，最终仍 `status:"ok"`；单条 `--write --status dismissed` 根本不调 `UpsertCandidateVerdict`；`pipeline-dismissed.json` 读写错误全忽略。
- **修复方法**：
  1. 把 dismissed 的 Upsert 移进 confirmed 的同一 `WithImmediateTx`：事务内先批量 `INSERT ... ON CONFLICT(scan_id,candidate_id) DO UPDATE`（可组 500 行一批的多值 INSERT），任一失败整批回滚。
  2. 响应字段改 `dismissed_written` / `dismissed_failed`；任何台账失败进 `errors/failed_details` 并非零退出；删除 `skippedDismissed` 提前自增逻辑。
  3. 单条 `--write` 与批量路径共用同一个 `persistVerdicts(tx, rows)` 函数，保证行为等价。
  4. `pipeline-dismissed.json` 的读/序列化/写错误必须上抛或进 errors，不得忽略。
- **验证**：用 DB 写锁注入（另一进程持 IMMEDIATE 事务）使 verdict 写失败 → 整批非零退出、无部分提交、failed_details 含原因。

### C-07 MAJOR candidate/auto/confirmed/dismissed 计数公式在多个输出中不一致
- **位置**：`sgre/internal/cli/scan.go:364-385,756-770,872-875`、`sgre/internal/cli/report.go:1124-1143`、`sgre/internal/report/markdown.go:177-180,213-221`、`sgre/internal/report/overview.go:241-260`
- **问题与证据**：(1) `scan_stats.final_count` 只含 needsReview，`report --stats` 却再算 `remaining=final_count-confirmed-auto_confirmed-dismissed` → auto 二次扣除，remaining 可提前为 0；(2) 扫描 report.md 的 Candidates 已是 needsReview，`CandidateMarkdown` 再执行 `awaiting=Candidates-AutoConfirmed`；(3) scan JSON 用 `distinctFindingLocations`、candidate markdown 用 `len(pkg.Candidates)`；(4) `distinctFindingLocations` 键无 rule_id；(5) auto-confirm `written++` 按 Upsert 调用次数而非 distinct 行数。
- **修复方法**：
  1. 在 `report/protocol.go` 定义唯一语义注释与函数：`CandidateCount = needsReview 候选数（不含 auto-confirmed）`，`Remaining = CandidateCount - AIConfirmed - AIDismissed`（**不得再减 auto**）。
  2. `report --stats`、`CandidateMarkdown`、status --per-type 三处全部改为调用同一函数计算；删除 markdown.go:213-221 的二次扣除。
  3. `distinctFindingLocations` 改用 C-03 的 candidateID（含 rule_id）。
  4. auto-confirm 写入改用 `INSERT ... RETURNING id` 的实际返回计数（或写入后 `SELECT COUNT(DISTINCT candidate_id)`）回填 written。
- **验证**：构造 needsReview=5、auto=10、未分类场景 → remaining=5（非 0）；report.md/scan JSON/audit 三处总数一致。

### C-08 MAJOR 多 CWE 契约在候选输入、MCP 传输、最终目录渲染三处连续断裂
- **位置**：`sgre/internal/report/markdown.go:268-275,814-838`、`extension/opencode/tools/secguard_report.ts:45-82,147-160`、`sgre/internal/cli/report.go:729-735,1867-1873`、`sgre/internal/planner/registry.go:382-405`、`sgre/internal/report/findings.go:615-624`
- **问题与证据**：(1) candidates md 只渲染 canonical CWE，无每候选实际 rule_id/category（SARIF 有，AI 主读 md 拿不到）；(2) MCP schema 无 vuln_type 且构造输入时丢弃，CLI 按 rule_id 反推——`divide-by-zero + int_min_div + CWE-190` 确定性归到 `integer-overflow`；(3) 即使 Bash 写对 vuln_type，`syncPerFindingAfterWrite`/`findingVulnType` 仍优先 rule_id 反推 → verdict 文件落错目录。
- **修复方法**：
  1. `writeCandidates`/`writeCandidateIndex` 每个候选输出显式字段行：`candidate_id`、`rule_id`、`vuln_type`、`category`（与 C-03 同批）。
  2. MCP `secguard_report` 的 finding schema 增加 `vuln_type: z.string().optional()` 并在构造 CLI JSON 时原样透传；CLI 端优先使用输入 vuln_type（经 `planner` registry 校验合法性），为空才回退 rule_id 反推。
  3. `findingVulnType`/`syncPerFindingAfterWrite` 统一改为：优先 `finding.VulnType`（registry 校验），仅 legacy 空值回退 `TypeForCWE`。
  4. 新增多 CWE 端到端测试：scan→AI write（int_min_div/CWE-190）→audit，断言 vuln_type=divide-by-zero、findings 目录归 divide-by-zero。
- **验证**：上述端到端用例通过；MCP 与 Bash 两条路径写入结果完全一致。

### C-09 MAJOR 增量重扫不复用 AI dismissed，历史驳回全部重新分派
- **位置**：`sgre/internal/cli/suppression.go:53-61,95-109`、`sgre/internal/db/crud_candidate_verdicts.go:8-23`
- **问题与证据**：`loadSuppressions` 只读 findings 中 dismissed 行，不读 candidate_verdicts；新 scan_id 下上轮已驳回候选全部重现重派；suppression 按 canonical CWE 过滤、auto-confirm 按实际 CWE 写入 → 多 CWE 历史驳回可能不命中。
- **超大仓库影响**：源码未变，数万 AI dismissed 仍重复消耗模型上下文与墙钟（大仓库 AI 阶段成本的主要来源之一）。
- **修复方法**：
  1. plan 阶段候选落 `candidates` 表时存 `content_fingerprint`（规范化语句文本+函数名+rule_id 的哈希）。
  2. `loadSuppressions` 增加读取上一 scan 的 candidate_verdicts，按 `(vuln_type, rule_id, content_fingerprint)` 匹配：指纹一致→继承 dismissed（新 verdict 行标 `inherited_from=<old_scan>`，不重复消耗 AI）；指纹变化→视为新候选。
  3. 匹配键用实际 rule_id 而非 canonical CWE；提供 `--no-inherit-dismissed` 开关强制全量复核。
- **验证**：无代码变更的二轮扫描，needsReview 分派数应≈0（仅新增/变化候选）；改一行候选语句后该候选重新出现。

### C-10 MINOR `--review-json` 用延迟事务，与 write-json 的 IMMEDIATE 修正自相矛盾
- **位置**：`sgre/internal/cli/report.go:990-1031`（对照 :754-765）
- **修复方法**：改 `WithImmediateTx`；事务外先用 `ListAutoConfirmedForReview` 批量预取 id→status 完成校验，事务内只执行 UPDATE；`UpdateFindingReview` 包 `withBusyRetryID`（与 findings 其他写路径一致）。验证：两个并发 review-json 各 500 行，双方均完整提交无 SQLITE_BUSY_SNAPSHOT。

### C-11 MINOR autoConfirmFindings 逐条 UPSERT 无批量事务
- **位置**：`sgre/internal/cli/scan.go:800-878`
- **修复方法**：按类型把 auto-confirm 行组成批次，单个 `WithImmediateTx` 内多值 UPSERT（500/批）；失败时该批回退逐条并保留 unwritten 回流语义；written 计数改 RETURNING 实际行数（同 C-07 第 4 点）。

---

## 4. O 组：编排层指令矛盾与容量模型

### O-01 CRITICAL F1 禁止重派 PARTIAL 类型，候选尾部被流程性放弃
- **位置**：`extension/shared/command-instructions.md:770-793`
- **问题与证据**：`0 < written_count < candidate_count` 判 PARTIAL 后"NOT re-dispatched"，仅写观察项；`written_count==0` 的恢复却要求单子代理 FULL candidate range，绕过自适应批次。
- **超大仓库影响**：大类型一次上下文溢出 → 数百/数千候选不进恢复队列，SARIF 永久缺失；零输出恢复用全类型单代理重复同样的溢出。
- **修复方法**：
  1. F1 改为："PARTIAL 类型必须进入恢复队列。恢复单元是 `status --per-type` 返回的 `uncovered_ranges`（S-06 提供），按 O-05 容量公式重新切分（不得超过 N_type），逐 range 重派直至 uncovered 为空或达到全局重试上限（建议 3 轮）。"
  2. 删除 FULL-range 恢复条款；任何恢复批次同样受 `N_type≤100` 与 host_max 约束。
  3. 达上限仍有缺口时：类型标 `failed`（S-07 的 MarkAIStageFailed），audit 保持 incomplete 并将缺口列入最终报告"missing candidates"节，禁止静默 finalize。
- **验证**：制造 5 批完成 2 批后 kill 的场景，恢复流程必须只补 uncovered 的 3 个 range（按候选区间），最终 uncovered 为空。

### O-02 CRITICAL 同步 OpenCode"首波补位"与"立即 finalize"矛盾，超 host_max 队列无合规路径
- **位置**：`extension/shared/command-instructions.md:278-285,462-478,513-516`
- **问题与证据**：F3a 要求每完成一批立即补派；同步宿主条款只描述"首波一次发出、超时走 F11"，F7 要求 N 个同步调用返回后"立刻 Collect+finalize"，F8 要求同回合出终报。1980 候选≈50 批、host_max=10 时首波后 40 批积压，遵守 F7/F8 就提前 finalize。
- **修复方法**：为同步宿主写唯一调度循环（替换 F3a/F7/F8 相关段落）：
  ```
  wave = min(host_max, len(pending))
  while pending_queue 非空 or in_flight 非空:
      发出当前 wave 的同步调用并等待全部返回（或单批超时走 F11）
      吸收 settlement（status --reports）→ 完成 range 结算（S-02）
      按 uncovered_ranges 重新计算 pending_queue
      wave = min(host_max - len(in_flight), len(pending))
  # 仅当 pending_queue 空 且 in_flight 空 且 uncovered_ranges 全空：
  进入 Collect + Step 5.5 + finalize
  ```
  异步宿主（Claude Code 等）沿用现有通知驱动模型，但 finalize 前置条件统一为上面同一行三条件。
- **验证**：构造 50 批、host_max=10 的同步执行日志，finalize 前必须存在 ≥5 个 wave，且 uncovered_ranges 为空。

### O-03 MAJOR 首批容量与 divide-by-zero 强制证据规则不兼容，二次下发无法闭合
- **位置**：`extension/shared/command-instructions.md:199-204,836-844`、`extension/shared/agent-body.md:74-86`、`extension/shared/skills/divide-by-zero/SKILL.md:21-33`
- **问题与证据**：首批 r=0.30 → N=40，但 divide-by-zero 要求每种 divisor shape confirmed 前必读 Code Context（实际 r=1），硬预算 12 次 → 首批 40 中最多 12 合规，28 个 needs_context；二次下发"恰好这些候选仅一次"仍只有 12 预算 → 至少 16 个永远悬置。
- **修复方法**：
  1. 在 `planner/registry.go` 的 VulnTypeSpec 增加 `EvidencePolicy`（如 `mandatory-per-candidate`），divide-by-zero 等强制证据类型登记之；`status --per-type` 对这类类型直接返回 `r_type=1` 的容量下界（首批 N≤12），不再用 0.30 默认值。
  2. 二次下发条款改为："needs_context 候选按同一容量公式重新拆分（每批 ≤ 剩余 evidence 预算对应的候选数），允许多轮，直至 candidate IDs 闭合"；删除"仅一次"限制。
  3. 若某类型设计上允许 Source+Hint 直接判驳（不开 Evidence），须在 SKILL.md 明确写出可判驳的 shape 清单，作为容量模型的 r 值依据。
- **验证**：divide-by-zero 类型 40 候选全流程，最终 needs_context=0 且单批 evidence_opens≤12。

### O-04 MAJOR 容量模型三处不自洽：context 公式漏 evidence 体量、12 次预算单位漂移、heavy 分组规则自相矛盾
- **位置**：`extension/shared/command-instructions.md:187-265,821-829`、`extension/shared/agent-body.md:74-86`
- **问题与证据**：(1) context 公式只含 skill+legend+N×index_token，不含实际打开的 Evidence 内容；integer-overflow 的 whole-function Evidence（~200 行/候选）无替代约束；(2) 12 次 Evidence 预算在容量公式/agent-body 是"每子代理全批"，F6 审计却按"每类型 >12"判违规 → 混合批实际 I/O 可达预期 4 倍；(3) 同段既写 heavy "SHALL NOT share with a light type" 又写 "one heavy type + at most one light type"。
- **修复方法**：
  1. 容量公式升级为三约束（与 O-05 引擎实现共用定义）：
     `N_type = min( floor(12 / r_type), floor((CONTEXT_BUDGET − skill − legend − N×evidence_bytes_estimate) / index_token), 100 )`
     其中 heavy 类型的 `evidence_bytes_estimate` 取 whole-function 上界（由 scan 时统计的候选 Evidence 平均字节×1.5 得出），light 类型取 ±8 行窗口上界。
  2. 明确 **12 次预算为 batch 级（每子代理全批总和）**：F6 审计改为对 `sum(evidence_opens across processed_types)` 判违规；混合批容量按各类型 evidence 预算共享同一 12 次池计算。
  3. heavy 分组只保留一种规则，建议"heavy 类型独占批次（不得与任何其他类型混批）"——实现最简单且消除混批预算歧义；另一处文字删除。
- **验证**：integer-overflow 首批 N 按 whole-function 上界计算后，worker 实际上下文占用不超 CONTEXT_BUDGET；F6 对 4 类型混合批 sum>12 判违规。

### O-05 MAJOR 引擎 `suggested_batch_size` 未实现文档双约束，r=0 回退 0.30 使轻类型永远无法放大批次
- **位置**：`sgre/internal/cli/settlement.go:438-440,470-520,624-634` vs `extension/shared/command-instructions.md:184-219,253-257`
- **问题与证据**：Go 只算 `floor(12/r_type)`，无 index token 约束、无 100 上限、无 SPLIT_CANDIDATE_THRESHOLD；r=0.01 时建议 1200；实测 r=0 又回退 0.30 固定 40。
- **修复方法**：
  1. scan 落地时统计并写入 scan_stats（或新 per-type meta）：`index_bytes`（该类型 _index 总分片字节）、`avg_evidence_bytes`（候选 Evidence 均值）、`skill_bytes/legend_bytes`（常量表）。
  2. `status --per-type` 的 suggested_batch_size 改实现 O-04 的三约束公式，硬上限 100；`suggested_batches = ceil(candidate_count / N)` 且不得小于 `ceil(candidate_count/100)`。
  3. `r_type==0`（历史零 Evidence 打开）不再回退 0.30，视为 r→0：evidence 约束失效，仅由 context 与 100 上限决定；`r_type` 样本为空时才用默认 0.30。
- **验证**：轻类型 r=0 时建议值= min(context 约束,100)（如 100）；r=0.01 时建议值不得超 100；与文档公式逐类型对拍一致。

### O-06 MAJOR F11/F11b 用 confirmed 数判断存活，dismissed-only worker 被误判死；恢复只给数量不给候选编号
- **位置**：`extension/shared/command-instructions.md:468-469,482-494`、`sgre/internal/db/crud_scan_stats.go:177-197`
- **问题与证据**：liveness 只看 `written_count`（仅 confirmed），dismissed-only worker 持续写台账也被看成无进展；F11b 对 written==0 立即重派，忽略 dismissed_count；"只重派 candidate-written-dismissed 个候选"无候选编号，多 range 并发时无法定位真实缺口；command 称 OpenCode worker 不落 chunk，agent-body 却要求所有 worker 每 ~10 候选写 chunk。
- **修复方法**：
  1. liveness 统一为 `progress = confirmed + dismissed`（`ListPerTypeStatus` 输出该和值）+ `heartbeat_age_ms`（S-05 提供）；判定矩阵：`heartbeat 新鲜 → alive`（无论 written 是否为 0）；`heartbeat 超阈值 且 progress 无增长 → stalled`。
  2. F11b 恢复一律改用 `uncovered_ranges`（S-06），删除按数量估算的条款。
  3. 心跳契约统一：MCP 与 shell worker 都必须按 ~10 候选节奏写 chunk（agent-body 为准），删除 command 中"OpenCode worker 不落 chunk"的说法。
- **验证**：全 dismissed range 的 worker 持续写 chunk 时，orchestrator 不得判死重派。

### O-07 MAJOR F11 的 r_type 超时反馈无持久闭环，历史 done 样本被大量 claim 挤出 LIMIT 50
- **位置**：`extension/shared/command-instructions.md:266-270`、`sgre/internal/cli/settlement.go:434-502`、`sgre/internal/db/crud_settlement.go:220-227`
- **问题与证据**：force-reject 后提高 r_type 无 CLI 记录入口，AvgWallMS 不参与批次计算；worker 被杀无有效 settlement → 无样本 → 下轮同样过大批次再超时；`ListSettlementStatsByType` 先取最近 50 行再过滤 done，大量新 claim 把历史 done 样本挤出。
- **修复方法**：
  1. S-05 的 fail-claim 落 status='failed' 行（含 wall_ms）；`settlementAggregate` 把 failed 行纳入反馈：`r_type_effective = max(r_type_done, r_type_done × 1.5^consecutive_timeouts)`，并在 suggested_batch_size 同时除以 wall 因子（实测 wall_ms/660s 超 0.8 时减半 N）。
  2. SQL 改 `WHERE vuln_type=? AND status='done' ORDER BY created_at DESC, id DESC LIMIT 50`（先过滤再限额），并加复合索引 `(vuln_type,status,created_at DESC,id DESC)`。
  3. F11 文档改为"超时反馈由引擎自动从 failed settlement 派生，orchestrator 不手工调 r_type"。
- **验证**：连续两次超时后 suggested_batch_size 必须下降；首波发 50+ claim 后 r_type 仍取到历史 done 样本。

### O-08 MAJOR group verdict 漏 chain-root 维度，跨调用链复用 guard 结论
- **位置**：`extension/shared/agent-body.md:296-303` vs `extension/shared/command-instructions.md:369-380`、`extension/shared/skills/null-deref/SKILL.md:76-96`
- **问题与证据**：agent-body 允许同 Function、同 origin、guard@none 共享 verdict，未要求 chain-root；另两处明确 chain-root 必需。
- **超大仓库影响**：group verdict 是海量候选降本主手段，该矛盾把一个调用链的非空证明错误复用到无保护链 → 真实漏洞批量漏报。
- **修复方法**：agent-body.md:296-303 改为与 skill 一致的四元组 `Function + origin + chain-root + guard@none`；补一条"存在 `sibling-callers@` 的候选不得参与跨组复用，必须逐链判定"；一致性脚本加断言（agent-body 的 group verdict 段必须包含 chain-root 字样）；在 `examples/c-vuln-benchmark` 增加一个跨链 FP 用例（链 A 有 guard、链 B 无 guard 的同 origin 候选，期望 B 仍被检出）。
- **验证**：benchmark 新用例通过；不同 chain-root 的同函数同 origin 候选不得共享 verdict。

### O-09 MAJOR Filtered Workflow 对单个大类型无限串行，且逐类型重复 full audit
- **位置**：`extension/shared/command-instructions.md:964-992`、`extension/opencode/tools/secguard_report.ts:96-99,201-215`
- **问题与证据**：filtered 无 scale gate/自适应分批/子代理/claim/断点恢复；写入未要求 finalize:false，MCP 默认每次 write 都 full audit；无 complete-type 与 Step 5.5。
- **修复方法**：
  1. Filtered Workflow 改为复用统一调度器：`candidate_count ≤ 20` 允许 orchestrator 顺序快路径；`>20` 一律走与 full scan 相同的 range 分派（O-05 容量 + S-06 claim）。
  2. 该流程所有 chunk 写入显式 `finalize:false`；全部类型完成后统一执行 complete-range 派生、Step 5.5 auto-confirmed review、一次 audit。
- **验证**：单类型 2000 候选的 filtered 扫描，orchestrator 主上下文不出现逐候选串行分类；audit 只执行一次。

### O-10 MAJOR 类型过滤未贯穿 MCP scan 与 status --per-type
- **位置**：`extension/opencode/tools/secguard_scan.ts:101-125`、`sgre/internal/cli/scan.go:315-316,1124-1141`
- **问题与证据**：MCP scan 只能传 path，filtered 扫描仍跑全类型；scan 用 `TypeFilteredActiveVulnTypes`，status 补全缺失类型却用 `ActiveVulnTypes` → 未选类型被追加为 unknown，触发 missing-type 误判。
- **修复方法**：MCP scan 增加 `types: z.array(z.string()).optional()` 透传 CLI type-filter；`status --per-type` 补全逻辑改用与 scan 相同的 `TypeFilteredActiveVulnTypes()`（读取当次 scan_runs 记录的 type filter，或 DB meta 中持久化的 active set），未选类型不得进入本轮完成判定。
- **验证**：filtered 扫描只跑所选类型的 detectors/plan；status 输出不含未选类型；finalize 不再报 missing-type。

### O-11 CRITICAL DSH 完成条件数学不可达，且无完整终审闭环
- **位置**：`extension/deepseek-harness/agent.cordis.yml:28-33`
- **问题与证据**：DSH 要求 `written_count >= candidate_count` 且 dismissed 不落库 → 只要有一个 dismissed 该式永不成立；无 shared 的 complete-type 与 Step 5.5；调度无 host_max/claim/断点恢复/settlement 契约，要求所有批次"同一轮全部发出"。
- **修复方法**：
  1. DSH 的 `agent.cordis.yml` 编排段与 worker prompt 改为**由 `release/build-packages.sh` 从 extension/shared 生成**（与 opencode/claude-code 相同的 include 机制），DSH 仓库内只保留宿主调用语法 wrapper；删除其私有完成条件。
  2. 完成条件统一为 shared 的 `terminal_state==done 且 uncovered_ranges 空`（S-01/S-06 派生），并补齐 complete-range、Step 5.5、claim/heartbeat/断点恢复契约。
  3. 若 DSH 宿主确无 turn cap 配置项，在 wrapper 注释中明示并在 prompt 写出自限值，同时纳入一致性脚本检查。
- **验证**：含 dismissed 的类型在 DSH 下能正常 finalize；DSH 大候选场景分批受 host_max 约束；一致性脚本对 DSH 私有协议的回归报错。

### O-12 MINOR DSH 私有分类规则与 shared skill 冲突；divide-by-zero 文档自相矛盾
- **位置**：`extension/deepseek-harness/agent.cordis.yml:41-48` vs `extension/shared/skills/crypto-misuse/SKILL.md:37-48,72-85`；`extension/shared/skills/divide-by-zero/SKILL.md:67-79,97-108` vs `command-instructions.md:741-743`、`sgre/internal/planner/registry_divide_by_zero.go:7-20`
- **修复方法**：随 O-11 的生成化删除 DSH 私有分类规则；divide-by-zero 的 Severity Matrix 与 command 示例改为只列 registry 中 `CategoryConfidence:"confirmed"` 的类别（int_min_div），field/global 统一描述为 suspected 走 AI 分类；一致性脚本加"文档示例中的 auto-confirmed 类别必须存在于 registry confirmed 集合"断言。

### O-13 MINOR shell-only 同类型 range worker 的 findings 临时文件名竞争
- **位置**：`extension/shared/command-instructions.md:26-33,702-708`、`extension/shared/agent-body.md:459-473`
- **修复方法**：文件名模板统一为 `<scan_id>-<claim_holder>-<type>-<range>-partN.json`（claim_holder 即 subagent_id 保证唯一）；写盘走 C-01 的 tmp+rename；删除 `<type>-partN.json`、`<type>.json/<type>-2.json` 旧模板；一致性脚本断言共享 `.tmp` 文件名模板必须含 holder 段。

---

## 5. M 组：MCP wrapper 与 Bash 契约漂移（OpenCode 系）

### M-01 CRITICAL OpenCode"禁止 shell"与最终 audit 要求冲突，MCP 无独立 audit 能力且吞错
- **位置**：`extension/shared/command-instructions.md:5-15,72-82`、`extension/opencode/tools/secguard_report.ts:44-104,117-136,205-236`
- **问题与证据**：顶部要求"Use those TOOLS, never shell"，后文要求最终执行 shell `secguard report --audit`；MCP 无 audit action，仅在非空 findings 写入且 finalize!=false 时附带 audit——正常大批次全部 finalize:false、全 dismissed 跳过写入 → 严格工具路径无法生成终态产物；附带 runAudit catch 所有异常返回 null，外层仍 status:"ok"。
- **修复方法**：
  1. `secguard_report.ts` 的 action 枚举扩展：`"audit" | "complete_range" | "stats"`，分别映射 `secguard report --audit [--allow-partial]`、`report --complete-range ...`（S-02）、`report --stats`；audit 动作支持 scan_id/output_dir/db_path 参数。
  2. `runAudit` 不再 catch 吞错：任何非零退出/异常 → 工具返回 `{status:"error", error:stderr}`，禁止包装成 ok。
  3. command-instructions.md 顶部条款改为"orchestrator 与 worker 一律使用 MCP 工具；终态渲染用 `secguard_report action:'audit'`"，删除 shell audit 要求。
- **验证**：全 dismissed 扫描（零 confirmed）用纯 MCP 路径能完成终态 SARIF 生成；audit 失败时工具返回 error 而非 ok。

### M-02 MAJOR secguard_report schema 与写契约双向漂移
- **位置**：`extension/opencode/tools/secguard_report.ts:45-87,147-160,217-230`
- **问题与证据**：无 vuln_type（见 C-08）；`summary` 必填但合规 dismissed 只给 reasoning → schema 验证误拒；响应不透传 skipped_dismissed/failed_count/failed_details。
- **修复方法**：finding schema 增加 `candidate_id`/`vuln_type`（C-03/C-08）；`summary` 改 optional（dismissed 仅需 reasoning）；构造 CLI JSON 全字段透传；响应解析后把 CLI 返回的 `written/findings_written/duplicates/dismissed_written/dismissed_failed/failed_count/failed_details/errors` 原样放进工具结果，不做字段裁剪。
- **验证**：只含 reasoning 的 dismissed 行通过 schema；工具结果中 failed_details 与 CLI 输出一致。

### M-03 MAJOR 错误路径丢部分写结果
- **位置**：`extension/opencode/tools/secguard_report.ts:117-132,168-197`、`sgre/internal/cli/report.go:827-839`
- **问题与证据**：CLI 部分写失败先输出含 written/errors/failed_details 的 JSON 再 exit 1；MCP catch 只读 stderr/message 不解析 stdout → 整批标 skipped=args.findings.length，真实已写/未写明细丢失 → 盲目重写整批。
- **修复方法**：统一错误处理 helper：
  ```ts
  catch (e) {
    const stdout = e?.stdout?.toString() ?? "";
    try { const r = JSON.parse(stdout); return { status:"partial", ...r }; }
    catch { return { status:"error", error: e?.stderr?.toString() || String(e) }; }
  }
  ```
  所有会"先输出 JSON 再非零退出"的 CLI 调用（write-json/review-json/audit）共用该 helper。
- **验证**：注入单行非法 finding 使 CLI 部分失败，工具返回 partial 且 written 为实际成功数。

### M-04 MAJOR withTimeout 只 reject 不杀子进程，超时后还删输入文件
- **位置**：`extension/opencode/tools/secguard_report.ts:12-21,169-197`、`extension/opencode/tools/secguard_review.ts:8-18`
- **问题与证据**：Promise.race 超时无 AbortSignal/kill；finally 删临时 JSON 而后台 CLI 可能未读或仍在写 DB → "调用方认为失败、DB 实际成功"的不确定状态。
- **修复方法**：
  1. 改用 `Bun.spawn({..., timeout: ms, killSignal:"SIGTERM"})`（或 AbortController+signal），超时后杀进程组并 `await proc.exited` 再清理临时文件。
  2. 超时返回 `{status:"timeout", outcome:"unknown", hint:"query status --per-type / findings before retry"}`，编排层按 outcome_unknown 处理：先查 DB 再决定补写，禁止直接重试整批。
  3. 该 helper 抽到 `secguard_types.ts` 或新 `proc.ts`，report/review/scan/status 共用。
- **验证**：人为让 CLI sleep 超过超时 → 无残留 secguard 进程（ps 验证）、临时文件在进程退出后才删除、工具返回 outcome:unknown。

### M-05 MAJOR secguard_scan 无超时/后台参数，F4 在 MCP 宿主不可执行；返回契约缺字段
- **位置**：`extension/opencode/tools/secguard_scan.ts:101-125,153-176,192-212` vs `command-instructions.md:386,388-395,998-1001`
- **问题与证据**：F4 要求 >100 C 文件用显式 ≥600s timeout 或 background+Monitor，MCP scan 只有 path 同步等 .text()；正常响应缺 index_summary/scan_metrics/scan_scope/completion_state（Go 已生成，wrapper 丢弃）；parse fallback 只提取 scan_id/scan_dir 仍返回"完成"形态，无 candidates_by_type/total_candidates → scale gate 可把未知规模当 0 跳过整个 AI 阶段。
- **修复方法**：
  1. scan 参数增加 `timeout_ms`（默认 600000，大仓库可上调）、`types`（O-10）、`background`（可选：返回 task 句柄，由宿主任务机制监控）；超时/取消用 M-04 的 helper。
  2. 正常响应直接透传 CLI JSON envelope（含 index_summary/scan_metrics/scan_scope/completion_state/candidates_by_type/total_candidates/disabled_types/incomplete_task_count），只附加宿主必需字段。
  3. parse fallback 若无法取得 candidates_by_type/total_candidates，则返回 `status:"error", recoverable:true` 并提示用 `secguard_status`/`secguard_metrics` 补齐——禁止缺字段的"成功"进入 scale gate。
- **验证**：>100 文件仓库用 MCP scan 可指定超时完成；fallback 场景不会静默跳过 AI 分类。

### M-06 MAJOR secguard_status 把所有错误伪装成"无索引请重扫"
- **位置**：`extension/opencode/tools/secguard_status.ts:120-131`
- **问题与证据**：claim 参数错误/SQLite busy/查询失败与缺 DB 共用一个 catch，统一 `indexed:false` + "Run secguard_scan" → 一次临时锁失败诱导编排器重跑完整 scan。
- **修复方法**：按 CLI 退出码与 stderr 分类：仅"database not found/no such file"→ `indexed:false`；`database is locked`→ `{status:"busy", retry_after_ms:...}`；claim 失败→ `{claimed:false, error:...}`；其他→ `{status:"error"}`。任何非 not-found 错误不得建议重扫。
- **验证**：写锁占用期间调 status claim，返回 busy 而非 indexed:false。

### M-07 MAJOR 多个 MCP 工具无法透传绝对 db_path
- **位置**：`extension/opencode/tools/secguard_report.ts:88-112`、`secguard_review.ts:69-75`、`secguard_db.ts:31-36`、`secguard_plan.ts:81-89`
- **问题与证据**：固定从 context.directory/worktree 推导 DB，仅 status/def 支持显式路径；agent 要求子代理用 scan_dir 派生的绝对 DB 路径（工作目录不受保证）→ 子代理 context 与扫描 root 不一致时可能读写错误项目。
- **修复方法**：所有 DB 消费工具统一增加 `db_path`/`scan_id`/`output_dir` 可选参数，解析优先级 `显式 db_path > output_dir 派生 > context 派生`；执行前校验解析出的 DB 的 scan_runs 含该 scan_id，不一致直接报错。
- **验证**：在不同 cwd 的子代理 context 下，用显式 db_path 写入与 Bash 路径结果一致；错误 DB+scan_id 组合被拒绝。

### M-08 MAJOR 列表接口无分页/无上限，大结果撑爆上下文
- **位置**：`extension/opencode/tools/secguard_report.ts:236-245`、`secguard_db.ts:46-52`、`secguard_plan.ts:100-122`、`secguard_review.ts:122-140`、`secguard_def.ts:71-76`；Go 侧 `sgre/internal/cli/report.go:337-341`
- **问题与证据**：report 读取固定 `--list` 全库所有扫描 findings（传 scan_id 也不用于 read）；db 允许无 LIMIT SELECT；plan 返回全部候选且自述 no cap 并丢弃 Hint/Source/Evidence；review 默认无 limit（Go 侧 `--list-auto-confirmed` limit=0 全量且每条附源码窗口）。
- **修复方法**：
  1. 所有列表工具加 `scan_id/type/limit/cursor`，默认 limit=50；结果超页时返回 `next_cursor`。
  2. 大结果改为写文件：工具把完整 JSON 写到 `<scan_dir>/.tmp/tool-result-<uuid>.json`，响应只返回 `{count, file, preview[:20]}`。
  3. `secguard_db` 强制 LIMIT（无 LIMIT 自动追加 500）与输出字节上限（如 256KB，超出走写文件）。
  4. Go 侧 `--list-auto-confirmed` 默认 limit=200，附 `total/has_more`；plan 透传 Hint/Source/Evidence（分页后单页体量可控）。
- **验证**：5 万 findings 仓库调用列表工具，响应 <64KB 且可翻页取全。

### M-09 MINOR wrapper 与 Bash 返回契约不等价的其它缺口
- **位置**：`extension/opencode/tools/secguard_scan.ts:154-176`（丢 disabled_types/incomplete_task_count 等）、`secguard_plan.ts:107-122`（丢证据字段）
- **修复方法**：确立"wrapper 只透传不裁剪"原则并落到代码审查清单；把 CLI 各命令的 JSON envelope 在 `secguard_types.ts` 定义 zod schema，wrapper 直接 parse 透传，新增字段自动可用；一致性脚本检查 wrapper 返回字段集合 ⊇ 编排文档所需字段集合。

---

## 6. E 组：sgre 引擎 —— 断点续扫与"假完整"

### E-01 CRITICAL 重建开始时从不清除 graph_build_complete，失败后续扫复用"半成品 graph + 上一轮旧 events"
- **位置**：`sgre/internal/cli/pipeline.go:141-158,289-298,382-389,589-595`
- **问题与证据**（已回源确认）：`graph_build_complete` 只在 graph+detectors 全成功后写 true，**开始重建时从不置 false**。失败时序：第 N 次成功 → 文件修改 → 第 N+1 次 ClearGraph 删旧图、builders 分批提交、任一 builder 出错在 :289 提前 return（此时 security_events 仍旧、graph 半成品、meta 仍 true）→ 第 N+2 次 FilesChanged==0 且 graph_edges 非空且 events 非空且 complete=true → **canReuse=true**，用"旧代码 events + 半成品 graph"出候选且标记 complete。OOM-kill 同构。
- **修复方法**：
  1. 最小修复（先做）：`canReuse=false` 分支第一步、ClearGraph 之前：
  ```go
  if !canReuse {
      if err := store.SetMeta(ctx, "graph_build_complete", "false"); err != nil {
          return nil, fmt.Errorf("invalidate graph completion: %w", err)
      }
      if err := store.ClearGraph(ctx); err != nil { ... }
  }
  ```
  2. 推荐代际模型（与 E-02/E-03 同批）：pipeline_meta 增加 `build_generation`；graph/events 表记录写入代际；canReuse 要求"完成标记=true 且 内容代际=最新完成代际"，彻底消除布尔位与内容不同步。
- **验证**：e2e 脚本——首轮成功扫描后改一个文件，注入 builder 失败（可用故障注入 env，如 `SECGUARD_FAIL_BUILDER=call_graph`），第三轮扫描日志必须出现 graph+detectors 重建而非 `phase skipped`；转正为 pinned 回归。

### E-02 CRITICAL detector 失败/事件批 flush 失败仍写 graph_build_complete=true，失败 detector 永久失去重跑机会
- **位置**：`sgre/internal/cli/pipeline.go:354-365,376-389`、`sgre/internal/evidence/detector.go:342-357`、`sgre/internal/evidence/registry.go:179-186`
- **问题与证据**：detector panic/error/slot 取消、InsertEventBatch 整批失败只转 DetectorError → completion_state=incomplete（仅本次 scan_id），meta 照样 true；下次无文件变更 → detectors 整阶段跳过 → 失败 detector 的 vuln type `seed_count=0` 被读作"代码干净"，新一轮 completion_state=complete。**一次偶发失败即不可自愈假阴性**。
- **修复方法**：
  1. pipeline_meta 增加 `detectors_complete`（或 per-detector 完成位图 `detector_done:<name>`）：`RunAllDetectorsWithSkip` 返回成功 detector 集合；写 meta 时只标记成功者；`EventFlushFailures()>0` 时对应 detector 不标完成。
  2. canReuse 判定增加"本次应运行 detector 集合 ⊆ 上次完成集合"；不满足时**只重跑缺失 detector**（`RunAllDetectorsWithSkip` 已支持 skipSet，反向构造 onlySet 即可），graph 不必重建。
  3. 新一轮扫描的 `detector_errors` 输出要包含"本轮重跑的历史失败 detector"清单，便于审计。
- **验证**：首轮注入 unchecked_return 失败 → 次轮无文件变更扫描必须重跑该 detector，且 seeds_by_type 恢复非零；不得整阶段 skipped。

### E-03 CRITICAL ConfigChecksum 不覆盖 CLI override 与工具版本，--skip-detectors 后全量扫描静默继承残缺事件集
- **位置**：`sgre/internal/config/config.go:1016-1031`、`sgre/internal/cli/scan.go:65-68`、`sgre/internal/cli/pipeline.go:125-145`
- **问题与证据**：`--skip-detectors`、`--exclude`、compile_commands 的 -D/-I、二进制版本均不进 checksum。先 `scan --skip-detectors buffer_overflow` 再无 flag 扫描：checksum 不变 → canReuse → detectors 不跑，输出 detectors_skipped 为空、seeds=0，无任何字段区分"被跳过"与"无问题"。升级二进制同样不重跑。
- **修复方法**：
  1. 新增 `reuseFingerprint()` 替代单一 config_checksum，内容：`secguard.toml 字节哈希 + cli.Version + evidence.DetectorNames() 排序哈希 + SkipDetectorNames() 排序哈希 + 有效 exclude 集合 + compile_commands 文件内容哈希与路径 + 目标 absPath`。
  2. pipeline 启动时计算并写入 meta；canReuse 比较完整指纹；任一变化 → graph/events 失效重建，并清理出 scope 的旧 events。
  3. type-filter 与 boundary-auto-dismiss 只影响 plan，不纳入指纹，但在注释中写明边界。
- **验证**：上述 skip→全量序列第二轮 detectors 必须重跑；仅升级二进制（版本变化）也使 reuse 失效。

### E-04 MAJOR index/evidence/plan 三条路径的文件级失败都不进 incomplete 账本
- **位置**：`sgre/internal/indexer/indexer.go:96-109`、`sgre/internal/evidence/detector.go:89-101,134-146,188-200`、`sgre/internal/planner/null_flow.go:2966-2974`、`sgre/internal/cli/scan.go:491-503`
- **问题与证据**：单文件读/解析失败仅 Warn+FilesSkipped（plan 的 functionBodiesForFile 失败连日志都没有，返回零值节点继续推理）；FilesSkipped 不参与 plannedState → 报告头仍 complete。
- **修复方法**：
  1. 定义 `FileFailure{Phase, FilePath, Err}` 收集器挂到 ctx；indexer/evidence/plan 三处失败点统一上报（plan 处补 Warn 日志）。
  2. 扫描收尾把收集结果聚合写入 `scan_incomplete_tasks`（按 phase+file 去重；每 phase 超 100 条时聚合为计数行，防账本爆炸）。
  3. `plannedState` 计算：`FilesSkipped>0 || len(fileFailures)>0` → 至少 incomplete；status/audit 输出 per-phase 失败文件清单。
- **验证**： fixture 中放一个无读权限文件与一个病态大文件，扫描结果 completion_state=incomplete 且账本含对应文件。

### E-05 MAJOR graph 边写入失败只 Warn，Build() 仍返回成功
- **位置**：`sgre/internal/graph/edge_batch.go:56-79`、`sgre/internal/graph/call_graph.go:169-170`
- **问题与证据**：批失败回退逐边、单条失败 continue；builders 不拿 total 与预期比对也不向上返回错误（违反 AGENTS.md"never swallow for Build"）。LOCK_ORDER/GLOBAL_ACCESS 边缺失 → race-condition/deadlock 收敛链把候选当"无共享访问"丢弃。
- **修复方法**：`edgeBatchWriter.flush` 返回 `(written, failed int, err error)`；逐边回退后统计最终 failed；各 builder 在 `failed>0` 时返回 error（走 pipeline 的 builder 失败路径，与 E-01 的完成标记失效联动）；若产品决定容忍部分边缺失，则必须写 `scan_incomplete_tasks{phase:"graph",detail:builder+failed数}` 且 completion_state=incomplete，二选一不得静默。
- **验证**：注入边写失败 → Build 返回 error 或账本有记录，status 显示 incomplete。

### E-06 MAJOR planner 基础数据加载吞错，把 DB 读失败转成空事实表
- **位置**：`sgre/internal/planner/filter.go:81-87,92-100`（与 `planner.go:497-508` 自我要求相反）
- **问题与证据**：ListFunctionsByIDs/listFilesByID 失败 → 空 map 继续；下游 fnByID[fid]==nil 把函数当不存在，候选被无依据保留或丢弃，FilterStats.Error 为空。
- **修复方法**：`loadFuncFiles`/`listFilesByID` 签名加 `error` 返回；filter.Apply 在加载失败时设置 `FilterStats.Error` 并经 `planner.go:192-200` 已有的 filterErr 通道上抛，使该类型进入 PlanErrors 与 incomplete 账本；禁止构造空 map 继续。
- **验证**：mock store 让 ListFunctionsByIDs 返回错误 → 该类型 plan 失败且错误可见，而非产出候选。

### E-07 MINOR 空结果仓库永远命中不了 canReuse
- **位置**：`sgre/internal/cli/pipeline.go:561-572`
- **修复方法**：删除 `graphExists/eventsExist` 两个内容非空条件，canReuse 只依赖 E-01/E-02 修复后的完成标记 + E-03 指纹 + FilesChanged；空仓库第二轮扫描日志必须显示 phase skipped。

### E-08 MINOR InsertEventBatch 失败时 inserted 返回值与回滚结果不符
- **位置**：`sgre/internal/db/crud_events.go:34-53`、`sgre/internal/evidence/detector.go:350-355`
- **修复方法**：批事务任一条失败整体 ROLLBACK 后返回 `(0, err)`（或把返回值改名 attempted 并在调用处区分）；日志输出实际落库数与丢失数，供 E-02 的位图判定使用。

---

## 7. P 组：超大仓库性能与内存

### P-01 MAJOR fileParseCache 的 borrow 使 max_cached_trees 形同虚设；returnSummaryResolver 构造即全仓库 prime
- **位置**：`sgre/internal/planner/null_flow.go:2877-2887`、`sgre/internal/parser/parser.go:272-293`、`sgre/internal/planner/return_summary.go:60-68,83-93`、`sgre/internal/planner/filter_range.go:70-74`
- **问题与证据**：LRU 只逐出 refs==0 的树，而 plan 阶段 fileParseCache 把每棵接触过的树 pin 住（`fc.trees` 持有 borrow，Close 才 Release）；`newReturnSummaryResolver` 构造时 buildGlobalConstants 对**仓库内每一个索引文件** rootForFile —— divide-by-zero 的 RangeFilter 一启动就把全仓库 AST+源码拉进内存并 pin 到 Apply 结束，与文件是否含候选无关；8 个 plan goroutine 并发叠加。GOMEMLIMIT 管不到 cgo AST → "配置都设了仍 OOM-kill"。
- **修复方法**：
  1. `buildGlobalConstants` 改流式：遍历文件时 `WithParseCached(file, func(root){ 提取常量后立即返回 })`，常量结果（标识符→字面值 map）存入 resolver，**不保存 root/Tree 引用**；单文件常量提取后 borrow 即刻 Release。
  2. `fileParseCache` 增加条目上限（如 256 文件，LRU）：evict 时对该文件树执行 Release；或更彻底地只缓存 `bodies/defs` 所需的轻量结构（函数起止行、参数名、guard 文本），不长期持有 `parser.Node`。
  3. resolver/fileParseCache 的驻留预算与 `max_cached_trees` 共用同一计数：pin 中的树计入缓存占用，超预算先 evict 可逐出项再 parse。
- **验证**：构造 5000 文件仓库跑 divide-by-zero plan，RSS 峰值有界（对比修复前后 pprof/heap 与 `/usr/bin/time -l`）；`max_cached_trees` 调小能实际降低峰值。

### P-02 MAJOR globalSourceLineCache 进程级无上限缓存所有候选文件全文，与 AST 缓存重复持有源码
- **位置**：`sgre/internal/report/snippet.go:96-123`、`sgre/internal/report/markdown.go:481-504`
- **问题与证据**：每候选文件整文件读入拆 []string 永久缓存（失败也缓存 nil），无 LRU/字节预算；同一份源码同时存在 Tree.src、sourceLineCache、os.ReadFile 临时副本三份；report 阶段 AST/CFG 缓存尚未 Reset → RSS 峰值叠加。
- **修复方法**：`sourceLineCache` 改容量受限 LRU（按总字节预算，如 256MB，或文件数 1024），用 `container/list`+map 实现即可；优先方案是复用 parser 已缓存的 `Tree.src`（存在时不再 ReadFile）；`candidateContext` 渲染按文件分组连续处理（`sortCandidatesByFunction` 已有基础），提高小缓存命中率；report 阶段开始前先 `sharedCFGCache.Reset()` 释放 AST borrow（当前在 runPipeline 返回后才执行，可提前）。
- **验证**：数万候选的 report 渲染阶段 RSS 不随候选文件数线性增长；缓存命中率指标（hits/misses）写入 log。

### P-03 MAJOR ParseCached 在全局互斥锁内执行 cgo parse，冷缓存时所有并发阶段退化为串行
- **位置**：`sgre/internal/parser/parser.go:230-267`
- **问题与证据**：`p.mu.Lock()` 包住 NewParser+Parse+缓存插入；graph builders(7)/detectors(8)/plan(8) 共享同一 Parser → 缓存未命中时全进程同一时刻只有一个 goroutine 在解析。CFGCache.Acquire 已用正确的"placeholder+锁外构建"模式（cfg_cache.go:128-150），parser 没用。大仓库首扫几乎全 miss，三个并发旋钮基本失效。
- **修复方法**：照搬 CFGCache 的 singleflight 模式：
  ```go
  p.mu.Lock()
  if t := p.cache.get(key); t != nil { p.mu.Unlock(); return t, nil }       // 命中
  if e := p.inflight[key]; e != nil { p.mu.Unlock(); <-e.done; return e.tree, e.err } // 等待在途
  e := &inflightEntry{done: make(chan struct{})}; p.inflight[key] = e
  p.mu.Unlock()
  ps := sitter.NewParser(); ps.SetLanguage(...); tree, err := ps.Parse(source, nil) // 锁外 cgo
  p.mu.Lock(); e.tree, e.err = tree, err; close(e.done); delete(p.inflight, key)
  // 插入 LRU / transient 分支逻辑保持不变
  p.mu.Unlock()
  ```
  保持"一棵树一个专用 parser"与 `closed` 检查不变量；transient 分支同样在锁外 parse。
- **验证**：冷缓存大仓库扫描，graph/detectors 阶段 CPU 核占用从 ≈1 核升至并发度对应核数；E2E 墙钟对比（修复前后同仓库同配置）。

### P-04 MAJOR status --reports 每次轮询全量读取并重写所有历史 settlement
- **位置**：`sgre/internal/cli/reports.go:81-206`、`sgre/internal/cli/settlement.go:79-157`、`sgre/internal/cli/scan.go:159-168`（.tmp 明确不清理）
- **问题与证据**：无增量游标；每次 poll 读全部历史 report/chunk 文件（含历史 scan 残留）并对去重后每份报告重新整组 UPSERT+MarkAIStageDone（IMMEDIATE 事务），report --audit 重复同一吸收；与 8 路并发 write-json 争写锁。
- **修复方法**：
  1. `listSubagentReports` 读目录后先按 `(scan_id)` 过滤文件名/manifest，再按吸收游标跳过：meta 表新键 `settlement_absorb_cursor` 存 `{path,mtime,size}` 集合（或独立 absorbed_files 表），未变化文件跳过重写；仅展示用的内存态仍可读全量当前 scan 文件。
  2. `persistSettlementReports` 对"内容未变且已吸收"的报告跳过 UPSERT 与 MarkAIStageDone；MarkAIStageDone 在状态已 done 时跳过写（先 SELECT）。
  3. `.tmp` 按 scan_id 建子目录（`<tmp>/<scan_id>/<subagent_id>-report.json`），新 scan 启动只归档旧 scan 目录（重命名到 `.tmp/archive/` 或删除策略可配）。
- **验证**：构造 5000 个历史 settlement 文件，连续两次 status --reports，第二次 DB 写次数≈0、耗时 <100ms；与并发 write-json 压测不再出现 busy 失败。

### P-05 MAJOR status / report --stats / --audit 为拿计数全表物化 findings（含全部大字段）
- **位置**：`sgre/internal/cli/scan.go:1180-1193`、`sgre/internal/cli/report.go:1093-1123,1898-1922`、`sgre/internal/db/crud_findings.go:164-172`
- **问题与证据**：只需 COUNT 的地方全量 ListFindings（21 列含 evidence/properties/reasoning 大 TEXT）再 len()；大仓库数万~数十万行 × 数 KB → 单次 status（轮询频率最高的命令）分配数百 MB 并全表扫描，同时还是写进程的锁竞争者。
- **修复方法**：
  1. store 增加聚合查询：`CountFindings(scanID)`、`CountFindingsByType(scanID)`（GROUP BY vuln_type）、`CountAutoConfirmedUnreviewed(scanID)`；`scan.go:1180-1193` 的 len(findings)/len(files)/len(functions) 全部替换为 COUNT。
  2. `report --stats` 改复用 `ListPerTypeStatus` 同款聚合，而非 `ListFindingsByScanID` 全量。
  3. 确需全字段的展示路径（--list/--audit 的明细段）加 LIMIT/OFFSET 或 keyset 分页；audit 的归一化阶段只取必要列（id/rule_id/file/line/variable/status），不读 evidence/reasoning。
- **验证**：10 万 findings 仓库，status 单次 RSS 增量与耗时为常数级；SQL 日志确认无全表 SELECT 21 列。

### P-06 MINOR planner 绕开 RepoIndex 快照，重复全表 ListFunctions/ListFiles
- **位置**：`sgre/internal/cli/pipeline.go:160-185` vs `sgre/internal/planner/planner.go:264,332,424-433`、`sgre/internal/planner/return_summary.go:60`
- **修复方法**：planner 各消费点优先 `graph.RepoIndexFromCtx(ctx)`（含 FuncsByFile/FileByID/name 索引），快照缺失再回退 DB；`isBoundary`/entry-point 判定在快照构建时一次计算缓存；`resolveCalleeDefs` 用快照 name 索引替代全量 ListFunctions。验证：10 万函数仓库 plan 阶段 DB 查询日志中 ListFunctions 全表调用次数≈0。

### P-07 MINOR config.Load() 无进程内缓存（43 处调用点），扫描中途改配置致阶段间不一致
- **位置**：`sgre/internal/config/config.go:715-756`、`sgre/internal/cli/scan.go:315` 对照 `sgre/internal/cli/pipeline.go:430`
- **修复方法**：CLI 启动时 `LoadE` 一次，存不可变快照（含 checksum）挂 ctx，全进程 `config.Load()` 改读快照（保留包级函数签名，内部返回快照）；`vulnTypes` 由 `pipelineOutcome` 显式返回（与 Plans 同序），`runScanCmd` 删除扫描后重算逻辑，消除索引错位隐患。

### P-08 MINOR 单文件读取/解析无大小上限、无超时，一个病态文件拖垮整个扫描
- **位置**：`sgre/internal/indexer/indexer.go:161-168`、`sgre/internal/parser/parser.go:191-206,230-267`、`sgre/internal/evidence/detector.go:89`
- **修复方法**：indexer/evidence 读文件前 `os.Stat`，超 `max_file_bytes`（新配置，默认 16MB）→ 记 FilesSkipped + E-04 的文件级 incomplete 账本并跳过；parser 层用 tree-sitter 的带进度回调/取消 API（或按字节预算预检）做文件级隔离；超限文件路径写入扫描 JSON 的 `skipped_large_files`，保证可见。

### P-09 MINOR WithImmediateTx 在 fn panic 时不回滚，事务随连接归还连接池
- **位置**：`sgre/internal/db/store_impl.go:63-83`
- **修复方法**：
  ```go
  if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil { return err }
  done := false
  defer func() {
      if !done { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }
  }()
  if err := fn(tx); err != nil { return err }        // defer 统一回滚
  if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil { return err }
  done = true
  return nil
  ```
  panic 时 defer 回滚后 panic 继续上抛（调用方按需 recover）；加测试：fn panic 后同一连接池后续写不卡 database is locked。

### P-10 MINOR 资源管理杂项
- **indexer 私有 parser 不 CloseAll**：`sgre/internal/indexer/indexer.go:42-49` → `Indexer` 加 `Close()`（内部 parser.CloseAll），`runPipeline` 在 `idx.Index` 后 defer；或直接把外层共享 parser 注入 indexer 消除第二实例。
- **locations 每事件一行不去重**：`sgre/internal/db/crud_locations.go:10-22`、`crud_events.go:39-51` → schema 加 `UNIQUE(file_id,line,column)`，写入改 `INSERT ... ON CONFLICT DO NOTHING` 后 SELECT id（批内先 map 去重），每事件 SQL 从 2 条降为近似 1 条。
- **Executor/SubprocessRunner 无界行为**：`sgre/internal/worker/executor.go:71-93` → 固定 worker 池（N=并发度）+任务 channel，不再每 batch 起 goroutine；`runners.go:43-51` → stdout/stderr 用 `io.LimitReader`（如 4MB），error 只保留 stderr 前 8KB。
- **r_type 聚合随历史变慢**：`sgre/internal/db/crud_settlement.go:220-234` → 按 O-07 加复合索引；提供 `secguard db --archive-settlements --before <scan_id>` 归档清理命令。

---

## 8. G 组：发布门禁

### G-01 MAJOR check-extension-consistency.py 只验证表面结构，上述漂移全部绿灯放行
- **位置**：`release/check-extension-consistency.py:82-112,115-141,226-318,360-384`、`extension/DESIGN.md:49-73`
- **问题与证据**：实测通过。覆盖 turn 数值/工具名集合/权限名/skill 结构/少量 DSH 字符串/打包路径；**未覆盖**：DSH 是否复用 shared 调度与 turn cap、MCP 的 vuln_type/db_path/scan_id/timeout 参数与响应字段、range 完成与 claim 生命周期、dismissed 持久化协议、settlement 文件可解析性、shared 三指令源语义矛盾、filtered 与 full scan 完成条件一致性。DESIGN.md 还保留"MAXTURNS sizes subagent batches"旧描述（现为 count-based 模型，已无 TURNS_PER_TYPE_ESTIMATE）。
- **修复方法**：
  1. 文档禁词/必含断言（文本级，成本最低）：C-01（不得出现"write the SAME fenced JSON to ... .json"）、C-02（dismissed 不持久化类措辞禁词）、O-04（heavy 分组唯一规则）、O-08（group verdict 段必含 chain-root）、O-12（auto-confirmed 示例须属 registry confirmed 集合）。
  2. MCP schema 断言：解析 `secguard_report.ts` 等工具源码，要求 finding schema 含 candidate_id/vuln_type、工具含 db_path/timeout/limit 参数（随 M 组落地逐项开启）。
  3. 契约级 e2e 测试（Go 侧 `contract_test.go` 扩展）：§10 验收矩阵中"多 range 部分完成/全 dismissed/截断写回/fenced JSON"四场景固化为 CI 必跑。
  4. DESIGN.md 容量模型描述更新为 count-based 三约束公式（O-04/O-05）。
- **验证**：对上述任一项做反向改动（回写旧措辞/删 MCP 参数），脚本必须失败。

---

## 9. 目标架构改建建议（重构蓝图）

以下按依赖顺序排列，供重构 Agent 作为设计基线；每项标注落地的问题编号。

### 9.1 统一候选身份（前置一切）
引入 `candidate_id`：scan 阶段对 needsReview 候选生成稳定 ID（内容寻址：`scan_id + vuln_type + rule_id + 规范化file + line + variable` 的哈希，或 DB 自增+映射表），写入 candidates md/json/SARIF 每个候选的显式字段。findings、candidate_verdicts、settlement_stats、scan_stats 的 candidate_count 全部以它为身份。**同时**在候选文档显式输出 rule_id/vuln_type/category（修 C-08）。AI 回填只需 candidate_id + verdict，rule_id/variable/function 由 CLI 从 candidate_id 反查回填——从根上消除 C-03/C-04/C-06 的键错位与 AI 填错可能。落地：C-03、C-04、C-07、C-08、M-02。

### 9.2 range 结构化与覆盖证明
`settlement_stats.range_str` 改为结构化区间 `(scan_id,type,range_start,range_end,holder,status,heartbeat_at,finished_at)`。claim 事务内做重叠检测；type 完成由"区间并集 == [1,candidate_count] 且无 needs_context 且无活 claim"派生（单一函数 `deriveTypeTerminalState(scan_id,type)`，settlement 吸收/complete-range/status/audit 四处共用）。needs_context/failed 进 per-range 条目。落地：S-01、S-02、S-06、S-07、O-01、O-06。

### 9.3 claim 租约与 fencing
holder 持 UUID token；chunk 心跳与 finding 写入续租（heartbeat_at）；stale 判定只看 heartbeat_at 超阈值；settlement 吸收 `WHERE holder=? AND status='dispatched'` CAS；迟到报告落 late_log 不覆盖。release/fail-claim 补齐生命周期。落地：S-05、O-07。

### 9.4 终态门禁
`report --audit` 默认要求：全部 active type `terminal_state=done`、无活 claim、无 unreviewed auto-confirmed（现有检查保留）、`unclassified==0`（按类型独立算）。不满足 → 拒绝终态产物或要求 `--allow-partial` 并在 SARIF/report/findings 全部打 partial 标。audit 重渲染用代际校验防 S-04 竞争删除。落地：S-03、S-04。

### 9.5 续扫复用的代际模型
pipeline_meta 增加 `build_generation`、`detectors_complete`（或 per-detector 位图）、`reuse_fingerprint`（工具版本+注册表指纹+skip/exclude/compile_commands+config checksum）。重建开始即写 `graph_build_complete=false` 并提交；成功后写完整指纹。canReuse 仅比较指纹与完成标记，不查内容非空。落地：E-01、E-02、E-03、E-07。

### 9.6 指令单一事实源与机器门禁
shared 三指令源（command-instructions/agent-body/SKILL）中所有**协议性陈述**（写回契约、完成条件、容量公式、预算单位、group verdict 维度）集中到一节"Protocol Contract"，其余处只引用不复制；check-extension-consistency.py 增加契约断言与 MCP schema 参数检查。DSH 编排与 worker 改为由 shared 生成。落地：C-01、C-02、O-04、O-08、O-11、G-01。

### 9.7 性能改造的耦合点
P-04 的增量吸收依赖 9.2 的结构化 settlement；P-05 的计数 SQL 化依赖 9.1 的身份统一；P-01/P-02/P-03 可独立先行（纯引擎内部）。建议顺序：9.1 → 9.2/9.3 → 9.4/9.5 → 9.6 → 性能批。

---

## 10. 修复优先级与验收矩阵

### 优先级路线（遵守"完成当前修复先提交再看下一个问题"：每批内按逻辑边界拆 commit，每批完成先提交再开下一批）
1. **批次一（结果正确性底线）**：C-01、C-02、S-01、S-02、S-03、C-05、C-06。
2. **批次二（身份与状态机重构）**：C-03（candidate_id）→ C-04/C-07/C-08 → S-06/S-07/S-05 → O-01/O-06。
3. **批次三（续扫正确性）**：E-01、E-02、E-03、E-04、E-05、E-06、S-08。
4. **批次四（编排一致性与 MCP）**：O-02、O-03、O-04、O-05、O-07、O-08、O-09、O-10、O-11、O-13、M-01～M-09、G-01。
5. **批次五（性能与加固）**：P-01～P-10、C-09、C-10、C-11、E-07、E-08、S-09、S-10、O-12。

### 端到端验收矩阵（每批修复必须跑对应场景，构建本地 CLI 二进制实测，不接受单测绿即完）
| 场景 | 构造 | 通过判据 | 覆盖项 |
|---|---|---|---|
| 多 range 部分完成 | 单类型 200+ 候选，拆 5 批，只完成 1 批 | status --per-type 该类型 remaining>0、不得 done；audit 拒绝终态或标 partial | S-01/S-02/S-03/O-02 |
| 全 dismissed range | 一批全部判驳 | candidate_verdicts 有逐候选记录；remaining 正确；恢复不重派 | C-02/C-03/C-06/O-06 |
| 截断写回 | 构造截断的 write-json chunk | 非零退出+truncated 标记；该 range 不标完成 | C-05 |
| 同行多变量/多 CWE | 同行两变量候选 + int_min_div(CWE-190) | verdicts/findings 各两条不互相覆盖；vuln_type 归属正确 | C-03/C-08 |
| worker 崩溃恢复 | 完成 2/5 批后 kill | 恢复只补缺失 range 的具体候选，不整类型重做、不 FULL-range | S-05/S-06/O-01 |
| 慢 worker 双活 | heavy batch 运行超 30 分钟仍有心跳 | 不被接管；迟到报告不覆盖新 holder | S-05 |
| graph 构建失败续扫 | builder 注入失败后重扫 | 第二轮必须重建，不得 canReuse | E-01/E-02 |
| skip-detectors 后全量 | 先 --skip-detectors 再无 flag | 第二轮 detectors 必须重跑 | E-03 |
| fenced/裸 JSON | 按 agent-body 原文写报告文件 | status --reports valid:true 且吸收 | C-01 |
| 超大仓库性能 | 数千文件/十万函数级仓库 | 无 OOM（RSS 有界）；冷缓存解析并发扩展；status 轮询毫秒~百毫秒级；settlement 吸收增量 | P-01～P-06 |
| DSH/同步宿主 | 超 host_max 队列 | 队列全部调度完成后才 finalize；完成条件含 dismissed | O-02/O-11 |
| 多 range 并发 audit | worker 写入中跑 audit | 不删新 finding 文件；终态门禁拦截 | S-03/S-04 |

每个场景修复后按项目纪律转正为 pinned 回归测试；涉及检测行为的在 `examples/c-vuln-benchmark` 留回归用例。

---

## 11. 已核实无问题、不要误改的点

- candidates **按类型拆分文件 + 90KB index 分片**已存在（`markdown.go:241-267,767-903`），缺口在容量模型（O-05）而非分片缺失。
- findings 的 UPSERT 原子性本身正确（`crud_findings.go:128-161` ON CONFLICT DO UPDATE RETURNING），问题在输入规范化与平行身份键。
- 正常新生成 scan_id 的数据隔离方向正确（findings/verdicts/scan_stats/settlement_stats 均带 scan_id），问题集中在显式同 ID 重扫（S-08）与孤儿写入（S-06）。
- `MAXTURNS=60` 四平台一致；`TURNS_PER_TYPE_ESTIMATE` 已不存在，容量为 count-based 模型——不要再按旧文档找它。
- `release/check-extension-consistency.py` 的现有检查项本身有效，需要**扩充**而非推翻。
- DB 每次全新创建、无 migration：schema 类修复（C-03/S-05/S-06/P-10）直接改 `schema.go`，禁止写迁移代码。

---

*本清单为检视交付物；修复由其他 Agent 按编号执行。所有结论基于 c6a8e92 源码静态检视（CRITICAL 项已回源复核），尚未跑端到端复现；修复 Agent 应先按 §10 对应场景复现确认，再动手。*