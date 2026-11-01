# 样例项目扫描问题与性能提升改进建议 — round1

> 分析对象：`examples/c-vuln-benchmark` 的一次真实全量扫描会话
> 扫描 ID：`sc_2026-11-01_125551_a885a5`（secguard-clang v0.11.9）
> 本文所有数字均来自本次会话的 `secguard_scan` / `secguard_status` / `report --audit` / `sgre.db` 输出，估算量会明确标注「估算」。

---

## 0. 结论摘要（TL;DR）

| # | 问题 | 影响 | 建议 | 预期收益 |
|---|------|------|------|----------|
| P0-1 | dismissed 判定不落库，`written_count == candidate_count` 无法区分「全部确认」与「中断」 | 中断后必须读索引 + 查库才能算出剩余候选（本会话多花约 6 次往返、~8k tokens） | 新增 `candidate_verdicts` 表（含 dismissed），`status` 暴露 `classified_count/remaining` | 断点恢复从「人工推断」变为「一条命令」 |
| P0-2 | 子代理只在**全部类型做完后**写一份 settlement 报告 | 中断时 10 个子代理的 settlement 全部丢失（`.tmp/*-report.json` 为 0） | 改为**每完成一个类型**写一份 `<subagent_id>-<type>-report.json` | 中断最多损失 1 个类型，而非整批 |
| P0-3 | 同一物理量三处口径不一致（divide-by-zero：scan 摘要 2 / mid-run status 3 / 终报 0；integer-overflow：3 / 5 / 5） | 汇总数字不可直接信任，需人工对账 | 统一由 `audits` 的同一查询派生，并加回归测试 | 报告数字可被程序化校验 |
| P0-4 | 派发提示词把工作流规则整段重复（19 次派发，估算 ~25k tokens 输出） | 编排器 token 与生成时间双重浪费 | 规则留在 `agent-body.md`，派发只传增量（类型/数量/范围/路径），≤400 tokens/次 | 估算省 ~17k tokens 编排输出 |
| P1-5 | 批次未打包大 light 类型与小类型（`dangerous-function` 39 条独占一批） | 首波 10 批、恢复波 9 批，本可 8 批 | 大 light 类型（>30）+ ≤3 个 tiny 类型（≤3）合批 | 少 1~2 次子代理启动 |
| P1-6 | `SMALL_TYPE_SEQUENTIAL_THRESHOLD`（≤15 候选直判）与「type_count≥4 强制并行」冲突，同步宿主无法两全 | 10 个小类型（共约 20 候选）仍走了子代理 | 明确同步宿主的混合策略与优先级 | 估算再省 5 次 spawn |
| P1-7 | 报告 Skill 表 CWE 取自行级 rule_id（`path-traversal` 被标成 `CWE-732`） | 交付物元数据错误 | 取自 `planner.VulnTypeSpec.CWE`（AGENTS.md 单一真源） | 消除错误标注 |
| P1-8 | 「integer-overflow Evidence 嵌入整函数」假设不成立（实际 ±8 行，子代理被迫读源） | 批次成本模型失真 | 生成侧确定性输出整函数跨度并加测试，或下调 heavy 假设 | 成本模型可信 |
| P1-9 | divide-by-zero 的 `_index.md` 图例与主流程提示规则冲突（图例要求 bare 也开 Evidence，主流程说 bare 免开） | 子代理行为不确定 | 图例与提示从同一 `hint_tokens` 源生成 | 消除歧义 |
| P2-10 | `secguard_status` 在索引为空时返回 `indexed: true` | 编排器需额外判断 | 增加 `empty`/`stale` 状态 | 少一次误判 |
| P2-11 | `ai_duration_ms` 包含宿主中断/空闲时间（本会话 579s 含模型切换窗口） | 生产 AI 耗时口径偏高 | 记录 `ai_started_at/ai_finished_at/interrupt_ms` 并分开上报 | 时间口径可解释 |
| P2-12 | `null-deref` 子代理对 2 个文件做**整文件读取**（p5、p23） | 读源预算超常规（虽为验证契约，仍属越界） | 明确「整文件读」需在报告中显式标注理由 | 读源审计可执行 |

**总体判断：本次 99.8% 的墙钟耗在 AI/编排阶段（自动分析仅 1.298s，AI 579s），因此优化重点应是「派发编排与断点恢复」，而不是索引或检测器。**

---

## 1. 会话事实时间线

| 阶段 | 实际动作 | 观测 |
|---|---|---|
| 0 | `secguard_status` | `indexed: true` 但 `files_indexed: 0`（空库） |
| 1 | `secguard_scan ./src` | 61 文件 / 419 函数 / 4924 行；689 seeds → 200 候选；47 自动确认；`detector_errors`/`plan_errors` 均为空 |
| 2 | 规模门（type_count=25 ≥4） | 按规则选 **PARALLEL**（禁止 SEQUENTIAL） |
| 3 | 首波派发 10 个 `task`（同一回合） | 全部返回 `[Tool execution was interrupted]`（切换宿主模型） |
| 3.1 | 恢复取证：`status --reports` + `status --per-type` + `findings` 全量查询 + 读 4 个 `_index.md` | 确认已落库 35 条 AI 判定（23% 的 AI 工作量），其余未判定 |
| 4 | 重派 9 批（覆盖 17 个整类型 + 3 个部分类型的剩余候选） | 9/9 完成，0 失败，0 `needs_context` |
| 5 | DB 复核 + `--complete-type` × 29 | 与子代理自报完全一致（无 partial、无 missing） |
| 5.5 | 复核 47 条机器判定（CWE-457×4 / CWE-134×1 / CWE-190×3 逐条对源） | 全部成立，0 驳回 |
| 6 | `report --audit` + 产物校验 | 199 confirmed（47 机器 + 152 AI）/ 48 dismissed / 0 unclassified；`result.sarif` 675KB、`findings/` 199 个文件 |
| 7 | 写 `ai-dismissed.json`（R1 台账） | 48 条驳回，needs_context 0 |

---

## 2. 本轮度量

### 2.1 规模与产出

| 指标 | 值 |
|---|---|
| 文件 / 函数 / 行 | 61 / 419 / 4924 |
| 原始种子 → 收敛候选 | 689 → 200（29.0%） |
| 机器自动确认 | 47（占候选 23.5%） |
| AI 确认 | 152（占候选 76.0%） |
| 驳回 | 48（占候选 24.0%） |
| 确认合计 | 199（199/200 = 99.5% 的候选被确认） |
| 严重度 | critical 28 / high 48 / medium 115 / low 8 |
| 未落库判定 | 0 |

> 说明：该样例仓是**刻意构造的漏洞集**，确认率偏高属预期；但 199 条确认仍建议按 10% 抽样人工复核（尤其 `dangerous-function` 25 条与 `null-deref` 24 条，二者合计占确认量的 24.6%）。

### 2.2 时间

| 口径 | 值 | 说明 |
|---|---|---|
| 自动分析 | **1.298 s** | 索引+建图+检测+收敛+auto-confirm+候选报告 |
| AI 研判 | **579 s** | 含宿主中断（切换模型）窗口，偏高 |
| 端到端 | ≈ 581 s | 自动 + AI |
| AI / 自动 比 | ≈ 446 : 1 | 优化重心明确 |

### 2.3 派发效率

| 指标 | 值 |
|---|---|
| 子代理 spawn 总数 | 19（首波 10 + 恢复 9） |
| 单批最大类型数 | 4（符合 `MAX_TYPES_PER_BATCH`） |
| 单批最大候选数 | 39（dangerous-function，符合证据打开预算：10/12） |
| 首波因中断损失 | 10 个 spawn 中的 settlement 全部丢失，仅 35 条 finding 幸存 |
| 证据打开 | 各类型 ≤12（上限 12）；`unchecked-return` repo_greps=1（≤1，合格） |

---

## 3. 发现的问题（按优先级）

### P0-1　dismissed 不落库 → 断点恢复不可判定

**现象**
- `secguard_status --per-type` 的 `written_count` 只统计 confirmed/auto-confirmed，dismissed 不落库（设计如此）。
- 因此 `written_count == candidate_count` 有两种含义：**「全部确认」** 或 **「中断在写入后、判定完成前」**，DB 无法区分。
- 本会话 5 个类型（out-of-bounds / crypto-misuse / switch-fallthrough / stack-address-escape / injection）都是 `written == candidates`，我不得不读 `_index.md` 并逐站点比对 82 行 findings 才能确认「真的全做完了」。
- `status --per-type` 的 `already_covered_ranges` 在本次全程为空——它来自 settlement 报告，而结算报告在中断时不存在。

**成本**：约 6 次额外工具往返 + ~8k tokens + 一次人工判断风险（若判错，要么漏判、要么重派产生陈旧 confirmed 行）。

**建议（高价值）**
1. 新增独立表（不影响 `findings`/SARIF 语义）：

```sql
CREATE TABLE candidate_verdicts (
  scan_id      TEXT NOT NULL,
  vuln_type    TEXT NOT NULL,
  candidate_no INTEGER NOT NULL,
  file_path    TEXT, line_number INTEGER, function_name TEXT, variable TEXT,
  verdict      TEXT NOT NULL,          -- confirmed | dismissed
  reason       TEXT,
  subagent_id  TEXT, created_at TEXT,
  UNIQUE(scan_id, vuln_type, candidate_no)
);
```

2. `secguard report --write-json` 接收 `dismissed` 数组（或允许 finding 对象 `status:"dismissed"`）并写入该表；
3. `status --per-type` 输出 `classified_count`、`remaining`、`already_covered_ranges`（改为从 `candidate_verdicts` 派生，而非 settlement 报告）；
4. R1 的 `ai-dismissed.json` 由该表自动生成，不再依赖子代理落盘报告。

**收益**：恢复 = 一条 `secguard status --per-type` 得出剩余；复核台账自动、可查询、可审计。

---

### P0-2　settlement 报告只在结束时写 → 中断全丢

**现象**
- 首波 10 个 `task` 被打断后，`.codeagent/.../.sgre/.tmp/` 下**没有任何** `*-report.json`（`status --reports` 返回 `count: 0`），尽管 DB 里已有 35 条 finding。
- 说明 agent-body 的「最终消息前写结算文件」只在子代理正常收尾时生效。

**建议**
- agent-body 改为：**每完成一个类型**即写一份 `<subagent_id>-<type>-report.json`（一个类型一个文件），最后再写汇总；
- 编排器的 `--reports` 吸收逻辑按「类型级」而非「批次级」匹配；
- 若同一子代理被中断，已写出的类型级报告仍然可用 → 恢复时只补缺失类型。

**收益**：中断最大损失从「整批」降到「当前 1 个类型」。

---

### P0-3　三处统计口径不一致（需修 + 需回归测试）

同一物理量在三个时点给出三个数：

| 类型 | `scan` 摘要 `auto_confirmed_by_type` | mid-run `status` (`auto_confirmed` / `written_count`) | 终报 `confirmed / auto_confirmed` |
|---|---|---|---|
| divide-by-zero | **2** | **3** / **5**（候选只有 2） | 2 / **0** |
| integer-overflow | **3** | **5** / 3 | 8 / **5** |

`divide-by-zero` 候选数仅 2，但 mid-run `written_count=5`，此时 DB 中 `CWE-369` 行数为 **0**（AI 尚未写），无法自洽。

**可能原因（需核实）**：`status` 的计数可能包含 legacy/`suspected` 行，或统计的是「auto-confirm 决策数」而终报统计的是「UPSERT 后的行状态」（AI 写入同键时会把 auto-confirmed UPSERT 成 confirmed，导致 auto 计数回落）。

**建议**
- 三处统一从同一查询派生（`audits` 的 per-type 结果），`status` 只做薄封装；
- 增加回归测试：无 AI 写入时 `scan.auto_confirmed_by_type == audit.auto_confirmed`；有 AI UPSERT 时 `confirmed + dismissed(不落库) == candidate_count`；
- `written_count` 明确为「该类型 findings 行总数」还是「AI 写入数」，二选一并写进 schema 文档。

**收益**：汇总数字可被程序化校验，避免人工对账。

---

### P0-4　派发提示词冗余（编排器侧最大 token 开销）

**现象**
- 本会话共 19 次派发；每次提示词 1,100~1,500 tokens（含分类规则、hint 语义表、写入契约的整段复述），估算合计 **~25k tokens** 的输出。
- 这些规则与 `agent-body.md` + 各 `SKILL.md` 高度重复；子代理本就会加载 skill。

**建议**
- `agent-body.md` 固化：写入契约（MCP/CLI 二选一）、`finalize:false`、BINARY 裁决、预算、结构化报告字段、类型级结算文件；
- 派发只传增量：`types + candidate_counts + ranges + scan_id + scan_dir + (db/tmp 绝对路径)`，目标 **≤400 tokens/次**；
- 类型特化规则留在 skill，不再在提示词里复述（本次我对 9 个批次手写了大量重复规则）。

**收益（估算）**：省 ~17k tokens 编排输出；按常见生成速度约 30~60s。

---

### P1-5　批次未做「大 light 类型 + tiny 类型」打包

**现象**
- 首波：`dangerous-function`(39) 独占 1 批；`divide-by-zero`(2)+`double-free`(3)+`format-string`(1)+`hardcoded-secret`(2) 一批；`race`(3)+`signed`(1)+`sizeof`(1)+`unbounded`(1) 一批。
- heavy 规则只约束 `integer-overflow`/`argument-type`，`dangerous-function` 属 light，可与其他 light 类型合批。

**建议**
- 批容量配置补一条：**「light 类型填满 4 个；候选数 >30 的 light 类型可与 ≤3 个、每个 ≤3 候选的 tiny 类型合批」**；
- 本会话按此可 10 批 → **8 批**（首波）、恢复波 9 → **8 批**。

**收益（估算）**：少 1~2 次 spawn；对 10 批的量级约 5~10% 的 AI 阶段。

---

### P1-6　`SMALL_TYPE_SEQUENTIAL_THRESHOLD` 与强制并行冲突（同步宿主）

**现象**
- 规则 A：`type_count ≥ 4` → **禁止 SEQUENTIAL**（强制并行）。
- 规则 B：≤15 候选且非整函数嵌入的类型，编排器直判更便宜。
- 本次 10 个小类型（divide-by-zero、double-free、format-string、hardcoded-secret、race、signed-compare、sizeof-misuse、unbounded-length-copy、stack-address-escape、switch-fallthrough）共约 20 候选，仍走了子代理。
- 在 OpenCode / claude-cac 这类**同步 `task`** 宿主上，编排器无法在等待子代理时并行做自己的判定，「直判小类型」只能串行插入。

**建议**
- 明确优先级与适用宿主：
  - 同步宿主：优先采用 P1-5 的打包规则（把小类型塞进并行批次），**不**做编排器直判；
  - 异步宿主（官方 Claude Code / DSH）：允许编排器在等待通知时直判小类型；
- 在 Batch Capacity Configuration 中写死「同步宿主不适用 SMALL_TYPE_SEQUENTIAL_THRESHOLD，改用打包」。

**收益（估算）**：避免 5 次左右 spawn；行为可预测。

---

### P1-7　报告元数据 CWE 错标

**现象**：`report.md:68`

```
| path-traversal | CWE-732 | 7 | 1 |
```

`path-traversal` 的声明 CWE 是 **CWE-22**（`secguard types`），但报告取到了该类型某条 auto-confirmed 行（`pm_permission.c:2 pm01_chmod_literal`，`permission_setting` 子类）的 `CWE-732`。

**建议**
- Skill 行的 CWE 一律取自 `planner.VulnTypeSpec.CWE`（AGENTS.md 已规定单一真源）；
- `permission_setting`（CWE-732）等子类要么单列一个 skill 行，要么在属主类型下注明子类 CWE，不得覆盖属主 CWE。

**收益**：消除交付物元数据错误。

---

### P1-8　integer-overflow「整函数 Evidence」假设不成立

**现象**：子代理回执明确记录

> Integer-overflow Evidence `## Code Context` covered only lines 20-31, so `src/p8_value_analysis.c` was read (offset/limit)…

而批次容量配置把 `integer-overflow` 定义为「整函数嵌入（heavy），Evidence 为整个函数跨度」。

**影响**：heavy 定性影响合批规则（heavy + ≤1 light）与候选上限，假设失真会导致批次预算偏差（既可能过度保守，也可能在真正整函数时低估）。

**建议**
- 生成侧：对 `integer-overflow` 确定性输出「签名 → 候选」的整段跨度，并在单测中断言长度 > ±8 窗口；
- 若短函数本就只有 12 行，允许，但成本模型应按**实际字节数**而非类型名定价；
- 在 `_index.md` 图例中标注本候选的 Evidence 实际行数。

**收益**：成本模型可信，批次规划不靠猜。

---

### P1-9　divide-by-zero 图例与主流程规则冲突

**现象**
- `candidates/divide-by-zero/_index.md` 图例：「**EVERY shape — including `bare` and `field` — requires the ±8-line Code Context before confirming**」。
- 主流程提示：「a `divisor@bare` row is settled from the `Source` column alone (an unguarded plain divisor → `dismissed`) with **NO evidence-file open**」。

两者直接矛盾，子代理行为不确定（本次该类型候选仅 2 条，未暴露后果）。

**建议**：图例与提示从同一 `hint_tokens.go` 源生成（AGENTS.md 已要求），并加一致性测试（`TestVulnTypeSkillConsistency` 的同类守卫）。

---

### P2-10　空索引仍返回 `indexed: true`

`secguard_status` 首次返回 `indexed: true, files_indexed: 0`。建议增加 `state: empty|stale|ready`，`files_indexed==0` 或源文件 mtime 晚于 `sgre.db` 时不得返回 ready。

### P2-11　AI 耗时混入宿主空闲

`ai_duration_ms=579000` 从「scan 返回」算到「finalize」，包含模型切换的中断窗口。建议 `scan_runs` 增加 `ai_started_at` / `ai_finished_at` / `interrupt_ms`，并把宿主空闲单列（或由宿主上报），否则生产 AI 耗时口径系统性偏高。

### P2-12　整文件读取未标注

`null-deref` 子代理对 `p5_null_flow.c`、`p23_opaque_type_null.c` 做了整文件读取（自报 `source_reads: 3`，但为整文件）。按 F6 属「确认候选异常读源」边缘情形。建议结构化报告增加 `whole_file_reads: [file:line-range, reason]`，并规定整文件读必须在报告中显式说明理由。

---

## 4. 改进优先级与落地顺序

| 顺序 | 事项 | 类型 | 实施面 | 验证方式 |
|---|---|---|---|---|
| 1 | `candidate_verdicts` 表 + dismissed 落库 + `remaining` 输出 | 功能 | Go（db/cli/report）+ agent-body（写入契约） | 中断注入测试：杀掉子代理后 `status` 能准确报剩余 |
| 2 | 类型级 settlement 文件 | 功能/流程 | agent-body + `status --reports` 匹配逻辑 | 模拟中途 kill，检查 `.tmp` 有已完成类型的报告 |
| 3 | 统计口径统一 | 缺陷 | report/db/cli 共用查询 | 单测：scan ↔ audit 计数一致 |
| 4 | 派发提示词瘦身 | 性能 | `command-instructions.md` + agent-body | 统计下一轮派发 token（目标 ≤400/次） |
| 5 | 批次打包规则 | 性能 | Batch Capacity Configuration | 下一轮 spawn 数 ≤ ceil(light_types/4) + heavy_batches |
| 6 | 同步宿主小类型策略 | 流程 | 同上 | 文档 + 下一轮观测 |
| 7 | Skill 表 CWE 取自 VulnTypeSpec | 缺陷 | report | 断言 `path-traversal` 行显示 CWE-22 |
| 8 | integer-overflow Evidence 跨度 | 缺陷/模型 | planner + 测试 | Evidence 行数断言 |
| 9 | 图例一致性 | 缺陷 | hint_tokens 生成 | 新一代一致性测试 |
| 10 | status state 枚举 / 时间拆分 / 整文件读标注 | 体验 | cli + agent-body | 观测 |

---

## 5. 本轮已做对、不要改的地方

1. **二元裁决 + 只落 confirmed**：`result.sarif` 干净，`findings/` 199 个文件与 audit 完全一致。
2. **证据打开预算**：各类型 `evidence_opens ≤ 12`，无「不读即弃」；`unchecked-return` 的 `repo_greps=1` 未越界。
3. **子代理写 `finalize:false`、编排器单点 `--audit`**：避免重复渲染与 `ai_stage_status` 竞态。
4. **中断恢复以 DB 为准**：35 条已落库判定被吸收、按缺口精确重派，没有重复计分、没有陈旧行。
5. **`detector_errors`/`plan_errors` 为空**：检测器与规划器本轮零故障。
6. **Step 5.5 定点复核**：只对 CWE-457/134/190 这类「证明前提可能失真」的行对源，其余按预算标记未复核，成本可控。

---

## 6. 下轮验证清单（round2）

- [ ] 注入一次子代理中断，确认 `status --per-type` 可直接给出 `remaining`，且恢复无需读 `_index.md`
- [ ] 统计派发提示词 token，确认 ≤400/次
- [ ] 确认 spawn 数 ≤ 8（本样例规模）
- [ ] 断言 `report.md` 中 `path-traversal` 的 CWE 为 `CWE-22`
- [ ] 断言 integer-overflow Evidence 实际跨度与成本模型一致
- [ ] 对比 AI 耗时：目标从 579s 降到 420~480s（估算 15~25%）
- [ ] 确认 `scan` 摘要、`status`、`audit` 三处 `auto_confirmed` 一致

---

### 附：本轮关键产物

| 产物 | 路径 |
|---|---|
| 扫描报告（199 条明细） | `.codeagent/secguard-clang/scans/sc_2026-11-01_125551_a885a5/report.md` |
| SARIF | `.../result.sarif`（675 KB） |
| 逐条确认文件 | `.../findings/`（199 个） |
| 驳回台账 | `.../ai-dismissed.json`（48 条） |
| 数据库 | `.codeagent/secguard-clang/.sgre/sgre.db` |
