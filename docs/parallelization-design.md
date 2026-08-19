# SecGuard 扫描并行化设计方案

> 目标：把一次完整审计（以 cJSON 为例，99 文件 / 1001 函数）从 **~613s 降到 ~150s**（约 4 倍），
> 在保持分类结果一致的前提下，最大化利用多核与 agent 扇出。

---

## 1. 背景与耗时模型

round5（`2026-08-13_175351_da24`）的 `scan.log` 给出了精确的分阶段耗时：

| 阶段 | 耗时 | 占比 | 可并行 | 瓶颈 |
|---|---|---|---|---|
| index | 0.22s | <1% | 否 | — |
| call_graph | 3.9s | 1% | 否（有依赖） | — |
| data_flow | 10.2s | 2% | 否（有依赖） | — |
| **17 个 detector（串行）** | **177s** | 29% | ✅ | 单 detector 最长 27s |
| 14 个 plan（串行） | 20s | 3% | ✅ | 单个 ~1.7s |
| **AI 分类 85 个候选（串行）** | **~400s** | 65% | ✅ | 单 agent 串行读源/加载 skill |
| **合计** | **~613s** | 100% | | |

两个大头：
- **Go 侧**：detector 串行 177s（占 scan 总时长 190s 的 93%）。
- **Agent 侧**：AI 分类串行 ~400s（占整体 65%）。

结论：提速必须**同时打两层**——Go 侧并行 detector/plan，Agent 侧扇出 14 类型分类。

---

## 2. 总体方案（两层、两阶段）

```
Layer 1（Go 侧，进程内并行）        Layer 2（Agent 侧，跨进程扇出）
─────────────────────────────      ──────────────────────────────────
 index ──► call_graph ──► data_flow        prepare（一次）
               │                              │
               ▼                              ▼
    detectors（波次并行）            14 个并行子 agent，各管 1 个类型
               │                              │
               ▼                              ▼
       plan ×14（并行）              secguard_plan <type> + 分类 + 写回
               │
               ▼
      report.md / per-finding
```

- **Layer 1** 是纯 Go 改动，低风险，`secguard_scan` 对外行为不变，只是更快（190s → ~60s）。
- **Layer 2** 是编排改动，把分类从「1 个 agent 串行」改成「14 个 agent 并行」，是整体 4 倍提速的关键。
- 两层可**独立上线**：先 Layer 1（~23% 整体提速），再 Layer 2（~4 倍整体提速）。

---

## 3. 第一层：Go 侧并行（detector + plan）

### 3.1 Detector 依赖图（决定波次划分）

`internal/evidence/registry.go` 按注册顺序生成 17 个 detector。逐一核对了
`internal/evidence/*.go` 里对 `security_events` 的**读取**（跨 detector 依赖的唯一来源）：

- 唯一读取事件的是 **`interprocedural`**（`interprocedural.go` 通过 `ListEventsByType`
  读取 `DEREFERENCE` / `NULL_GUARD` / `NULL_VALUE`）。
- 其余 16 个 detector 只**写**自己的事件，不读别的 detector 的产物。

因此依赖图是单边的：

```
null_source ─┐
dereference  ┼──► interprocedural
null_guard   ┘
（其余 13 个 detector 独立）
```

**波次划分：**

| 波次 | detector | 各自耗时 | 墙钟目标 |
|---|---|---|---|
| 波 1（并行） | null_source, dereference, null_guard | 16.7s / 13.3s / 6.8s | ~17s |
| 波 2（并行） | interprocedural + 其余 13 个 | 最长 use_after_free 27s, memory_leak 26.5s, double_free 20.4s | ~27–45s（受核数限制） |

> 注：detector 都是 CPU 密集（AST 遍历 + 内存分析），实际加速比受机器核数约束。
> 波 2 有 14 个 detector 竞争 `GOMAXPROCS` 个核，现实预估 detector 段 ~45–60s（理论下限 27s），
> 约 **3 倍**提速，而非理想化的 6.5 倍。

### 3.2 改动点

**① `internal/parser/parser.go` — `ParseCached` 加锁**

当前 `cache map[string]*Tree` 与 `parsers map[string]*sitter.Parser` 无锁。并发 detector
会 race。改为 `sync.RWMutex`：
- 命中缓存 → `RLock` 读；
- 未命中 → `Lock` 填充，之后返回的 tree 只读（`Close` 已是 no-op，`CloseAll` 统一释放）。

**② `internal/db/connection.go` — 放开连接数 + busy_timeout**

当前 `db.SetMaxOpenConns(1)` 把所有 DB 读写串行成单连接，会吃掉并行收益。改为：
- `SetMaxOpenConns(N)`（N = `max(4, runtime.NumCPU())`）；
- DSN 追加 `_pragma=busy_timeout(5000)`（modernc.org/sqlite 语法，实现时核对）——
  已有 `journal_mode(WAL)`，WAL 下多读单写，detector 以读为主，写只在收尾 `InsertSecurityEvent`，
  写锁竞争可接受。

**③ `internal/evidence/registry.go` — `RunAllDetectors` 波次并行**

把串行 for 改成两波 goroutine 执行，用 `chan struct{}` 信号量把并发数限到 `GOMAXPROCS`。
波次归属不靠名字硬编码，推荐给 `Detector` 接口加一个可选方法：

```go
// 读取其它 detector 事件类型者实现；未实现视为无依赖，可入波 1。
type EventReader interface{ ReadEventTypes() []string }
```

runner 据此做简单的拓扑分组（当前只会分出两波，为未来更复杂依赖留扩展点）。

**④ `internal/cli/scan.go` — plan 循环并行**

14 个 `planner.Plan(ctx, vulnType)` 互不依赖（各自读 `security_events` + 写 `scan_stats`），
同样用 goroutine + 信号量并行，注意 `scan_stats` / `evidencePackages` 的结果要按类型归位（用
`sync.Mutex` 或每类型一个槽位写回）。

### 3.3 收益

| 段 | 串行 | 并行后 |
|---|---|---|
| detectors | 177s | ~45–60s |
| plan ×14 | 20s | ~2s |
| index + graph | 14s | 14s（不变） |
| **scan 合计** | **190s** | **~60–75s** |

---

## 4. 第二层：Agent 侧扇出（14 类型并行分类）

### 4.1 现状 vs 目标

**现状**：1 个 `security-auditor` 串行完成——`secguard_scan` → 读 report.md → 加载 **14 个**
skill → 读最多 10 个源文件 → 分类 **85 个候选** → `secguard_report` 一次写回。

**目标**：prepare 一次，然后 **14 个并行子 agent**，每个只负责 1 个类型：
加载 **1 个** skill、读 **1–2 个**源文件、分类 **≤30 个**候选、写回自己的 findings。

分类段从 ~400s 降到最长单个类型的墙钟（null-deref / uninit 这类大类型 ~60–90s）。

### 4.2 编排机制（三选一）

**方案 A：主 agent 一次性发 14 个并行 `task`（推荐先试）**

`/secguard` 命令（或新命令）指示主 agent：先跑一次 prepare，再**在同一条消息里发出 14 个并行
`task` 调用**，每个 `subagent_type=security-auditor`、prompt 限定单类型（走已有的 Filtered Workflow）。
依赖 OpenCode 主 agent 的并行 tool 执行能力——实现第一步就验证这一点。

**方案 B：编排子 agent 负责扇出（兜底）**

新增一个 `security-auditor-parallel` 子 agent，其 system prompt 明确「先 `secguard prepare`，
再发 14 个并行 `task`」。把扇出逻辑收进一个可复用的编排 agent，主 agent 只调它一次。

**方案 C：Go 侧命令行编排（进程级，非 LLM 扇出）**

新增 `secguard scan --parallel`：Go 进程内用 goroutine 跑 14 个 `plan` + **直接产出 14 份
待分类证据包**，agent 侧只做分类。这条把「并行」的确定部分（plan）下沉到 Go，agent 只保留
LLM 分类。可作为 Layer 1 的自然延伸，避免依赖 OpenCode 并行 task 的不确定性。

> 推荐顺序：**先 A（改动最小，验证 OpenCode 并行 task）→ 不行则 B → 想要确定性再上 C**。
> A/B/C 三者的分类 worker 都是 `security-auditor` 的 Filtered Workflow，只是扇出者不同。

### 4.3 改动点

1. **新增 `secguard prepare`**（或 `secguard detectors`）：从 `runScanCmd` 抽出
   `index + call_graph + data_flow + detectors` 这段，**不做 plan、不写 report**。这样
   14 个子 agent 各自跑 `secguard_plan <type>`（~1.7s），plan 只跑一次、且并行。
2. **`command-instructions.md` 增补并行模式**：`/secguard --parallel` 或 `/secguard-parallel`
   的编排指令（prepare 一次 + 14 并行 task）。
3. **子 agent prompt**：每个 task 的 prompt 只含「类型 + 目标路径 + scan_id/output_dir」，
   触发 Filtered Workflow。
4. **写回并发**：14 个子 agent 并行 `secguard_report` 写 findings，SQLite 单写会串行化，
   但每个只写几行，可接受；`audit-report.md` 由**最后一个**完成者（或主 agent 收尾）统一生成，
   避免 14 次互相覆盖。

### 4.4 收益

| 段 | 串行 | 并行后 |
|---|---|---|
| prepare（= Layer 1 的 scan 前段） | ~60–75s | ~60–75s |
| 14 类型分类 | ~400s | ~60–90s |
| **合计** | **~613s** | **~150–165s** |

---

## 5. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| `ParseCached` 并发 race | 崩溃/错误 AST | 加 `sync.RWMutex`（3.2 ①） |
| SQLite 单写锁竞争 | detector 写回串行 | WAL 已开 + `busy_timeout` + 写集中在收尾（3.2 ②） |
| 波次依赖漏判 | interprocedural 读到空表 → 漏报 | 波次拓扑分组 + 单测断言「interprocedural 在波 2」 |
| OpenCode 不真正并行 `task` | 分类仍串行 | 退到方案 B（编排 agent）或方案 C（Go 编排） |
| 14 子 agent 并发写 findings / audit-report | 覆盖或重复 | 单写者收尾生成 audit-report；findings 无唯一约束但按 (scan_id,type) 归位 |
| 结果非确定性 | 波 2 detector 依赖 CPU 调度顺序 | 检测结果只依赖「波 1 完成」，与波 2 内顺序无关，可复现 |

---

## 6. 分阶段实施计划

### 阶段 1（Layer 1，低风险，先合）
1. `parser.go` 加 `RWMutex`（+ 并发单测）。
2. `connection.go` 多连接 + busy_timeout。
3. `registry.go` `RunAllDetectors` 波次并行（+ `EventReader` 接口）。
4. `scan.go` plan 循环并行。
5. 验证：`go test ./...` + cJSON 全量 scan，对比 `scan.log` 的 detector/plan 段耗时与最终 findings 一致性。

### 阶段 2（Layer 2，编排，后合）
1. 抽出 `secguard prepare` 命令。
2. 验证 OpenCode 并行 `task` 能力（方案 A 探针）。
3. 增补 `command-instructions.md` 并行编排 + 子 agent 单类型 prompt。
4. 收尾 audit-report 单写者。
5. 验证：cJSON 全量审计墙钟从 ~613s → ~150s，findings 与串行基线一致。

### 里程碑
- **M1**：scan 190s → ~70s（Layer 1 完成）。
- **M2**：整体 613s → ~150s（Layer 2 完成）。

---

## 7. 验证与回滚

- **正确性**：并行版与串行版的 `security_events` 数量、`findings`（confirmed/suspected/dismissed）
  完全一致（用同一 cJSON 快照跑两遍 diff）。
- **性能**：`scan.log` 的 `phase timing` 已有打点，直接比对 detector_total / plan_* 段。
- **回滚**：Layer 1 用 `--parallel=false`（或环境变量）切回串行；Layer 2 保留原 `/secguard`
  串行路径不变。
