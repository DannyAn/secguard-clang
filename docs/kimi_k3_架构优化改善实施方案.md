# SecGuard-Clang 架构重构实施方案（kimi-k3，2026-10-23）

> **本文档是 `docs/kimi_k3_架构设计检视.md` 的落地实施方案**。目标读者是执行重构的 AI Agent（或工程师），读完本文档后应能**独立、按阶段、可回滚地**完成全部重构工作，无需回头追问方案作者。
>
> **工作模式**：本方案本身只做"设计 + 拆解"，**不直接改代码**；每个 Phase 由执行 Agent 按"Step 1..N"顺序落地，每 Phase 结束**必须先提交 commit 再开始下一个 Phase**。

---

## 0. 方案概览

### 0.1 目标

对应检视报告的三个用户痛点：

| 痛点 | 对应检视章节 | 本方案命中 Phase |
|---|---|---|
| 扫描速度无提升 | PERF-1 / PERF-2 / PERF-3 / PERF-4 | Phase 1 / Phase 13 / Phase 14 |
| 误报率高、准确度停滞 | ACC-1 / ACC-2 / ACC-3 / ACC-4 / ACC-5 | Phase 2 / Phase 4 / Phase 6 / Phase 10 / Phase 11 / Phase 12 |
| 架构演进成本随类型数线性增长 | DEBT-1..6 | Phase 3 / Phase 5 / Phase 7 / Phase 8 / Phase 9 |

### 0.2 范围与非目标

**范围内（本方案覆盖）**：
- 短期 S1/S2/S3/S4/S5/S6（对应检视 §六短期表）
- 中期 M1/M2/M3/M4/M5/M6/M7（对应检视 §六中期表）
- 中期 M8（增量扫描）只到 **graph 层增量** 为止，evidence/plan 层增量留作后续方案

**范围外（本方案不做，仅登记方向）**：
- 长期 L1（单遍 AST 遍历 + 访问者分发 detector V2 接口）——需在 M1 完成后另行立项
- 长期 L2（AI 举证"零阅读"目标）——依赖 Phase 6 与 Phase 10 完成后的实证数据
- 长期 L3（Infer 风格 compositional summary）——依赖 Phase 12/13 完成
- 新增任何 vuln type、修改任何 CWE 映射、改动 `findings` 表 schema、引入 DB migration
- 修改 `extension/` 下任何平台 wrapper（本方案纯 Go 侧重构）

### 0.3 总体节奏

| Phase | 名称 | 对应检视 | 预估工作量 | 风险 | 可独立 revert |
|---|---|---|---|---|---|
| 0 | 开工准备（分支、基线、守护） | — | 0.5 天 | 无 | — |
| 1 | S1：函数级 CFG 缓存 | PERF-1 | 2 天 | 低 | 是 |
| 2 | S3：confirmed 证明链机器守卫 | ACC-1 | 3 天 | 中 | 是 |
| 3 | S5：benchmark PR 级 CI | DEBT-6 | 1 天 | 低 | 是 |
| 4 | S2：apikb 函数分类集中 | ACC-4 | 3 天 | 中 | 是 |
| 5 | S6：config 显式告警 + 注入 | DEBT-5 | 1 天 | 低 | 是 |
| 6 | S4：Evidence Contract v2 全量推广 | ACC-3 | 5-8 天（分批） | 中 | 按子批 revert |
| 7 | M5：filter chain 声明式化 | DEBT-3 | 2 天 | 低 | 是 |
| 8 | M6：registry.go 拆分 | DEBT-1 | 3 天 | 低 | 是 |
| 9 | M7：Candidate/eventProps 分层 | DEBT-2 | 3-4 天 | 中 | 是 |
| 10 | M1：graph 语义查询服务 | ACC-2 | 5 天 | 高 | 是（双轨期） |
| 11 | M2：类型系统建模 | ACC-2 / ACC-5 | 5 天 | 高 | 是（双轨期） |
| 12 | M3：跨函数别名分析 | ACC-2 | 5 天 | 高 | 是（双轨期） |
| 13 | M4：通用函数 summary | ACC-2 | 4 天 | 中 | 是（双轨期） |
| 14 | M8（部分）：graph 层增量 | PERF-3 | 5-8 天 | 高 | 是（独立分支） |

**关键路径**：Phase 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 →（评估点 A）→ 10 → 11 → 12 → 13 →（评估点 B）→ 14。

**评估点 A**（Phase 9 完成后）：v0.9.9 + Phase 0-9 合入后应已达到"误报率显著下降、plan 阶段耗时下降 30%+、新增 vuln type 改动面收敛"的短期目标。是否继续推进 Phase 10-13 由用户根据实测数据决定。

**评估点 B**（Phase 13 完成后）：Phase 14（graph 层增量）是对性能的最后一击，但也是风险最高的一项。是否启动由用户单独决策，**默认不启动**。

### 0.4 feature 分支策略

- **主分支**：`main`（保持随时可发布）
- **总 feature 分支**：`feature/arch-refactor-2026q4`——Phase 0-9 全部在此分支上推进，Phase 9 完成且评估点 A 通过后合并回 main
- **子分支**（可选，用于高风险 Phase）：
  - `feature/arch-refactor-2026q4-m1-graph-query`（Phase 10）
  - `feature/arch-refactor-2026q4-m2-types`（Phase 11）
  - `feature/arch-refactor-2026q4-m3-alias`（Phase 12）
  - `feature/arch-refactor-2026q4-m4-summary`（Phase 13）
  - `feature/graph-incremental`（Phase 14，**独立分支**，不从 arch-refactor 派生）
- **合并纪律**：每个 Phase 内部的若干 commit 直接落在 feature 分支上；子分支在对应 Phase 完成后以 merge commit 形式合入总 feature 分支（不 squash，保留 Phase 内部历史）
- **打 tag 纪律**：**不在本 feature 分支上打任何 release tag**；发布仍走 main 分支 `v*` tag 触发 CI 的既有流程（AGENTS.md §Release Process）

---

## 1. 不可破坏的既有契约（红线）

以下任何一条在任一 Phase 被破坏，该 Phase 必须 revert：

1. **三层流水线**：indexer → graph → evidence → planner → agent → report 的方向不变；任何 Phase 不得让 planner 反过来调用 detector，也不得让 detector 写 findings。
2. **AI 研判边界**：`confirmed` 必须对应四类证明手段（CFG must / 区间常量 / 字面量 / 类型固有）之一；suspected/possible 全部交 AI；**不得引入新的 auto-confirm 类别而不登记**。
3. **数据模型四分层**：Layer 1（程序事实）/ Layer 2（语义图）/ Layer 3（security_events）/ Layer 4（findings）；skills 只做查询消费，不建表；dismissed 不持久化。
4. **`VulnTypeSpec.CWE` 是 CWE↔type 映射的唯一来源**；禁止在 report/db/cli/extension 任何位置硬编码平行 CWE map。
5. **`extension/shared/` 是 agent 行为唯一来源**；`.claude/` `.opencode/` 是生成产物，任何 Phase 不得直接编辑。
6. **`secguard report --write-json` 幂等 UPSERT**：`(scan_id, rule_id, file, line, function, variable)` 六元组作为 conflict key 的语义不得变更。
7. **`TestVulnTypeSkillConsistency` 必须全程绿**：detector 注册表 / planner registry / skills 目录三份名单 drift 则构建失败。
8. **24 个 vuln type 全量行为兼容**：重构完成后，对同一代码基、同一配置，`secguard scan` 的候选总数、auto-confirm 数、最终 findings 数必须满足 Phase 内规定的差集要求（默认双向差集为空；明确允许变化的 Phase 会在 §验收标准里写明方向）。
9. **nosqlite 子集绿**：`go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` 是底层防线，任何 Phase 不得打破。
10. **不引入 DB migration**：sgre DB 即建即用；任何 schema 变更必须通过"新建并列用一段双写期 + 旧字段下线"的方式完成，不得改既有列语义。

---

## 2. 全程验证协议（每个 Phase 必须执行）

### 2.1 构建与测试基线

每个 Phase 的**每个 commit 前**必须跑：

```bash
cd sgre
go build -buildvcs=false ./...
go test -buildvcs=false ./...
go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/
```

如 `GOCACHE` 不可写：`GOCACHE=$PWD/.tmpcache TMPDIR=$PWD/.tmpcache go build -buildvcs=false ./...`。

### 2.2 本地 CLI 构建（用于端到端验证）

```bash
cd sgre
CGO_ENABLED=1 GOFLAGS=-mod=mod go build -buildvcs=false -o ../bin/secguard ./cmd/secguard
```

### 2.3 benchmark A/B 干净目录协议（**强制**）

涉及 detector / filter / graph / registry 行为变化的 Phase（1、2、4、6、7、9、10、11、12、13、14），**每个 Phase 结束必须跑一次 A/B**：

```bash
# 准备工作目录
rm -rf /tmp/sgre-ab && mkdir -p /tmp/sgre-ab/{pre,post}
cp -r examples/c-vuln-benchmark/src /tmp/sgre-ab/pre/
cp -r examples/c-vuln-benchmark/src /tmp/sgre-ab/post/

# 构建 Phase 前的基线二进制（main 或 Phase 起点）
git stash  # 或切到基线 commit
cd sgre && go build -buildvcs=false -o /tmp/sgre-ab/secguard-pre ./cmd/secguard && cd ..
git stash pop

# 构建 Phase 后的当前二进制
cd sgre && go build -buildvcs=false -o /tmp/sgre-ab/secguard-post ./cmd/secguard && cd ..

# 双侧各自在干净目录扫描（独立 --db，避免 suppression index 污染）
cd /tmp/sgre-ab/pre  && /tmp/sgre-ab/secguard-pre  scan . --db /tmp/sgre-ab/pre/sgre.db
cd /tmp/sgre-ab/post && /tmp/sgre-ab/secguard-post scan . --db /tmp/sgre-ab/post/sgre.db

# 对比（差集必须为空，或严格符合 Phase 内声明的方向）
diff <(cd /tmp/sgre-ab/pre  && /tmp/sgre-ab/secguard-pre  report --db /tmp/sgre-ab/pre/sgre.db  | jq -S '.') \
     <(cd /tmp/sgre-ab/post && /tmp/sgre-ab/secguard-post report --db /tmp/sgre-ab/post/sgre.db | jq -S '.')
```

**红绿对照**：`no_finding` 用例对 suspected-tier 类型本地平凡通过，FP 抑制修复的红绿对照必须用 **candidates** 而不是 findings，控制组须与 `no_finding` 行间隔 > 3（参考 `benchmark_no_finding_suspected_tier_vacuous`）。

### 2.4 回归测试落点（**强制**）

每个 Phase 修复的缺陷或引入的行为变化，**必须**在以下三处至少一处留下回归：

1. `sgre/internal/<module>/zz_<feature>_test.go`（pinned 单测 / characterization test）
2. `sgre/testdata/tc<N>_<slug>.c`（end-to-end fixture）
3. `examples/c-vuln-benchmark/src/p<N>_<slug>.c` + `expected-results.json`（benchmark 回归）

fixture 规则：
- 复现用户报告的缺陷时**必须用原帖精确形态**（`fixture_use_exact_user_report_form`）
- 涉及安全函数变体时必须同时覆盖 `sprintf_s` / `snprintf_s` / `strcpy_s` 等（`user_company_safe_function_variants`）
- 涉及 taint 追踪的 TP fixture，污点源必须是**函数参数**，不能是局部变量（`tp_fixture_taint_needs_function_param`）

### 2.5 commit 边界纪律

- **一个 Phase 内部允许多个 commit**，但每个 commit 必须独立编译通过、独立跑过 §2.1 基线；
- **Phase 结束必须先 commit 再开始下一个 Phase**（`commit_before_next_task`）；
- **commit 粒度**：按逻辑边界拆分（如 Phase 6 应按 vuln type 分子批 commit，不要一个大 commit 改 20 个类型；也不要逐文件碎提交）；
- **commit message 格式**：`type(scope): subject`，type ∈ {`refactor`, `feat`, `fix`, `test`, `chore`, `docs`, `perf`}，scope 取模块名（`planner` / `evidence` / `graph` / `cli` / `apikb` / `config` / `benchmark` / `ci`）。

---

## 3. Phase 0：开工准备

### 3.1 目标

把重构的"跑道"铺好：feature 分支、基线数据采集、守护用例体检、工作目录约定。

### 3.2 前置条件

- `main` 分支是绿的（`go build` + `go test` + nosqlite 子集全过）
- 工作区 clean（`git status` 无未提交改动）

### 3.3 实施步骤

**Step 1** 拉分支：

```bash
git checkout main
git pull origin main
git checkout -b feature/arch-refactor-2026q4
git push -u origin feature/arch-refactor-2026q4
```

**Step 2** 采集基线数据，落盘到 `docs/arch-refactor-baseline-2026q4.md`：

```bash
# 在 main 分支的干净目录跑
git checkout main
rm -rf /tmp/sgre-baseline && mkdir -p /tmp/sgre-baseline
cp -r examples/c-vuln-benchmark/src /tmp/sgre-baseline/
cd sgre && go build -buildvcs=false -o /tmp/sgre-baseline/secguard-baseline ./cmd/secguard && cd ..
cd /tmp/sgre-baseline && ./secguard-baseline scan . --db /tmp/sgre-baseline/sgre.db 2>&1 | tee /tmp/sgre-baseline/scan.log
./secguard-baseline metrics --db /tmp/sgre-baseline/sgre.db > /tmp/sgre-baseline/metrics.json
./secguard-baseline report --db /tmp/sgre-baseline/sgre.db > /tmp/sgre-baseline/findings.json
```

基线文档需包含：`scan_runs` 表的 `index_ms` / `graph_ms` / `detectors_ms` / `plan_ms` / `total_ms`、24 个 vuln type 的 `seed_count` / `final_count` / `auto_confirmed_count`、benchmark 的 TP/FP/FN 计数。

**Step 3** 守护用例体检：

```bash
cd sgre
go test -buildvcs=false -run TestConfirmedTierPolicy ./internal/planner/
go test -buildvcs=false -run TestVulnTypeSkillConsistency ./internal/skills/
go test -buildvcs=false -run TestDeclarationFactInvariance ./internal/repofacts/
```

三个守卫全部绿才允许进入 Phase 1。任何一个红，先修复再开工（这是历史回归守卫，不属于本方案范围）。

**Step 4** 在 `docs/arch-refactor-2026q4-progress.md` 建立进度追踪表（按 §20 模板初始化）。

### 3.4 验收标准

- [ ] `feature/arch-refactor-2026q4` 分支已推送
- [ ] `docs/arch-refactor-baseline-2026q4.md` 已落盘且包含完整基线数据
- [ ] 三个守护测试全绿
- [ ] `docs/arch-refactor-2026q4-progress.md` 已初始化

### 3.5 Commit 边界

1 个 commit：`chore(arch): bootstrap arch-refactor-2026q4 branch with baseline`

### 3.6 回滚预案

`git checkout main && git branch -D feature/arch-refactor-2026q4`。

---

## 4. Phase 1：S1 函数级 CFG 缓存

### 4.1 目标

引入**进程内函数级 `*graph.StmtCFG` 缓存**，同一函数在一次扫描中只构建一次 CFG，被所有 detector 与 filter 共享。对应检视 §PERF-1。

### 4.2 对应检视项

PERF-1：`BuildStmtCFG` 被 14 处独立调用，redis 规模下 plan + evidence 阶段浪费 60s+。

### 4.3 前置条件

Phase 0 完成。

### 4.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/graph/control_flow.go` | 新增 | 暴露 `CFGCache` 类型 |
| `sgre/internal/graph/cfg_cache.go`（新建） | 新增 | 缓存主体，含 mutex + map |
| `sgre/internal/planner/planner.go` | 修改 | `Planner` struct 增加 `cfgCache` 字段 |
| `sgre/internal/planner/null_flow.go` | 修改 | `flowAnalyzer` 持有 cache 引用 |
| `sgre/internal/planner/range_flow.go` | 修改 | `analyzeRangesWithCalls` 走 cache |
| `sgre/internal/planner/filter_*.go`（7 处 `BuildStmtCFG` 调用点） | 修改 | 统一从 `planner.Planner` 拿 cache |
| `sgre/internal/evidence/detector.go` | 修改 | 在 `Detector` 共享 context（新建）里放 cache |
| `sgre/internal/evidence/memory_leak.go` / `resource_leak.go` / `use_after_free.go` / `uninit_variable.go` / `race_condition.go` / `free_summary.go` | 修改 | 6 处 `BuildStmtCFG` 调用点走 cache |
| `sgre/internal/graph/cfg_cache_test.go`（新建） | 新增 | 缓存命中/穿透/并发安全测试 |
| `sgre/internal/planner/zz_cfg_cache_integration_test.go`（新建） | 新增 | pinned：同一函数被两个 filter 消费时 `BuildStmtCFG` 只调用一次 |

### 4.5 实施步骤

**Step 1** 在 `sgre/internal/graph/cfg_cache.go` 新建缓存类型：

```go
package graph

// 公开给 planner/evidence 使用
type CFGCache struct {
    // 内部 sync.RWMutex + map[int64]*StmtCFG
    // key = function ID（db.Function.ID）
}

func NewCFGCache() *CFGCache
// GetOrBuild 命中返回缓存，未命中调 builder 构建并写入
// builder 签名：func() *StmtCFG
func (c *CFGCache) GetOrBuild(fnID int64, builder func() *StmtCFG) *StmtCFG
// Invalidate 一个函数（增量扫描用，本 Phase 仅预留接口）
func (c *CFGCache) Invalidate(fnID int64)
// Reset 清空（跨扫描复用进程时用）
func (c *CFGCache) Reset()
```

约束：
- 缓存 key 用 `db.Function.ID` 而非 `(fileID, startLine)`，因为前者单调稳定；
- `builder` 返回 nil 时**不写入**缓存（避免缓存 nil 后无法区分"未构建"与"无函数体"）；
- 不加 LRU——一次扫描内函数数量有界（最大场景 ~50K 函数），全量驻留可接受；
- 内部并发安全（`sync.RWMutex`），允许 planner 8 并发 + evidence 8 并发同时访问。

**Step 2** Planner 持有 cache：

`sgre/internal/planner/planner.go` 的 `Planner` struct 增加 `cfgCache *graph.CFGCache` 字段，`NewPlanner` 初始化。对照 `taintCache` / `macro` / `callReachCache` 的既有模式（`planner.go:20-40`）。

**Step 3** Planner 暴露 helper：

```go
// planner.go
func (p *Planner) StmtCFGFor(fn *db.Function, body parser.Node) *graph.StmtCFG {
    return p.cfgCache.GetOrBuild(fn.ID, func() *graph.StmtCFG {
        return graph.BuildStmtCFG(body, fn.EndLine)
    })
}
```

**Step 4** 把 planner 层 7 处 `BuildStmtCFG` 调用改为走 `p.StmtCFGFor(...)`：

具体调用点（检视 §PERF-1 已列）：
- `filter_contract_gap.go:122`
- `filter_uninit_flow.go:223`
- `filter_uninit_heapstruct.go:70`
- `null_flow.go:305` 与 `null_flow.go:326`（两处，`analyzeFlow` 与 `analyzeFlowMust` 共享 cache）
- `range_flow.go:160`

`null_flow.go` 的 `flowAnalyzer` 需要新增字段 `cfgCache *graph.CFGCache`，由 `newFlowAnalyzer` 注入。`analyzeFlow` / `analyzeFlowMust` 都改从 cache 取。

**Step 5** evidence 层共享 cache：

evidence 层没有现成的"Planner"角色。在 `evidence/detector.go` 新建 `SharedContext`：

```go
// evidence/detector.go
type SharedContext struct {
    Store    db.Store
    Parser   *parser.Parser
    Logger   *log.Logger
    CFGCache *graph.CFGCache
}

// DetectorFactory 签名扩展（兼容旧签名，另加 V2）：
type DetectorFactoryV2 func(sc *SharedContext) Detector
```

`RunAllDetectors` 创建一份 `SharedContext`（含一份 `CFGCache`），传给所有 detector factory。`evidence/registry.go` 的 32 个 `RegisterDetector` 调用点同步改签名。

`cli/pipeline.go:163` `evidence.RunAllDetectors(ctx, store, p, logger)` 这一处**不动签名**，内部新建 `SharedContext` 即可。

**Step 6** 把 evidence 层 6 处 `BuildStmtCFG` 调用改为 `sc.CFGCache.GetOrBuild(...)`：

- `evidence/free_summary.go:114/208`
- `evidence/memory_leak.go:64`
- `evidence/resource_leak.go:51`
- `evidence/uninit_variable.go:451`
- `evidence/use_after_free.go:64`
- `evidence/race_condition.go:578`

**Step 7** 关键约束：planner 的 `CFGCache` 与 evidence 的 `CFGCache` 是**同一个实例**——由 `cli/pipeline.go:runPipeline` 创建，**同时**传给 `evidence.RunAllDetectors` 与 `planner.NewPlanner`。这是性能收益的关键（detector 阶段构建的 CFG 在 plan 阶段直接命中）。

修改 `cli/pipeline.go`：

```go
// runPipeline 内，在 detector 阶段前
cfgCache := graph.NewCFGCache()
// 传给 evidence
detectorErrors := evidence.RunAllDetectorsWithCache(ctx, store, p, logger, cfgCache)
// 传给 planner
pl := planner.NewPlannerWithCache(store, p, logger, cfgCache)
```

为向后兼容，保留 `RunAllDetectors(ctx, store, p, logger)` 与 `NewPlanner(store, p, logger)` 旧签名（内部各自新建一份 cache），新增 `RunAllDetectorsWithCache` / `NewPlannerWithCache`。**只允许 `runPipeline` 使用带 cache 的新签名**，其他调用方（单测）默认走旧签名。

**Step 8** 单测：

- `graph/cfg_cache_test.go`：并发读写、命中穿透、Invalidate、Reset；
- `planner/zz_cfg_cache_integration_test.go`：起一个 detector + 两个 filter 的小型 fixture，通过计数器断言 `graph.BuildStmtCFG` 实际被调用次数 = 不同函数数，而非 `不同函数数 × 消费者数`。

**Step 9** 端到端验证（§2.2 + §2.3）：基准扫描 redis-like 大规模 fixture（`testdata/perf/large_codebase`），对比 `detectors_ms` 与 `plan_ms` 与基线文档。

### 4.6 验收标准

- [ ] §2.1 三条命令全绿
- [ ] `go test -buildvcs=false -run TestCFGCache ./internal/graph/` 绿
- [ ] `go test -buildvcs=false -run TestStmtCFGSharedAcrossFilters ./internal/planner/` 绿
- [ ] benchmark A/B（§2.3）候选与 findings 双向差集为空
- [ ] `scan_runs.detectors_ms` 与 `plan_ms` 相比基线**至少一项下降 ≥ 20%**（redis 规模 fixture）；若未达成，在 commit message 里说明原因并经用户确认
- [ ] 24 个 vuln type 的 `seed_count` / `final_count` / `auto_confirmed_count` 与基线完全一致

### 4.7 回归测试落点

- `sgre/internal/graph/cfg_cache_test.go`（新建）
- `sgre/internal/planner/zz_cfg_cache_integration_test.go`（新建，pinned）

### 4.8 Commit 边界

3 个 commit：
1. `feat(graph): add CFGCache for per-function statement CFG reuse`
2. `refactor(evidence,planner): route BuildStmtCFG through the shared CFGCache`
3. `test(planner): pin CFG sharing across filters (zz_cfg_cache_integration_test)`

### 4.9 回滚预案

`git revert` 三个 commit，恢复 `BuildStmtCFG` 直接调用。缓存是纯加法（不改判定语义），revert 安全。

### 4.10 完成定义（DoD）

§4.6 全部勾选 + 3 个 commit 已推送 + Phase 1 在进度表标 done。

---

## 5. Phase 2：S3 confirmed 证明链机器守卫

### 5.1 目标

把 `TestConfirmedTierPolicy` 从"只守卫静态 confirmed 集合"扩展到"**同时守卫所有动态升级路径**"，任何 filter 在任何条件下把候选升级为 confirmed 都必须登记证明手段。对应检视 §ACC-1。

### 5.2 对应检视项

ACC-1：confirmed 精准性靠单点测试兜底；buffer-overflow / divide-by-zero / uninit / unchecked-return 历史上出现过 confirmed 违规（BO-04 / DBZ-01/02/03 / CR-01/02/03 / UN-09）。

### 5.3 前置条件

Phase 1 完成（非强依赖，但推荐——后续 Phase 都跑在更快基线上）。

### 5.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/planner/proof_class.go`（新建） | 新增 | `ProofClass` 枚举 + `Proof` 结构体 |
| `sgre/internal/planner/filter.go` | 修改 | `Filter` 接口可选实现 `ProofRegistrar` |
| `sgre/internal/planner/filter_nullable_source.go` | 修改 | 登记动态升级证明类别 |
| `sgre/internal/planner/filter_lifetime.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_double_free.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_uninit_flow.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_range.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_range_oob.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_int_overflow.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_taint_source.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_return_check.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_lock_order.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_shared_access.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_contract_gap.go` | 修改 | 同上 |
| `sgre/internal/planner/filter_ownership.go`（`LeakProofFilter`） | 修改 | 同上 |
| `sgre/internal/planner/filter_extended.go`（`HardcodedSecretProofFilter`） | 修改 | 同上 |
| `sgre/internal/planner/zz_ai_judgment_boundary_test.go` | 修改 | 新增 `TestDynamicConfirmedUpgradesRegistered` |
| `AI_JUDGMENT_BOUNDARY.md` | 修改 | 补充"动态升级证明登记"章节 |

### 5.5 实施步骤

**Step 1** 定义证明分类与证据结构：

```go
// planner/proof_class.go
package planner

// ProofClass 对应 AI_JUDGMENT_BOUNDARY.md 的四类证明手段
type ProofClass string

const (
    ProofClassCFGMustDataflow ProofClass = "cfg-must-dataflow"
    ProofClassInterval        ProofClass = "interval-or-const-fold"
    ProofClassLiteral         ProofClass = "literal"
    ProofClassTypeInherent    ProofClass = "type-inherent"
)

// Proof 是一条 confirmed 决策的可追溯证据
type Proof struct {
    Class    ProofClass // 证明类别
    Rule     string     // 简短规则名（如 "must-null-on-all-paths"）
    Evidence string     // 人读证据描述（含 file:line 引用）
    TestRef  string     // 覆盖此证明路径的 Go 测试名（如 TestNullableSourceFilter_MustNull）
}
```

**Step 2** 定义 `ProofRegistrar` 接口：

```go
// planner/filter.go
// ProofRegistrar 是可选接口：任何会把候选升级为 confirmed 的 Filter 必须实现。
type ProofRegistrar interface {
    // DeclaredProofs 返回此 filter 所有可能升级 confirmed 的证明类别。
    // 返回空 slice 表示该 filter 不做 confirmed 升级。
    DeclaredProofs() []Proof
}
```

**Step 3** 审计现有 filter，为每个会升级 confirmed 的 filter 补 `DeclaredProofs()`：

对 14 个 filter 逐一审计（用 `grep -n '"confirmed"' sgre/internal/planner/filter_*.go` 定位升级点）：

| Filter | 升级点（示例行号） | 证明类别 | 规则名 |
|---|---|---|---|
| `NullableSourceFilter` | has_definite_null 升级 | `cfg-must-dataflow` | `must-null-on-all-paths` |
| `LifetimeFilter` | must freed | `cfg-must-dataflow` | `must-freed-on-all-paths` |
| `DoubleFreeFilter` | must double free | `cfg-must-dataflow` | `must-double-free-on-all-paths` |
| `DefiniteInitFilter` | must uninit | `cfg-must-dataflow` | `must-uninit-on-all-paths` |
| `RangeFilter` | divisor interval = [0,0] | `interval-or-const-fold` | `divisor-always-zero` |
| `RangeOOBFilter` | index lo >= capacity | `interval-or-const-fold` | `index-past-capacity` |
| `IntOverflowGuardFilter` | literal overflow | `interval-or-const-fold` | `constant-overflow` |
| `TaintSourceFilter` | taint reaches sink | `cfg-must-dataflow` | `taint-reaches-sink-on-all-paths` |
| `ReturnCheckFilter` | callee failure contract known + unchecked | `type-inherent` | `known-failure-contract-unchecked` |
| `LockOrderFilter` | cycle in LOCK_ORDER graph | `cfg-must-dataflow` | `lock-order-cycle` |
| `SharedAccessFilter` | same global write in two threads | `cfg-must-dataflow` | `shared-global-write-race` |
| `ContractGapFilter` | （审计后确定） | 按审计结果 | 按审计结果 |
| `LeakProofFilter` | no release/escape/transfer on any path | `cfg-must-dataflow` | `definite-leak-no-release` |
| `HardcodedSecretProofFilter` | value itself secret-shaped | `literal` | `secret-shaped-literal` |

每个 filter 在 struct 初始化时返回对应的 `[]Proof`，`TestRef` 必须真实存在（用 `go test -run <TestRef>` 能跑到）。

**Step 4** 在 `zz_ai_judgment_boundary_test.go` 新增 `TestDynamicConfirmedUpgradesRegistered`：

```go
func TestDynamicConfirmedUpgradesRegistered(t *testing.T) {
    // 1. 枚举 planner 包内所有 Filter 实现
    // 2. 对每个 filter，若其 Apply 中含 `SuspicionLevel = "confirmed"` 赋值
    //    （AST 扫描 go/parser 包内源码，或用约定的 marker 注释），
    //    断言该 filter 实现了 ProofRegistrar 且 DeclaredProofs 非空
    // 3. 断言每个 Proof.TestRef 在 *_test.go 中真实存在
    // 4. 断言每个 Proof.Class 是四类合法证明手段之一
}
```

实现方式二选一（执行 Agent 自行选择，方案不规定）：
- **marker 注释法**：在 filter 源码的 `SuspicionLevel = "confirmed"` 行上方必须写 `// proof: <class>` 注释，测试扫描源码提取并断言与 `DeclaredProofs` 一致；
- **AST 扫描法**：测试用 `go/ast` 解析 `filter_*.go`，定位 `SuspicionLevel = "confirmed"` 赋值点，与 `DeclaredProofs` 对账。

推荐 marker 注释法（更简单、更易审计）。

**Step 5** 更新 `AI_JUDGMENT_BOUNDARY.md`：

在"机器守则"一节追加：

```markdown
### 动态升级登记（v0.10.0 起）

任何 filter 在 `Apply` 中把候选升级为 `confirmed` 都必须：

1. 在该 filter 上实现 `ProofRegistrar` 接口（`DeclaredProofs() []Proof`），
   声明其使用的证明类别与规则；
2. `Proof.TestRef` 必须指向一个真实存在的 Go 测试；
3. `TestDynamicConfirmedUpgradesRegistered` 会扫描所有 filter 并断言此契约；
   未登记的升级路径会导致构建失败。
```

**Step 6** 对历史违规做补偿性回查：

用 `git log --all --oneline -S 'SuspicionLevel = "confirmed"'` 找出所有历史上的 confirmed 升级点，对照本 Phase 登记表补齐。若发现某升级路径**无法**映射到四类证明手段之一，**默认行为是降级为 suspected**（并在 commit message 说明），**不得保留"无证明 confirmed"**。

### 5.6 验收标准

- [ ] §2.1 三条命令全绿
- [ ] `TestDynamicConfirmedUpgradesRegistered` 存在且绿
- [ ] `TestConfirmedTierPolicy` 原有断言不破坏
- [ ] 14 个会升级 confirmed 的 filter 全部实现 `ProofRegistrar`
- [ ] `AI_JUDGMENT_BOUNDARY.md` 已补充"动态升级登记"章节
- [ ] benchmark A/B 差集为空（若 Step 6 降级了任何"无证明 confirmed"，则需要在 expected-results.json 中同步，并作为独立 commit）
- [ ] `grep -rn '"confirmed"' sgre/internal/planner/filter_*.go | grep -v 'proof:'` 为空（所有升级点都有 proof marker）

### 5.7 回归测试落点

- `sgre/internal/planner/zz_ai_judgment_boundary_test.go` 新增 `TestDynamicConfirmedUpgradesRegistered`
- 若 Step 6 有降级，对应 vuln type 的 `zz_<type>_proof_demotion_test.go`

### 5.8 Commit 边界

3 个 commit：
1. `feat(planner): ProofClass + ProofRegistrar interface`
2. `refactor(planner): register DeclaredProofs on all 14 confirmed-upgrading filters`
3. `test(planner): TestDynamicConfirmedUpgradesRegistered machine guard`
4. （可选）`fix(planner): demote <type>/<filter> unproven confirmed to suspected`

### 5.9 回滚预案

`git revert` 全部 commit。`ProofRegistrar` 是纯加法接口，revert 后 filter 不再声明证明但功能不变；若 revert 包含 Step 6 的降级，需要手动恢复预期候选数。

### 5.10 DoD

§5.6 全部勾选 + commit 推送 + 进度表更新。

---

## 6. Phase 3：S5 benchmark PR 级 CI

### 6.1 目标

把 `examples/c-vuln-benchmark` 的 ground truth 校验从"release 时手动跑"提前到"PR 自动跑"，防止 IO-21 式腐烂（单测与 benchmark ground truth 矛盾无人察觉）。对应检视 §DEBT-6。

### 6.2 对应检视项

DEBT-6：benchmark 无 PR 级 CI，ground truth 易腐烂（IO-21 实例）。

### 6.3 前置条件

无（可与 Phase 1/2 并行推进）。

### 6.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `.github/workflows/pr-benchmark.yml`（新建） | 新增 | PR 级 CI 工作流 |
| `examples/c-vuln-benchmark/scripts/validate-benchmark.py` | 修改（若需） | 确保退出码与输出适合 CI 消费 |
| `examples/c-vuln-benchmark/scripts/build-secguard.sh`（新建，可选） | 新增 | CI 专用的二进制构建脚本 |
| `docs/benchmark-ci.md`（新建） | 新增 | 使用文档：CI 红时如何本地复现 |

### 6.5 实施步骤

**Step 1** 审视 `validate-benchmark.py`：

```bash
ls examples/c-vuln-benchmark/scripts/
python3 examples/c-vuln-benchmark/scripts/validate-benchmark.py --help
```

确认其：
- 接受 `--db` / `--scan-id` / `--expected` 参数
- 退出码：0 = 全过，1 = 有 mismatch
- 输出机器可读（JSON 或 junit XML）

若不满足，修改使其满足（单独 commit）。

**Step 2** 新建 `.github/workflows/pr-benchmark.yml`：

```yaml
name: pr-benchmark

on:
  pull_request:
    paths:
      - 'sgre/**'
      - 'examples/c-vuln-benchmark/**'

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.25'
      - name: Install tree-sitter-cli
        run: go install github.com/tree-sitter/go-tree-sitter@latest || true
      - name: Build secguard
        working-directory: sgre
        run: |
          mkdir -p .tmpcache
          GOCACHE=$PWD/.tmpcache CGO_ENABLED=1 go build -buildvcs=false -o ../bin/secguard ./cmd/secguard
      - name: Scan benchmark
        run: |
          rm -rf /tmp/bench && mkdir -p /tmp/bench
          cp -r examples/c-vuln-benchmark/src /tmp/bench/
          cd /tmp/bench
          $GITHUB_WORKSPACE/bin/secguard scan . --db /tmp/bench/sgre.db
      - name: Validate against ground truth
        run: |
          python3 examples/c-vuln-benchmark/scripts/validate-benchmark.py \
            --db /tmp/bench/sgre.db \
            --expected examples/c-vuln-benchmark/expected-results.json
```

**Step 3** 验证 CI 在 Phase 3 自己的 PR 上能跑通（先用一个 dummy PR 触发，确认红绿行为符合预期）。

**Step 4** 写 `docs/benchmark-ci.md`：说明 CI 红时本地复现步骤（`git checkout <pr-branch>` → 构建 → `cd /tmp/bench && ... scan` → `validate-benchmark.py`）。

**Step 5** 顺手处理 IO-21 遗留：

`examples/c-vuln-benchmark/expected-results.json` 的 `P8-04` / `P8-05` 与 `sgre/internal/evidence/value_analysis_size_test.go` + `sgre/testdata/tc66_value_analysis_size.c` 目前矛盾（记忆 `integer_overflow_detection_defects.md` §IO-21）。

执行 Agent 在 Phase 3 内**必须**裁定这一对用例的权威期望：
- 运行当前 CLI 二进制扫描 `tc66_value_analysis_size.c`，记录实际行为；
- 若实际行为与单测一致（`malloc(n+1)` / `malloc(n*4)` 不报），把 benchmark 的 `P8-04` / `P8-05` 从 `expect: finding` 改为 `expect: no_finding`，并加 `known_issue` 字段说明历史变迁；
- 若实际行为与 benchmark 一致，反过来改单测；
- **二选一，不允许继续矛盾**。

### 6.6 验收标准

- [ ] `.github/workflows/pr-benchmark.yml` 存在且语法正确（`actionlint` 通过或人工 review）
- [ ] 在 Phase 3 的 PR 上 CI 实际跑通
- [ ] IO-21 矛盾已裁定并同步两侧
- [ ] `docs/benchmark-ci.md` 存在
- [ ] §2.1 三条命令全绿

### 6.7 回归测试落点

CI 本身就是回归。同时 `P8-04` / `P8-05` 的裁定结果要落进 `expected-results.json`。

### 6.8 Commit 边界

2-3 个 commit：
1. `ci(benchmark): add pr-benchmark.yml workflow`
2. `fix(benchmark): resolve IO-21 ground truth drift for P8-04/P8-05`
3. `docs(benchmark): document PR CI usage`

### 6.9 回滚预案

删除 `.github/workflows/pr-benchmark.yml`；IO-21 的裁定 commit 单独 revert。

### 6.10 DoD

§6.6 全部勾选 + CI 在 PR 上跑过一次 + commit 推送。

---

## 7. Phase 4：S2 apikb 函数分类集中

### 7.1 目标

把分散在 evidence/planner 各处的 `strings.Contains(name, "alloc")`、`strings.Contains(name, "free")`、类似的函数名启发式判定，集中收敛到 `sgre/internal/apikb/classify.go`，对外暴露三态查询（Yes/No/Unknown）。对应检视 §ACC-4。

### 7.2 对应检视项

ACC-4：文本子串启发式在 detector 间扩散，跨类型语义互相污染（ML-08/10、IO 相关、BO-12）。

### 7.3 前置条件

Phase 3 完成（CI 保护已就位）。

### 7.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/apikb/classify.go`（新建） | 新增 | 分类函数集中地 |
| `sgre/internal/apikb/classify_test.go`（新建） | 新增 | 表驱动单测 |
| `sgre/internal/apikb/external_api.go` | 修改 | 把 `IsDeclaredAllocator` 等已有查询迁移到 classify.go 或与之对齐 |
| `sgre/internal/evidence/memory_leak.go` | 修改 | 移除本地 `strings.Contains(name, "alloc")` |
| `sgre/internal/evidence/integer_overflow.go` | 修改 | `isSizeFunction` 改为走 apikb |
| `sgre/internal/evidence/buffer_overflow.go` | 修改 | `BoundedCopyFunctions` 判定改为走 apikb |
| `sgre/internal/evidence/resource_leak.go` | 修改 | 同上 |
| `sgre/internal/evidence/use_after_free.go` / `double_free.go` | 修改 | 释放函数判定走 apikb |
| `sgre/internal/evidence/unchecked_return.go` | 修改 | allocator 判定走 apikb |
| `sgre/internal/planner/filter_return_check.go` | 修改 | 同上 |

### 7.5 实施步骤

**Step 1** 审计现有启发式判定：

```bash
grep -rn 'strings\.Contains.*name.*"' sgre/internal/evidence/ sgre/internal/planner/ | grep -v _test.go
grep -rn 'func is[A-Z]' sgre/internal/evidence/ sgre/internal/planner/ | grep -v _test.go
```

产出审计清单 `docs/arch-refactor-apikb-audit.md`，逐条列出：
- 位置（file:line）
- 当前判定逻辑
- 服务的 detector / filter
- 目标分类（allocator / deallocator / bounded-copy / format / safe / ownership-transfer / guard / iterator / ...）
- 当前是 Yes-only 还是三态

**Step 2** 设计 `classify.go` 公开接口：

```go
// apikb/classify.go
package apikb

// Tri 三态判定
type Tri int
const (
    TriUnknown Tri = iota  // 证据不足，交 AI
    TriYes
    TriNo
)

// 查询接口（仅示例，执行 Agent 按审计清单补全）：
func IsAllocator(name string) Tri
func IsDeallocator(name string) Tri
func IsBoundedCopy(name string) Tri
func IsFormatFunction(name string) Tri
func IsSafeFunction(name string) Tri        // memcpy_s / strcpy_s / ...
func IsOwnershipTransfer(name string) Tri
func IsGuard(name string) Tri               // *_CHECK / *_ASSERT / ...
func IsIterator(name string) Tri
func IsOutputParamAllocator(name string) Tri
```

每个函数内部按以下优先级判：
1. 精确表（`config.Load().Allocators()` / `Deallocators()` 等已有 config 驱动表）→ Yes
2. 内置精确表（libc 标准函数）→ Yes
3. 内置**反**表（`dealloc` / `alloc_stats` / `realloc_stats` 等已知非 allocator）→ No
4. 前缀/后缀启发式（`*_new` / `*_dup` / `alloc_*`）→ Unknown
5. 默认 → Unknown

**严禁**：`return strings.Contains(name, "alloc")` 这种直接 Yes。

**Step 3** 把 `apikb/external_api.go` 的既有 `IsDeclaredAllocator` / `IsDeclaredDeallocator` / `IsKnownNullableReturn` / `IsEscapeFunction` 迁移/对齐到 `classify.go`——保留旧符号作为 wrapper 以保持外部调用兼容，内部全部走新三态。

**Step 4** 逐个 detector/filter 替换本地启发式：

以 `memory_leak.go` 为例：

```go
// 旧：
if strings.Contains(calleeName, "alloc") { ... }

// 新：
switch apikb.IsAllocator(calleeName) {
case apikb.TriYes:
    // 原 Yes 分支
case apikb.TriNo:
    // 明确 No（已知非 allocator）——跳过
case apikb.TriUnknown:
    // 证据不足——发 suspected 候选（原逻辑可能直接当 Yes 处理，改为 Unknown 更保守）
}
```

**注意**：从"启发式 Yes"改为"Unknown 发 suspected"会**改变候选数量**（通常会减少误报，但也可能增加 suspected）。每个替换点都要在 commit message 说明预期变化方向，并在 §2.3 A/B 验证中确认。

**Step 5** 补齐 `classify_test.go` 表驱动单测，至少覆盖：
- 每个查询的 Yes / No / Unknown 至少 3 个用例
- 反表用例（`dealloc` 不是 allocator、`alloc_stats` 不是 allocator）
- 大小写敏感（`Malloc` vs `malloc`，按 C 惯例大小写敏感）

### 7.6 验收标准

- [ ] §2.1 全绿
- [ ] `classify_test.go` 覆盖每个查询函数的三态
- [ ] `grep -rn 'strings\.Contains.*[Nn]ame.*"' sgre/internal/evidence/ sgre/internal/planner/ | grep -v _test.go | grep -v apikb` 只剩极少白名单条目（commit message 说明每一处的合理性）
- [ ] benchmark A/B 差集**必须为空**——若某处替换改变了候选集合，说明该处不是"等价替换"，需要回查改动是否超范围
- [ ] `docs/arch-refactor-apikb-audit.md` 已归档

### 7.7 回归测试落点

- `sgre/internal/apikb/classify_test.go`
- 若某 detector 的判定语义在替换中有意变化（如 ML-08 修复），该变化必须落 benchmark fixture

### 7.8 Commit 边界

按 detector 分 commit（`commit_batching_preference`）：
1. `feat(apikb): Tri-state classify.go with audited tables`
2. `refactor(evidence/memory_leak): route allocator check through apikb`
3. `refactor(evidence/integer_overflow): isSizeFunction via apikb`
4. ... 每个 detector 一个 commit
5. `test(apikb): classify_test.go table-driven`

### 7.9 回滚预案

每个 detector 的 refactor commit 独立 revert；`classify.go` 本身是纯加法，revert 安全。

### 7.10 DoD

§7.6 全部勾选 + commit 推送 + 进度表更新。

---

## 8. Phase 5：S6 config 显式告警与注入

### 8.1 目标

消除 `config.Load()` 全局单例的静默吞错 + 测试注入困难。对应检视 §DEBT-5。

### 8.2 对应检视项

DEBT-5：`scanHasEntryPoint` 在 detector.go 里直接调 `config.Load()`；v070 调查实证 `secguard.toml` 写错位置时静默归零。

### 8.3 前置条件

Phase 4 完成（apikb 中部分查询依赖 config 表，先完成 apikb 再改 config 注入，避免两轮冲突）。

### 8.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/config/config.go` | 修改 | `Load()` 改为返回 `(Config, error)`；新增 `LoadOrZero(path)` 显式容错版本 |
| `sgre/internal/cli/root.go` | 修改 | 启动时一次性 `LoadE`，失败则退出并提示配置文件路径 |
| `sgre/internal/cli/pipeline.go` | 修改 | `runPipeline` 接收 `*config.Config` 参数，向下游传递 |
| `sgre/internal/cli/scan.go` / `diff.go` / `index.go` | 修改 | 移除内部 `config.Load()` 调用 |
| `sgre/internal/evidence/detector.go` | 修改 | `SharedContext` 增加 `Config *config.Config` 字段 |
| `sgre/internal/evidence/dangerous_function.go` | 修改 | 从 `sc.Config` 读，不再 `config.Load()` |
| `sgre/internal/evidence/null_source.go` | 修改 | 同上（`scanHasEntryPoint`） |
| `sgre/internal/evidence/caller_null.go` / `opaque_null.go` / `contract_gap.go` 等 | 修改 | 同上 |
| `sgre/internal/planner/planner.go` | 修改 | `Planner` 增加 `cfg *config.Config` |
| `sgre/internal/config/config_test.go` | 修改 | 补"显式路径不存在 → 返回 error"测试 |

### 8.5 实施步骤

**Step 1** 审计 `config.Load()` 全部调用点：

```bash
grep -rn 'config\.Load()' sgre/ | grep -v _test.go
```

**Step 2** 重构 `config.Load` 签名：

```go
// config/config.go
// Load 返回错误；调用方必须显式处理。
func Load() (*Config, error)

// LoadOrZero 是兼容旧行为的容错版本：读不到返回零值 Config 并打 Warn 日志。
// 仅允许 cli/root.go 在启动时使用；其他位置禁止调用。
func LoadOrZero() *Config
```

**Step 3** `cli/root.go` 启动时一次性加载，失败立即报错退出：

```go
// cli/root.go
cfg, err := config.Load()
if err != nil {
    WriteErrorJSON(fmt.Sprintf("config load failed: %v (looked in <path>)", err))
    return 1
}
```

把 `cfg` 通过函数参数传到 `runScanCmd` / `runDiffCmd` / `runIndexCmd` → `runPipeline` → `planner.NewPlanner` + `evidence.RunAllDetectors`。

**Step 4** evidence 层改造：`SharedContext` 增加 `Config *config.Config`；detector 全部改从 `sc.Config` 读。

**Step 5** planner 层改造：`Planner` 增加 `cfg *config.Config`，`NewPlanner` 注入。

**Step 6** 清理：`grep -rn 'config\.Load()' sgre/` 应只剩 `cli/root.go` 一处。

**Step 7** 测试：

- `config_test.go` 新增"显式路径不存在 → 返回 error"
- `config_test.go` 新增"显式路径存在但损坏 → 返回 error"
- `config_test.go` 新增"默认路径不存在 → 返回零值 Config + nil error（向后兼容）"

### 8.6 验收标准

- [ ] §2.1 全绿
- [ ] `grep -rn 'config\.Load()' sgre/ | grep -v _test.go | grep -v 'cli/root.go'` 为空
- [ ] config 显式路径不存在时 CLI 明确报错（不再是静默零值）
- [ ] v070 场景回归：`secguard.toml` 放项目根（而非 `.codeagent/`）时，CLI 启动报"未找到配置，使用默认"Info 级别日志（而非静默）
- [ ] benchmark A/B 差集为空

### 8.7 回归测试落点

- `sgre/internal/config/config_test.go` 新增 3 个测试

### 8.8 Commit 边界

2 个 commit：
1. `refactor(config): Load returns error, add LoadOrZero compat`
2. `refactor(cli,evidence,planner): inject config via parameter, drop global singleton`

### 8.9 回滚预案

逐 commit revert。

### 8.10 DoD

§8.6 全部勾选 + commit 推送。

---

## 9. Phase 6：S4 Evidence Contract v2 全量推广

### 9.1 目标

把 Evidence Contract v2（`BuildVerdictFacts` hook）从当前 4 个 vuln type（null-deref / crypto-misuse / buffer-overflow / out-of-bounds）推广到全部 24 个。对应检视 §ACC-3。

### 9.2 对应检视项

ACC-3：`agent-body.md` 60+ hint token 本质是"举证不足"；Evidence Contract v2 只落地 4/24。

### 9.3 前置条件

Phase 1 / 2 / 3 完成。推荐 Phase 4 / 5 也完成（apikb 与 config 稳定后，写 VerdictFacts 时依赖的分类函数语义不再变）。

### 9.4 推广范围与批次

按"AI 研判成本 + 用户使用频率"分两批：

**批次 A（5 个，先做）**：
1. `unchecked-return`
2. `integer-overflow`
3. `memory-leak`
4. `resource-leak`
5. `uninit`

**批次 B（15 个，后做）**：
6. `use-after-free`
7. `double-free`
8. `format-string`
9. `injection`
10. `path-traversal`
11. `divide-by-zero`
12. `race-condition`
13. `deadlock`
14. `hardcoded-secret`
15. `signal-handler`
16. `dangerous-function`
17. `argument-type`
18. `data-representation`
19. `sizeof-misuse`
20. `signed-compare`

**批次 C（视需要）**：`implicit-contract` 等已在 registry 但未在 AI_JUDGMENT_BOUNDARY 主表的辅助类型。

### 9.5 每个类型的统一模板

对每个 vuln type `X`，在 `sgre/internal/planner/registry.go`（Phase 8 完成后在 `planner/types/<X>.go`）的 `VulnTypeSpec` 里补 `BuildVerdictFacts`：

```go
BuildVerdictFacts: func(c Candidate) []VerdictFact {
    facts := []VerdictFact{}
    // 每条 fact 必须满足：
    // - Token: "<dimension>@<value>" 格式
    // - Sentence: 一句人读判决性陈述
    // - Provenance: file:line（AI 可定点验证）
    return facts
},
```

**VerdictFact 设计三原则**（从检视 §ACC-3）：
1. 每条 fact 必须带 provenance file:line
2. 每条 fact 必须是"判定性事实"，不是"线索"
3. token 命名遵循 `<dimension>@<value>`，维度表全局唯一（见 `planner/hint_tokens.go` 的既有注册表，新维度须先注册）

### 9.6 每个类型的改动文件清单（模板）

以 `unchecked-return` 为例：

| 文件 | 改动 |
|---|---|
| `sgre/internal/planner/registry.go`（或 `types/unchecked_return.go`） | 补 `BuildVerdictFacts` |
| `extension/shared/skills/unchecked-return/SKILL.md` | 补充"Verdict Facts"章节 |
| `sgre/internal/planner/zz_unchecked_return_facts_test.go`（新建） | 表驱动单测：给定 Candidate → 期望 VerdictFacts |
| `sgre/testdata/tc<N>_unchecked_return_facts.c`（新建） | end-to-end fixture |
| `examples/c-vuln-benchmark/src/p<N>_unchecked_return.c` + `expected-results.json` | 若覆盖了新形态，落 benchmark |

### 9.7 实施步骤（每批次通用）

**Step 1** 选定批次 A 的 5 个类型，每个类型一个子分支（`feature/arch-refactor-2026q4-ec-<type>`）。

**Step 2** 对该类型做"举证审计"：
- 读 `SKILL.md` 的 "Evidence Pattern" 与 "False Positive" 章节
- 读该类型的 detector 与 filter 代码，列出 pipeline 已算出的语义事实清单
- 对照现有 hint token，识别哪些 hint 可以升级为 VerdictFact（带 provenance）

**Step 3** 实现 `BuildVerdictFacts`。

**Step 4** 更新 `SKILL.md`：在 "Evidence Pattern" 章节前插入 "Verdict Facts" 章节，列出本类型所有 fact token 及含义；**明示 AI 判决优先读 VerdictFacts，仅在 facts 不足时才打开 Code Context**。

**Step 5** 写 `zz_<type>_facts_test.go` 表驱动单测。

**Step 6** 端到端：构建 CLI → 扫 `sgre/testdata/tc<N>_<type>.c` → 打开 candidates markdown → 人工核对 VerdictFacts 渲染正确。

**Step 7** benchmark A/B：差集为空（本 Phase 不改判定，只改举证，候选集合不变）。

**Step 8** 把子分支合回 `feature/arch-refactor-2026q4`。

**Step 9** 批次 A 完成后，检查 AI 举证成本：对 `testdata/perf/large_codebase` 扫描后，统计 `_index.md` 中"含 VerdictFacts 的候选占比"，目标 ≥ 60%。

### 9.8 验收标准

- [ ] 批次 A 5 个类型全部实现 `BuildVerdictFacts` + SKILL.md 更新 + 单测
- [ ] 批次 B 15 个类型全部实现
- [ ] `TestVulnTypeSkillConsistency` 全绿
- [ ] benchmark A/B 差集为空
- [ ] `_index.md` 含 VerdictFacts 的候选占比 ≥ 60%（批次 A 完成后）
- [ ] `agent-body.md` 中对应类型的 hint token 已标"deprecated, see VerdictFacts"（**不删除**，向后兼容；hint token 下线是后续 L2 的事）

### 9.9 回归测试落点

每个类型一个 `zz_<type>_facts_test.go`。

### 9.10 Commit 边界

每类型 1-2 个 commit（实现 + 测试）；批次 A / B 各一个收尾 commit 更新 `CHANGELOG.md`（若有用户可见变化）。

### 9.11 回滚预案

按类型 revert；`BuildVerdictFacts` 是 `VulnTypeSpec` 的可选字段，置 nil 即恢复原状。

### 9.12 DoD

批次 A 完成即可标 Phase 6 部分完成；批次 B 完成后整个 Phase 6 完成。**批次 B 可以视 token 预算与 v1.0.0 时间窗决定是否拆到下一阶段。**

---

## 10. Phase 7：M5 filter chain 声明式化

### 10.1 目标

把 `planner.go:55-158` 的 `getFilters(chain string)` switch-case 改为声明式：`VulnTypeSpec.FilterFactories []FilterFactory`，新增 vuln type 不再需要修改 `planner.go`。对应检视 §DEBT-3。

### 10.2 对应检视项

DEBT-3。

### 10.3 前置条件

Phase 1 / 2 / 3 完成；Phase 6 不强制（但推荐至少批次 A 完成，避免同时改 VerdictFacts 与 FilterFactories 两处 `VulnTypeSpec` 字段）。

### 10.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/planner/filter.go` | 修改 | 新增 `FilterFactory` 类型 |
| `sgre/internal/planner/registry.go` | 修改 | `VulnTypeSpec` 新增 `FilterFactories` 字段；24 个 `init()` 注册点逐个迁移 |
| `sgre/internal/planner/planner.go` | 修改 | `getFilters` 改为读 `spec.FilterFactories` |
| `sgre/internal/planner/zz_filter_chain_test.go`（新建） | 新增 | 断言每类型的 `FilterFactories` 长度与顺序与预期一致 |

### 10.5 实施步骤

**Step 1** 定义 `FilterFactory`：

```go
// planner/filter.go
// FilterFactory 在 Plan 时被调用以实例化一个 Filter。
// 接收 Planner 的共享资源（store / parser / logger / caches）。
type FilterFactory func(deps FilterDeps) Filter

type FilterDeps struct {
    Store          db.Store
    Parser         *parser.Parser
    Logger         *log.Logger
    CallReachCache *callReachCache
    TaintCache     *taintSummaryCache
    Macro          *macroContextDetector
    CFGCache       *graph.CFGCache  // Phase 1 引入
    Config         *config.Config   // Phase 5 引入
}
```

**Step 2** `VulnTypeSpec` 增加字段：

```go
type VulnTypeSpec struct {
    // ... 既有字段
    // FilterChain 保留（向后兼容），新增 FilterFactories
    FilterChain     string          // deprecated，双写期使用
    FilterFactories []FilterFactory // 新
}
```

**Step 3** `planner.go:getFilters` 改造：

```go
func (p *Planner) getFilters(spec *VulnTypeSpec) ([]Filter, error) {
    // 双写期：FilterFactories 非空则优先，否则回退到旧 switch-case
    if len(spec.FilterFactories) > 0 {
        deps := FilterDeps{Store: p.store, Parser: p.parser, ...}
        out := make([]Filter, 0, len(spec.FilterFactories))
        for _, f := range spec.FilterFactories {
            out = append(out, f(deps))
        }
        return out, nil
    }
    return p.getFiltersLegacy(spec.FilterChain)
}
```

**Step 4** 逐类型迁移：把 `getFilters` 里 13 个 case 的内容，逐字搬到 `registry.go` 里对应 `VulnTypeSpec` 的 `FilterFactories` 字段。注意 `null-deref` / `memory-leak` / `buffer-overflow` 等链条有特定顺序，**顺序即语义**，迁移时必须保持。

**Step 5** 全部 24 个类型迁移完成后，把 `planner.go` 的 `getFiltersLegacy` 标 `// Deprecated`，但**保留一个版本**（双写期护栏）；`TestFilterChainMigration` 断言 `spec.FilterFactories` 长度 > 0 对所有类型成立。

**Step 6** 删除双写期护栏（独立 commit，标 `chore(planner): drop legacy FilterChain switch-case`）。

### 10.6 验收标准

- [ ] §2.1 全绿
- [ ] 所有 24 个类型的 `FilterFactories` 非空
- [ ] benchmark A/B 差集为空
- [ ] 新增 vuln type 时 `planner.go` 零改动（用一个 mock 类型在测试里验证）

### 10.7 回归测试落点

`sgre/internal/planner/zz_filter_chain_test.go`。

### 10.8 Commit 边界

3 个 commit：
1. `feat(planner): FilterFactory + FilterDeps + VulnTypeSpec.FilterFactories`
2. `refactor(planner): migrate 24 vuln types to FilterFactories`
3. `chore(planner): drop legacy FilterChain switch-case`

### 10.9 回滚预案

逐 commit revert。

### 10.10 DoD

§10.6 全勾 + 推送。

---

## 11. Phase 8：M6 registry.go 拆分

### 11.1 目标

把 83K / 1744 行的 `planner/registry.go` 拆成"1 个索引 + 24 个类型独立文件"。对应检视 §DEBT-1。

### 11.2 对应检视项

DEBT-1。

### 11.3 前置条件

Phase 7 完成（FilterFactories 已迁入 `VulnTypeSpec`，拆分时不再受 switch-case 牵扯）；推荐 Phase 6 完成（`BuildVerdictFacts` 已就位，拆分时一并搬走）。

### 11.4 改动文件清单

新建目录 `sgre/internal/planner/types/`：

```
sgre/internal/planner/types/
├── doc.go                    # 包说明 + 所有类型的 init() 汇总注释
├── null_deref.go
├── buffer_overflow.go
├── out_of_bounds.go
├── memory_leak.go
├── resource_leak.go
├── injection.go
├── uninit.go
├── use_after_free.go
├── double_free.go
├── format_string.go
├── integer_overflow.go
├── race_condition.go
├── hardcoded_secret.go
├── deadlock.go
├── crypto_misuse.go
├── divide_by_zero.go
├── unchecked_return.go
├── path_traversal.go
├── sizeof_misuse.go
├── signed_compare.go
├── signal_handler.go
├── dangerous_function.go
├── argument_type.go
├── data_representation.go
└── implicit_contract.go      # 若在册
```

保留 `sgre/internal/planner/registry.go`，但**只保留**：
- `VulnTypeSpec` struct 定义
- `vulnTypeRegistry` map 与 `RegisterVulnType` / `GetVulnTypeSpec` / `AllVulnTypes` / `ActiveVulnTypes` / `ValidateRegistry` / `AllSeedEventTypes` / `AuxEvidenceEventTypes` / `CWEForType` / `CWEForCategory` / `TypeForCWE` / `AllCWEs` 等查询函数
- 目标：**registry.go 控制在 300 行以内**

把 24 个 `init()` + 24 个 `buildXXXVerdictFacts` + 24 个 `buildXXXEvidence` 全部搬到 `types/` 下对应文件。

### 11.5 实施步骤

**Step 1** 新建 `types/` 目录与 `doc.go`。

**Step 2** 为每个 vuln type 新建 `types/<name>.go`：内容 = 该类型的 `init()` + `VulnTypeSpec` 注册 + `BuildVerdictFacts` + `BuildEvidence` + `ConvergeKey`。

**Step 3** 每个新文件的包名是 `types`，但 import 侧需要注意：**`types/null_deref.go` 里的 `init()` 只是声明 spec，真正的注册动作依赖 `types/` 包被 import**。在 `planner/registry.go` 顶部加：

```go
import _ "github.com/DannyAn/secguard-clang/internal/planner/types"
```

`types/` 包里每个文件 `func init() { planner.RegisterVulnType(...) }`——但这样会产生 import cycle（`types` import `planner`，`planner` import `types`）。

**解法**（两种，执行 Agent 选其一并在 commit message 说明）：

**方案 A（推荐）**：`types/` 不 import `planner`，而是声明一个本地 `Spec` 类型别名 + `func init() { register(...) }`，注册函数由 `planner` 在 init 时通过 blank import 触发，再回调 `planner.RegisterVulnType`：

```go
// types/null_deref.go
package types

import "github.com/DannyAn/secguard-clang/internal/planner/spec" // 新建的轻量 spec 包

func init() {
    spec.Register(&spec.VulnTypeSpec{Name: "null-deref", ...})
}
```

新建 `sgre/internal/planner/spec/` 子包，只放 `VulnTypeSpec` 定义 + 注册表；`planner/registry.go` 改为从 `spec` 包读。

**方案 B**：保留单包，但把 `registry.go` 拆成同包多个文件（`planner/registry_null_deref.go` 等）。简单但没解决"单包巨型文件"问题，仅作兜底。

**推荐方案 A**：`spec` 包作为"声明层"，`planner` 包作为"执行层"，分层更清晰。

**Step 4** 逐类型搬运（24 个 commit 或按 CWE 家族合并为 6-8 个 commit）。

**Step 5** 搬运完成后，`registry.go` 只留查询函数；跑 `TestVulnTypeSkillConsistency` 验证 drift。

**Step 6** `buildXXXVerdictFacts` / `buildXXXEvidence` 若在搬运中需要跨文件共享 helper（如 `derivedSuffix` / `otherDerefLines` / `joinLines`），把这些 helper 一并搬到 `types/internal_helpers.go`。

### 11.6 验收标准

- [ ] `wc -l sgre/internal/planner/registry.go` ≤ 300 行
- [ ] `wc -l sgre/internal/planner/types/*.go` 每个文件 ≤ 500 行
- [ ] §2.1 全绿
- [ ] `TestVulnTypeSkillConsistency` 绿
- [ ] benchmark A/B 差集为空

### 11.7 回归测试落点

`TestVulnTypeSkillConsistency` 即回归。无新增测试。

### 11.8 Commit 边界

按 CWE 家族分 commit（每 commit 3-5 个类型），或 24 个类型每 3 个一个 commit，共 8 个 commit：
1. `refactor(planner/types): extract spec subpackage + move null-deref/buffer-overflow/out-of-bounds`
2. `refactor(planner/types): move memory-leak/resource-leak/use-after-free`
3. ...

### 11.9 回滚预案

按 commit revert；因为是同包内搬运（方案 B）或子包纯加法（方案 A），revert 安全。

### 11.10 DoD

§11.6 全勾 + 推送。

---

## 12. Phase 9：M7 Candidate/eventProps 分层

### 12.1 目标

把 `Candidate`（70+ 字段）与 `eventProps`（70+ 字段）拆为 `Common + per-type payload`。对应检视 §DEBT-2。

### 12.2 对应检视项

DEBT-2。

### 12.3 前置条件

Phase 8 完成（类型已经分文件，payload 定义可以就近放在 `types/<name>.go` 旁）。

### 12.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/planner/candidate.go`（新建） | 新增 | `CommonCandidate` + `Candidate` wrapper |
| `sgre/internal/planner/props.go` | 修改 | `eventProps` 拆为 `commonProps` + per-type `xxxProps` |
| `sgre/internal/planner/types/<name>.go` | 修改 | 每类型定义自己的 payload struct |
| `sgre/internal/evidence/<detector>.go` | 修改 | detector 写事件时用类型化 props（而不是 `map[string]string`） |
| `sgre/internal/planner/planner.go` | 修改 | `seedCandidatesByType` 用类型化解析 |

### 12.5 实施步骤

**Step 1** 设计 `CommonCandidate`：

```go
// planner/candidate.go
type CommonCandidate struct {
    DerefEventID  int64
    FunctionID    int64
    FunctionName  string
    VariableName  string
    Expression    string
    APIName       string
    Category      string
    LocationID    int64
    FileID        int64
    Line          int
    SuspicionLevel string
    FunctionSignature string
    FuncStartLine int
    FuncEndLine   int
    MacroContext  bool
    // ... 所有 24 个类型都用到的字段
}

type Candidate struct {
    Common CommonCandidate
    // per-type payload，通过类型断言访问
    Payload any
}

// 类型安全的访问：
func (c *Candidate) NullDeref() *NullDerefPayload { ... }
func (c *Candidate) Leak() *LeakPayload { ... }
```

**Step 2** `eventProps` 同样拆分：

```go
// planner/props.go
type commonProps struct {
    Variable   string `json:"variable"`
    Expression string `json:"expression"`
    Category   string `json:"category"`
    Function   string `json:"function"`
    // ... 所有类型共用字段
}

// 每类型一个 payload props（在 types/<name>.go 里定义）
// types/null_deref.go
type nullDerefProps struct {
    commonProps
    NonNullable string `json:"non_nullable"`
    IsTypeExpr  string `json:"is_type_expr"`
    Origin      string `json:"origin"`
    FieldPath   string `json:"field_path"`
    // ...
}
```

**Step 3** 改造 `seedCandidatesByType`：

```go
// 旧：candidates = append(candidates, Candidate{ ... 70 个字段 ... })
// 新：
common := decodeCommonProps(e.Properties)
payload := spec.DecodePayload(e.Properties)  // 每类型一个 decoder
candidates = append(candidates, Candidate{Common: common, Payload: payload})
```

`VulnTypeSpec` 新增 `DecodePayload func(raw string) (any, error)`。

**Step 4** 改造 detector 写入侧：

```go
// evidence/null_source.go
// 旧：emitEvent(..., map[string]string{"variable": name, "origin": origin, ...})
// 新：
emitEvent(..., nullDerefEventProps{
    Common: commonEventProps{Variable: name, ...},
    Origin: origin,
    ...
})
```

`evidence/` 包不再需要构造 `map[string]string`，而是用类型化 struct。

**Step 5** 兼容策略（重要）：SQLite 中 `security_events.properties` 的 schema **不变**（仍是 JSON blob），只是写入侧与读取侧都用类型化 struct 序列化/反序列化。**不涉及 DB migration**（符合红线 §1.10）。

**Step 6** 逐步迁移：先迁 null-deref 一个类型，跑通 §2.1 + §2.3，再推广到其他 23 个。

### 12.6 验收标准

- [ ] §2.1 全绿
- [ ] `Candidate` struct 字段数从 70+ 降到 ≤ 25（CommonCandidate）
- [ ] 每类型的 payload 在 `types/<name>.go` 内聚
- [ ] benchmark A/B 差集为空
- [ ] `grep -n 'flexInt' sgre/internal/planner/props.go` 剩余 ≤ 5 处（仅保留真正需要兼容字符串数字的字段）

### 12.7 回归测试落点

- `planner/zz_candidate_payload_test.go`：序列化/反序列化 round-trip
- 每类型 detector 的既有测试（不应破坏）

### 12.8 Commit 边界

按类型分批 commit（3-5 个一批），共 6-8 个 commit。

### 12.9 回滚预案

按批 revert；新旧 props 字段在 JSON 层兼容，回滚安全。

### 12.10 DoD

§12.6 全勾 + 推送。

---

## 13. Phase 10：M1 graph 语义查询服务

### 13.1 目标

把 `graph` 包从"数据存储层"升级为"**语义查询服务层**"。新建 `sgre/internal/graph/query.go`，对外暴露声明式查询接口，detector/filter 不再自己解释 AST/行号。对应检视 §ACC-2。

**这是本方案中风险最高的 Phase 之一**，采用**双轨期**策略：新接口与旧实现并存至少一个版本，待所有 detector 迁移完成且 benchmark 稳定后再删除旧路径。

### 13.2 对应检视项

ACC-2。

### 13.3 前置条件

Phase 1（CFG 缓存）+ Phase 8（registry 拆分）完成；推荐 Phase 9 完成（类型化 payload 已就位）。

### 13.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/graph/query.go`（新建） | 新增 | 公开查询接口 |
| `sgre/internal/graph/query_must_nonnull.go`（新建） | 新增 | MustNonNullAt 实现 |
| `sgre/internal/graph/query_interval.go`（新建） | 新增 | IntervalAt 实现 |
| `sgre/internal/graph/query_alias.go`（新建） | 新增 | AliasSet 实现（初版可为占位，完整实现归 Phase 12） |
| `sgre/internal/graph/query_summary.go`（新建） | 新增 | ReturnSummaryOf 实现（初版可只覆盖 null，完整推广归 Phase 13） |
| `sgre/internal/graph/query_test.go`（新建） | 新增 | 表驱动测试 |
| `sgre/internal/evidence/<detector>.go`（逐步） | 修改 | 逐 detector 迁移到 query 接口 |

### 13.5 实施步骤

**Step 1** 定义公开查询接口：

```go
// graph/query.go
package graph

// Querier 是一次扫描的语义查询入口。
// 由 cli/pipeline.go 在 runPipeline 启动时构建一份，
// 通过 evidence.SharedContext 与 planner.Planner 共享。
type Querier struct {
    store    db.Store
    parser   *parser.Parser
    cfgCache *CFGCache
    // 内部维护各种分析结果缓存（lazy）
}

func NewQuerier(store db.Store, p *parser.Parser, cfgCache *CFGCache) *Querier

// MustNonNullAt 报告变量 v 在 fn 的 line 行是否在所有路径上非空。
func (q *Querier) MustNonNullAt(ctx context.Context, fn *db.Function, v string, line int) Tri

// MayBeNullAt 报告变量 v 在 fn 的 line 行是否在某条路径上可能为空。
func (q *Querier) MayBeNullAt(ctx context.Context, fn *db.Function, v string, line int) Tri

// IntervalAt 报告变量 v 在 fn 的 line 行的整数区间。
// 若无法确定返回 topInterval + ok=false。
func (q *Querier) IntervalAt(ctx context.Context, fn *db.Function, v string, line int) (Interval, bool)

// AliasSet 报告变量 v 在 fn 的 line 行的别名集（含 v 本身）。
// 初版只支持函数内 q=p 别名；跨函数别名在 Phase 12 扩展。
func (q *Querier) AliasSet(ctx context.Context, fn *db.Function, v string, line int) []string

// TypeOf 报告表达式在 fn 内的类型（初版只支持标识符 + 字段访问）。
// 完整类型系统在 Phase 11 落地。
func (q *Querier) TypeOf(ctx context.Context, fn *db.Function, expr string) (Type, bool)

// ReturnSummary 报告 callee 的返回 summary（null-ness / interval / taint）。
// 初版只覆盖 null-ness（复用 computeRetNullable），其他维度在 Phase 13 扩展。
func (q *Querier) ReturnSummary(ctx context.Context, callee string) (ReturnSummary, bool)
```

`Tri` 复用 `apikb.Tri`。

**Step 2** 实现 `MustNonNullAt` 与 `MayBeNullAt`：

内部复用 `null_flow.go` 的既有 reaching-sources 引擎。关键是把"返回 suspected/confirmed 候选"的判定逻辑，反转为"返回三态事实"的查询逻辑。`planner/filter_nullable_source.go` 逐步改为调用此查询而非自己跑数据流。

**Step 3** 实现 `IntervalAt`：

复用 `range_flow.go`。对外暴露 `Interval{Lo, Hi int64, Top bool}`。

**Step 4** 实现 `AliasSet`（占位版）：

```go
// 初版：只支持函数内 q=p 别名，不做跨函数
// Phase 12 会替换为完整实现
```

**Step 5** 实现 `ReturnSummary`（占位版）：

```go
type ReturnSummary struct {
    Null Tri // callee 返回值是否可空（复用 computeRetNullable）
    // Phase 11 扩展：Width, Signed
    // Phase 13 扩展：Taint, Interval, NonZero
}
```

**Step 6** 接入：

- `cli/pipeline.go:runPipeline` 构建一份 `*graph.Querier`，通过 `evidence.SharedContext.Querier` 与 `planner.Planner.Querier` 共享；
- detector/filter **新增代码**全部走 `Querier`；**既有代码**双轨保留（标注 `// Deprecated: migrate to Querier.MustNonNullAt`）。

**Step 7** 迁移策略（双轨期）：

- 不在本 Phase 强制迁移所有 detector；只迁移 2-3 个**示范性 detector**（推荐 `null_deref` 的 `caller_null.go` + `null_source.go`）作为"迁移模板"；
- 其他 detector 的迁移在后续版本逐步完成（每个迁移是独立 commit，独立验证）；
- 当所有 detector 迁移完成且 benchmark 连续 3 个版本稳定后，再删除旧路径（独立 Phase，不在本方案内）。

### 13.6 验收标准

- [ ] §2.1 全绿
- [ ] `graph/query_test.go` 表驱动覆盖每个查询函数
- [ ] 至少 2 个 detector（`caller_null` / `null_source`）完成迁移并 benchmark A/B 差集为空
- [ ] `grep -rn 'querier\.' sgre/internal/evidence/caller_null.go sgre/internal/evidence/null_source.go` 非空
- [ ] 旧路径仍可工作（其他 detector 不受影响）

### 13.7 回归测试落点

`graph/query_test.go` + 两个迁移 detector 的既有测试。

### 13.8 Commit 边界

4 个 commit：
1. `feat(graph): Querier skeleton with Must/May/Interval/Alias/ReturnSummary`
2. `feat(graph): MustNonNullAt + MayBeNullAt implementation`
3. `feat(graph): IntervalAt implementation`
4. `refactor(evidence/null): migrate caller_null + null_source to Querier`

### 13.9 回滚预案

逐 commit revert；Querier 是纯加法，迁移 commit 单独 revert。

### 13.10 DoD

§13.6 全勾 + 推送。**评估点 A 在此 Phase 完成后做**：若 Querier 在 null_deref 两个 detector 上的实证数据符合预期（无候选漂移、性能不退化），继续 Phase 11；否则回查设计。

---

## 14. Phase 11：M2 类型系统建模

### 14.1 目标

在 `graph` 层建立 C 类型模型：**宽度 / 符号性 / 浮点 vs 整数 / 指针 vs 值**。对应检视 §ACC-2 与 §ACC-5。

### 14.2 对应检视项

ACC-2 / ACC-5。直接受益类型：`integer-overflow` / `signed-compare` / `data-representation` / `argument-type` / `divide-by-zero`（浮点豁免） / `sizeof-misuse`。

### 14.3 前置条件

Phase 10 完成（Querier 骨架就位，类型查询作为 Querier 的扩展）。

### 14.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/graph/types.go`（新建） | 新增 | `Type` struct + 类型推断 |
| `sgre/internal/graph/types_width.go`（新建） | 新增 | LP64/LLP64 模型 + sizeof 计算 |
| `sgre/internal/graph/types_test.go`（新建） | 新增 | 表驱动测试 |
| `sgre/internal/graph/query.go` | 修改 | `Querier.TypeOf` 完整实现 |
| `sgre/internal/evidence/integer_overflow.go` | 修改 | 迁移到 `Querier.TypeOf` |
| `sgre/internal/evidence/divide_by_zero.go` | 修改 | 浮点豁免走 `Querier.TypeOf` |
| `sgre/internal/evidence/signed_compare.go` | 修改 | 迁移 |
| `sgre/internal/evidence/data_representation.go` | 修改 | 迁移 |
| `sgre/internal/evidence/argument_type.go` | 修改 | 迁移 |
| `sgre/internal/evidence/sizeof_misuse.go` | 修改 | 迁移 |

### 14.5 实施步骤

**Step 1** 设计 `Type` 模型：

```go
// graph/types.go
type TypeKind int
const (
    TypeUnknown TypeKind = iota
    TypeInt            // 任意宽度有符号整数
    TypeUint           // 任意宽度无符号整数
    TypeFloat          // float / double / long double
    TypePointer        // T*
    TypeArray          // T[N]
    TypeStruct         // struct S
    TypeUnion
    TypeFunction
    TypeVoid
)

type Type struct {
    Kind      TypeKind
    Width     int    // bits，仅 Int/Uint/Float 有效；0 = unknown
    Signed    bool   // 仅 Int/Uint 有效
    Pointee   *Type  // 仅 Pointer 有效
    Elem      *Type  // 仅 Array 有效
    ArrayLen  int64  // 仅 Array 有效；-1 = unknown
    Name      string // 原名（如 "uint32_t" / "size_t"），用于显示
    TypedefOf string // 若是 typedef，指向底层类型名
}
```

**Step 2** 实现 LP64 类型宽度表：

```go
// graph/types_width.go
// 默认 LP64（macOS / Linux 64 位）；LLP64（Windows 64 位）通过 config 注入
var lp64Widths = map[string]int{
    "char": 8, "short": 16, "int": 32, "long": 64, "long long": 64,
    "float": 32, "double": 64, "long double": 128,
    "size_t": 64, "ssize_t": 64, "ptrdiff_t": 64,
    "int8_t": 8, "int16_t": 16, "int32_t": 32, "int64_t": 64,
    "uint8_t": 8, "uint16_t": 16, "uint32_t": 32, "uint64_t": 64,
}
```

`Config` 增加 `TypeModel string`（`"lp64"` / `"llp64"`），默认 `lp64`。

**Step 3** 实现类型推断：

`Querier.TypeOf(ctx, fn, expr)`：
- 标识符：查 `db.Variable` / `db.Function` 声明；
- 字段访问 `p->f` / `s.f`：查 `repofacts` 的 struct 布局；
- 字面量：`1` → `TypeInt{Width: 32, Signed: true}`，`1u` → `TypeUint{32}`，`1.0` → `TypeFloat{64}`；
- `sizeof(T)`：`TypeUint{64}`（`size_t`）；
- 二元表达式：按 C 整数提升规则计算结果类型（`graph/types_promote.go`）。

**Step 4** 迁移 `divide_by_zero.go` 的浮点豁免：

```go
// 旧（文本子串）：
if isFloatDivisionText(line) { skip }

// 新：
dividend, _ := q.TypeOf(ctx, fn, dividendExpr)
divisor, _ := q.TypeOf(ctx, fn, divisorExpr)
if dividend.Kind == TypeFloat || divisor.Kind == TypeFloat { skip }
```

**Step 5** 迁移 `integer_overflow.go` 的宽度判定（IO-21 关联）：

```go
// 旧：硬编码 guardMaxBound=32768（假设 32 位 int）
// 新：按 TypeOf 结果的实际宽度计算上界
t, ok := q.TypeOf(ctx, fn, expr)
if !ok { /* Unknown */ }
maxVal := int64(1)<<(t.Width-1) - 1  // signed
```

**Step 6** 迁移其他 detector。每迁移一个，跑 §2.1 + §2.3。

**Step 7** `TypeOf` 对未知类型返回 `ok=false`，调用方**必须**走 Unknown 分支（通常是 suspected，而非默默当成 int32）。

### 14.6 验收标准

- [ ] §2.1 全绿
- [ ] `graph/types_test.go` 覆盖至少 20 个类型推断用例
- [ ] 6 个 detector 完成迁移
- [ ] benchmark A/B 差集为空（或有明确方向的改进，commit message 说明）
- [ ] `divide_by_zero` 的 typeof 浮点豁免测试（`tc_typeof_float`）绿

### 14.7 回归测试落点

`graph/types_test.go` + 每个迁移 detector 的既有测试。

### 14.8 Commit 边界

4-5 个 commit：
1. `feat(graph): Type model + LP64 width table`
2. `feat(graph): Querier.TypeOf implementation`
3. `refactor(evidence/divide_by_zero): float exemption via TypeOf`
4. `refactor(evidence/integer_overflow): width-aware overflow bounds`
5. `refactor(evidence): migrate signed_compare/data_representation/argument_type/sizeof_misuse to TypeOf`

### 14.9 回滚预案

逐 commit revert；TypeOf 是纯加法，detector 迁移单独 revert。

### 14.10 DoD

§14.6 全勾 + 推送。

---

## 15. Phase 12：M3 跨函数别名分析

### 15.1 目标

扩展 `graph/alias.go`（当前 174 行）支持**跨函数别名**：`q = p` / `return p` / 参数别名 / 字段别名。对应检视 §ACC-2。直接受益类型：use-after-free / double-free / memory-leak / resource-leak。

### 15.2 对应检视项

ACC-2（`AliasSet` 完整实现）；历史：UF-02 / UF-04 / ML-02。

### 15.3 前置条件

Phase 10 完成（`AliasSet` 占位已在 Querier 中）；Phase 11 推荐（类型系统可用于"同类型别名"过滤）。

### 15.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/graph/alias.go` | 扩展 | 函数内别名已存在，保留 |
| `sgre/internal/graph/alias_interproc.go`（新建） | 新增 | 跨函数别名 |
| `sgre/internal/graph/alias_interproc_test.go`（新建） | 新增 | 测试 |
| `sgre/internal/graph/query_alias.go` | 修改 | `AliasSet` 走跨函数实现 |
| `sgre/internal/evidence/use_after_free.go` | 修改 | `findAllFreeEvents` 接入别名 |
| `sgre/internal/evidence/double_free.go` | 修改 | 同上 |
| `sgre/internal/evidence/memory_leak.go` | 修改 | `findFrees` 接入别名 |
| `sgre/internal/evidence/resource_leak.go` | 修改 | 同上 |

### 15.5 实施步骤

**Step 1** 函数内别名已存在（`alias.go`），先审计其覆盖面：
- `q = p`
- `q = (T*)p`（cast 别名）
- `q = &p[i]`（元素地址）
- `q = p->f`（字段别名，field-sensitive）

若已有缺口，补齐（独立 commit）。

**Step 2** 跨函数别名：

```go
// graph/alias_interproc.go
// InterproceduralAlias 构建跨函数别名图：
// - return p：callee 的 return value 与 caller 的接收变量别名
// - f(p)：callee 的形参与 caller 的实参别名
// - g = p（全局）：跨函数共享
func BuildInterproceduralAlias(ctx context.Context, store db.Store, q *Querier) (*AliasGraph, error)
```

`AliasGraph` 是 `map[AliasKey][]AliasKey`，`AliasKey = (functionID, varName)` 或 `(global, varName)`。

**Step 3** `AliasSet` 完整实现：

```go
func (q *Querier) AliasSet(ctx context.Context, fn *db.Function, v string, line int) []string {
    // 1. 函数内别名（alias.go）
    // 2. 跨函数别名（alias_interproc.go）
    // 3. 去重 + 返回
}
```

**Step 4** 迁移 detector：

- `use_after_free.go`：检测 `free(p); q->x` 时，`q` 若在 `AliasSet(p)` 中则视为同一对象；
- `double_free.go`：`free(p); free(q)`，`q ∈ AliasSet(p)` → 真 double-free；
- `memory_leak.go`：`p = malloc(); q = p; free(q)` → `p` 不泄漏；
- `resource_leak.go`：同上。

**Step 5** 特别处理：

- `free((void*)p)`：cast 别名必须识别；
- `g = (T*)p`（全局别名）：跨函数；
- `q = p` 后 `p = NULL`：q 仍持有原对象（别名 ≠ 值同步）。

**Step 6** 测试：每类别名形态一个 fixture（函数内 / return / 参数 / 全局 / cast / 字段）。

### 15.6 验收标准

- [ ] §2.1 全绿
- [ ] `alias_interproc_test.go` 覆盖至少 6 种别名形态
- [ ] 4 个 detector 迁移完成
- [ ] benchmark A/B：预期**候选数下降**（UF-02/ML-02 类误报被消除），`expected-results.json` 相应更新
- [ ] 历史误报 fixture（`q=p;free(q)` / `free((void*)p)` / `g=(T*)p`）的 no_finding 断言全部通过

### 15.7 回归测试落点

`alias_interproc_test.go` + benchmark fixture。

### 15.8 Commit 边界

3 个 commit：
1. `feat(graph): interprocedural alias graph`
2. `refactor(evidence): use-after-free/double-free/memory-leak/resource-leak consume AliasSet`
3. `test(benchmark): pin alias-aware fixtures for UF-02/ML-02 forms`

### 15.9 回滚预案

逐 commit revert。

### 15.10 DoD

§15.6 全勾 + 推送。

---

## 16. Phase 13：M4 通用函数 summary

### 16.1 目标

把 `computeRetNullable` 模式泛化为**通用函数返回 summary**：return-null / return-nonzero / return-capacity / return-taint。对应检视 §ACC-2。

### 16.2 对应检视项

ACC-2；间接受益：integer-overflow（`malloc(get_len() * sizeof(T))` 跨函数 size 可大性）、divide-by-zero（跨函数非零 summary 已有，纳入统一框架）、path-traversal（跨函数 taint）、injection（跨函数 taint）。

### 16.3 前置条件

Phase 10 / 11 完成。

### 16.4 改动文件清单

| 文件 | 改动类型 | 说明 |
|---|---|---|
| `sgre/internal/graph/summary.go`（新建） | 新增 | 通用 summary 框架 |
| `sgre/internal/graph/summary_null.go` | 新增 | null-ness（迁移 computeRetNullable） |
| `sgre/internal/graph/summary_interval.go` | 新增 | 返回区间 |
| `sgre/internal/graph/summary_taint.go` | 新增 | 返回 taint |
| `sgre/internal/graph/summary_capacity.go` | 新增 | 返回 capacity |
| `sgre/internal/graph/summary_test.go` | 新增 | 测试 |
| `sgre/internal/planner/return_summary.go` | 修改 | 迁移到 graph/summary_null.go |
| `sgre/internal/planner/filter_taint_source.go` | 修改 | 走 summary_taint |
| `sgre/internal/evidence/divide_by_zero.go` | 修改 | 跨函数非零走 summary_interval |
| `sgre/internal/evidence/integer_overflow.go` | 修改 | 跨函数 size 走 summary_interval |

### 16.5 实施步骤

**Step 1** 设计通用框架：

```go
// graph/summary.go
// Summary 是一函数的"返回行为摘要"。
// 不同维度（null-ness / interval / taint / capacity）各自有独立 fixpoint。
type Summary struct {
    Function   string
    Null       Tri        // 返回值可空性
    Interval   Interval   // 返回值区间
    Taint      Tri        // 返回值是否 tainted
    Capacity   int64      // 返回值作为 buffer 时的 capacity；-1 = unknown
}

// SummaryComputer 是 fixpoint 计算器，每维度一个实例。
type SummaryComputer struct {
    store  db.Store
    parser *parser.Parser
    cfg    *CFGCache
    querier *Querier
    cache  map[string]*Summary
}

func (sc *SummaryComputer) SummaryOf(ctx context.Context, funcName string) (*Summary, bool)
```

**Step 2** 迁移 `computeRetNullable`（`planner/return_summary.go`）到 `graph/summary_null.go`，作为 `Summary.Null` 维度的计算。

**Step 3** 实现 `summary_interval.go`：复用 `range_flow.go` 的区间引擎，跨函数传播返回值区间。

**Step 4** 实现 `summary_taint.go`：复用 `filter_taint_source.go` 的 taint summary，对外暴露为 `Summary.Taint`。

**Step 5** 实现 `summary_capacity.go`：返回 `malloc(N)` 时 `Capacity = N`；返回静态数组时 `Capacity = ArrayLen`；其他场景 -1。

**Step 6** 迁移消费方：filter_taint_source / divide_by_zero / integer_overflow。

### 16.6 验收标准

- [ ] §2.1 全绿
- [ ] `summary_test.go` 覆盖 4 个维度
- [ ] 3 个消费方迁移完成
- [ ] benchmark A/B 差集为空
- [ ] `grep -n 'computeRetNullable' sgre/internal/planner/` 只剩 wrapper

### 16.7 回归测试落点

`graph/summary_test.go` + 消费方既有测试。

### 16.8 Commit 边界

4 个 commit：
1. `feat(graph): SummaryComputer framework`
2. `refactor(graph): migrate computeRetNullable to summary_null`
3. `feat(graph): summary_interval + summary_taint + summary_capacity`
4. `refactor(planner,evidence): consume SummaryComputer`

### 16.9 回滚预案

逐 commit revert。

### 16.10 DoD

§16.6 全勾 + 推送。**评估点 B 在此 Phase 完成后做**：v1.0.0 的功能完备性已达成；是否启动 Phase 14（graph 增量）由用户根据实测性能决定。

---

## 17. Phase 14：M8 graph 层增量（**默认不启动**）

### 17.1 目标

对 graph 层做增量：只重建受影响函数的边，未受影响函数保留。对应检视 §PERF-3 的"graph 增量"部分。**evidence/plan 层增量留作后续方案。**

### 17.2 前置条件

Phase 10-13 完成；`feature/arch-refactor-2026q4` 已合入 main 并发布至少一个版本；用户明确批准启动。

### 17.3 独立分支

从 `main` 派生 `feature/graph-incremental`，**不从 `arch-refactor-2026q4` 派生**——两者改动面不同，混合会增加 review 难度。

### 17.4 高层设计

1. indexer 已有 checksum 增量，把"受影响文件集合"向上暴露；
2. graph 层按"受影响函数集合 = 受影响文件内的函数 + 这些函数的直接调用方/被调方"计算增量范围；
3. 受影响函数的 CALL / DATA_FLOW / ALIAS / OWNERSHIP / INTERPROC / LOCK_ORDER / GLOBAL_ACCESS 边删除重建；
4. 未受影响函数的边保留；
5. CFG cache 调用 `Invalidate(fnID)` 失效受影响函数的缓存。

### 17.5 验收标准

- 小改动（单文件 < 10 行）重扫：`graph_ms` 相比全量下降 ≥ 80%；
- 大改动（重构涉及 > 50% 文件）：退化为全量，不慢于现状；
- benchmark A/B 差集为空（同一最终代码基，全量 vs 增量必须产出完全一致的图）。

### 17.6 风险

- 增量范围算错 → 漏建边 → 漏报。必须有"最终代码基一致"的 A/B 对比；
- 与 Phase 1 的 CFGCache 交互要小心：cache 必须按函数失效，不能按文件。

**本 Phase 详细实施步骤在启动时另行评审**（届时代码基已不同于本文档写作时，硬编码步骤会失真）。

---

## 18. 收尾与合并标准

### 18.1 合并 `feature/arch-refactor-2026q4` 到 `main` 的硬性条件

- [ ] Phase 0-9 全部完成（Phase 10-13 按评估点 A 的结果可选）
- [ ] §2.1 三条命令全绿
- [ ] benchmark A/B 差集为空
- [ ] `scan_runs.plan_ms` 相比基线下降 ≥ 30%（redis 规模）
- [ ] `scan_runs.detectors_ms` 相比基线下降 ≥ 20%
- [ ] `_index.md` 含 VerdictFacts 的候选占比 ≥ 60%
- [ ] 历史缺陷清单（`docs/GLM5.2检视sgre实现20260926.md` / `sgre_four_chain_review_20260930.md` / `buffer_overflow_oob_detection_defects.md` / `use_after_free_double_free_detection_defects.md` / `memory_leak_detection_defects.md` / `integer_overflow_detection_defects.md` / `divide_by_zero_detection_defects.md` / `uninit_detection_defects.md` / `GLM5.3检视typeof预处理链路20261002.md`）中**已修复**的条目，逐条复核未在本重构中回潮
- [ ] CHANGELOG.md 已补充本重构的用户可见变更

### 18.2 合并流程

```bash
git checkout main
git pull origin main
git merge --no-ff feature/arch-refactor-2026q4 -m "chore(release): merge arch-refactor-2026q4"
# 跑完整验证（§2.1 + §2.3 + 生产样例项目端到端）
git push origin main
```

**不在本 feature 分支上打 release tag**；合并到 main 后按既有 Release Process 走。

---

## 19. 风险登记册

| 风险 | 概率 | 影响 | 缓解 |
|---|---|---|---|
| Phase 1 CFGCache 并发 bug | 中 | plan 结果错误 | `zz_cfg_cache_integration_test.go` 并发断言；A/B 差集验证 |
| Phase 2 动态升级登记遗漏某 filter | 高 | confirmed 精准性违规继续 | marker 注释 + AST 扫描双重检查 |
| Phase 6 批次 B 体量过大 | 高 | Phase 6 拖延 | 允许批次 B 拆到下一阶段；批次 A 完成即可标 Phase 6 部分完成 |
| Phase 10 Querier 引入性能回退 | 中 | plan 变慢 | 双轨期 + benchmark 对比；发现回退立即 revert 迁移 detector |
| Phase 11 类型推断错误 → 误报 | 高 | 新形态误报 | `TypeOf` 返回 Unknown 时必须走 suspected；逐 detector 迁移 + A/B |
| Phase 12 跨函数别名过宽 → 漏报 | 中 | UAF/DF/ML 漏报 | 严格限定别名判定规则；宁可 suspected 不可 confirmed |
| Phase 14 增量范围算错 → 漏报 | 高 | 漏报 | 最终代码基 A/B 强一致性；默认不启动 |
| 多 Phase 并行导致冲突 | 中 | merge 冲突 | 严格按 §0.3 顺序推进，不并行（除 Phase 3 可与 1/2 并行） |
| token 预算不足 | 中 | Phase 6 批次 B / Phase 10-13 无法完成 | 允许在评估点 A 收尾；剩余 Phase 列为下一阶段工作 |

---

## 20. 进度追踪表

> 执行 Agent 在每完成一个 Phase 后更新此表，并同步更新 `docs/arch-refactor-2026q4-progress.md`。

| Phase | 名称 | 状态 | 完成日期 | 关键 commit | 实测收益 |
|---|---|---|---|---|---|
| 0 | 开工准备 | ☐ | | | |
| 1 | S1 CFG 缓存 | ☐ | | | detectors_ms / plan_ms 对比 |
| 2 | S3 confirmed 证明链 | ☐ | | | confirmed 精准审计报告 |
| 3 | S5 benchmark CI | ☐ | | | CI 首次运行链接 |
| 4 | S2 apikb 集中 | ☐ | | | 启发式替换计数 |
| 5 | S6 config 注入 | ☐ | | | `config.Load()` 调用数 |
| 6 | S4 VerdictFacts 推广 | ☐ | | 批次 A / 批次 B | `_index.md` facts 覆盖率 |
| 7 | M5 filter chain 声明式 | ☐ | | | registry.go 行数变化 |
| 8 | M6 registry 拆分 | ☐ | | | registry.go 行数变化 |
| 9 | M7 Candidate 分层 | ☐ | | | Candidate 字段数 |
| 10 | M1 graph 查询服务 | ☐ | | | 迁移 detector 数 |
| 11 | M2 类型系统 | ☐ | | | 迁移 detector 数 |
| 12 | M3 跨函数别名 | ☐ | | | UF/ML 误报修复计数 |
| 13 | M4 通用 summary | ☐ | | | 迁移消费方数 |
| 14 | M8 graph 增量 | ☐ 默认不启动 | | | graph_ms 对比 |

状态标记：`☐` 未开始 / `◐` 进行中 / `☑` 已完成 / `✗` 已取消。

---

## 21. 给执行 Agent 的最后叮嘱

1. **严格按 Phase 顺序推进**，不要跳步；每个 Phase 内部的 Step 也不要跳步。
2. **每个 commit 前跑 §2.1**，每个 Phase 结束前跑 §2.2 + §2.3。
3. **遇到方案与实际代码不符**（例如行号漂移、函数已改名），以代码为准并在 commit message 说明偏差；**不要硬套方案**。
4. **遇到方案未覆盖的决策点**，参考 `AGENTS.md` / `CLAUDE.md` / `AI_JUDGMENT_BOUNDARY.md`；仍无法决断时，**默认采取更保守的方向**（suspected 优于 confirmed，不误报优于不漏报）。
5. **任何"疑似用户既有偏好/历史决策"的冲突**，查阅 `MEMORY.md` 与本方案 §1 红线；仍冲突时**停下来问用户**，不要自作主张。
6. **修复用户报告的缺陷**时，fixture 必须用原帖精确形态（`fixture_use_exact_user_report_form`）。
7. **不要把 suspected 留给用户**——按 `suspected_findings_trust_rule.md`，AI 研判后不应再出现 suspected；本方案的所有"降级为 suspected"都**只在 AI 研判前的 pipeline 层**发生。
8. **本方案规模很大**，允许在评估点 A（Phase 9 完成后）或评估点 B（Phase 13 完成后）收尾，剩余 Phase 列为下一阶段工作。**不要为了"做完"而牺牲每个 Phase 的质量。**

---

**方案作者**：kimi-k3  
**基线 commit**：`db2f184e`（v0.9.9 预发布自检后）  
**输入文档**：`docs/kimi_k3_架构设计检视.md`  
**预期总工作量**：45-70 个工作日（Phase 0-13），Phase 14 另计