# 架构重构 Phase 7-13 收尾总结（2026-10-23 深夜）

> 分支：`feature/arch-refactor-2026q4`
> 前序：Phase 0-6 见 `docs/arch-refactor-2026q4-phase0-6-summary.md`
> 本段：Phase 7-13 共 11 个 commit

## 本轮落地范围

按方案推进 Phase 7-13。**Phase 14（M8 graph 层增量）按方案默认不启动**，留作后续独立评审。

| Phase | 名称 | 交付形态 | 关键 commit |
|---|---|---|---|
| 7 | M5 filter chain 声明式化 | **完整落地** | `0a5ca67f` / `12aef7d9` |
| 8 | M6 registry.go 拆分 | **完整落地** | `6f4d03fa` |
| 9 | M7 Candidate/eventProps 分层 | **零破坏落地**（嵌入方案撤回，改类型化视图） | `fc399d5a` / `98c0bfa0` |
| 10 | M1 graph 语义查询服务 | **骨架版**（Querier 接口 + IntervalAt 实现 + Must/MayNull 保守 seam） | `80a9992d` / `80b0ae53` / `8c14c342` |
| 11 | M2 类型系统 | **骨架版**（Type model + LP64 宽度表 + TypeByName） | `0e344fd0` |
| 12 | M3 跨函数别名 | **骨架版**（AliasGraph + AliasQuerier 接口） | `3e969384` |
| 13 | M4 通用函数 summary | **骨架版**（SummaryQuerier 接口 + 未知占位） | `984b8e4f` / `e0247397` |

## 关键架构判断

### Phase 7：filter chain 声明式化

- `VulnTypeSpec.FilterFactories []FilterFactory` 字段就位；`RegisterVulnType` 在 FilterFactories 为空时自动从 `FilterChain` 字符串映射到声明式 chain——**迁移桥**。
- `Planner.buildFilters(spec)` 替代 `getFilters(chain string)`，优先走声明式。
- 25 个 vuln type 全部通过 `filterFactoriesFor` 自动桥接，零行为变化；`TestFilterChainMigration` 锁定 25 个类型的 filter 名称与顺序。
- **后续**（不在本段）：把每个类型的 FilterFactories 从桥接改为显式声明，然后删除 `FilterChain` 字符串字段。

### Phase 8：registry.go 拆分

- 1901 行的 `registry.go` 拆为 **985 行主体 + 25 个 `registry_<type>.go` 独立文件**（每文件 25-83 行）。
- 采用**包内分文件**方案（25 个 init() 都在 `package planner`），避免 import cycle 与私有 builders 可见性问题。
- `skills/vuln_type_skill_fragments_test.go` 同步修正：`registryFragmentSets` 扫描 `registry.go` + `registry_*.go`。

### Phase 9：Candidate 分层（零破坏方案）

**嵌入方案撤回**：`Candidate struct { CommonCandidate; ... }` 在 struct literal 场景要求所有调用点改为嵌套初始化，涉及 17 个测试文件，改动成本远超收益。

**采纳方案**：`Candidate` 保持 70+ 字段平铺（向后兼容），新增**类型化只读视图**：
- `Common() CommonCandidate`：共用字段快照
- `Leak() LeakPayload` / `Free() FreePayload` / `Buffer() BufferPayload`
- `IntOverflow() IntOverflowPayload` / `Race() RacePayload`
- `Divisor() DivisorPayload` / `Contract() ContractPayload`

视图是快照（snapshot），修改视图不影响源 Candidate。测试 `TestCandidateTypedViews` 锁定契约。

**后续**（不在本段）：逐步把 filter / report 消费侧从"直接读 70+ 字段"改为"读对应 payload 视图"，然后才能把字段从 Candidate 搬到各 payload。

### Phase 10：Querier 骨架（graph 层语义查询服务起点）

- `graph.Querier` 接口：`MustNonNullAt` / `MayBeNullAt` / `IntervalAt`
- `graph.Tri` 三态（`TriUnknown / TriYes / TriNo`）
- `graph.Interval` 区间类型
- `planner.querier` 实现：`IntervalAt` 委托给 `analyzeRangesWithCalls`（复用 Phase 1 的 cfgCache），`MustNonNullAt` / `MayBeNullAt` 保守返回 `TriUnknown`（**诚实 seam**，防止调用方基于不完整证明升级候选）
- Planner 持有 Querier，通过 `Planner.Querier()` 暴露；挂在同一份 `cfgCache` 上，与 Phase 1 的缓存贯通

**关键设计**：Querier 接口在 graph 包（让 evidence / cli 可消费而不依赖 planner），实现在 planner 包（复用现有 null_flow / range_flow 引擎）。

### Phase 11：Type 模型骨架

- `graph.Type{Kind, Width, Signed, Pointee, Elem, ArrayLen, Name, TypedefOf}`
- `TypeKind` 枚举：Unknown / Int / Uint / Float / Pointer / Array / Struct / Union / Function / Void
- `lp64Widths` 类型宽度表（LP64 模型，LLP64 后续通过 config 注入）
- `TypeByName(name)` 按名字解析（`int` → Int32 signed，`uint32_t` → Uint32，`double` → Float64）
- `SignedMax / SignedMin / UnsignedMax` 边界助手

**未做**（留后续）：detector 迁移到 `Querier.TypeOf`；LLP64 支持；跨 typedef / struct 字段的类型推断。

### Phase 12：AliasGraph 骨架

- `graph.AliasKey{FunctionID, Name}`：跨函数变量标识
- `graph.AliasGraph`：邻接表 + `AliasesOf` 传递闭包查询
- `graph.AliasQuerier` 接口：`AliasSet(ctx, fn, v, line) []string`

**未做**（留后续）：跨函数别名的实际构建逻辑（`BuildInterproceduralAlias`）；4 个 detector（UAF / double-free / memory-leak / resource-leak）迁移到 AliasQuerier。

### Phase 13：SummaryQuerier 骨架

- `graph.Summary{Function, Null, Interval, Taint, Capacity}`：跨函数返回行为摘要
- `graph.SummaryQuerier` 接口：`SummaryOf(name)` / `SummaryByID(fn)`
- `planner.summaryQuerier` 骨架实现：**所有维度返回"未知占位"**——诚实 seam，防止调用方误信

**未做**（留后续）：把 `computeRetNullable`（null 维度）/ `nonZeroReturn`（interval 维度）/ taint summary（taint 维度）/ capacity 分析迁移到统一 SummaryComputer；3 个消费方（filter_taint_source / divide_by_zero / integer_overflow）迁移。

## 验收结果

| 验收项 | 结果 |
|---|---|
| `go build ./...` | ☑ |
| `go test ./...`（14 个包） | ☑ |
| `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | ☑ |
| benchmark A/B（`examples/c-vuln-benchmark`） | final=84 / seeds=681（与基线完全一致） |
| benchmark validator（`--allow-fn`） | exit=0，FP=0/113 |
| `TestConfirmedTierPolicy` | ☑ |
| `TestVulnTypeSkillConsistency` | ☑ |
| `TestDynamicConfirmedUpgradesRegistered` | ☑ |
| `TestFilterChainMigration`（新） | ☑ |
| `TestCandidateTypedViews`（新） | ☑ |
| `TestQuerierIntervalAt` / `TestQuerierNullSeam`（新） | ☑ |
| `TestTypeModel` / `TestTypeByName`（新） | ☑ |
| `TestAliasGraphClosure` / `TestAliasQuerierInterface`（新） | ☑ |
| `TestSummaryQuerierSeam`（新） | ☑ |

## extension 侧兼容性

- extension 仅通过 `execFile("secguard", ...)` 调 CLI，**零 Go 包依赖**
- 本段未改任何 CLI 命令 / 参数 / stdout JSON schema
- `secguard scan / metrics / report / types` 端到端已验证

## 后续工作（按优先级）

### 立即（下个 PR）

1. **FilterFactories 显式声明**（Phase 7 后续）：25 个类型的 `RegisterVulnType` 里把 `FilterFactories: chainXxx()` 显式写出，删除 `FilterChain` 字符串字段与 `filterFactoriesFor` 桥接
2. **registry builders 拆分**（Phase 8 后续）：`buildXXXVerdictFacts` 与 `buildXXXEvidence` 从 registry.go 搬到对应 `registry_<type>.go`

### 短期（1-2 周）

3. **Querier.MustNonNullAt 实现**：把 null_flow 的 guardModel + reaching-sources 引擎暴露为 must-non-null 查询（当前是保守 Unknown）
4. **TypeOf 实现**：基于 `graph.Type` 表 + db.Variable / db.Function 声明，让 divide-by-zero / integer-overflow / argument-type / data-representation 迁移
5. **AliasGraph 构建**：`BuildInterproceduralAlias` 从 q=p / return p / 参数别名 / 全局别名提取边；4 个 detector 迁移

### 中期（2-4 周）

6. **SummaryComputer 全维度**：把 computeRetNullable / nonZeroReturn / taint / capacity 迁移为统一 fixpoint
7. **detector 迁移到 Querier**：每个 detector 一个 commit，逐类型迁移 + A/B 验证
8. **Phase 14（M8 graph 层增量）**：独立分支、独立评审，需要最终代码基 A/B 强一致性

## Commit 时间线（Phase 7-13）

```
0a5ca67f feat(planner): FilterFactory + FilterDeps + VulnTypeSpec.FilterFactories with RegisterVulnType bridge
12aef7d9 test(planner): TestFilterChainMigration pins declarative filter chain order
6f4d03fa refactor(planner): split registry.go 25 RegisterVulnType calls into per-type files
7aed18e1 chore(planner): gofmt spacing around SetCFGCache methods
fc399d5a fix(skills): registryFragmentSets reads registry.go + registry_*.go (Phase-8 split)
98c0bfa0 feat(planner): typed views over Candidate (Common/Leak/Free/Buffer/IntOverflow/Race/Divisor/Contract)
80a9992d feat(graph): Querier interface + Tri verdict + Interval type (semantic-query facade)
80b0ae53 feat(planner): Querier implementation delegating to null_flow/range_flow engines
8c14c342 test(planner): pin Querier IntervalAt + conservative null seam
0e344fd0 feat(graph): Type model + LP64 width table + TypeByName (M2 type-system skeleton)
3e969384 feat(graph): AliasGraph + AliasQuerier interface (M3 interprocedural-alias skeleton)
984b8e4f feat(graph,planner): SummaryQuerier interface + skeleton (M4 cross-function summary seam)
e0247397 test(planner): pin SummaryQuerier unknown-placeholder contract
```