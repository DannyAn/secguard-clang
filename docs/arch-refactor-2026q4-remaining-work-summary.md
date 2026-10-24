# 架构重构遗留工作收尾总结（2026-10-24）

> 分支：`feature/arch-refactor-2026q4`
> 前序：Phase 0-6（`docs/arch-refactor-2026q4-phase0-6-summary.md`）+ Phase 7-13（`docs/arch-refactor-2026q4-phase7-13-summary.md`）
> 本段：8 项遗留工作中 6 项落地（另 2 项按方案默认不做）

## 遗留工作落地清单

| # | 遗留项 | 状态 | 关键 commit |
|---|---|---|---|
| 5 | FilterFactories 显式化 + 删 FilterChain 桥接 | ☑ | `f39f7c5c` |
| 6 | buildXXXVerdictFacts 拆到 registry_<type>.go | ☑ | `d3add17c` |
| 1 | Querier MustNonNullAt/MayBeNullAt 真实实现 | ☑ | `5e4c4131` |
| 4 | SummaryQuerier 接入 computeRetNullable | ☑ | `2945ef2c` |
| 3 | AliasGraph 构建器 + ctx 挂载 | ☑ | `2ac3005b` / `8fd41aa4` |
| 2 | TypeOf 骨架落地 + TypeByName signed/unsigned | ☑ | `abc8b7bb` |
| 7 | Phase 14（M8 graph 层增量扫描） | ✗ 按方案默认不启动 | — |
| 8 | F1-F4 修复后的真实 AI 研判会话复测 | ✗ 需真实 AI 会话，本 agent 无法执行 | — |

## 各项落地详情

### 遗留 5：FilterFactories 显式化（`f39f7c5c`）

- 25 个 `registry_<type>.go` 全部显式声明 `FilterFactories: chainXxx()`
- `RegisterVulnType` 删除桥接：FilterFactories 为空 → **panic**（注册期 bug，而非运行期回退）
- `Planner.buildFilters` 删除 `getFilters` legacy switch 回退
- 删除 `filterFactoriesFor` 桥接函数 + `getFilters` legacy switch（-176 行）
- `ValidateRegistry` 改为走 `buildFilters`（声明式）
- 全量测试绿，A/B 一致

### 遗留 6：registry builders 拆分（`d3add17c`）

- 15 个 `buildXXXVerdictFacts` 从 `registry.go` 搬到对应 `registry_<type>.go`
- 共享 builder（`buildBufferVerdictFacts` / `buildLeakVerdictFacts`）留 `registry.go`（buffer-overflow + out-of-bounds / memory-leak + resource-leak 共用）
- `registry.go` 从 985 行降到 **592 行**
- helpers（`derivedSuffix` / `otherDerefLines` / `joinLines` / `containsString` / `maskSecret` / `nullableSourceDetail` / `taintSourceDetail` / `victimSuffix`）留 `registry.go`（同包可用）

### 遗留 1：Querier null 真实实现（`5e4c4131`）

- `MayBeNullAt(ctx, fn, v, line)`：通过 `nullFlowFor` 构建 fn 的 null-source reaching-sources 流（复用 Phase 1 的 cfgCache + `buildNullModel` + `nullSourcesFor`），`flow.reaching(v, line)` → `TriYes` / 否则 `TriUnknown`
- `MustNonNullAt(ctx, fn, v, line)`：`flow.reachingDefinite(v, line)` → `TriNo`（证明 v 是 null → must-non-null 为假）；否则 `TriUnknown`（**保守 seam**——无 must-non-null lattice，不证明"不可能 null"）
- pinned 测试 `TestQuerierMayBeNullAt_RealFlow`：`p = NULL; *p` 场景 `MayBeNullAt=TriYes` / `MustNonNullAt=TriNo`；无 source 变量两个都 `TriUnknown`

**关键设计**：`nullFlowFor` 复用 detector 阶段的 `NULL_VALUE` 事件池（与 NullableSourceFilter 同源），答案与 pipeline 的 null-deref 判定**一致**，不是独立推导。

### 遗留 4：SummaryQuerier Null 维度（`2945ef2c`）

- `SummaryOf(ctx, funcName)` 的 `Null` 维度通过**递归 return 语句下降**计算：
  - `return NULL/0` → `TriYes`
  - `return foo()` → 递归 `SummaryOf(foo)`（带 cycle guard）
  - 所有 return 都可证非空（string literal / 非零数字 / `&x`）→ `TriNo`
  - 其他 → `TriUnknown`
- `memo` 缓存 + `visiting` cycle guard
- pinned 测试 `TestSummaryQuerierNullDimension`：`returns_null` → TriYes / `returns_propagated`（递归）→ TriYes / `returns_int` → TriNo / `returns_string` → TriNo / `nonexistent` → TriUnknown
- Interval / Taint / Capacity 保持 unknown 占位

### 遗留 3：AliasGraph 构建器 + ctx 挂载（`2ac3005b` / `8fd41aa4`）

- `graph.BuildInterproceduralAlias(ctx, store, parser)`：每文件一次解析，按函数提取别名
- 函数内别名形态全覆盖：
  - 声明初始化 `T *q = p;`
  - 普通赋值 `q = p;`
  - cast 别名 `q = (T*)p;`
  - 字段别名 `q = p->f;`
  - 元素地址 `q = &p[i];`
- `extractIdentifierFromDeclarator` 处理 `*q` / `**p` / `arr[8]` / `(*fp)` 声明符
- `graph.WithAliasGraph` / `AliasGraphFromCtx` ctx 传递（与 Phase 1 的 CFGCache 同模式）
- `pipeline.runPipeline` 启动时构建一次，通过 ctx 共享给 detector 和 planner
- pinned 测试 `TestBuildInterproceduralAlias_LocalShapes`：`p/q/r` 一个别名集，`s = p+1`（算术）与 `n = 42`（字面量）正确排除

**未做**：detector 迁移（UAF 已有自己的 `findAliases`，double_free 迁移会改变行为，需单独 A/B 验证——留作后续独立 PR）。

### 遗留 2：TypeOf 骨架落地（`abc8b7bb`）

- `graph.Querier` 接口新增 `TypeOf(ctx, fn, v) (Type, bool)`
- `planner.querier.TypeOf`：扫描 fn body 的 declaration，按声明符匹配变量名，`graph.TypeByName(typ.Text())` 解析
- `TypeByName` 扩展支持 `unsigned X` / `signed X` 前缀（`unsigned long` → Uint64 / `signed char` → Int8）
- pinned 测试 `TestQuerierTypeOf`：`int i` → Int / `unsigned long ul` → Uint / `size_t s` → Uint / `double d` → Float / `void *p` → ok=false（指针不在名字表，诚实 Unknown）

## 验收

| 验收项 | 结果 |
|---|---|
| `go build ./...` | ☑ |
| `go test ./...`（14 个包） | ☑ |
| `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | ☑ |
| benchmark A/B（`examples/c-vuln-benchmark`） | final=84 / seeds=681（与基线完全一致） |
| benchmark validator（`--allow-fn`） | exit=0，FP=0/113 |
| 新增 pinned 测试 | `TestQuerierMayBeNullAt_RealFlow` / `TestSummaryQuerierNullDimension` / `TestBuildInterproceduralAlias_LocalShapes` / `TestQuerierTypeOf` 全绿 |

## 后续工作（优先级排序）

### 高（直接影响跨函数看护准确率）

1. **UAF / double-free / memory-leak / resource-leak 四 detector 迁移到 `AliasGraphFromCtx`**——替换各自 `findAliases` / 补 double_free 的别名缺失（历史 UF-02/UF-04/ML-02 根因），每 detector 独立 commit + A/B 验证
2. **Querier.MustNonNullAt 的 must-non-null lattice**——当前保守 Unknown，接入 guardModel 的 dominator 分析后可给 TriYes
3. **TypeOf 参数类型解析**——从 fn.Signature 解析参数类型（当前只覆盖局部声明）

### 中（性能与架构完备性）

4. **AliasGraph 跨函数扩展**：return 别名（`return p`）/ 参数别名（`f(p)` 形参↔实参）/ 全局别名（`g = p`）
5. **SummaryQuerier 其他维度**：Interval（接 `nonZeroReturn`）/ Taint（接 taint summary）/ Capacity（接 malloc 大小分析）
6. **TypeOf 的 typedef / struct 字段解析**——接 repofacts

### 低（独立评审）

7. **Phase 14（M8 graph 层增量扫描）**——方案默认不启动，需独立 feature 分支 + 最终代码基 A/B 强一致性验证
8. **F1-F4 真实 AI 研判会话复测**——需 deploy.sh 部署后真实 AI 会话，本 agent 无法执行

## Commit 时间线（本段）

```
f39f7c5c refactor(planner): FilterFactories explicit on all 25 types, drop legacy FilterChain bridge
d3add17c refactor(planner): move 15 buildXXXVerdictFacts into per-type registry_<type>.go (registry.go 985->592 lines)
5e4c4131 feat(planner): Querier MayBeNullAt/MustNonNullAt real implementation via null_flow engine
2945ef2c feat(planner): SummaryQuerier Null dimension via recursive return-statement descent
2ac3005b feat(graph): BuildInterproceduralAlias function-local alias shapes (init/assign/cast/field/elem-addr)
8fd41aa4 feat(graph,cli): AliasGraph ctx plumbing, built once per scan and shared across stages
abc8b7bb feat(graph,planner): Querier.TypeOf skeleton + TypeByName signed/unsigned prefix support
```