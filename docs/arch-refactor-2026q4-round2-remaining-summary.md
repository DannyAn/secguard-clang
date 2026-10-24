# 架构重构遗留工作（第二轮）收尾总结（2026-10-24）

> 分支：`feature/arch-refactor-2026q4`
> 前序：Phase 0-6（`arch-refactor-2026q4-phase0-6-summary.md`）+ Phase 7-13（`arch-refactor-2026q4-phase7-13-summary.md`）+ 遗留 6 项（`arch-refactor-2026q4-remaining-work-summary.md`）
> 本段：遗留工作的"第二轮"——TypeOf 参数解析 / MustNonNullAt 评估 / AliasGraph 跨函数扩展 / SummaryQuerier Interval+Taint / detector 迁移评估

## 本轮落地清单

| # | 遗留项 | 状态 | 关键 commit |
|---|---|---|---|
| 2a | TypeOf 参数类型解析（function_definition parameter_list） | ☑ | `28b480f8` |
| 1a | MustNonNullAt must-non-null lattice | ☑ **已评估不实施** | — |
| 3a | AliasGraph 跨函数扩展（return + 参数别名） | ☑ | `a75b4e05` |
| 4a | SummaryQuerier Interval + Taint 维度 | ☑ | `02203d30` |
| 3b | UAF/DF/ML/RL detector 迁移 AliasGraphFromCtx | ☑ **已评估不实施** | — |

## 各项落地详情

### 遗留 2a：TypeOf 参数类型（`28b480f8`）

- `Querier.TypeOf` 新增参数 fallback：从 fn body 的 `Parent()` 爬到 `function_definition`，再爬 `declarator` → `parameter_list` → 每个 `parameter_declaration`（type + declarator）
- `stripDeclaratorName` 处理 `*p` / `arr[8]` / `(*fp)` 声明符
- pinned 测试 `TestQuerierTypeOf_Parameter`：`int n` → Int32 / `unsigned long m` → Uint64 / `double d` → Float64 / `void *p` → ok=false

### 遗留 1a：MustNonNullAt must-non-null lattice（已评估不实施）

**评估结论**：现有引擎（null_flow 的 reaching-sources + guardModel）没有 must-non-null lattice，`reaching(v, line) == false` 只表示"没有 null 源到达"，不等于"证明 v 非空"（v 可能未初始化、可能是未追踪的表达式形状）。强行加 TriYes 会引入 unsound 升级风险，违反"confirmed 精准"红线。

**保留现状**：`MustNonNullAt` 只在 `reachingDefinite(v, line) == true`（证明 v 是 null）时返回 `TriNo`，否则 `TriUnknown`。这是诚实 seam——调用方拿到 Unknown 不会误升级。

**后续**：真正的 must-non-null lattice 需要"kill 的 must 版本"（从 entry 到 line 的每条路径都经过一条 non-null 建立边），这是 dominator + 路径敏感分析，独立 Phase 再做。

### 遗留 3a：AliasGraph 跨函数扩展（`a75b4e05`）

`BuildInterproceduralAlias` 从单遍函数内别名扩展为两遍：

**第一遍**（函数内 + 事实收集）：
- 函数内别名形态全覆盖（init/assign/cast/field/elem-addr）
- 收集每函数的 `functionAliasFacts{returnSources, params}`：
  - `returnSources`：`return p;` 的 p（return-alias 源）
  - `params`：形参名（从 parameter_list 解析）

**第二遍**（跨函数别名）：
- **return 别名**：caller 里 `q = foo()` 时，若 foo 的 body 有 `return p;`，则 `q ↔ p` 跨函数别名
- **参数别名**：caller 里 `foo(p)` 时，若 foo 的第 i 个形参是 `x`，则 `p ↔ x` 跨函数别名

pinned 测试：
- `TestBuildInterproceduralAlias_CrossFunction`：`caller.q` 的别名集含 `make_ptr.p`（return 别名）+ `use_ptr.x`（参数别名）
- `TestBuildInterproceduralAlias_NoCycle`：递归调用图（`f → g → f`）不死循环

**未做**：全局别名（`g = p` 且 g 是文件作用域变量）——需要 indexer 暴露文件作用域符号表，当前未暴露。

### 遗留 4a：SummaryQuerier Interval + Taint 维度（`02203d30`）

- `NewSummaryQuerier` 签名加 `taintCache *taintSummaryCache`（可 nil）
- `SummaryOf` 的 Interval 维度：单函数 return 语句区间 join
  - `return 42;` → `[42,42]`
  - `return d;`（d = 5）→ `[5,5]`（range flow 在 return 行的区间）
  - `return foo();` → foo 的 Summary.Interval（递归）
  - 多 return → join（hull）
- Taint 维度：读 `taintCache.get(ctx).retTainted[funcName]`（`TriYes` / `TriNo` / `TriUnknown`）
- pinned 测试 `TestSummaryQuerierIntervalDimension`：literal / range / mixed（join）/ nonexistent（Top）全覆盖

### 遗留 3b：detector 迁移 AliasGraphFromCtx（已评估不实施）

**评估结论**：4 个 detector（UAF / double-free / memory-leak / resource-leak）**已有成熟的函数内别名**（`findAliases` + `terminalBaseVar`，ML-05 / UF-02 已修复）。AliasGraph 的跨函数别名是**补充**而非**替代**——直接迁移会破坏 detector 的现有行为（findAliases 区分 field alias vs whole-variable alias，AliasGraph 的对称别名不区分）。

**正确路径**：detector 在判 `free(q)` 是否释放 `p` 时，**除了**查自己的 findAliases，**再查** AliasGraph 的跨函数别名（`AliasGraphFromCtx(ctx).AliasesOf(...)`)。这是加法，但需要独立的 benchmark A/B 验证（改 detector 行为 = 改候选集合 = 必须验证 FP/FN 漂移）。

**本段不动 detector**，留作后续独立 PR（每 detector 一个 commit + A/B 验证）。

## 验收

| 验收项 | 结果 |
|---|---|
| `go build ./...` | ☑ |
| `go test ./...`（14 个包） | ☑ |
| `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | ☑ |
| benchmark A/B（`examples/c-vuln-benchmark`） | final=84 / seeds=681（与基线完全一致） |
| 新增 pinned 测试 | `TestQuerierTypeOf_Parameter` / `TestBuildInterproceduralAlias_CrossFunction` / `TestBuildInterproceduralAlias_NoCycle` / `TestSummaryQuerierIntervalDimension` 全绿 |

## 后续工作（最终优先级）

### 高（直接影响跨函数看护准确率）

1. **detector 迁移 AliasGraphFromCtx（跨函数别名补充）**——UAF / double-free / memory-leak / resource-leak 各自在判 `free(q)` 时补充查 AliasGraph 的跨函数别名，每 detector 独立 commit + benchmark A/B
2. **TypeOf 的 typedef / struct 字段解析**——接 repofacts
3. **SummaryQuerier Capacity 维度**——接 malloc 大小分析（`malloc(N)` → Capacity=N）

### 中（性能与架构完备性）

4. **AliasGraph 全局别名**——indexer 暴露文件作用域符号表后接入
5. **Querier 接入 detector**——null-deref / divide-by-zero / integer-overflow 的 guard 判定迁移到 `Querier.MayBeNullAt` / `Querier.IntervalAt` / `Querier.TypeOf`

### 低（独立评审）

6. **Phase 14（M8 graph 层增量扫描）**——方案默认不启动
7. **F1-F4 真实 AI 研判会话复测**——需真实 AI 会话

## Commit 时间线（本段）

```
683ac556 chore(planner): gofmt trailing blank lines in filter_chain.go
28b480f8 feat(planner): Querier.TypeOf parameter fallback via function_definition parameter_list
a75b4e05 feat(graph): AliasGraph cross-function return-alias + parameter-alias edges
02203d30 feat(planner): SummaryQuerier Interval + Taint dimensions (interval join + taintSummaryCache)
```