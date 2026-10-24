# 架构重构 2026Q4 关闭清单（2026-10-24）

> 分支：`feature/arch-refactor-2026q4`（累计 45+ commits）
> 本文档关闭所有"已评估不实施"的悬而未决项，说明理由，不留模糊地带。

## 关闭项清单

| # | 项 | 状态 | 理由 |
|---|---|---|---|
| 1 | **MustNonNullAt must-non-null lattice** | **关闭** | 现有引擎（null_flow reaching-sources + guardModel）没有 must-non-null lattice；`reaching(v,line)==false` 只表示"没有 null 源到达"，不等于"证明 v 非空"（v 可能未初始化/未追踪表达式）。强行加 TriYes 会引入 unsound 升级风险，违反 confirmed 精准红线。保留保守 seam（reachingDefinite→TriNo，否则 Unknown）。 |
| 2 | **Phase 14（M8 graph 层增量扫描）** | **关闭（本版本）** | 方案默认不启动；增量扫描需独立 feature 分支 + 最终代码基 A/B 强一致性验证，工作量 5-8 天，不在本版本范围。 |
| 3 | **F1-F4 真实 AI 研判会话复测** | **关闭（本版本）** | 需真实 AI 会话（Claude Code / OpenCode / claude-cac）部署后实测 evidence_opens ≤ 20；本 agent 无法执行真实 AI 会话，留待用户本地 E2E 验证。 |
| 4 | **UAF/DF/ML/RL detector 迁移 AliasGraphFromCtx** | **关闭（本版本）** | 4 个 detector 已有成熟函数内别名（findAliases + terminalBaseVar，ML-05/UF-02 已修复）；跨函数别名是**补充**而非替代，直接迁移会破坏 field alias vs whole-variable alias 的区分。跨函数 double-free 骨架已就位但未启用（需 AliasGraph 标记边 provenance 才能正确聚合）。 |
| 5 | **TypeOf 的 typedef / struct 字段解析** | **关闭（本版本）** | typedef/struct 字段解析需接 repofacts 的结构体布局表；当前 TypeOf 已覆盖局部声明 + 参数（parameter_list），typedef/struct 是后续独立 Phase。 |
| 6 | **AliasGraph 全局别名完整实现** | **关闭（本版本）** | 全局别名骨架已落地（`g = p` 且 g 不在 locals → FunctionID=0）；完整实现需 indexer 暴露文件作用域符号表（含 static 全局 vs extern 全局的区分），后续独立 Phase。 |
| 7 | **SummaryQuerier Capacity 维度的非字面量大小** | **关闭（本版本）** | 当前只覆盖 `malloc(N)` / `calloc(N,M)` 字面量大小；非字面量大小（`malloc(n)` 变量）需接 range_flow 的区间分析，后续独立 Phase。 |

## 启用条件（留给后续版本）

- **跨函数 double-free**（`detectCrossFunctionDoubleFree`）：需 `AliasGraph.Add` 加 `EdgeKind` 标记（`return-alias` / `parameter-alias` / `global-alias` / `local-alias`），然后 detectCrossFunctionDoubleFree 只聚合 `return-alias` 边。
- **MustNonNullAt TriYes**：需 graph 层实现 must-non-null lattice（kill 的 must 版本，dominator + 路径敏感）。
- **TypeOf typedef/struct**：需 repofacts 暴露 `StructLayout(name) → map[field]Type` 查询。

## 本版本交付确认

- [x] 全部 Go 测试绿（14 个包）+ nosqlite 子集绿
- [x] benchmark A/B `final=84 seeds=681` 与基线完全一致
- [x] benchmark validator `--allow-fn` exit=0，FP=0/113
- [x] 无未提交改动
- [x] 无"半完成"状态（所有骨架要么完整落地，要么明确关闭并写入启用条件）