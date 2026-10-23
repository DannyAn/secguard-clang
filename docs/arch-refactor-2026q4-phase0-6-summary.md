# 架构重构 Phase 0-6 收尾总结（2026-10-23）

> 分支：`feature/arch-refactor-2026q4`
> 基线：main @ `db2f184e` → 完成于 `c74b7b63`
> 输入方案：`docs/kimi_k3_架构优化改善实施方案.md`

## 本次落地范围

按方案的「评估点 A 前」部分推进，完成 Phase 0-6 共 7 个阶段、14 个 commit。

| Phase | 名称 | 状态 | 关键 commit |
|---|---|---|---|
| 0 | 开工准备（feature 分支 + 基线） | ☑ | `932077de` |
| 1 | S1 函数级 CFG 缓存 | ☑ | `5a42aa91` / `deff32d9` / `d18e3045` |
| 2 | S3 confirmed 证明链机器守卫 | ☑ | `621541de` / `17917b9b` / `cc45cfa2` |
| 3 | S5 benchmark PR 级 CI | ☑ | `784b815b` |
| 4 | S2 apikb 函数分类集中（`integer_overflow.isSizeFunction`） | ☑ | `0e3c2fd0` |
| 5 | S6 config 显式告警（`Load` 读不到/解析失败打 stderr） | ☑ | `d5f2d9a1` |
| 6 | S4 Evidence Contract v2 批次 A（补 `integer-overflow` + `unchecked-return`） | ☑（2/2 示范） | `3b95ea34` / `c74b7b63` |

Phase 7-14（M5 filter chain 声明式化 / M6 registry 拆分 / M7 Candidate 分层 / M1-M4 graph 层升级 / M8 增量）**留作下一阶段**。理由：
- 短期 6 项（S1-S6）已全部落地；
- Phase 6 批次 A 的 5 个目标类型中，memory-leak / resource-leak / uninit 在现状 registry.go 里已有 `BuildVerdictFacts`，本轮只需补 integer-overflow / unchecked-return 两个缺失项（已完成）；
- 中期 M5/M6/M7 是结构性大改造，token 预算内做完会牺牲质量；方案明确允许在评估点 A 收尾。

## 落地数据

### Phase 1：CFG 缓存架构收益

`secguard scan examples/c-vuln-benchmark` 一次扫描内：

```
cfg cache stats after detectors: builds=366 hits=3299
cfg cache stats after plan:      builds=366 hits=3525
```

**366 个唯一函数 / 3891 次 CFG 访问 / 3525 次 cache 命中**——同一函数 CFG 从"每个消费者重建一次"（理论 3891 次构建）降到"每函数一次"（366 次构建），**消除 90.6% 的重复构建**。

绝对耗时在小负载（53 文件 / 366 函数）下处于本机噪音范围（1277ms vs 基线 1307ms，<3%）；在 redis 级负载（786 文件 / 11225 函数）下按 cache 命中率外推，plan + detectors 阶段预期降 30-50%。

### Phase 2：confirmed 证明链

- 新建 `planner/proof_class.go`：四类证明手段（`cfg-must-dataflow` / `interval-or-const-fold` / `literal` / `type-inherent`）+ `Proof` 结构 + `ProofRegistrar` 接口
- 12 个会升级 confirmed 的 filter 全部实现 `DeclaredProofs()`：NullableSourceFilter / LifetimeFilter / DoubleFreeFilter / TaintSourceFilter / RangeFilter / RangeOOBFilter / ReturnCheckFilter / LockOrderFilter / SharedAccessFilter / DefiniteInitFilter / LeakProofFilter / HardcodedSecretProofFilter
- `TestDynamicConfirmedUpgradesRegistered` 机器守卫上线：**新增任何 filter 内 confirmed 升级而未登记者，构建失败**
- `AI_JUDGMENT_BOUNDARY.md` 新增「动态升级登记（v0.10.0 起）」章节

### Phase 3：benchmark PR CI

- `.github/workflows/pr-benchmark.yml`：PR 触发，构建 → nosqlite 测试 → 扫 benchmark → `report --audit` → validator
- 校验红线：`validate-benchmark.py --allow-fn`（FP=0 强制；FN 允许因 CI 无 LLM 环节）
- `docs/benchmark-ci.md` 记录本地复现步骤

### Phase 4：apikb 集中

- `integer_overflow.isSizeFunction` 从 `strings.Contains(name, "alloc")` 改为 `apikb.IsAllocator(name)`——享受 alloca 反表 / `_create` 反表 / `IsDeclaredAllocator` 精确表的全部既有积累
- 其他 detector 审计后无需改动（memory_leak / resource_leak / unchecked_return / use_after_free / double_free / buffer_overflow 已无 `strings.Contains(name, ...)` 启发式）

### Phase 5：config 显式告警

- `config.Load()` 在配置文件**找到但读不出/解析失败**时打 `secguard: config load warning: ...` 到 stderr，不再静默吞错（历史 v0.7.0 事故的根因修复）
- pinned 测试 `TestLoad_LogsOnUnreadableConfig` 锁定该契约
- 完全向后兼容：detector / planner 的 14 处 `config.Load()` 调用点零改动

### Phase 6：Evidence Contract v2 批次 A

- `integer-overflow` 新增 `buildIntegerOverflowVerdictFacts`：`cat@<category>` / `lhs@<kind>` / `rhs@<kind>` / `sink@<shape>` 四个维度
- `unchecked-return` 新增 `buildUncheckedReturnVerdictFacts`：`api@<name>` / `contract@known|unknown` / `discard` / `callee@<file>:<line>` 四个维度
- pinned 测试 `zz_verdict_facts_phase6_test.go` 锁定两 builder 产出

## 验收

| 验收项 | 结果 |
|---|---|
| `go build ./...` | ☑ |
| `go test ./...`（14 个包） | ☑ |
| `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | ☑ |
| benchmark A/B 候选 / 种子数 | 84 / 681（与基线完全一致） |
| benchmark validator（`--allow-fn`） | exit=0，**FP=0/113** |
| `TestConfirmedTierPolicy` | ☑ |
| `TestVulnTypeSkillConsistency` | ☑ |
| `TestDynamicConfirmedUpgradesRegistered`（新） | ☑ |
| `TestStmtCFGSharedAcrossFilters`（新） | ☑ |
| `TestLoad_LogsOnUnreadableConfig`（新） | ☑ |
| `TestIntegerOverflowVerdictFacts` / `TestUncheckedReturnVerdictFacts`（新） | ☑ |
| `TestCFGCache*`（5 个新测试） | ☑ |

## 未启动项与理由

- **Phase 7 M5（filter chain 声明式化）**：改动 `VulnTypeSpec` 与 `planner.getFilters`，量大但收益单一（可维护性）；
- **Phase 8 M6（registry 拆分）**：83K 单文件拆 25 个，纯体力活，任何阶段可做；
- **Phase 9 M7（Candidate 分层）**：涉及 detector 写入侧与 planner 读取侧同步改造，改动面最大；
- **Phase 10-13 M1-M4（graph 语义查询服务 / 类型系统 / 跨函数别名 / 通用 summary）**：架构性升级，每个独立估算 3-5 天，需要独立评审与独立 feature 分支；
- **Phase 14 M8（graph 层增量）**：方案默认不启动。

以上 5 项均已在 `docs/kimi_k3_架构优化改善实施方案.md` 中有完整的 Step / 验收 / 回滚预案，**下一阶段可直接由方案驱动**，无需重新设计。

## extension 侧兼容性确认

- extension 下所有对 sgre 的调用都通过 `execFile("secguard", [...])` CLI 边界，**不 import Go 包**；
- 本重构**未改动**任何 CLI 命令名 / 参数 / stdout JSON schema；
- 已用 `secguard scan` / `secguard metrics` / `secguard report --audit` 端到端验证 CLI 契约稳定；
- `secguard types` 输出不变（25 个注册类型名单保持一致）。

## 关键架构判断（留给下次评审）

1. **S1 CFG 缓存已铺好"detector 与 planner 共享一份"的通道**，是未来 graph 层语义查询服务（Phase 10 M1）的物理通道——`Querier` 落地时可以直接复用 `planner.cfgCache` + `evidence.withCFGCache` 这一对机制；
2. **S3 证明链机器守卫已把"confirmed 精准性"从文档约束升级为构建约束**，后续任何 filter 升级 confirmed 而未登记将被构建失败拦截；
3. **S4 批次 A 仅做 2 个示范类型**，但 VerdictFacts 的模式已固定在 registry.go 里（17/25 已有）；批次 B 的 8 个剩余类型（use-after-free / race-condition / deadlock / signed-compare / dangerous-function / injection / implicit-contract 精化 / format-string 精化）可按同模板逐类型补齐；
4. **io-21 遗留**（integer-overflow benchmark ground truth 与单测矛盾）**未在本轮裁定**——需要用户确认权威期望后再动，本 PR 不夹带。

## Commit 时间线

```
ff4560fc docs(arch): kimi-k3 architecture review + refactor implementation plan
932077de chore(arch): bootstrap arch-refactor-2026q4 branch with baseline
5a42aa91 feat(graph): add CFGCache for per-function statement CFG reuse
deff32d9 refactor(evidence,planner,cli): route BuildStmtCFG through the shared CFGCache
d18e3045 test(planner): pin CFG sharing across filters (zz_cfg_cache_integration_test)
621541de feat(planner): ProofClass + ProofRegistrar interface
17917b9b refactor(planner): register DeclaredProofs on all 12 confirmed-upgrading filters
cc45cfa2 test(planner): TestDynamicConfirmedUpgradesRegistered machine guard + boundary doc
784b815b ci(benchmark): add pr-benchmark.yml workflow + local repro docs
0e3c2fd0 refactor(evidence/integer_overflow): route isSizeFunction through apikb.IsAllocator
d5f2d9a1 refactor(config): Load logs a stderr warning on unreadable/invalid config
3b95ea34 feat(planner): BuildVerdictFacts for integer-overflow and unchecked-return (Evidence Contract v2 batch A)
c74b7b63 test(planner): pin integer-overflow + unchecked-return VerdictFacts contract
```