# SecGuard-Clang 工程质量审计报告（阶段一 · 只读）

| 项目 | 值 |
|---|---|
| 仓库 | `DannyAn/secguard-clang` |
| 审计对象 | `sgre/`（Go 模块 `github.com/DannyAn/secguard-clang`） |
| 审计基线 | `main` @ `c6887e6`（Merge pull request #307），审计时工作区干净 |
| 工具链 | Go 1.25.3 darwin/arm64 |
| 审计日期 | 2026-11-21；同日按仓库所有者补充安装的工具完成第二轮工具复核 |
| 审计模式 | 只读：未修改任何 Go 源文件、测试、`go.mod`/`go.sum`，未格式化、未安装依赖、未提交、未推送 |
| 规模 | 生产代码 91,022 行 / 645 个 `.go` 文件；测试代码 64,703 行；生产函数 2,810 个（不含 `_test.go`） |
| 工具复核 | `golangci-lint` v1.64.8、`staticcheck` 2026.2.2、`gocyclo`、`gocognit`、`dupl`、`crapper`、`dryer`、`mutator`（均在 `~/.local/bin`，已实际执行） |

> 本报告只用于建立可验证的改进清单。阶段二开始前，需要由仓库所有者批准治理单元与顺序。
>
> **复核修正**：初版报告把 Crapper / Dryer / Mutator 记为“未安装”，这是错误的——三者一直在 `~/.local/bin`，现在已用于复核；初版的复杂度/CRAP/重复率结论已按工具输出修正，并新增了静态检查、变异测试与系统性重复的证据。详细修正见 §3.7。
>
> **阶段二执行状态（2026-11-21）**：PR #309–#313 已合入 main（`8d165e9`）；PR #314 进行中。U1/U2/U1b/U4a/U4c/U5/U7a(参数层)/U4d/U6/U4b 完成；M-07 chunked `List*ByIDs` 完成；U3a 核心完成（626 处 Build/Detect 断言，另修复 9 条生产 errcheck；当前 uncapped 157 条：测试 127、生产 30）；U3b 关键零覆盖路径完成，并修复指针/数组字段类型解析（`892fed9`）。剩余 U3a 其余 errcheck、M-07 其余 scan/CRUD 模板、U7b、M-12、L-03/L-04、U7a 函数体拆分见 §9/§10。§6 L-01 保留审计时的清单描述。

---

## 0. 总体评价

SecGuard-Clang 的工程质量高于同规模静态分析项目的常见水平，核心链路有真实的生产打磨痕迹：

- `go build ./...`、`go vet ./...` 通过；`go test ./...` 全部包通过；`go test -race ./...` 无数据竞争；`-tags nosqlite` 子集通过。
- 套件级合并覆盖率（`-coverpkg=./...`，本次审计合并计算）为 **82.3%**（29,759 / 36,168 语句）。
- 生产包之间**没有循环依赖**：`parser`/`db`/`typeinfo`/`apikb` 位于底层，`graph`/`indexer`/`repofacts` 居中，`evidence` 与 `planner` 是互不依赖的兄弟层，`cli` 负责编排，`report` 只依赖 `db` 与 `planner` 的注册表。核心分层与 `CLAUDE.md` 的描述一致。
- 并发与内存背压是有意设计的：`concurrency.Gate`、`sync.WaitGroup`、`recover`、错误聚合、共享 CFG 缓存、`BEGIN IMMEDIATE` 批量事件写入都实现正确；全仓库仅 6 处 `go func`，均有生命周期/错误回收。
- CI 有一个**端到端召回门禁**：`pr-benchmark.yml` 在基准语料上要求 recall=100%、FP=0、FN=0，直接保护检测能力。
- 工具复核确认了两个被重点怀疑的单元（`signed_compare.go`、`filter_range_oob.go`）的**定向变异测试为 100% killed**（76/76、82/82）：这说明有测试的地方并不弱，问题集中在覆盖不均与测试脚手架。

主要风险集中在四类：

1. **少数超大函数**：`runReportCmd`（1,472 行，gocyclo 232 / Crapper CC 234，cognitive 569，CRAP 2,434）、`UninitVariableDetector` 的三个子检测函数（676/505/272 行；20/14/13 个位置参数；cognitive 454/313/157）、`buildHintParts`（648 行，cognitive 421，CRAP 186）。这些函数承担核心输出契约或检测语义，改动成本与回归风险最高。
2. **静默降级**：三处检测器整树遍历的错误被 `_ =` 丢弃，遍历失败时检测结果会静默变少（假阴性），与项目自己“跳过必须记录”的注释约定不一致。
3. **测试基座不均**：测试中 383 处 `.Build(ctx)` 与 13 处 `Detect(ctx)` 忽略错误（golangci-lint 报出 48 个测试内 errcheck）；`runReviewCmd`/`runIndexCmd`/`runClassifyCmd` 几乎零覆盖；`relationalNonZeroVar`、`cfgBuilder.buildDo` 等检测路径在整套测试中零覆盖。两个定向变异测试为 100% killed，说明“有测试的单元很扎实”，但覆盖缺口是真实的。
4. **系统性重复**：Dryer 在 ≥0.82 阈值下报出 **460 对**结构重复，其中 **107 对**是“≥100 节点且 ≥10 行”的大块，**62 对的两侧都在 `internal/db`**。这不是风格问题，而是维护与语义漂移风险；其中空指针语义、数据流加载器、文件遍历、`enclosingWorktree` 等重复尤其值得去重。

阶段二建议顺序：先用低风险清理（死代码、gofmt、静态检查小项）建立节奏；再修静默错误；然后补测试基座；再做语义去重并补特征测试；最后才碰 CLI 报告入口与 uninit 巨函数；CI 门禁应尽早补上（独立单元，风险为零）。

---

## 1. 审计范围、方法与限制

### 1.1 范围

- 包含：`sgre/` 全部 Go 源码、测试、testdata 使用方式；模块依赖/包边界；CI 工作流对 Go 代码的质量门禁。
- 不包含：`extension/`、`docs/` 既有文档、`.claude/`、`.opencode/`、`.codeagent/`、`dist/`（按 `AGENTS.md` 的检视范围约定）。`docs/` 仅写本报告，不引用既有文档结论。
- 本轮没有运行会改写仓库内容的检查；基准扫描与工具输出写到 `/tmp` 下的模块副本，未在仓库内产生运行产物。

### 1.2 已执行检查与工具

| 检查/工具 | 版本/方式 | 结果 |
|---|---|---|
| `go build -buildvcs=false ./...` | Go 1.25.3 | 通过 |
| `go vet -buildvcs=false ./...` | Go 1.25.3 | 通过（无输出） |
| `gofmt -l sgre` | gofmt (Go 1.25.3) | 28 个文件未格式化（21 生产 + 7 测试） |
| `go test -buildvcs=false ./...` | Go 1.25.3 | 21/21 有测试的包通过，0 失败 |
| `go test -buildvcs=false -race ./...` | Go 1.25.3 | 21/21 通过，无 data race |
| `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | Go 1.25.3 | 通过 |
| `golangci-lint run --timeout 10m ./...` | v1.64.8，无仓库配置（默认 linters：errcheck/gosimple/govet/ineffassign/staticcheck/unused） | 默认配置报告 **85 条**（每 linter 50 条 / 同文本 3 条上限，**截断**）；关闭上限后 **821 条**：生产 56 + 测试 765；errcheck 794、gosimple 19、ineffassign 7、SA4004 1（阶段二 U1 后 unused=0） |
| `staticcheck ./...` | 2026.2.2 (0.8.2) | 30 条：U1000 18、SA4006 4、SA4004 1、S1011 1、S1021 2、S1039 4 |
| `gocyclo -over 10` | fzipp/gocyclo | 生产 476 个函数 >10；含测试 660 个；生产平均 6.7 |
| `gocognit -over 15` | uudashr/gocognit | 生产 452 个函数 >15，171 个 >30；含测试 555 / 185 |
| `dupl -t 100 .` | mibk/dupl | 53 个克隆组，其中生产-only 14 组 |
| `crapper`（项目根 = `/tmp` 模块副本） | CRAP 工具，默认 `go test ./... -coverprofile` | 2,796 个函数条目；CRAP>100 共 49 个；30–100 共 137 个；10–30 共 604 个 |
| `dryer`（默认阈值 0.82） | Dryer 结构相似度 | 460 对候选；≥0.9 的 353 对；=1.0 的 344 对；≥100 节点且 ≥10 行的 107 对 |
| `mutator`（两个定向单元） | 变异测试，`--no-coverage` + 聚焦测试命令 | `signed_compare.go` 76/76 killed；`filter_range_oob.go` 82/82 killed（详见 §3.5） |
| 套件级覆盖率 `-coverpkg=./... -coverprofile` | Go 1.25.3 | 82.3%（见 §2.2） |
| 基准扫描 `examples/c-vuln-benchmark` | 默认配置 | 1.32s（见 §2.3） |

工具说明：

- Crapper 的 Go 覆盖率来自各包**自己的**测试（默认 `go test ./... -coverprofile`），跨包集成覆盖不计入；例如 `graph.SharedAccessBuilder.Build` 被 planner 集成测试驱动，但 Crapper 仍显示 0%。因此 CRAP 表的“覆盖率”列与 §2.2 的合并覆盖率口径不同，报告会分别标注。
- Dryer 会归一化局部名/字段名/字面量，但保留调用名/操作符/树形，因此它抓到的是**结构重复**，可与精确 token 克隆（本报告初版方法）和 `dupl` 互相补充。
- 变异测试只覆盖两个定向文件，不是全仓库变异分数；不能据此推断所有测试都强或都弱。

### 1.3 未执行（按要求记录，不擅自安装/升级）

- `govulncheck`、`nilaway`：未安装，未执行。
- 全仓库变异测试（Mutator 只跑了两个定向单元）；模糊测试；长时间稳定性/内存泄漏压测：未执行。
- 生产客户代码库扫描、跨平台构建（Windows/arm64/linux）、CPU/内存 profile：未执行；只在本机 darwin/arm64 与公开基准 C 语料上验证。
- 完整基准召回门禁（`validate-benchmark.py` + `benchmark-secguard.toml`）：未执行；本轮只跑了默认配置的基准扫描。
- `-race` 之外的并发压力测试（多扫描进程共享 WAL、并行 `report --write-json`）：未执行。

### 1.4 指标口径

- 圈复杂度（gocyclo）：`1 + if/for/range/case/&&/||` 等分支点；Crapper 的 CC 实现与 gocyclo 略有差异（`runReportCmd`: 234 vs 232）。
- 认知复杂度（gocognit）：按嵌套与结构加权，比圈复杂度更能反映“读懂成本”；工具提示“部分调用无法从源码单独解析，递归可能被低估”，因此该数值偏保守。
- CRAP：Crapper 原值 `CC² × (1 − coverage)³ + CC`；覆盖率为各包自测覆盖（见 §1.2 说明）。初版报告用合并覆盖率手算的 CRAP 只作补充参考。
- Dryer 分数：结构指纹的 Jaccard 相似度；默认阈值 0.82。
- 克隆：`dupl` 的 token 序列 + 本报告初版的精确 token 扫描（窗口 50，≥100 token）。
- 覆盖率：合并所有测试二进制对全部内部包的覆盖（`-coverpkg=./...`），按语句块去重取最大命中数。

---

## 2. 当前质量基线

### 2.1 构建、静态检查与测试

| 项 | 值 |
|---|---|
| `go build` | 通过 |
| `go vet` | 通过 |
| `golangci-lint` | 默认截断 85 条；关闭上限 821 条（生产 56 / 测试 765，errcheck 794）；见 §3.4、§3.6 |
| `staticcheck` | 30 条；见 §3.4、§3.6 |
| `go test ./...` | 21/21 有测试的包通过，0 失败 |
| `go test -race ./...` | 21/21 通过，无数据竞争 |
| nosqlite 子集 | 通过 |
| 测试函数 | 1,635 个 `Test*`；386 个 `_test.go`；9 处 `t.Skip`；0 个 `Benchmark*` |
| 测试代码量 | 64,703 行 |
| Mutator（定向） | `signed_compare.go` 76/76 killed；`filter_range_oob.go` 82/82 killed |

### 2.2 合并覆盖率（`-coverpkg=./...`）

总体：**82.3%**（29,759 / 36,168 语句）。

| 包 | 覆盖率 | 语句数 |
|---|---:|---:|
| `internal/skills` | 0.0% | 37 |
| `cmd/secguard` | 0.0% | 5 |
| `internal/agent` | 0.0% | 8 |
| `internal/cli` | 62.3% | 4,088 |
| `internal/worker` | 68.7% | 150 |
| `internal/db` | 70.0% | 1,407 |
| `internal/graph` | 80.3% | 1,891 |
| `internal/git` | 80.6% | 72 |
| `internal/indexer` | 80.9% | 278 |
| `internal/log` | 82.9% | 35 |
| `internal/parser` | 83.4% | 971 |
| `internal/macros` | 83.5% | 340 |
| `internal/report` | 84.0% | 1,623 |
| `internal/symbols` | 84.7% | 177 |
| `internal/repofacts` | 85.0% | 539 |
| `internal/planner` | 85.1% | 9,948 |
| `internal/build` | 86.1% | 137 |
| `internal/typeinfo` | 86.6% | 157 |
| `internal/evidence` | 87.2% | 13,443 |
| `internal/config` | 88.3% | 333 |
| `internal/allocdiscover` | 89.5% | 351 |
| `internal/apikb` | 94.8% | 155 |
| `internal/concurrency` | 95.7% | 23 |

说明：`internal/skills` 的 0% 不是“没有测试文件”，而是现有测试只读取 `SKILL.md` 文本并与 `planner` 注册表比对，没有调用本包的 `Registry`/`VulnTypeSkill` API（见 M-14）。

### 2.3 代表性扫描基线

命令（输出与 DB 均在 `/tmp`，不改仓库）：

```bash
go build -buildvcs=false -o /tmp/audit-tools/secguard ./cmd/secguard
/tmp/audit-tools/secguard scan examples/c-vuln-benchmark \
  --db /tmp/audit-scan/sgre.db \
  --output-dir /tmp/audit-out/sc_2026-11-21_181500_abcdef
```

| 项 | 值 |
|---|---|
| 完成状态 | `complete` |
| 墙钟时间 | 1.32s（user 4.75s / sys 0.58s，多核并行） |
| 索引 | 61 文件 / 419 函数 / 4,924 行 |
| 阶段耗时 | index 62ms，graph 242ms，detectors 666ms，plan 单类型最高 169ms |
| 候选 | 185 个；pipeline 自动确认 40 个 |
| 候选 Top 类型 | dangerous-function 40、unchecked-return 27、memory-leak 21、null-deref 18、buffer-overflow 16、resource-leak 16 |
| SARIF | 2.1.0；driver `secguard-clang` 0.12.9；185 results 全部 `level=note`；28 个 ruleId；properties 含 `stage`/`suspicion_level` |
| 输出 | `report.md`、`candidates.sarif`、`candidates/`、`dismissed.json`、`scan.log`；未执行 AI 分类，故无 `result.sarif`/`findings/` |

约束说明：本次用的是默认配置，不是 `examples/c-vuln-benchmark/benchmark-secguard.toml` 的召回门禁配置；因此该结果只作“耗时/规模/输出形状”基线，不能替代 `pr-benchmark.yml` 的 recall=100%/FP=0 门禁。

### 2.4 Git 工作区

审计开始时 `git status` 干净；本报告写入后工作区只有 `docs/engineering-quality-audit.md` 一个未跟踪文件（阶段一禁止提交，未提交）。

---

## 3. 各质量维度结果

### 3.1 函数复杂度

工具结果：

- gocyclo：生产 2,810 个函数中 **476 个圈复杂度 >10**；平均 6.7。含测试文件时为 660 个 >10。
- gocognit：生产 **452 个 >15、171 个 >30**；含测试为 555 / 185。
- Crapper：2,796 个函数条目，**CRAP>100 共 49 个**，30–100 共 137 个，10–30 共 604 个（覆盖率口径见 §1.2）。

| 函数 | 位置 | 行数 | gocyclo CC | gocognit | Crapper CRAP | Crapper 覆盖率 |
|---|---|---:|---:|---:|---:|---:|
| `runReportCmd` | `internal/cli/report.go:317` | 1,472 | 232 | 569 | 2,434.4 | 65.7% |
| `runReviewCmd` | `internal/cli/diff.go:35` | 318 | 39 | 51 | 1,640.0 | 0.0% |
| `runClassifyCmd` | `internal/cli/classify.go:23` | 205 | 42 | 93 | 1,353.8 | 10.8% |
| `runIndexCmd` | `internal/cli/index.go:20` | 163 | 25 | 24 | 650.0 | 0.0% |
| `relationalNonZeroVar` | `internal/evidence/divide_by_zero.go:457` | 40 | 22 | 26 | 506.0 | 0.0% |
| `SharedAccessBuilder.Build` | `internal/graph/shared_access.go:27` | 64 | 20 | – | 420.0 | 0.0%¹ |
| `stripLiteralsAndComments` | `internal/macros/macros.go:653` | 65 | 24 | 58 | 401.4 | 15.6% |
| `UninitVariableDetector.detectStackUninit` | `internal/evidence/uninit_variable.go:246` | 676 | 192 | 454 | 378.3 | 82.8% |
| `linkGotoLabels` | `internal/graph/control_flow.go:255` | 51 | 22 | 37 | 354.5 | 11.8% |
| `runDefCmd` | `internal/cli/def.go:71` | 76 | 18 | – | 342.0 | 0.0% |
| `parseIntLiteral` | `internal/parser/macro_values.go:39` | 41 | 17 | 18 | 342.0 | 0.0% |
| `runScanCmd` | `internal/cli/scan.go:35` | 727 | 80 | 124 | 290.3 | 68.3% |
| `MergeWriteSummaries` | `internal/macros/macros.go:366` | 49 | 16 | 49 | 272.0 | 0.0% |
| `buildHintParts` | `internal/planner/evidence_package.go:306` | 648 | 179 | 421 | 186.2 | 93.9% |
| `UninitVariableDetector.detectHeapUninit` | `internal/evidence/uninit_variable.go:1406` | 505 | 134 | 313 | 180.7 | 86.2% |
| `UninitVariableDetector.detectStructPartialUninit` | `internal/evidence/uninit_variable.go:1937` | 272 | 72 | 157 | 74.4 | 92.3% |

¹ `SharedAccessBuilder.Build` 被 `planner/zz_shared_access_test.go` 集成测试调用；Crapper 默认只统计 graph 包自测覆盖，因此显示 0%。这正说明“覆盖率口径”需要区分：§2.2 的合并覆盖率不为 0。

判断：复杂度问题不是“函数多/抽象多”，而是**少数承担核心契约的函数把过多状态与分支压在一起**。`detectStackUninit` 的 20 个参数中有 10 个 `[]parser.Node` 与 4 个 map 同类型参数，调用点写错顺序不会编译失败，只会悄悄改变检测结果——这是比“行数长”更实质的风险。`runReportCmd` 同时承担 10 个布尔模式与 23 个字符串 flag 的处理，任何输出模式变更都必须在同一个函数里改。

### 3.2 重复代码

三种口径互相补充：

| 方法 | 结果 | 说明 |
|---|---|---|
| Dryer（结构相似度，阈值 0.82） | **460 对**；≥0.9 的 353 对；=1.0 的 344 对；≥100 节点且 ≥10 行的 **107 对** | 覆盖 111 个生产文件；**62 对大块的两侧都在 `internal/db`** |
| dupl（token 克隆，≥100 token） | **53 个克隆组**，其中生产-only **14 组** | 39 组涉及测试；生产组覆盖空语义、DB CRUD、遍历骨架等 |
| 初版精确 token 克隆（窗口 50，≥100 token） | 65 对 | 只认逐字相同片段，偏保守；与上两者不矛盾 |

按类型分：

| 类型 | 工具证据 | 风险 |
|---|---|---|
| 空指针语义 | dupl：`evidence/null_check_helper.go:94-121` <> `parser/guard.go:307-334`；`evidence/null_source.go:611-644` <> `planner/null_flow.go:2749-2782` | 同一 C 语义多处实现，修复只改一处即漂移 |
| 文件遍历/解析骨架 | dupl：`evidence/detector.go:56-77` <> `graph/helpers.go:32-53`；Dryer 亦确认大块结构相似 | 跳过/日志/RepoIndex 语义需同步修改，日志前缀已分叉 |
| 数据流边加载 | Dryer：`null_flow.go` 相关大块；初版精确克隆三处 `loadDFGCopies`/`loadAliases`/`loadFreeSites` | 空指针/UAF/double-free 共享数据流；规则漂移会改变三类检测 |
| 检测器前置扫描 | dupl：`evidence/argument_type.go:59-86` <> `evidence/data_representation.go:73-100` | 作用域/遮蔽规则需重复维护 |
| 区间过滤流水线 | Dryer/初版：`filter_buffer_range.go:46` 与 `filter_range_oob.go:38` 的加载/缓存/释放段相同 | 候选分桶/缓存/释放逻辑重复 |
| 同文件内小助手 | dupl：`signed_compare.go:183-214` <> `signed_compare.go:254-283`；Dryer：`unchecked_return.go:505-545` <> `:1728-1775`（score 0.83，661 节点，41 行） | 同文件两套实现，需同步修 |
| 注入检测 taint 提取 | Dryer：`crlf_injection.go:156-185` <> `log_injection.go:80-120`（score 0.91，30 行） | C-format 参数规则重复 |
| DB 数据层 | Dryer：`crud_events.go:111-138` <> `crud_locations.go:38-65`（0.843，28 行）；`crud_scan_runs.go:193-210` <> `crud_variables.go:40-56`（1.0）；`crud_files.go:57-73` <> `crud_function_declarations.go:22-39`（1.0） | 系统性模板重复；见 M-07 |
| 跨包 worktree 探测 | Dryer：`cli/scan_scope.go:55-73` <> `repofacts/repofacts.go:402-420`（1.0，19 行） | `.git` 向上探测规则两份；见 M-15 |
| 证据片段拼装 | dupl：`registry_buffer_overflow.go:53-61` <> `registry_out_of_bounds.go:38-46`；Dryer：`registry_deadlock.go` <> `registry_signed_compare.go`（0.93） | 证据文本是 AI 分类契约，暂不建议机械合并 |

判断：Dryer 将初版“可合并的重复”从“若干处”升级为**系统性**问题，尤其 `internal/db`（107 对大块中 62 对两侧都在 db）。但并非所有 Dryer 命中都该合并：`internal/apikb` 中大量 4 行、score=1.0 的命中是**配置数据表的同构行**，合并会损害可读性；`registry_*` 的 `BuildEvidence` 是类型差异，合并会改变 AI 证据文本。去重应优先处理“语义应当唯一”的重复（空判定、数据流、遍历、worktree 探测、DB 模板），而不是数据表。

### 3.3 架构与包依赖

生产代码包规模（不含测试）：

| 包 | 文件 | 行数 | 说明 |
|---|---:|---:|---|
| `internal/evidence` | 49 | 30,742 | 检测器（自注册），不依赖 `planner` |
| `internal/planner` | 85 | 26,010 | 收敛/过滤器/注册表；不依赖 `evidence` |
| `internal/cli` | 27 | 10,011 | 编排与命令入口 |
| `internal/report` | 9 | 4,742 | SARIF/Markdown/XLSX 输出 |
| `internal/graph` | 22 | 4,464 | 调用图/数据流/CFG/锁序/共享访问 |
| `internal/db` | 28 | 4,323 | 数据层 |

结论：

- **无生产循环依赖**。`evidence` 与 `planner` 互不 import（测试二进制中可以互相引用），这是正确的兄弟分层。
- `report` 只依赖 `db` 和 `planner`（CWE/类型注册表），符合“CWE 单一来源”的项目约定。
- `internal/planner` 的 85 个文件大多是“每漏洞类型一个 `registry_*.go` / `filter_*.go`”，这是按领域拆分，不是过度抽象。
- 遗留的架构异味是**全局可变状态**与**单次扫描假设**：`eventBatch`/`batchMode`（`evidence/detector.go:308-315`）、`db.SupportedFindingCWEs`（`db/crud_findings.go:17`）、`report.globalSourceLineCache`（`report/snippet.go:107`）、`planner.liveFileParseCaches`（`planner/null_flow.go:2860`）。CLI 一进程一次扫描的前提下可控，mutex 保护也到位；但若将来嵌入库或并行扫描，会互相污染。见 M-10。
- 跨包重复的 worktree 探测（M-15）说明 `cli` 与 `repofacts` 之间存在一个本应共享的小工具边界。
- 没有发现不必要的接口层/包装层；`Detector`/`Filter` 接口有真实多实现。

### 3.4 Go 工程实践

**优点（已验证）**

- 并发：6 处 `go func` 全部有 `WaitGroup`/`Gate`/`recover`/错误聚合；`planErrors` 有互斥保护；`summaryReady` 用 defer 保证关闭；无 `time.Sleep` 轮询。
- 资源：`defer tree.Release()` 成对出现；解析器有 LRU + 引用计数 + singleflight；批量事件用 `BEGIN IMMEDIATE`，失败计数上抛，不静默丢事件。
- SQLite：WAL、`busy_timeout(10000)`、`foreign_keys`、`SetMaxOpenConns`、应用层 BUSY 重试、`url.URL` 构造 DSN 防路径注入；多步写入有事务边界。
- 错误包装：413 处 `fmt.Errorf` 中 366 处使用 `%w`（约 89%），整体规范。
- 未发现 goroutine/channel 泄漏路径；`time.Sleep` 0 处；非测试 `panic` 仅 2 处且均为“初始化守卫/重抛”。
- **Mutator 定向结果**：`internal/evidence/signed_compare.go` 76/76 killed，`internal/planner/filter_range_oob.go` 82/82 killed（聚焦测试命令，`--no-coverage`）。这两处复杂的判定/区间逻辑被测试充分固定。

**问题**

- 3 处检测器整树遍历错误被 `_ =` 丢弃（H-03）。
- `returnSummaryResolver.funcNonZero` 在分析内部改用 `context.Background()`（`planner/return_summary.go:175`），创建时传入的 `ctx` 没有保存，取消信号无法穿透。（初版把 `range_flow.go:166` 的 `analyzeRanges` 记为死代码，这是错的：`range_flow_test.go:40`、`range_guard_test.go:25` 在使用它；它是测试用的便捷包装，不是死代码。）
- `parser.NewParser` / `ParseCached` 中 `p.SetLanguage(lang)`、`ps.SetLanguage(p.lang)` 的返回 error 未检查（`internal/parser/parser.go:170`、`:290`，errcheck）；tree-sitter 语言版本不匹配时会静默得到不可用 parser。
- 静态检查发现 7 处 `ineffassign`，其中 `internal/cli/settlement.go:200-214` 的 `rowsByScan` 是**真实死查询**：`ListSettlementStatsByScan` 的结果从未被读取（只写入 map），每个 scan 白跑一次 DB 查询；其余是死赋值/无用初始化。
- `internal/evidence/uninit_variable.go:1208` 的 `for` 循环在第一次迭代无条件 return（SA4004）：行为符合“只看第一个子节点”的设计，但循环是多余的，应改为显式取 `children[0]`。
- 60 处 `forEachFile*` 调用点各自 `os.ReadFile` 一次；解析树有缓存，源字节没有缓存，同一文件在一次扫描中被 35+ 个检测器重复读取（M-12；需先测再改）。
- 测试代码普遍忽略 builder 错误（H-04）；golangci 关闭默认上限后测试内 errcheck 达 765 条，是工具级证据。

### 3.5 测试质量

- 广度好：1,635 个测试、386 个测试文件，检测器有大量 TP/FP 命名用例和 testdata 夹具；SARIF 测试断言了 `level` 与 `properties`（`report/sarif_test.go:67`、`:206`、`:240`）；findings 树有 `ReconcileFindings`/`SyncPerFinding` 测试。
- 证明力“不均”而非“普遍弱”：
  1. **强的地方**：Mutator 在 `signed_compare.go`（76/76）与 `filter_range_oob.go`（82/82）上全部 killed；这两个文件的判定逻辑有测试固定。
  2. **弱的地方**：383 处测试内 `.Build(ctx)` 忽略错误；golangci 关闭默认上限后测试内 errcheck 765 条（默认 50 条上限只显示 48 条）；`evidence/security_test.go:88-124` 连续忽略 13 个 `Detect` 错误。
  3. 整套测试中零覆盖：`relationalNonZeroVar`（除零关系证明，36 语句）、`cfgBuilder.buildDo`（do-while CFG，34 语句）、`BuildPlanSummary`（23 语句）、`SubprocessRunner.Run`（26 语句）、`findFieldTypeName`（19 语句）、`writeSecondCalleeDefinition`（18 语句）。
  4. CLI 命令零/低覆盖：`runReviewCmd` 0%、`runIndexCmd` 0%、`runClassifyCmd` 10.8%、`runPlanCmd`/`runDefCmd`/`runMetricsCmd`/`runQueryCmd` 0%。
  5. 无任何 `Benchmark*`，而 `CLAUDE.md` 文档化了 `-bench=.` 的用法；性能回归没有基线。
  6. 151 个 `zz_*_test.go`（占测试文件 39%）是追加式回归测试命名，缺少按功能组织的索引；不影响正确性，但影响可发现性。
  7. `internal/skills` 包 API 0% 覆盖，现有测试只做文本/注册表一致性比对。
- 正面：覆盖率不是“只测内部实现”，检测器测试大量使用真实 C 夹具走完 index→detector→plan；基准 CI 还有端到端召回门禁，这比纯单元测试更能证明检测行为。

### 3.6 质量工具

- 已运行：`gofmt`、`go vet`、`go build`、`go test`、`go test -race`、`nosqlite` 子集、`golangci-lint`、`staticcheck`、`gocyclo`、`gocognit`、`dupl`、`crapper`、`dryer`、`mutator`（两个定向单元）、覆盖率、基准扫描。
- 未运行：`govulncheck`、`nilaway`（未安装）；全仓库变异测试、模糊测试、长时间压测（见 §1.3）。
- CI 仅运行 `nosqlite` 子集 + 基准召回门禁（`.github/workflows/pr-benchmark.yml:33`），**没有**运行 `go test ./...`、`go vet`、`gofmt`、`golangci-lint` 或覆盖率。见 M-08。

### 3.7 本轮工具复核的修正与新发现

| 初版结论 | 复核结果 | 处理 |
|---|---|---|
| “Crapper/Dryer/Mutator 未安装” | 错误：三者都在 `~/.local/bin`，本轮已执行 | 已修正 §1.2/§1.3/§3.6/§7 |
| 手算 CRAP>100 共 26 个（合并覆盖率） | Crapper（各包自测覆盖）为 49 个；数值与口径不同 | CRAP 表改用 Crapper 原值，并标注口径 |
| 圈复杂度 >10 共 474 个（生产） | gocyclo 生产 476 个（含测试 660）；差异来自统计实现 | 改用 gocyclo 结果 |
| 精确 token 克隆 65 对 | Dryer 结构重复 460 对；dupl 53 组（生产 14 组） | 三种口径并列；重复问题升级为系统性 |
| `range_flow.go:166 analyzeRanges` 是死代码 | 错误：测试在用（`range_flow_test.go:40`、`range_guard_test.go:25`） | 已从 M-11 / 死代码中移除 |
| 死代码 15 个 | staticcheck/golangci U1000 确认 18 个（新增 `summaryMap.hasSummary`、`cfgCacheFromCtx`、`nullLiteralParensBalanced`） | 更新 L-01 |
| 未做静态检查 | 新增 golangci 默认 85（截断）/关闭上限 821、staticcheck 30 条 | 新增 M-15/M-16/L-06，更新 H-04 |
| 未做变异测试 | 两个定向单元 100% killed | 写入 §3.4/§3.5；范围有限，不代表全仓 |

新发现（工具驱动）：

- `internal/cli/settlement.go:200-214` 的 `ListSettlementStatsByScan` 结果未使用（死查询）。
- `internal/cli/scan_scope.go:55-73` 与 `internal/repofacts/repofacts.go:402-420` 的 `enclosingWorktree` 逐字重复（Dryer 1.0）。
- `parser.SetLanguage` 错误未检查（2 处）。
- 18 个未使用函数（staticcheck U1000），含 `divOrModDivisor`、`isNullLiteralExpr`、`nullLiteralParensBalanced` 等。
- 9 条 gosimple、7 条 ineffassign、1 条 SA4004（SA4004 不是逻辑 bug，而是可简化的冗余循环）。

---

## 4. 高风险问题清单

### H-01 `runReportCmd` 单体函数，报告/判定/输出模式全部耦合

- **位置**：`sgre/internal/cli/report.go:317`（函数 317–1788，1,472 行；文件 2,448 行）
- **证据**：gocyclo 232 / Crapper CC 234，cognitive 569，CRAP 2,434.4，Crapper 覆盖率 65.7%；函数内处理 10 个布尔模式（`--audit`、`--write`、`--write-json`、`--list`、`--list-auto-confirmed`、`--review`、`--review-json`、`--stats`、`--complete-type`、`--allow-partial`）和 23 个字符串 flag（`--scan-id`、`--type`、`--rule-id`、`--status`、`--severity`、`--evidence`、`--fix-strategy`、`--output-dir` 等）。同一函数里既做 DB 读取、finding 归一化/去重，又做 JSON/SARIF/Markdown 落盘与 verdict 回放。
- **原因**：报告子命令随扫描协议演进不断叠加模式，所有分支共享“打开 DB → 解析 flag → 输出”的前半段，历史修复（去重、`(void)` 丢弃、auto-confirmed 复审、审计概览）都直接加在同一个入口。
- **建议**：保持入口只做参数解析与 DB 打开，把每个模式抽成独立 handler（`runReportListAutoConfirmed`、`runReportWrite`、`runReportAudit`、`runReportReview`、`runReportStats` 等）；抽取前先为每个模式的 JSON 字段集、SARIF 输出和 DB 写入顺序建立特征测试/基准输出快照。
- **预期收益**：CRAP 从 2,434 降到可控范围；每个输出模式可独立测试与修改；输出契约变更的影响面可枚举。
- **回归风险**：中高。DB 写入顺序、JSON 字段集合/省略规则、SARIF 排序与去重行为都可能因拆分改变；必须用基准输出 + `report --audit` 端到端测试锁定。

### H-02 `uninit` 检测器的超长函数与 20 位置参数

- **位置**：
  - `sgre/internal/evidence/uninit_variable.go:246` `detectStackUninit`（676 行；gocyclo 192、cognitive 454、CRAP 378.3、20 个参数）
  - `sgre/internal/evidence/uninit_variable.go:1406` `detectHeapUninit`（505 行；gocyclo 134、cognitive 313、CRAP 180.7、14 个参数、嵌套 9 层）
  - `sgre/internal/evidence/uninit_variable.go:1937` `detectStructPartialUninit`（272 行；gocyclo 72、cognitive 157、CRAP 74.4、13 个参数）
- **证据**：函数签名 246–248 行连续 20 个参数，其中 10 个 `[]parser.Node` 参数与 4 个 map 参数按位置传递；调用点在 `Detect`（同文件 43–95 行）里一次传入 20 个实参。三个子检测器各自维护未初始化变量集合、赋值点、输出参数初始化行等局部状态。
- **原因**：为消除“每函数重复 AST 遍历”的性能问题，把全文件 AST 节点一次性 hoist 后按位置下传；三个子检测器的状态没有收拢成结构体，历史修复持续增加参数。
- **建议**：引入 `uninitScanInputs`/`uninitFileFacts` 结构体（AST 节点切片、`summaries`、`macroWrites`、`objectMacroWrites`、`bound`、`tree`），三个子函数改为接收该结构体；再按“收集赋值/声明 → 路径判定 → 事件发射”拆出纯函数。先补三个子检测器的特征测试（现有 testdata 已覆盖大部分），再做结构变更。
- **预期收益**：消除同类型参数错位的静默错误；单函数 CRAP 下降；uninit 的 FP/TP 规则可以按阶段单测（当前只能整检测器集成测）。
- **回归风险**：高。uninit 是高误报敏感类型；参数映射错误不会编译失败，只会改变结果。必须用现有夹具 + 基准 recall 门禁 + 逐案例前后对比。

### H-03 检测器整树遍历错误被静默丢弃，可能产生假阴性

> **阶段二状态（2026-11-21）**：已修复——3 处 collect 返回/传播 error，新增 5 个故障注入测试（`traversal_error_test.go`）；改动未提交。

- **位置**：
  - `sgre/internal/evidence/unchecked_return.go:1553` `collectNoreturnFuncs`
  - `sgre/internal/evidence/unchecked_return.go:1622` `collectNonNullReturns`
  - `sgre/internal/evidence/contract_gap.go:278` `(*ContractGapDetector).collectSiblingContracts`
- **证据**：三处均是 `_ = forEachFileIncludingEmpty(...)` / `_ = forEachFile(...)`。被调函数在 `ctx.Done()` 或 `store.ListFiles` 失败时返回 error（`evidence/detector.go:61-64`、`:78-83`、`:168-192`）。当前实现丢弃该 error，也不 `logger.Warn`：`collectNoreturnFuncs` 返回部分/空的 noreturn 集合，`collectNonNullReturns` 返回部分集合，`collectSiblingContracts` 返回部分契约索引，检测器最终仍返回成功。
- **原因**：这些是“best-effort 全树收集”，为了不把可选增强变成硬失败，直接用 `_ =`；但项目在 `forEachFile` 的注释里明确“跳过必须记录，否则是静默假阴性”，此处未遵守同一约定。
- **建议**：让三个 collect 函数返回 `(result, error)`，在检测器 `Detect` 中向上返回（或至少 `logger.Warn` + 在 `DetectResult` 标记不完整）；与 `eventFlushFailures` 的做法一致，把“结果不完整”变成可观测状态。若担心单点失败中断扫描，可记录日志并继续，但必须可观测。
- **预期收益**：消除一条静默假阴性路径；取消/DB 故障在扫描日志中可归因；符合项目自己的假阴性策略。
- **回归风险**：低-中。改为向上返回时，原先“降级继续”的扫描可能失败；需要决定策略（warn+继续 vs 失败）。建议 warn+继续并增加不完整标记，避免改变生产可用性。

### H-04 测试基座不均：忽略错误与关键路径零覆盖

- **位置/证据**：
  - 测试中 383 处 `graph.New...Builder(...).Build(ctx)` 直接忽略返回错误；例如 `internal/planner/zz_b2_extensions_test.go:42-43`、`zz_shared_access_test.go:59`、`zz_lock_order_test.go:58`。
  - golangci-lint 关闭默认上限后，测试代码内有 **765 条 errcheck**（默认 50 条上限只显示 48 条）；383 处裸 `.Build(ctx)` 只是其中一部分。`internal/evidence/security_test.go:88-124` 连续 13 个 `xxxDetector.Detect(ctx)` 忽略错误（同一文件 46–61 行的另一辅助函数则正确检查，说明不是有意约定）。
  - 整套测试零覆盖：`relationalNonZeroVar`（`divide_by_zero.go:457`，36 语句）、`cfgBuilder.buildDo`（`control_flow.go:644`，34 语句）、`BuildPlanSummary`（`report/summary.go:162`，23 语句）、`SubprocessRunner.Run`（`worker/runners.go:66`，26 语句）、`findFieldTypeName`（`buffer_overflow.go:1986`，19 语句）、`writeSecondCalleeDefinition`（`markdown.go:724`，18 语句）。
  - 正面反证：Mutator 在 `signed_compare.go`（76/76）与 `filter_range_oob.go`（82/82）上 100% killed，说明“有测试的复杂单元”并不弱；问题在覆盖不均与脚手架，而不是测试策略整体失效。
- **原因**：集成测试脚手架优先“少写样板”，错误被忽略；新增检测修复以追加 `zz_*` 测试为主，缺少“失败必须显式”的统一 helper；覆盖率从未在 CI 中度量，零覆盖不会被发现。
- **建议**：提供 `mustBuild(t, func() error)`/`mustDetect(t, det)` helper 并替换 383+13 处；修复测试内 errcheck（全量 765 条，按包分批）；为零覆盖的检测函数补最小表驱动测试（尤其是 do-while CFG、除零关系证明、计划摘要）；在 CI 中输出合并覆盖率（可先不设阈值，只做趋势/文件级报告）。
- **预期收益**：阶段二任何重构都有可执行的“行为未变”证据；builder/检测器故障不再伪装成“候选为空”。
- **回归风险**：低（仅测试）；补测可能暴露真实缺陷，需要按发现单独处理，不阻塞审计。

---

## 5. 中风险问题清单

### M-01 空指针/空字面量语义跨包重复实现

- **位置**：
  - `parser/guard.go:34` `IsNullOperand` ≡ `evidence/null_check_helper.go:126` `isNullOperand`（逐行相同）
  - `parser/guard.go:307` `ExprNullChecksParam` ≡ `evidence/null_check_helper.go:94` `exprNullChecksParam`（dupl 确认同一克隆组；仅函数名与调用名不同）
  - `evidence/null_source.go:611` `isNullLiteral` ≡ `planner/null_flow.go:2749` `isNullLiteralNode`（dupl 确认同一克隆组，逐行相同）
- **原因**：跨包复用时选择了本地复制；`evidence` 已经 import `parser`，`parser.ExprNullChecksParam` 也已被 `planner/null_contract.go:352` 使用，说明共享调用完全可行。
- **建议**：在 `parser` 保留唯一实现并导出 `IsNullLiteral`，`evidence`/`planner` 删除副本改为调用；先加 NULL/nullptr/0/(void*)0/指针 cast 的特征测试。
- **预期收益**：一份 C 空语义；修复自动覆盖所有检测器。
- **回归风险**：低（当前逐行相同）；若未来三处已悄悄不同，合并会改变行为，因此必须先加测试再删副本。

### M-02 文件遍历/解析骨架四份实现

- **位置**：`evidence/detector.go:51` `forEachFile`、`:116` `forEachIndexedFile`、`:160` `forEachFileIncludingEmpty`、`graph/helpers.go:27` `forEachFile`
- **证据**：`dupl` 确认 `evidence/detector.go:56-77` 与 `graph/helpers.go:32-53` 为克隆组；三个 evidence 变体的读文件/ParseCached/Release/ctx 检查循环相同，仅“是否包含空函数文件/是否按函数分组”不同；日志前缀已经分叉（`evidence:` vs `graph:`）。
- **原因**：两个包各自演进，先有 `forEachFile`，再复制出变体。
- **建议**：抽 `internal/scanwalk`（或 parser 内）通用遍历器，选项化 `includeEmptyFiles`/`groupFunctions`/日志前缀；至少先把 evidence 的三个收敛为一个带选项的函数。
- **预期收益**：跳过/错误/RepoIndex 语义只维护一处；减少 4 份 O(F) 逻辑。
- **回归风险**：中。`RepoIndex` 路径与“空文件也要扫描”的行为差异必须保留；用现有检测器集成测试覆盖。

### M-03 数据流边加载器三份复制

- **位置**：`planner/null_flow.go:1691` `loadDFGCopies`、`:1778` `loadAliases`、`:1900` `loadFreeSites`
- **证据**：三者都先 `ListGraphEdgesByType`，再 `ListGraphNodesByEntityType("variable_ref")`，并逐字重复“按 funcIDs 过滤 → 解析 `Properties` 的 name/line → 建 node→function 映射”的代码块；初版精确克隆两两合计 250 token（最长连续 200）。
- **原因**：按边类型复制加载器；只有边属性结构不同。
- **建议**：抽 `loadVariableRefIndex(ctx, funcIDs)` + `loadEdgesByType(ctx, type, decode)`；三个加载器只保留 decode 差异。
- **预期收益**：节点解析只维护一份；null/UAF/double-free 的数据流输入保持一致。
- **回归风险**：中。字段/元素 alias 的过滤规则（`loadAliases` 丢弃 field/element alias）不能丢；用三类过滤器的现有测试 + 基准召回验证。

### M-04 区间过滤流水线重复

- **位置**：`planner/filter_buffer_range.go:46` `BufferRangeFilter.Apply`、`planner/filter_range_oob.go:38` `RangeOOBFilter.Apply`
- **证据**：候选分桶、`loadFuncFiles`、`newFileParseCache`、`analyzeRangesWithCalls` 构建 `flows`、`releaseRangeFlows` 的整段逻辑相同（初版精确克隆合计 250 token，最长连续 200），差异只在“哪些候选有资格”和“区间怎么比较”。
- **建议**：抽 `buildRangeFlows(ctx, candidates, eligible func(Candidate) bool, ...)`；比较逻辑留在各自过滤器。
- **预期收益**：减少一份易漂移的缓存/释放代码；两个过滤器只保留证明逻辑。
- **回归风险**：低-中；资格条件与 logger 输出需参数化，避免改变候选集合。Mutator 已证明 `filter_range_oob.go` 自身逻辑测试充分，合并时可用它做回归。

### M-05 检测器 per-file 作用域收集重复

- **位置**：`evidence/argument_type.go:46` 与 `evidence/data_representation.go:65`；`buildGlobalTypedefs` 被 9 个 detector 文件使用。
- **证据**：`dupl` 确认 `argument_type.go:59-86` 与 `data_representation.go:73-100` 为克隆组（per-file globals/locals 收集）；两个 `Detect` 的后续检查不同。
- **建议**：抽 `collectFileScope(root)`（globals + per-function locals）供多个 detector 复用；保留每个 detector 的检查逻辑。
- **预期收益**：作用域/遮蔽规则一份；减少 9 个 detector 的重复前置代码。
- **回归风险**：中。遮蔽/作用域结束的语义敏感（已有 `TestResolveScopedVar_*` 测试）；必须保留按行最近声明规则。

### M-06 同文件/同族检测器的重复判定助手

- **位置**：
  - `evidence/signed_compare.go:183` `unsignedVsNegative` 与 `:254` `isDeadBranchTautology`（dupl 确认克隆组；结果分别走 `deadUnsignedCompare` 与 `isAlwaysFalse`）
  - `evidence/unchecked_return.go:505` `allUsesNullSafe` 与 `:1728` `neverUsedAfter`（Dryer：score 0.83，661 节点，41 行）
  - `evidence/crlf_injection.go:156` `crlfTaintVariable` 与 `evidence/log_injection.go:80` `logTaintVariable`（Dryer：score 0.91，30 行）
- **原因**：同一语义分两次加入不同检测路径，复制了操作数/使用点/参数提取前奏。
- **建议**：抽取纯的“无符号/负常量/操作符”分类结果、`fprintf` 首个非字面量参数提取、变量使用点候选扫描；两个调用点各自做最终判定。
- **预期收益**：避免一处修复遗漏另一处；减少同族检测器维护成本。
- **回归风险**：中（检测语义）；Mutator 在两个目标文件的 100% killed 结果可作为重构回归基线。

### M-07 DB `List*ByIDs`/CRUD 的模板化重复是系统性的

- **位置（代表）**：`db/crud_events.go:111`、`db/crud_locations.go:38`、`db/crud_summary.go:44`、`db/crud_functions.go:83`、`db/crud_scan_runs.go:193`、`db/crud_variables.go:40`、`db/crud_files.go:57`、`db/crud_function_declarations.go:22`
- **证据**：Dryer 的 107 对大块中 **62 对两侧都在 `internal/db`**；`crud_events.go:111-138` 与 `crud_locations.go:38-65` 相似度 0.843（28 行），`crud_scan_runs.go:193-210` 与 `crud_variables.go:40-56` 为 1.0；dupl 确认 `crud_scan_runs.go:193-210` <> `crud_variables.go:40-56`、`crud_graph.go:75-91` <> `crud_locations.go:67-83`。同构的 `chunkIDs(ids, 500)` → 拼 `?` 占位符 → 扫描 → `rows.Err()` 模板重复多份。
- **原因**：每个实体一个 `crud_*.go`，列表/批量读取用手工模板复制，未抽公共查询助手。
- **建议**：泛型 `listByIDs[T]`/`queryInChunks` + 统一的 `scanRows`/`rows.Err` 收尾；SQL 列清单仍是每实体自己的常量；先把 `List*`、`scan*`、`chunk` 三类模板收敛。
- **预期收益**：减少 DB 层重复与漏 `rows.Err()` 的风险；改动一个模板即可覆盖多实体。
- **回归风险**：中。DB 层是正确性边界，必须覆盖空 ids、>500 ids、扫描失败、事务内读取；Dryer 的命中里也可能有“数据表同构”而非可合并逻辑，需逐组确认。

### M-08 CI 未运行完整测试/静态检查/格式检查

- **位置**：`.github/workflows/pr-benchmark.yml:33`（仅 `go test -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/`）；`release.yml` 只构建发布物。
- **证据**：CI 没有 `go test ./...`、`go vet ./...`、`gofmt -l`、`golangci-lint`、覆盖率；当前仓库 28 个文件不符合 gofmt，golangci 默认 85（截断）/关闭上限 821，staticcheck 30 条，长期未被门禁发现。
- **建议**：新增一个 Go 质量 job：`go vet ./...` + `go test ./...` + `gofmt -l` + `golangci-lint run`（或至少 staticcheck）；`-race` 可 nightly；保留现有基准召回门禁。
- **预期收益**：82.3% 的测试套件真正成为合并门禁；格式、vet 与静态检查不再漂移。
- **回归风险**：低；CI 时间会增加，需注意 SQLite/tree-sitter 依赖在 runner 上已具备（基准 job 已构建成功）。

### M-09 `buildHintParts` 的 29 路类型分发

- **位置**：`planner/evidence_package.go:306`（648 行；gocyclo 179、cognitive 421、CRAP 186.2、Crapper 覆盖率 93.9%）
- **证据**：单个 `switch spec.Name` 覆盖全部漏洞类型的提示 token 构造；每个类型内再按 candidate 字段追加 token（`contract@...`、`null@...`、`callee@...`、`size@...` 等）。
- **原因**：提示词汇是每类型的领域知识，随类型增加持续追加；为避免抽象层，集中在一个函数。
- **建议**：不做机械拆分。先加每类型 token 的 golden 测试（当前证据契约测试只覆盖 skill 片段，不覆盖 hint 文本）；把重复的 `callee@`/`size@`/`null@` 格式化抽成小助手；仅在改动某类型时把该类型块迁到对应 `registry_<type>.go`。
- **预期收益**：AI 证据契约可回归；降低后续新增类型时的冲突面。
- **回归风险**：中-高。hint 文本会影响 AI 分类；golden + recall 门禁是前提。

### M-10 进程级全局可变状态与单次扫描假设

- **位置**：`evidence/detector.go:308` `batchMode`、`:314` `eventBatch`、`:333` `eventFlushFailures`；`db/crud_findings.go:17` `SupportedFindingCWEs` + `:47` `SetSupportedCWEs`；`report/snippet.go:107` `globalSourceLineCache`；`planner/null_flow.go:2860` `liveFileParseCaches`；`planner/user_contracts.go:10-11`。
- **证据**：事件批处理是包级变量，`RunAllDetectors` 前后设置/清理；CWE 集合由 CLI 启动时覆盖；source 行缓存/LRU 是进程级；`liveFileParseCaches` 是用于泄漏诊断的全局 `sync.Map`。
- **建议**：把“一进程一次扫描”写成显式约束（注释/`ValidateRegistry` 类守卫）；为测试提供 reset；若要支持库式嵌入，再把 batch 收进 `RunAllDetectors` 的实例状态。当前不急着抽象。
- **预期收益**：避免未来的并行/嵌入误用；测试隔离更可靠。
- **回归风险**：低。

### M-11 `context` 取消未贯穿区间分析

- **位置**：`planner/return_summary.go:175`（`analyzeRangesWithCalls(context.Background(), ...)`）；`planner/registry.go:291`（启动校验，可接受）。
- **证据**：`newReturnSummaryResolver(ctx, ...)` 只在构造时使用 ctx 查询 DB，没有保存；`funcNonZero` 内部的分析用 `Background`。`funcNonZero` 被 `filter_range.go:101`、`global_invariants.go:252` 调用，属于扫描期路径。
- **建议**：resolver 保存 ctx 或让 `funcNonZero` 接收 ctx。
- **预期收益**：取消/内存压力可以中断长分析。
- **回归风险**：低；签名内部，行为不变。
- **备注**：初版把 `range_flow.go:166 analyzeRanges` 列为死代码是错的；它被 `range_flow_test.go:40`、`range_guard_test.go:25` 使用，是测试便捷包装。

### M-12 每个检测器重复读取源文件

- **位置**：`evidence/detector.go:72-95`（`forEachFile` 内 `os.ReadFile` + `p.ParseCached`）；全仓 60 处 `forEachFile*` 调用。
- **证据**：解析树按文件名缓存，源字节不缓存；每个 detector pass 都要重新读同一文件。基准语料 61 文件 × 35+ pass ≈ 2,000+ 次读取；大仓库按文件数放大（操作系统 page cache 会缓解，但仍是系统调用与内存拷贝）。
- **建议**：先在大语料上量化 I/O 占比；若显著，考虑由 `RepoIndex`/扫描上下文持有有界源字节缓存，或让 parser 在一次扫描内缓存源字节（带内存上限）。
- **预期收益**：detector 阶段（当前 666ms/1.32s）的重复 I/O 下降；大仓库收益更明显。
- **回归风险**：中。内存上限与 parser 的 LRU/引用计数交互需要验证；不能破坏 `Release` 语义。

### M-13 CLI 命令覆盖缺口

- **位置**：`cli/diff.go:35` `runReviewCmd`（Crapper 0%，CRAP 1,640）、`cli/classify.go:23` `runClassifyCmd`（10.8%，CRAP 1,354）、`cli/index.go:20` `runIndexCmd`（0%，CRAP 650）、`cli/plan.go:17`、`cli/def.go:71`、`cli/metrics.go:44`、`cli/query.go:14`、`cli/schema.go:126`。
- **原因**：测试集中在 scan/report 主链路；命令入口依赖 os.Args/stdio，缺少可注入的 runner。
- **建议**：提供命令级测试 harness（临时 DB + 捕获 stdout），至少覆盖参数解析、错误路径、关键输出字段；优先 `runReviewCmd`/`runClassifyCmd`（CRAP 最高且覆盖最低）。
- **预期收益**：CLI 从 10k 行/62.3% 覆盖的盲区变为可回归；降低命令层重构风险。
- **回归风险**：低（测试代码）。

### M-14 `internal/skills` 包 API 零覆盖

- **位置**：`skills/skill.go:22-38`（`NewRegistry`/`Register`/`Get`/`List`）、`skills/vuln_type_skill.go:24-115`（`NewVulnTypeSkill`/`Query`/`DefaultRegistry`/`AllDomains`/`SkillsByDomain`）
- **证据**：合并覆盖率 0%（37 语句）；现有测试只读取 `SKILL.md` 文本并与 `planner` 注册表比对，不调用这些函数。
- **建议**：为 registry 的重复注册、未知名称、Query 的 DB 查询路径补单测。
- **预期收益**：`secguard query`/默认注册表的可靠性有证据。
- **回归风险**：低。

### M-15 `enclosingWorktree` 跨包逐字重复

- **位置**：`cli/scan_scope.go:55-73` 与 `repofacts/repofacts.go:402-420`
- **证据**：Dryer 报为 score=1.0、19 行的重复；两处都从目标路径向上查找 `.git`（目录或 worktree/submodule 文件）。
- **原因**：扫描范围元数据与 repofacts 各自实现了同一探测规则，未抽共享工具。
- **建议**：移到 `internal/git`（或一个不依赖上层的小包）并由两处调用；补“目录 / worktree 文件 / 子模块 / 非 git 路径”测试。
- **预期收益**：worktree 判定规则一份；扫描范围与 repofacts 不会对同一路径给出不同答案。
- **回归风险**：低。两处当前逐字相同，抽出不改变行为；测试覆盖四个边界即可。

### M-16 `settlement` 吸收路径的死查询与死赋值（静态检查新发现）

- **位置**：`internal/cli/settlement.go:200-214`（`rowsByScan` / `ListSettlementStatsByScan`）；同类 ineffassign：`cli/metrics.go:56`、`cli/settlement.go:140`、`evidence/buffer_overflow.go:2310`、`planner/filter_constant_path.go:282`、`planner/planner.go:199`、`planner/registry_buffer_overflow.go:202`
- **证据**：staticcheck SA4006 与 golangci ineffassign 共 7 条。`rowsByScan` 的查询结果从未被读取（只写入 map，随后用 findings/verdict 计算 complete），是每个 scan 一次白跑的 DB 查询；其余为死赋值/无用初值。
- **原因**：完成度判定已改为 verdict ledger（见 215–219 行注释），旧的 settlement-range 读取未删干净；部分修复留下了为可读性服务的死赋值。
- **建议**：删除 `rowsByScan`/`ListSettlementStatsByScan` 的死查询；清理 6 处死赋值；把 staticcheck/ineffassign 加入 CI（M-08）。删除前确认没有通过事务内读取产生副作用的预期。
- **预期收益**：减少每次 absorb 的 DB 往返；代码意图清晰；静态检查归零。
- **回归风险**：低。行为不变；只需确保 `candidateCountByScan`/`knownByScan` 的来源不受影响。

---

## 6. 低风险问题清单

### L-01 死代码（工具确认 18 个未使用函数 + 1 个死包）

- **位置/证据**（staticcheck U1000 与 golangci unused 一致）：
  - `graph/edge_batch.go:86` `total`、`:93` `failedTotal`
  - `graph/ownership.go:204` `firstArgIdentifier`
  - `cli/pipeline.go:639` `graphExists`、`:646` `eventsExist`、`:752` `configChecksumUnchanged`
  - `evidence/dereference.go:288` `collectNonNullableArrays`
  - `evidence/divide_by_zero.go:164` `divOrModDivisor`（已被 `:185` `divOperands` 取代）
  - `evidence/free_summary.go:1079` `summaryMap.hasSummary`
  - `evidence/memory_leak.go:2279` `getDestroyCounterpart`
  - `planner/cfg_cache_ctx.go:25` `cfgCacheFromCtx`、`:39` `buildStmtCFGFromCtx`
  - `planner/filter_uninit_heapstruct.go:246` `addressTakenFieldPath`
  - `planner/null_flow.go:322` `mustReaching`、`:2733` `isNullLiteralExpr`、`:2787` `nullLiteralParensBalanced`
  - `planner/user_contracts.go:27` `resetUserContractsForTest`
  - `planner/zz_null_deref_guard_review_test.go:60` `hasLine`
  - 整个 `internal/agent` 包（28 行，无任何 import；U1000 不检查包级死包）
- **建议**：作为一个纯删除单元，先 `grep` 确认无 build-tag/反射/接口调用，再删除；`divOrModDivisor`/`isNullLiteralExpr` 的删除能消除“哪份才是权威实现”的歧义。
- **收益**：减少维护面；避免未来有人修复到已死的实现。
- **回归风险**：低（未引用）；`go build ./...` + 全测试即可证明。

### L-02 gofmt 债务

- **位置/证据**：`gofmt -l sgre` 28 个文件（21 生产 + 7 测试）：`cli/report.go`、`db/entities.go`、`evidence/buffer_unchecked_index.go`、17 个 `planner/registry_*.go`、`worker/executor.go` 及 7 个测试文件；单文件 diff ≤20 行，均为格式/注释缩进。
- **建议**：单个纯格式化单元；随后在 CI 加 `gofmt -l` 门禁。
- **收益**：消除无意义 diff 噪声；格式门禁防止回退。
- **回归风险**：无（仅格式）；不要与逻辑修改混在同一提交。

### L-03 无基准测试 + `zz_` 测试堆积

- **证据**：0 个 `Benchmark*`；151 个 `zz_*_test.go`（386 个测试文件的 39%）；`CLAUDE.md` 文档化了 `go test -bench=.`。
- **建议**：为 index/graph/detector/plan 增加基准（复用 `testdata/perf/gen_codebase.go`）；新测试按功能命名，不要求一次性重命名 151 个历史文件。
- **收益**：性能回归有基线；测试可发现性逐步改善。
- **回归风险**：低。

### L-04 `db.SupportedFindingCWEs` 默认 map 与注册表漂移

- **位置**：`db/crud_findings.go:17`（23 个 CWE）vs `planner` 的 29 个类型。
- **证据**：默认集合缺少当前类型的 CWE（例如 argument-type/CWE-686、dangerous-function/CWE-676、implicit-contract/CWE-20、data-representation/CWE-843、stack-address-escape/CWE-562、invalid-free/CWE-761、switch-fallthrough/CWE-484、unbounded-length-copy/CWE-1284、signal-handler/CWE-479 等）；CLI 启动时用 `planner.AllCWEs()` 覆盖，所以生产路径正确。但直接用默认集合的 db 单测会拒绝这些 CWE 的 finding。
- **建议**：保持 CLI 注入不变；在 `db_test`（外部测试包，可 import `planner` 而不构成循环）加“默认集合是注册表子集/或不再维护默认”的 parity 测试；更彻底的做法是把 CWE 集合移到 `planner` 与 `db` 都能依赖的叶子包（改动较大，暂不建议）。
- **收益**：防止测试路径与生产路径语义不一致。
- **回归风险**：低。

### L-05 `registry_*` 证据拼装的结构重复（暂不合并）

- **位置**：`planner/registry_buffer_overflow.go:53-61` 与 `registry_out_of_bounds.go:38-46`（dupl 克隆组，合计约 150 token）；`registry_deadlock.go:30-45` 与 `registry_signed_compare.go:33-48`（Dryer 0.93）。
- **建议**：这些文本是 AI 分类契约，当前**不建议**机械合并；若后续修改其中任一类型，再抽“字段存在则追加 fragment”的小助手，并用 skill/证据契约测试锁定。
- **收益**：降低未来修改成本，不改变当前输出。
- **回归风险**：合并会改变候选文件文本，进而影响 AI 分类；必须用基准 recall 门禁验证。

### L-06 静态检查剩余项（style / 死赋值 / 未检查的 parser 语言）

- **位置/证据**：
  - `parser/parser.go:170` `p.SetLanguage(lang)`、`:290` `ps.SetLanguage(p.lang)` 返回 error 未检查（errcheck；语言版本不匹配时会静默得到不可用 parser）。
  - `evidence/uninit_variable.go:1208` SA4004：`for` 第一次迭代无条件 return；行为符合“只看第一个子节点”的设计，但循环是多余的，应显式取 `children[0]`。
  - `graph/call_graph.go:77`、`graph/funcptr_writes.go:49` S1021；`repofacts/layout_census.go:38` S1011；`planner/filter_macro_uncertain.go:63`、`report/markdown.go:236/237/456` S1039（4 条）。
  - `cli/metrics.go:56`、`planner.go:199` 等死赋值（与 M-16 合并处理；此条保留 parser/风格项）。
- **建议**：parser 的 `SetLanguage` 错误返回；SA4004 改成显式 `children[0]`；gosimple 按文件顺手清理。
- **收益**：静态检查归零；parser 初始化失败不再静默。
- **回归风险**：低；仅 parser 的 error handling 需要确认调用方不会因错误返回而改变启动行为。

---

## 7. 未执行检查

- `govulncheck`、`nilaway`：未安装，未执行。
- 全仓库变异测试：Mutator 只对 `internal/evidence/signed_compare.go` 与 `internal/planner/filter_range_oob.go` 做了定向运行；其余文件未做变异分数统计。
- 模糊测试、长时间稳定性/内存泄漏压测：未执行。
- 生产客户代码库扫描、不同编译器/平台编译（Windows/arm64/linux）、CPU/内存 profile：未执行；仅在本机 darwin/arm64 与公开基准语料上验证。
- `-race` 之外的并发压力测试（多扫描进程共享 WAL、并行 `report --write-json`）：未执行；代码注释显示历史上做过，但本轮没有复现。
- 完整基准召回门禁（`validate-benchmark.py` + benchmark 配置）：未执行；本轮只跑了默认配置的基准扫描。

---

## 8. 阶段二建议的治理单元与顺序

按“高风险、明确收益、低回归风险”排序。每个单元都应先建立行为基线（测试、基准输出），再改代码，最后用相同命令证明行为一致。

1. **U1 纯清理**：删除 L-01 的 18 个死函数 + `internal/agent` 死包；L-02 gofmt；L-06 的 gosimple/SA4004/parser.SetLanguage。零行为变更，先建立治理节奏。
2. **U2 静默错误**：修复 H-03 三处 `_ = forEach...`，加故障注入测试；决定“warn+继续”或“向上返回”的策略。
3. **U3 测试基座**：H-04 的 `mustBuild`/`mustDetect` helper、765 条测试 errcheck（按包分批）、零覆盖检测函数补测、CLI 命令 smoke test（M-13）；把 Mutator 定向结果保留为重构回归基线。
4. **U4 语义去重（低风险）**：M-01 空语义、M-03 数据流加载器、M-02 文件遍历、M-07 DB 模板、M-15 `enclosingWorktree`；每项单独作为治理单元，前后跑检测器夹具 + 基准召回。
5. **U5 CI 门禁**：M-08（完整测试 + vet + gofmt + golangci-lint/staticcheck + 覆盖率报告），独立于代码重构，风险最低。
6. **U6 中型去重**：M-04 区间流水线、M-05 作用域收集、M-06 同族检测器助手；M-16 死查询/死赋值。
7. **U7 复杂度**：H-02 uninit 参数结构体化（先测试后结构）；H-01 `runReportCmd` 按模式拆分（先 golden 输出）；M-09 `buildHintParts` 先补 golden，再决定是否迁移到 `registry_<type>.go`。
8. **U8 性能/上下文**：M-11 ctx 修复、M-12 源文件 I/O 量化后再决定。

不建议在阶段二一开始就做：大规模架构重构、把 `evidence`/`planner` 再拆包、机械拆分所有高 CRAP 函数、合并 `registry_*`/`apikb` 数据表的全部重复。这些要么收益不明确，要么会改变检测/输出语义。

---

## 9. 阶段二执行状态（2026-11-21）

| 单元 | 状态 | 证据/说明 |
|---|---|---|
| U1 死代码清理 | 完成 | 删除 18 个 staticcheck U1000 函数 + `internal/agent` 死包；220 行删除、0 新增；静态检查 unused 归零 |
| U2 静默遍历错误 | 完成 | 3 处 collect 返回/传播 error；新增 5 个故障注入测试；基准/扫描行为不变 |
| U1b 格式化与静态小项 | 完成 | `gofmt` 28→0；staticcheck 30→0；parser.SetLanguage 错误处理；settlement 死查询；7 处 ineffassign、9 条 gosimple 清零 |
| U4a 空指针语义单源 | 完成 | `parser.IsNullLiteral`/`ExprNullChecksParam` 单源；删除 evidence/planner 三份副本；新增 parser 特征测试 |
| U4c worktree 探测单源 | 完成 | `git.EnclosingWorktree` + 测试；cli/repofacts 两处 1.0 克隆消除 |
| U8 context 贯穿 | 完成 | `returnSummaryResolver` 保存 ctx，`funcNonZero` 用 `r.ctx` 不再用 Background |
| U5 CI 门禁 | 完成 | 新增 `.github/workflows/go-quality.yml`：gofmt + vet + 全量 test + staticcheck |
| U7a uninit 参数结构体 | 完成（参数层） | `uninitScanInputs` 替换 20/14/13 位置参数；676/505/272 行函数体仍未拆分 |
| U3a 测试错误传播基座 | 部分完成（核心） | 626 处裸 Build/Detect 已加断言（`b76beb5`）；另修复 9 条生产 errcheck（`82ac5e2`）；当前 uncapped 157（测试 127、生产 30） |
| U3b 零覆盖检测路径补测 | 完成（关键路径） | do-while CFG、`relationalNonZeroVar`、`BuildPlanSummary`、`SubprocessRunner.Run`（`5f185c2`/`404567c`）；`findFieldTypeName`/`writeSecondCalleeDefinition` + 指针/数组字段修复（`892fed9`） |
| U4b 文件遍历骨架统一 | 完成 | `internal/scanwalk.Each` 统一 evidence/graph 的 ReadFile+ParseCached+Release；新增 parse/skip/cancel 测试（commit `385d441`） |
| U4d 数据流加载器统一 | 完成 | `loadVarRefMaps` 单源；DATA_FLOW/ALIAS/RELEASE 加载器只保留边处理 |
| U6 中型去重 | 完成 | `buildRangeFlowsForCandidates`、`collectFileScope`、`classifyUnsignedCompare`、`firstFormatTaintArg`、`scanUsageTargets` |
| M-07 DB 模板去重 | 部分完成 | `listByIDs` 统一 4 个 chunked `List*ByIDs`（commit `5e896ac`）；其余 scan/CRUD 模板与 Dryer 大块未做 |
| U7b runReportCmd 拆分 | 未完成 | 1,472 行、10 个模式；需先建 golden 输出，属独立大型 PR |
| M-12 源文件重复读取 | 未完成 | 需在大语料量化 I/O 后再决定缓存方案 |
| L-03/L-04 基准与 CWE parity | 未完成 | 0 个 Benchmark；db 默认 CWE 集合仍需 parity 测试 |

**验证基线（合入 main + U3b 字段修复 + 生产 errcheck）**：`go build`/`go vet` 通过；`go test -count=1 ./...` 全通过；nosqlite 子集通过；`staticcheck` **0 findings**；`gofmt -l` **0**；基准召回 **132/132、FP 0、FN 0、193 候选、40 SARIF findings、263 passed**；默认扫描 **185 候选、40 自动确认、SARIF 2.1.0/185 results/28 ruleId**。历史 #309–#313 已合入 main `8d165e9`；当前分支新增 U3b 字段修复 `892fed9`、gosimple `c515a74`、生产 errcheck `82ac5e2`。


---

## 10. 回放实施手册（给其他 fork）

> 目标：让另一个 fork 不必重新做审计，也能按顺序复现/实施已确认的治理单元，并用同一组门禁证明行为未变。**不要**把本报告当成“改几行就完事”的清单：每个单元都先建立基线，再改一个独立单元，最后用命令验收。

### 10.1 前置条件与环境

| 项 | 要求 |
|---|---|
| Go | 1.25.x（审计/实现基线为 1.25.3；`go.mod` 是 `go 1.25.0`） |
| CGO | 必须开启（tree-sitter C 解析器）；需要 C 编译器 |
| SQLite | 代码使用 `modernc.org/sqlite`（纯 Go）；测试与扫描需要可写临时目录 |
| Python | 基准校验脚本 `examples/c-vuln-benchmark/scripts/validate-benchmark.py` 需要 Python 3 |
| 工具（可选） | `golangci-lint`、`staticcheck`、`gocyclo`、`gocognit`、`dupl`；Crapper/Dryer/Mutator 若可用更好 |
| 目录 | `sgre/` 是 Go module；所有 `go` 命令在 `sgre/` 下执行 |
| 数据 | 基准语料 `examples/c-vuln-benchmark/`；无需 AI 分类即可跑 CI 门禁 |

建议的 fork 初始基线（先确认你自己的 fork 与下列预期一致，再开始改）：

```bash
cd sgre
go build -buildvcs=false ./...
go vet -buildvcs=false ./...
go test -buildvcs=false -count=1 ./...
go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/
staticcheck ./...
gofmt -l cmd internal testdata          # 应为空
```

审计基线（`c6887e6`）：全量测试通过、race 无数据竞争、合并覆盖率 **82.3%**、golangci 默认截断 85（关闭上限 821）、staticcheck 30、gofmt 28。治理后（main `b8ee94d` + M-07 `5e896ac`）：staticcheck **0**、gofmt **0**、unused **0**、基准召回 **132/132、FP 0、FN 0、193 候选、40 SARIF、263 passed**、默认扫描 **185 候选、40 自动确认、SARIF 2.1.0/185 results/28 ruleId**。

### 10.2 回放方式（三选一）

**A. Cherry-pick 已合入的上游提交（最快，但要求 fork 与上游足够接近）**

```bash
git remote add upstream https://github.com/DannyAn/secguard-clang.git
git fetch upstream main
git checkout -b quality-replay upstream/main
# 代码提交（按顺序）
git cherry-pick a12c78d   # batch1: U1/U2/U1b/U4a/U4c/U5/U7a/U8
git cherry-pick abe22c7   # batch2: U4d/U6 range+scope
git cherry-pick 44ea5b2   # batch3: U4b evidence traversal
git cherry-pick d8a33f5   # batch4: U6 signed/injection helpers
git cherry-pick 4cf10a0   # batch5: U6 unchecked-return helper
git cherry-pick 5e896ac   # M-07 chunked List*ByIDs
git cherry-pick 385d441   # U4b shared scanwalk (evidence + graph)
git cherry-pick 5f185c2   # U3b do-while CFG + relationalNonZeroVar tests
git cherry-pick b76beb5   # U3a: assert Build/Detect errors in 106 test files
git cherry-pick 404567c   # U3b: plan summary + subprocess runner tests
git cherry-pick 892fed9   # U3b: pointer/array field type fix + second callee test
git cherry-pick c515a74   # U3a: drop blank map assignments (gosimple)
git cherry-pick 82ac5e2   # U3a: production errcheck paths
# 文档提交可按需 cherry-pick：ba05a99、faa51a6、0c3a331，或直接保留本报告
```

若 cherry-pick 冲突：停下，先跑 10.3 的基线；冲突说明 fork 的代码布局已偏离审计基线，改用方式 C，不要强行合。

**B. 从合并后的 main 取差异（适合 fork 只是跟随上游）**

```bash
git fetch upstream main
git diff c6887e6..b8ee94d -- sgre .github > /tmp/quality-remediation.patch
git apply --3way /tmp/quality-remediation.patch
```

再补本批 M-07（`git show 5e896ac | git apply --3way`）。补丁不包含本报告时，从上游拷 `docs/engineering-quality-audit.md`。

**C. 逐单元手工实施（适合 fork 已大幅偏离）**

按 §10.4/§10.5 的单元卡逐条做：每个卡都给出证据位置、最小改动、验收命令、回滚方式。**一次只做一个单元**，做完立即跑门禁并提交；不要把所有单元混成一个无法回滚的提交。

### 10.3 全局验收门禁（每个单元后都跑）

```bash
cd sgre
go build -buildvcs=false ./...
go vet -buildvcs=false ./...
go test -buildvcs=false -count=1 ./...
go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/
staticcheck ./...
gofmt -l cmd internal testdata          # 必须为空
```

行为/输出门禁（与基线逐项比较，任何差异都停下来解释）：

```bash
# 1) 基准召回（CI 的 canonical 命令；输出全部写 /tmp，不写仓库）
BENCH=/tmp/quality-bench
rm -rf "$BENCH" && mkdir -p "$BENCH"
cp -r examples/c-vuln-benchmark/src "$BENCH/"
cd "$BENCH"
"$REPO/bin/secguard" --config "$REPO/examples/c-vuln-benchmark/benchmark-secguard.toml" \
  scan . --db "$BENCH/sgre.db" > scan.log 2>&1
SCAN_ID=$(ls .codeagent/secguard-clang/scans | grep -v latest | head -1)
"$REPO/bin/secguard" report --audit --scan-id "$SCAN_ID" \
  --output-dir "$BENCH/.codeagent/secguard-clang/scans/$SCAN_ID" \
  --db "$BENCH/sgre.db" --allow-partial > audit.log 2>&1
python3 "$REPO/examples/c-vuln-benchmark/scripts/validate-benchmark.py" \
  --root "$BENCH" --expected "$REPO/examples/c-vuln-benchmark/expected-results.json" --json
# 期望：recall 132/132, false_positives=0, false_negatives=0, candidate_findings=193, sarif_findings=40

# 2) 默认扫描 shape（与 CI 基准不同的配置，不要混用）
rm -rf /tmp/quality-default && mkdir -p /tmp/quality-default/sc_2026-11-21_000000_abcdef
"$REPO/bin/secguard" scan examples/c-vuln-benchmark \
  --db /tmp/quality-default/sgre.db \
  --output-dir /tmp/quality-default/sc_2026-11-21_000000_abcdef
# 期望：185 candidates, 40 auto-confirmed, candidates.sarif: 2.1.0 / 185 results / 28 ruleId
```

禁止/避免：

- 不改 `CHANGELOG.md`、`VERSION`、`sgre/internal/cli/root.go` 的版本 fallback、`report/protocol.go` 的 `ToolVersion`。
- 不改 SARIF schema、Finding 字段语义、结果排序/去重/证据生成规则。
- 不升级依赖；不为了降低指标机械拆分函数。
- 每个 PR 保持“检测语义、CLI、SARIF、基准召回”不变；如果确实要改变行为，必须单独授权并更新期望值。
- `--output-dir` 的 basename 必须是 `sc_YYYY-MM-DD_HHMMSS_xxxxxx`，否则 CLI 直接拒绝。

### 10.4 已完成单元（可直接对照/回放）

| 单元 | 提交 | 关键改动 | 最小验收 |
|---|---|---|---|
| U1 死代码 | `a12c78d` | 删除 18 个 U1000 函数 + `internal/agent` 死包；删除 `edgeBatchWriter.flushed`（唯一读者已删） | `staticcheck` U1000=0；全测试 |
| U2 静默遍历错误 | `a12c78d` | 3 个 collect 返回/传播 `forEachFile*` error；`traversal_error_test.go` 5 个故障注入测试 | 新测试 + 全测试 + 基准 |
| U1b 格式化/静态小项 | `a12c78d` | gofmt 28→0、staticcheck 30→0、parser.SetLanguage error、settlement 死查询、ineffassign/gosimple | `gofmt -l` 空、`staticcheck` 0 |
| U4a 空指针语义单源 | `a12c78d` | `parser.IsNullLiteral`/`ExprNullChecksParam`；删除 evidence/planner 副本 | parser 测试 + 检测器测试 |
| U4c worktree 单源 | `a12c78d` | `git.EnclosingWorktree`；删 cli/repofacts 副本 | `go test ./internal/git` |
| U8 ctx 贯穿 | `a12c78d` | `returnSummaryResolver.ctx`；`funcNonZero` 用 `r.ctx` | 全测试 + 基准 |
| U5 CI 门禁 | `a12c78d` | `.github/workflows/go-quality.yml`（gofmt+vet+test+staticcheck） | workflow 2/2 green |
| U7a uninit 参数层 | `a12c78d` | `uninitScanInputs` 替代 20/14/13 位置参数；函数体未拆 | uninit/全测试 + 基准 |
| U4d 数据流加载器 | `abe22c7` | `loadVarRefMaps` 单源 | null/UAF/double-free 测试 + 基准 |
| U6 range/detector | `abe22c7` | `buildRangeFlowsForCandidates`、`collectFileScope` | range/detector 测试 + 基准 |
| U4b evidence 遍历 | `44ea5b2` | `forEachParsedFile` 统一三变体 | 全 evidence 测试 + 基准 |
| U6 signed/injection | `d8a33f5` | `classifyUnsignedCompare`、`firstFormatTaintArg` | 相关检测器测试 + 基准 |
| U6 unchecked-return | `4cf10a0` | `scanUsageTargets`；删未读 `freed` | 相关检测器测试 + 基准 |
| M-07 chunked List | `5e896ac` | `listByIDs` 统一 4 个 `List*ByIDs` | `go test ./internal/db` + 全测试 + 基准 |
| U4b evidence/graph 遍历 | `385d441` | `internal/scanwalk.Each` 统一读/解析/释放循环 | `go test ./internal/scanwalk` + evidence/graph + 全测试 |
| U3b 首批零覆盖测试 | `5f185c2` | do-while CFG 边、`relationalNonZeroVar` 边界 | `go test ./internal/graph ./internal/evidence` |
| U3a Build/Detect 断言 | `b76beb5` | 626 处裸调用改为显式错误检查（106 个测试文件） | `go test -count=1 ./...` + 基准 |
| U3b summary/runner 测试 | `404567c` | `BuildPlanSummary` 分支、`SubprocessRunner.Run` 成功/失败/解析 | `go test ./internal/report ./internal/worker` |
| U3b 字段类型修复 | `892fed9` | `fieldDeclarationName` 下钻指针/数组声明；`findFieldTypeName`/`writeSecondCalleeDefinition` 测试 | `go test ./internal/evidence ./internal/report` + 基准 |
| U3a 生产 errcheck | `82ac5e2` | JSON parse、hash write、Sscanf 错误处理 | `go test ./internal/planner ./internal/cli ./internal/evidence` + 全测试 |

回滚：每个单元可以用 `git revert <commit>` 或恢复该单元涉及的文件；已合入的提交都在 main 历史中，revert 后必须重跑 10.3 全部门禁。U1b 的 `parser.SetLanguage` 错误处理只在“语言版本不匹配”时改变行为，回滚时注意保留 error 语义。

### 10.5 剩余单元执行卡（未完成，按卡实施）

#### U3a 测试错误传播基座（核心已完成；剩余非 Build/Detect errcheck）

- **已完成**：626 处裸 Build/Detect 已加显式错误断言（`b76beb5`，106 个测试文件）；关闭 golangci 上限后 errcheck 794→166（测试 139，生产约 27），gofmt/staticcheck/全测试/基准均通过。
- **剩余**：其它测试调用（非 Build/Detect）的 errcheck，按文件/包继续；不要机械包一层忽略错误，先确认调用语义。
- **验收**：`go test -count=1 ./...`、nosqlite 子集、基准不变；每包提交。
#### M-07 剩余 DB 模板

- **证据**：Dryer 107 对大块中 62 对两侧都在 `internal/db`；`listByIDs` 只统一了 4 个 chunked `List*ByIDs`。
- **做法**：继续抽 `scan*`/`List*` 的 rows 生命周期（`scanEvents`、`scanLocations` 等），保留每实体 SQL；不要合并只是“数据形状相似”的查询。
- **验收**：`go test ./internal/db` + 全测试 + 基准；Dryer 复跑确认大块下降。
- **风险**：SQL 列/扫描目标差异；空 ids、>500 ids、扫描失败、事务内读必须覆盖。

#### U7b `runReportCmd` 拆分（大型，需 golden）

- **证据**：`internal/cli/report.go:317`，1,472 行、10 个布尔模式、23 个字符串 flag。
- **做法**：先为 `--list/--list-auto-confirmed/--write/--write-json/--audit/--review/--stats` 各建 golden 输出（JSON 字段集、SARIF、DB 写入顺序）；再抽 `runReportListAutoConfirmed`/`runReportWrite`/`runReportAudit`/`runReportReview`/`runReportStats`；入口只保留参数解析和 DB 打开。
- **验收**：golden 逐字节/逐字段一致；`report --audit` 端到端；基准 SARIF 不变。
- **风险**：DB 写入顺序、JSON 省略规则、SARIF 排序；这是独立大型 PR，不要与去重混在一起。

#### M-12 源文件 I/O

- **做法**：先在较大语料（`sgre/testdata/perf/gen_codebase.go` 生成）测量 detector 阶段 `os.ReadFile` 占比；若显著，再加有界源字节缓存（受 parser LRU/内存水位约束），不要先改。
- **验收**：扫描耗时对比 + RSS；行为不变。

#### L-03/L-04

- L-03：为 index/graph/detector/plan 增加 `Benchmark*`，复用 `testdata/perf`；`go test -bench` 记录基线，不进入默认 CI。
- L-04：在 `db_test`（外部测试包，可 import `planner`）加默认 CWE 集合与 `planner.AllCWEs()` 的 parity 测试；不要在生产代码硬编码第二份 CWE 表。

### 10.6 常见坑（回放时最容易踩）

1. **golangci 默认会截断**：`--max-issues-per-linter 50`、`--max-same-issues 3`；审计数字 85 不是全量，关闭上限才看到 821。
2. **Crapper 的 Go 覆盖率是各包自测**，不是 `-coverpkg=./...` 合并值；`SharedAccessBuilder.Build` 这类跨包集成函数会被误报 0%。
3. **Dryer 是结构相似度**：`apikb` 数据表里 4 行 score=1.0 的命中不应当合并；只处理“语义应当唯一”的重复。
4. **Mutator 只做了两个定向文件**：`signed_compare.go` 76/76、`filter_range_oob.go` 82/82 killed；不是全仓变异分数。
5. **基准配置 vs 默认配置**：benchmark 配置是 193 候选，默认是 185；不要把两者混为同一基线。
6. **SARIF 两阶段**：`candidates.sarif` 是未分类 lead（level=note）；`result.sarif` 由 `report --audit` 在 AI 判定后生成；不要用前者断言 verdict。
7. **Draft PR 不能 merge**：需要 `gh pr ready <n>`；本仓库要求人合并，不启用 auto-merge。
8. **worktree / 生成目录**：不要编辑 `.claude/`、`.opencode/`、`.codeagent/`、`dist/`；审计/回放只在 `sgre/` 与 `extension/shared/`（若涉及）。
9. **Go 1.25 gofmt**：旧版本格式化的文件会被新版 gofmt 标记；U1b 的一次性格式化要单独提交，避免和逻辑改动混在一起。
10. **无 VCS 构建**：CI/临时 worktree 用 `-buildvcs=false`，否则可能报 `error obtaining VCS status`。

### 10.7 完成检查清单（每个 fork/每个单元）

- [ ] 先记录 `git status`、当前 commit、完整测试与基准结果。
- [ ] 只改一个独立单元；改动文件/函数与报告证据一致。
- [ ] 新增/调整测试；失败测试先复现，再修。
- [ ] 跑 10.3 全部门禁；与基线比较候选数、SARIF、召回。
- [ ] `git diff` 只含预期改动；`git diff --check` 通过。
- [ ] 不含 `CHANGELOG.md`/`VERSION`/依赖/输出 schema 变更。
- [ ] PR 描述写明问题证据、改动、验证命令与结果、剩余风险。
- [ ] 自动审查意见按“先验证再处理”评估，不盲从；人负责合并。

---

## 附录 A：可复现命令

```bash
cd sgre

# 构建/静态检查/格式
go build -buildvcs=false ./...
go vet -buildvcs=false ./...
gofmt -l .
golangci-lint run --timeout 10m ./...
staticcheck ./...
gocyclo -over 10 -top 30 .
gocognit -over 15 .
dupl -t 100 .

# 全量测试与竞态
go test -buildvcs=false ./...
go test -buildvcs=false -race ./...

# nosqlite 子集（CI 实际运行的门禁）
go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/

# 合并覆盖率（本次审计使用）
go test -buildvcs=false -coverpkg=./... -coverprofile=/tmp/cover-all.out ./...
go tool cover -func=/tmp/cover-all.out | tail -1

# Crapper / Dryer / Mutator（在模块副本中运行，避免写仓库；--root 指定指标输出目录）
cd ..
rm -rf /tmp/audit-copy && mkdir -p /tmp/audit-copy
cp -a sgre /tmp/audit-copy/sgre
cd /tmp/audit-copy/sgre
crapper --root /tmp/audit-copy/sgre
dryer --root /tmp/audit-dry -s /tmp/audit-copy/sgre
mutator --scan --root /tmp/audit-copy/sgre internal/evidence/signed_compare.go
mutator --root /tmp/audit-copy/sgre --no-coverage --max-workers 4 \
  --test-command "go test -buildvcs=false ./internal/evidence -run TestNewDetector_SignedCompare -count=1" \
  internal/evidence/signed_compare.go

# 基准扫描（输出到 /tmp，不改仓库）
go build -buildvcs=false -o /tmp/secguard ./cmd/secguard
mkdir -p /tmp/out/sc_2026-11-21_181500_abcdef
/tmp/secguard scan ../examples/c-vuln-benchmark \
  --db /tmp/sgre.db \
  --output-dir /tmp/out/sc_2026-11-21_181500_abcdef
```

## 附录 B：审计结论摘要表

| 维度 | 结论 | 主要证据 |
|---|---|---|
| 构建/静态检查 | 通过；golangci 默认 85（截断）/关闭上限 821、staticcheck 30 条 | build、vet、golangci、staticcheck |
| 测试通过性 | 通过（含 race） | 21/21 包，无 data race |
| 覆盖率 | 82.3%（合并） | `-coverpkg=./...` |
| 复杂度 | 生产 476 个函数 gocyclo >10；452 个 gocognit >15；Crapper CRAP>100 49 个 | gocyclo/gocognit/crapper |
| 重复 | Dryer 460 对 ≥0.82（107 对大块）；dupl 53 组（生产 14 组） | dryer/dupl |
| 架构 | 无生产循环依赖，兄弟层清晰；遗留进程级全局状态 | 生产 import 图 |
| Go 实践 | 并发生命周期良好；3 处遍历错误静默；ctx 有断点；2 处 SetLanguage 未检查 | 代码检查、golangci/staticcheck |
| 测试质量 | 定向变异 100% killed；但覆盖不均、765 条测试 errcheck、关键路径零覆盖 | Mutator、golangci、合并覆盖率 |
| CI | 有召回门禁；缺完整测试/vet/gofmt/lint/覆盖率 | `pr-benchmark.yml` |
| 输出兼容性 | 基准 SARIF 2.1.0 形状稳定；未跑 AI 分类 | 基准扫描 |
