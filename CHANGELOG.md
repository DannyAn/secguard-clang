# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。所有显著变更记录于此。

## [Unreleased]

### P1 竞品弱项改进（并行化 + 结构化证据链）

基于 `docs/pk/competitive-analysis.md` 的 P1 弱项分析，实施两项改进：

- **并行检测管线**：graph builder（5 个）、detector（21 个独立 + Interprocedural 后置）、planner（20 个）全部并行化，连接池从 1 放宽到 4 + busy_timeout=5000ms。大代码库（redis 11K 函数）扫描时间显著下降。
- **`--timeout <秒>` 超时控制**：`context.WithTimeout` 包 scan 顶层，超时后所有阶段（index/graph/detector/planner/report）协同取消，不再无限挂起。
- **`GetOrCreateGraphNode` 原子化**：`graph_nodes` 加 `UNIQUE(entity_type, entity_id, properties)` 约束 + `INSERT OR IGNORE`，消除并行 builder 的 SELECT-then-INSERT 竞态。迁移 `migrateGraphNodesUnique` 自动重建旧表。
- **SARIF codeFlows 2 步路径**：`Candidate` 加 `SourceLine` 字段，`NullableSourceFilter` 从 `flowResult.nodeIn`（reaching-definitions 源节点）提取源行号，SARIF result 加 `codeFlows` 结构（source→sink 2 步 threadFlow），GitHub Code Scanning 可直接展示"null 引入→解引用"路径。

## [0.2.0] - 2026-08-19

语义图完成度与收敛引擎的全面升级：把"声明未用"的语义图边真正落库并接入收敛管线，把数据流引擎从 null/free 扩展为可复用的污点/所有权/锁集引擎。这是对标业界同类产品（CodeQL / Infer / Semgrep 的 C 语义分析）的第一版。

### 竞品对标改进（精度 + 可集成性 + 召回率）

基于与 CodeQL/Infer/Coverity/Semgrep 的竞品分析（`docs/pk/competitive-analysis.md`），实施三项最高 ROI 改进：

- **suppression 持久化回路**：扫描启动时从 DB 加载 `status='dismissed'` 的 findings，按 `(file, line, rule_id)` 跳过已审阅误报，AI 不再重复审同一批 FP。新增 `--baseline <scan-id>` 只报与上次扫描相比新增的 finding。`internal/cli/suppression.go`。
- **CI gate**：`secguard scan --fail-on confirmed` 有 confirmed finding 时退出码 2，`--fail-on suspected` 退出码 3。从"AI 助手"升级为"可阻断 CI 的 gate"。
- **SARIF fingerprints + suppressions**：SARIF result 加 `fingerprints`（稳定指纹，GitHub 跨扫描追踪）和 `suppressions` 字段结构。
- **`malloc(n * sizeof(T))` 溢出检测**：`integer_overflow.go` 的 `sizeCalcExprs` 放开 `var * sizeof(T)` 模式——这是 CWE-190 最经典的 CVE 模式（CVE-2021-43267 等），此前被显式排除。
- **`strncpy(dst, src, n)` 大小比对**：新增 `BoundedCopyFunctions` 集合（strncpy/strncat/memcpy/memmove），当 n 是常量且 > dst 容量时报 `bounded_copy_overflow`。此前 strncpy 被列入 SafeFunctions 完全跳过。

### 语义图层（补齐 + 修复）

- **5 种边从"声明未用"到真正落库**：`ALIAS`（`q=p`/`q=p->f`/`q=p[i]`）、`OWNERSHIP_TRANSFER`（return-to-caller / store-to-global）、`RELEASE`（free/close 站点）；新增 `PARAM_BINDING`（实参→形参）、`RETURN`（callee 返回→caller 接收变量）。构建器：`internal/graph/{alias,ownership,interproc}.go`。
- **修复 `GetOrCreateGraphNode` 去重 bug**：原查询只按 `(entity_type, entity_id)` 去重、忽略 `properties`，导致同函数内所有 `variable_ref` 塌缩成同一节点、`DATA_FLOW` 边源/目标指向同一节点。修复为按 `(entity_type, entity_id, properties)` 去重。
- **删除 `BRANCH` 边**（声明但从未使用，CFG 分支结构无需落库），迁移 `migrateGraphEdgesTable` 自动重建旧表。

### 数据流引擎扩展

- **污点追踪**（`filter_taint_source.go`）：injection / path-traversal / format-string 从"仅 call-reach"升级为路径敏感 source→sink 分析（gen=污点源、kill=确定无污点、copy=赋值）。
- **过程间污点**：return-taint（`computeRetTainted` 沿 RETURN/CALL 边做不动点）+ param-taint（`computeParamTainted` 沿 PARAM_BINDING 边正向传播），消费语义图边。
- **别名传播**（`null_flow.go` 的 `loadAliases`/`expandGenToAliases`）：修复 `q=p; free(p); *q` 漏检（`findAliases` 扩展到普通赋值语句）。
- **resource-leak 所有权+路径分析**：对齐 memory-leak，return-to-caller / store-to-global 不算泄漏，错误路径漏关正确识别。

### 检测器升级

- **race-condition 锁集**：从"任意锁范围"升级为 CFG 级 must-hold 锁集 + 跨函数交集，识别条件加锁、不同 mutex 保护、跨线程函数竞态。
- **deadlock 传递闭包环**：从 2 环反向对升级为 Tarjan SCC 强连通分量检测（A→B→C→A）。
- **integer-overflow 路径敏感**：`int_overflow_guard` 过滤丢弃被小常数边界保护的尺寸计算。
- **退役旧 BuildCFG**：uninit 迁移到语句级 `StmtCFG`，删除 `internal/graph/cfg.go`；修复 `NodeAt` 行碰撞（控制流头节点 vs 叶子语句）。

### 修复

- `StmtCFG.NodeAt` 对"头节点 + 单语句体"同行返回头节点而非叶子语句，导致 `hasLeakingPath` 把 if 头加入 avoid、堵死所有路径（潜伏 bug，memory-leak 也受影响）。

### 发布前检视修复

v0.2.0 发布前最后一轮检视发现并修复的问题：

- **SARIF/markdown 报告版本号硬编码 `0.1.3`**：新增 `report.ToolVersion` 变量，由 `cli/root.go` 在启动时注入 `cli.Version`，确保报告始终携带实际发布版本。
- **10 处 graph builder `Build(ctx)` 返回值被丢弃**：`scan.go` 和 `index.go` 中 5 个 graph builder 的 `(*BuildResult, error)` 返回值被完全忽略，Build 失败时 scan 继续跑并产出"成功"报告但 graph 层空，导致静默漏报。全部改为检查 error 并 `return 1`。
- **migration sentinel 错位**：`migrateSecurityEventsTable` 用 `DIVIDE_BY_ZERO` 作"schema 已最新"的 sentinel，但 `SIGNED_COMPARE` 是最后加入的 event type。旧 DB 升级时 migration 误判已最新，`SIGNED_COMPARE` 事件插入被 CHECK 拒绝，signed-compare 检测器静默失效。sentinel 改为 `SIGNED_COMPARE`。
- **race_condition lockset map aliasing**：`acc.lockset = ls` 直接赋值共享 `heldByLine[line]` 底层 map，后续 `delete(acc.lockset, m)` 污染 `heldByLine[line]`，同一行多 global 访问时 lockset 计算错误。改为深拷贝。
- **5 处 `InsertEvent` error 丢弃但计数器递增**：`resource_leak`/`memory_leak`/`interprocedural`/`crypto_misuse`/`null_source` 中 DB 写入失败时事件未落盘但 `EventsCreated++`，统一为 `if _, err := ...; err == nil { EventsCreated++ }`。
- **`db_test.go`/`definite_null_test.go` 缺 `//go:build !nosqlite` tag**：导致 CLAUDE.md 声称的 `go test -tags nosqlite ...` 命令实际失败。
- **`crud_findings.go` 缺 crypto-misuse LegacyCWEs**：补全 `CWE-326`/`CWE-338`。
- **`schema_test.go` event_type 覆盖不全**：从 16 个补全到 26 个。
- **scan-id 后缀 4-hex→6-hex**：`TestGenerateScanID_Uniqueness` 因 4-hex 后缀碰撞概率 7.6% 而 flaky，增加到 6-hex（碰撞率降至 0.003%），同步更新 pattern/文档/测试。
- **CLAUDE.md edge_type enum 文档过时**：移除已删除的 `BRANCH`，补全 `PARAM_BINDING`/`RETURN`。

## [0.1.5] - 2026-08-17

狗粮测试（生产冒烟测试）后的全面自检与修复。重点解决管道死锁导致 report.md 不落盘、Agent 上下文被原始候选污染、findings 不持久化、DB schema 不可发现等致命问题。

### 修复

- **管道死锁导致 report.md 不落盘**：`secguard scan` 原先将 398KB+ JSON（含完整 `evidence_packages`）输出到 stdout 后才写 `report.md`，stdout 管道缓冲区仅 64KB 导致 Go 进程阻塞在 `fmt.Fprintln`，永远执行不到 `Write()`。修复：移除 `evidence_packages`，替换为 `candidates_by_type` 摘要（stdout 从 398KB→几 KB）；JSON 输出移到 `Write()` 之后；新增强制落盘验证（`os.Stat` 检查 `report.md` + `sarif.sarif` 存在且非空，失败返回退出码 1）。
- **`secguard plan`/`secguard query` 候选污染 Agent 上下文**：原先完整 candidates 直接输出到 stdout（上千行），触发 OpenCode 截断并存到 `~/.local/share/opencode/tool-output/`，诱导 Agent 读取截断文件并触发权限弹窗。修复：candidates 写入文件（`plan-<vuln>-<ts>.json`），stdout 只返回摘要 + `candidates_file` 路径。
- **`secguard_scan`/`secguard_plan` catch 分支返回原始大输出**：工具异常时不再透传原始大输出，改用正则提取 `scan_id`/`scan_dir` 返回精简信息，避免触发 OpenCode 截断。
- **安装包二进制权限检测失败**：`release/lib.sh` 的 `sg_select_binary()` 移移除 `[ -x "$candidate" ]` 检查（zip 解压后权限为 644 无 +x 位），仅保留 `[ -f "$candidate" ]`。
- **`secguard report` 无 findings 时返回 `[]`**：改为返回 `{findings:[], count:0, message:"..."}`，避免 Agent 误判命令出错。
- **Agent 报告引用不存在的 SARIF 文件**：`agent-body.md` 新增 SARIF 存在性验证指令——引用前先读 `<scan_dir>/sarif.sarif` 确认文件存在且非空。

### 特性

- **`secguard schema` 命令**（新增）：返回 5 张 Agent 可查询表（`findings`、`scan_stats`、`files`、`functions`、`security_events`）的列名、类型、约束与示例查询。Agent 不再需要猜列名（如误用 `vulnerability_type` 而非 `vuln_type`）。支持 `secguard schema`（全部表）和 `secguard schema <table>`（单表）。
- **`secguard_schema` OpenCode 工具**（新增）：`secguard schema` 的 OpenCode 工具包装，已注册到 `opencode.json` 权限列表和 Claude Code `settings.json`。
- **Agent findings 落盘强制指导**：`agent-body.md` 新增 `secguard_report` 具体调用示例（含 JSON payload 格式）和写后读回验证步骤——写完 findings 后调 `secguard_report`（无 `findings` 参数）确认 `count > 0`，失败则停止报告。

### 变更

- **stdout 是控制通道，不是数据通道**：完整数据（candidates、evidence packages）写文件，stdout 只返回摘要 + 文件路径。这是本轮修复的核心设计原则，贯穿 `scan`/`plan`/`query` 三个命令。
- **Claude Code 权限补全**：`.claude/settings.json` 新增 `Bash(secguard types *)`、`Bash(secguard db *)`、`Bash(secguard schema *)` 权限。
- **`agent-body.md` 工具调用指导**：明确区分 OpenCode 工具名（`secguard_scan`）与 bash 命令名（`secguard scan`），避免 Agent 混淆。

## [0.1.3] - 2026-08-17

安装验证后的缺陷修复（Bugfix release）。

### 修复

- **skill 缺少 YAML frontmatter**：为 `uninit` 与 `resource-leak` 两个 skill 的 `SKILL.md` 补充 YAML frontmatter（`name` / `description` / `license` / `compatibility` / `metadata`）。此前 OpenCode 因缺少 frontmatter 无法识别并加载这两个 skill，导致扫描时 agent 报 `Skill "uninit" not found`；其余 18 个 skill 均已具备 frontmatter。

## [0.1.2] - 2026-08-16

生产环境审计暴露的缺陷修复（Bugfix release）。重点解决扫描输出截断、上下文爆炸、CWE 缺口与检测器归属错误，并修复 Windows/Linux 交叉编译与发布组装流程，使 CI 发布可端到端跑通。

### 修复

- **扫描输出截断**：`secguard_scan` / `secguard_plan` 工具不再透传原始 JSON（曾导致 117KB+ 的工具输出被截断），改为只返回元数据（`scan_id`、`output_dir`、各类型候选计数）；Agent 改从 `report.md` 读取候选详情。
- **上下文爆炸**：重写 `agent-body.md` / `command-instructions.md` 的 Full/Filtered 工作流为按类型分批处理——每批只加载 1 个 skill、读取 ≤5 个源文件、写入 1 种类型的 findings，消除一次性「加载全部 skills + 读取全部源码」的模式。
- **CWE 缺口**：`crypto-misuse` 的 `VulnTypeSpec` 增加 `LegacyCWEs`（`CWE-326`/`CWE-338`），`injection` 保留 `CWE-89` 作为遗留 CWE；`AllCWEs()` 现返回 23 项（20 个规范 CWE + 3 个遗留 CWE），历史 finding 可继续写入。
- **findings 表结构未文档化**：`agent-body.md` 记录 findings 表列名（`file_path`、`line_number`，而非 `file`/`line`），避免 Agent 猜列名导致查询失败。
- **检测器函数归属错误**：`detectUndersizedKey` 按声明行所在函数（`funcLineRange`）归属 undersized-key 事件，此前所有事件都被错误归属到 `funcs[0]`。
- **CWE 单一事实来源**：`VulnTypeSpec` 新增 `CWE` 字段并派生 `AllCWEs()` / `CWEForType()` / `TypeForCWE()`；`db.SupportedFindingCWEs` 在启动时由 `planner.AllCWEs()` 注入，`report` 不再硬编码 CWE→类型映射。
- **跨扫描隔离**：`secguard scan` 的 findings 列表改为按 `scan_id` 过滤（`ListFindingsByScanID`），不再把其它扫描的 findings 混入当前输出。
- **scan_id 校验**：显式 `--output-dir` 的 basename 必须匹配 `YYYY-MM-DD_HHMMSS_xxxx` 格式（防路径穿越 / 任意 scan_id 注入）；`report` 写入 finding 前校验 `scan_id` 存在。
- **`security_events` 查询封堵**：`secguard db` 对该表的禁用改为词边界正则，覆盖 `main.security_events`、字符串字面量与 `pragma_table_info('security_events')` 等变体。

### 构建与 CI

- **zig 0.14.1 下载 URL**：修正 artifact 命名（`zig-linux-x86_64-…` → `zig-x86_64-linux-…`），旧 URL 返回 404 导致 Windows 交叉编译（进而整个发布）失败。
- **Windows 交叉编译环境**：与 `lib.sh build_target` 对齐，补充 `CGO_CFLAGS/CGO_CXXFLAGS`、本地 zig cache、`TMPDIR`、`GOFLAGS`，修复 tree-sitter-c cgo 交叉编译的 `AccessDenied`。
- **`ZIG` 未绑定变量**：`build-packages.sh` 在 `set -u` 下将 `ZIG` 初始化为空，修复 `--assemble-only` 步骤的 `ZIG: unbound variable`。
- **claude-code 源包装文件未被追踪**：`.gitignore` 把 `.claude/` 锚定为根目录 `/.claude/`，并追踪 `extension/claude-code/.claude/` 下的源包装文件，修复 CI checkout 缺失导致的 assemble 失败（`cannot stat .../commands/secguard.md`）。

### 变更

- **发布工具目录重命名**：`extension/dist/` 重命名为顶层 `release/`（构建/安装工具而非分发产物），`dist/` 保持为唯一分发输出目录；移除过时的 `deploy/` 目录，文档路径同步更新。

## [0.1.1] - 2026-08-16

部署验证后的缺陷修复（Bugfix release）。

### 修复

- **`.codeagent` 输出位置**：扫描结果现在解析到启动目录（被扫描项目），而不是 git 仓库根，避免在嵌套项目（如 `examples/c-vuln-benchmark/src`）下审计时把结果写到仓库根。
- **单次扫描单目录**：`secguard_scan` 不再预创建输出目录（改由 Go 二进制创建），并移除遗留的 `secguard_quick_scan` 工具，一次扫描只产生一个 scan 目录。
- **报告表格**：汇总/报告表增加 `Skill` 列、报告头（代码仓绝对路径 + 扫描目录）与简洁的观察项表。
- **`/secguard` 直接执行**：命令 frontmatter 不再声明 `agent:`，避免被包装成 subagent 转发后被压成纯文本，表格直接作为终端输出。
- **agent 模式**：`security-auditor` 由 `subagent` 改为 `all`，可被直接调用，也为后续按 skill 并发调度预留编排能力。
- **安装/卸载清理**：install/uninstall 会清理旧版平铺式安装（`~/.config/opencode` 下的 tools/skills/agents），避免与新扩展目录并存漂移。

## [0.1.0] - 2026-08-15

首个可部署版本（First deployable release）。

### 特性

- **20 种漏洞类型**：null-deref、buffer-overflow、memory-leak、injection、resource-leak、uninit、use-after-free、double-free、format-string、integer-overflow、race-condition、hardcoded-secret、deadlock、crypto-misuse、out-of-bounds、divide-by-zero、unchecked-return、path-traversal、sizeof-misuse、signed-compare。
- **4 层数据模型**（SQLite）：程序事实 → 语义图（调用图 / 数据流 / 控制流）→ 安全证据 → 发现。
- **22 个安全证据检测器**，基于 tree-sitter 的 C 语法解析，自注册于 `registry.go`。
- **漏斗式收敛流水线**：候选从原始线索收敛为去重后的高置信证据包，**无候选数量上限**（AI Agent 分批复核全部去重候选）。
- **跨函数图分析**：null-deref 的「到达空值源」数据流、use-after-free 的「free→use」控制流可达性。
- **多平台 AI Agent 扩展**：OpenCode 与 Claude Code 双平台（shared-core + thin-wrapper），`security-auditor` 子代理负责分类与落库。
- **报告输出**：SARIF 2.1 + Markdown 摘要 + 逐条 finding 详情。
- **基准回归门禁**：`examples/c-vuln-benchmark` 53 用例，TP=26 / FP=0 / TN=27 / FN=0（精度 100%、召回 100%）。

### 已知限制

- 依赖 **CGO**（tree-sitter 运行时与 C 语法解析器为 C 实现），因此无法用 `CGO_ENABLED=0` 纯静态构建；Linux 产物为 zig/musl 静态链接。
- 仅支持 **C**（`.c` / `.h`）；C++/Objective-C 暂未覆盖。
- `memory-leak` / `resource-leak` 仍使用检测器内的路径分析（旧 `BuildCFG`），尚未迁移到新的语句级 CFG（需所有权转移感知）。
- 去重后的候选仍需 AI Agent 分类确认，流水线自身不产出最终 verdict。

### 本次发布前的版本一致性修复

- 统一版本号为 `0.1.0`：`internal/cli.Version` 改为 `var` 以支持 `-ldflags -X` 注入，`VERSION` 文件、构建脚本 `build_target` 均已同步。
- 修正 OpenCode 扩展层硬编码的「15 种类型 / <=30 候选上限」描述，改为以 `secguard types`（Go 二进制）为唯一权威来源。
