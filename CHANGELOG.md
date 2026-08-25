# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/)。所有显著变更记录于此。

## [0.4.6] - 2026-08-25

### 修复两类"守卫事实被重赋值污染"的假阴性

`range_analysis.go` 由 `if` 条件推导的"非空 / 上界"事实此前不因后续整变量重赋值而失效，导致两类漏报：

- **null-deref**：`if (p == NULL) return; p = NULL; return *p;` —— 守卫建立"p 之后非空"，但 `p = NULL` 没失效该事实，dereference 检测器直接跳过发射事件、GuardFilter 又按旧 scope 二次误删，definite null-deref 漏报。修复：`NonZeroAt` 在"RHS 可能为零"的重赋值处 kill；`null_guard` 的 EARLY_RETURN / REASSIGN_GUARD scope 在首次重赋值处截断（`guardScopeEnd`）。
- **buffer-overflow**：`if (n <= cap) { n = 1000; memcpy(dst, src, n); }` —— 守卫推导 `n ≤ cap`，但 `n = 1000` 重赋值后上界失效，`UpperBoundAt` 仍返回旧上界，溢出被错误抑制。修复：`UpperBoundAt` 在守卫体内任何重赋值处失效。

`RangeFacts` 的重赋值跟踪重构为"行号 + RHS 文本"：`NonZeroAt` 只对"可能为零"的重赋值 kill（`v = 5` 重新确立非零，避免除零回归），`UpperBoundAt` 对任何重赋值 kill。

### 性能与可维护性

- **memory-leak RAII 配对不再每候选重读盘**：原 `functionHasFrees` 对每个 `_create/_destroy` 候选都 `os.ReadFile` + 全文件 `FindAll`，改为每文件一次 free 预扫描（`freeFuncs` 按函数 ID 存）。
- **`extractFunctionBodyFrom` O(F²) → `functionBodyMap` O(1)**：memory/resource/race/uninit + free_summary 六处调用统一换成每文件建一次 body map。
- **删除死代码** `flowResult.reachingAtExit`（含误导性的 "leak condition" 注释）。
- **`ownership.go` 补契约注释**：检测器=宽口径主判定，图级 OWNERSHIP_TRANSFER=窄口径安全网。

### 测试

- 新增 `tc74_raii_create_destroy` 回归（RAII 路径原本零覆盖）。
- `zz_review_verify_test.go` 的 TEMP 草稿转成真 recall 断言（4 个流敏感 FN 用例全 KEPT）。
- 新增 `range_analysis_test.go`，直接断言 `UpperBoundAt` 有/无重赋值两个行为。

## [0.4.5] - 2026-08-25

### 安装器与插件注册修正

- **CodeAgent 插件注册**（claude-code / claude-cac）：安装时向
  `installed_plugins.json` 注册插件、在 `settings.json` 的 `enabledPlugins` 中启用，并在
  插件目录与 `plugins/cache/local-secguard/` 各写一份 `codeagent-extension.json` 运行时清单；
  卸载时同步注销并清理 cache。缓存复制改用 `/.`（`*` 不匹配点文件，会漏掉
  `.claude-plugin/`/`.cac-plugin/` 清单）。
- **修复卸载不清理权限**：`sg_remove_permissions` 的 Python 代码里模块级 `return` 是
  SyntaxError，权限移除从未生效（被 `|| true` 掩盖），改为 `sys.exit(0)`。
- **opencode-nga 清单改名**：`code-extension.json` -> `codeagent-extension.json`、
  `code-extension-install.json` -> `.codeagent-extension-install.json`（安装占位符替换逻辑
  不变）；安装/部署时清理 <=0.4.4 遗留的旧清单名，避免同目录两套清单。
- **修复 SARIF 双击找不到文件**：`candidates.sarif` / `result.sarif` 的
  `artifactLocation.uri` 由裸绝对路径改为 `file://` URI（裸绝对路径不是合法 URI，SARIF
  查看器按相对引用解析后报 "Unable to find <file>"）；相对路径仅做斜杠归一化保持相对。
- **修复 claude-code / claude-cac 不并行分类**：`/secguard` 命令的 `allowed-tools` 补齐
  子代理分发工具（`Agent`，旧版为 `Task`）与编排所需工具（`Write`/`Edit`/`TodoWrite`/
  `Skill`），并统一指令中的工具名。此前编排器无法派发 `security-auditor` 子代理，被迫
  单上下文顺序处理大扫描，导致上下文耗尽并报 `unknown`（上下文限制）。
- **修复 claude-cac 子代理模型不可用**：`security-auditor` 移除硬编码的 `model: sonnet`，
  子代理改为继承当前模型（等效 general-purpose）。此前 fork 环境无 `sonnet` 模型别名，
  并发派发的 4 个子代理全部报「子代理类型需要不可用模型」而失败。
- **修复 codeagent-extension.json 的 author 字段类型**：OpenCode-NGA / CodeAgent 格式要求
  `author` 为字符串，此前写成对象 `{name,url}` 导致 opencode-nga 扩展无法注册，改为
  `"author": "Zhuque Security"`（`sg_write_codeagent_extension` 同步修正）。

## [0.4.4] - 2026-08-24

### 生产环境安装与部署修正

修复多平台 agent 扩展的安装位置错误，并按官方约定新增两个开源分支部署方案。

- **Claude Code 改走官方插件目录**：不再把整套扩展塞进 `~/.claude/skills/`（那是全局
  单技能目录），改安装到 `~/.claude/plugins/secguard-clang/`（`.claude-plugin/plugin.json`
  清单 + commands/agents/skills/hooks）。
- **OpenCode 清理误装配置**：安装/卸载时移除 OpenCode 扩展目录里误残留的
  `.claude-plugin`/`.claude-plugins`（张冠李戴）。
- **新增 `claude-cac` 平台**（Claude Code 开源分支）：部署到 `~/.cac/plugins/secguard-clang/`，
  清单改为 `.cac-plugin/plugin.json`，其余与 claude-code 一致。
- **新增 `opencode-nga` 平台**（OpenCode 开源分支）：部署到 `~/.config/opencode/extensions/secguard-clang/`，
  `extension.json`->`code-extension.json`，新增 `code-extension-install.json`（其 `source`
  由占位符在安装时替换为实际路径），其余与 opencode 一致。
- 权限清单补齐 `types`/`schema` 两项，`--target` 支持 4 平台（opencode / opencode-nga /
  claude-code / claude-cac / all），build-packages.sh / install.sh / uninstall.sh / deploy.sh
  全部同步。

### 修复 result.sarif / result.xlsx 文件定位与代码上下文缺失

- **修复 result.sarif 同一类型重复出现**：agent 用「绝对路径」与「截断相对路径」各写一次
  同一缺陷时，因唯一索引含 `file_path` 落成两行，导致同一 rule 输出两份。写入时
  `resolveFindingFilePath` 归一化路径、审计时 `dedupeAndNormalizeFindings` 收敛重复行。
- **修复 report.md 截断路径**：`shortFile`（只留最后两段）改为 `displayPath`（仓库相对/
  绝对完整路径），agent 不再抄走不可定位的截断路径。
- **修复双击找不到文件 / 缺代码上下文**：`candidates.sarif` 与 `result.sarif` 的
  `artifactLocation.uri` 改为绝对路径；`report.md`/`result.sarif`/`result.xlsx` 均能解析
  源码并嵌入代码上下文。
- `result.sarif` 规则去重把 legacy CWE 归一化到 canonical（如 CWE-89→CWE-78），避免
  injection/crypto-misuse 因混用 CWE 拆出两条同名 rule。

### 调度与提示词修正

- **Scale Gate 强制约束**：`total_candidates > 200` 时禁止 SEQUENTIAL，并行不可用时须明确
  告知用户而非擅自降级；缺失类型失败原因澄清 `maxturns-exceeded`（特指子代理）与
  `unknown`（从未分发）语义。
- **候选文件读取性能**：明确「扫描阶段」的 `report.md` 是候选索引（其逐类型表已含
  `File:Line` + `Suspicion`），禁止为取 file:line 逐个 READ `candidates/<type>/NNN_*.md`。
  说明：`report.md` 是双阶段文件——扫描后暂为候选索引，`report --audit` 时会从 findings
  表覆写为最终综合报告，与 `result.sarif` 同源（仅展示形式不同）。

### 漏洞分层筛选精度增强

- **path-traversal 跳过带 cast 的字符串常量**：`fopen((const char *)"/etc/x", ...)` 此前因
  参数文本以 `(` 开头（而非 `"`）被误判为非字面量，报 CWE-22。`isStringLiteralText` 现在
  先剥离前导成对括号再判断字面量，这类常量路径不再进入 AI。
- **null-deref 把「确定为空」反映到 suspicion**：此前所有 null-deref 候选一律标
  `confirmed`，AI 只能橡皮图章式全盘确认。现在 must 分析已算出的 `has_definite_null`
  （`p = NULL` 在每条路径都成立）反映到标签上——确定为空 → `confirmed`（AI 轻量核对），
  可能为空（malloc 返回 / 函数返回）→ `suspected`（AI 深度推理、可 dismiss）。让 AI 的
  工作量对齐管道的确定性，而不是无差别确认。

## [0.4.3] - 2026-08-23

### result.xlsx Excel 导出（供研发团队集中确认）

findings 落库后，研发团队需要在表格里定位、分析、确认每一条漏洞。本轮为
`secguard report --audit` 新增 `result.xlsx`：单 sheet（`Findings`）、13 列，每行一条
可行动 finding（confirmed + suspected，dismissed 排除），让研发不打开源码树也能在
一张表里完成确认。

- **`report --audit` 自动生成 `result.xlsx`**：从 `findings` 表重生成，与 `result.sarif`
  同生命周期（分类前不存在，`--audit` 响应新增 `xlsx_path`）。单向导出——不回读，
  表格里的修改不回写数据库。
- **13 列自包含**：序号 / 漏洞类型 / CWE / 严重级别 / 结论 / 置信度 / 文件 / 行号 /
  函数 / 问题摘要 / 详细分析 / 修复建议 / 代码上下文。漏洞类型由
  `TypeForCWE(rule_id)` 反查，摘要走 `summary → reasoning → evidence → function_name`
  回退链，修复建议与 `[exception check]` 一并带入。
- **代码上下文列**：内嵌 ±`--context-lines`（默认 15）源码窗口，命中行标 `>`、等宽
  字体渲染；`--context-lines 0` 时该列留空（源码不得外流的仓库）。
- **表格能力**：冻结表头 + `A1:M{n+1}` 自动筛选 + 按列宽优化，按
  漏洞类型 → 文件 → 行号排序，输出稳定、可集中管理。
- 新增 `report.WriteXlsxFromFindings`（`sgre/internal/report/xlsx.go`）与 4 个测试，
  `ResultXlsxFile = "result.xlsx"` 常量，接线 `cli/report.go` audit 块与 `--audit`
  帮助文本；新增依赖 `github.com/xuri/excelize/v2`（纯 Go、无 cgo）。

## [0.4.2] - 2026-08-23

### sgre 引擎 semantic graph 收敛能力提升

基于 c-vuln-benchmark 样例项目扫描分析：98 个候选中 57 个为 suspected（58%），
全部需 AI 读源推理，导致 9 分钟扫描耗时。本次通过增强 filter 链确定性收敛能力，
预计减少 ~14 个 suspected 候选进入 AI 分类阶段。

#### 代码层

- **unchecked-return ReturnCheckFilter (REQ-1)**：新增 `filter_return_check.go`，
  使用 parser AST 分析调用点上下文。裸调用（`malloc(size);`）与赋值/声明后无
  后续空值/错误码检查的调用升级为 confirmed。过滤器**只升级、不 dismiss**——
  “返回值已在后续 if 中检查”这类候选由检测器在事件层直接抑制，避免过滤器
  误把“后续 if 只是解引用使用”（`p = malloc(); if (p->len > 0)`）当成检查而
  漏报真缺陷。同时收紧检测器 `checkedVars`：`if (p->len > 0)` 测试的是 `p->len`
  而非 `p`，不再把 `p` 记为已检查；`if (!e->buffer)` 只把 `e->buffer` 记为已
  检查、外层 `e` 保持未检查（修复 `field_expression` 在 `unary_expression` 中
  的误判）。unchecked-return 从 default 链移至专用链
  （call_reach → safe_function → return_check）。
- **sizeof-misuse 指针层级 + typedef 解析 (REQ-2)**：新增 `evidence/typedefs.go`
  的 typedef 解析表——tree-sitter 给的是语法树不是语义类型解析，但
  `typedef` 声明（`type_definition` 节点）本身就在树里，检测器据此**传递地**
  解析“是否是指针类型”。解析表是**跨文件**的：`buildGlobalTypedefs` 遍历
  `store.ListFiles` 把每个被索引文件（含 `.h` 头文件，多数 typedef 都定义在
  头文件里）的 typedef 汇总到一张表，检测器在每个文件内 clone 后叠加本文件的
  typedef（本文件 typedef 遮蔽头文件），故 `types.h` 里 `typedef char *cstr_t`
  在 `main.c` 中也能被解析。单级指针 `T *p`（且 T 解析后不是指针）的
  `sizeof(p)` 恒为指针宽度、是确证 CWE-467（category `sizeof_pointer`，
  confirmed）；指向指针的 `T **p` 或 `T *p` 且 T 是指针 typedef（`typedef char
  *cstr_t; cstr_t *s`）分配指针数组时 `sizeof(p)` 是正确尺寸、仅 suspected
  （category `sizeof_pointer_ambig`）。
- **signed-compare typedef 解析 (REQ-3)**：`unsignedVars` 改为按 declarator 取
  声明名（`unsigned int x = n;` 取 `x` 而非初始化表达式里的 `n`，多声明符
  `unsigned a, b;` 取 `a` 与 `b`），并把类型判断从“整条声明文本子串”改为
  “类型说明符 + typedef 解析”（`typedef unsigned int my_uint; my_uint m;
  if (m < 0)` 可识别），typedef 解析同样走 `buildGlobalTypedefs` 跨文件表，
  头文件里的 `my_uint` 也能识别。检测器仅在声明类型可证明为 unsigned 时才
  emit，故 category `signed_compare` 设为 confirmed，DefaultSuspicion 保留
  suspected 兜底。
- **buffer-overflow format_overflow 分层 (REQ-4)**：把原来的单一
  `format_overflow` 拆为两档——`format_overflow`（常量输出长度已证明
  ≥ capacity，confirmed）与 `format_overflow_var`（含非常量参数、只可能溢出，
  suspected）。原 `formatCanOverflow` 对“任何非常量参数”都返回 true，会把
  `sprintf(buf, "%d", n)` 误判为确定性溢出；分层后 AI 只对确证分支走轻量验证。

#### 测试

- 新增 `filter_return_check_test.go`：覆盖裸调用、赋值已检查、赋值未检查、
  声明已检查、外层未检查/内层 struct member 已检查，以及“后续 if 只是解引用
  使用而非空值检查”的回归用例（`if (e->size > 0)` 应保留为 confirmed 而非
  误判 checked）。
- 新增 registry 配置测试：验证 sizeof-misuse（`sizeof_pointer` confirmed /
  `sizeof_pointer_ambig` suspected）、signed-compare（`signed_compare` confirmed）
  的 CategoryConfidence、unchecked-return FilterChain、buffer-overflow
  format_overflow / format_overflow_var 两档 CategoryConfidence。
- 新增跨文件 typedef 测试夹具 `testdata/tc73_cross_file_typedef/`（`types.h`
  定义 `my_uint`/`cstr_t`，`main.c` 使用）与
  `TestNewDetector_SignedCompare_CrossFileTypedef` /
  `TestNewDetector_SizeofMisuse_CrossFileTypedef`：验证头文件 typedef 能跨文件
  解析（`my_uint` 触发 signed-compare、`cstr_t *s` 判 suspected 而非
  over-confident confirmed）。
- 新增 `TestPlan_UncheckedReturn_UsesReturnCheckFilter` 集成测试。

#### 指令层

- **Confirmed 零读源契约强化 (REQ-1)**：`extension/shared/agent-body.md`
  Pipeline Confidence Tiers 的 confirmed 条目从模糊 "Spend minimal effort"
  精确化为分层硬约束——禁止重推导性读源（`Do NOT re-derive the dataflow or
  re-prove the defect by reading the source file`）、允许验证性查看（`You MAY
  verify the reported file:line by viewing the cited line and its immediate
  context (±3 lines)`）、明确判定条件（confirm/dismiss）、声明不影响
  suspected/possible 候选。配合 sgre-graph-convergence 将 ~9 个 unchecked-return
  及 sizeof-misuse/signed-compare 升级为 confirmed，确保这些候选处理耗时趋近于
  轻量验证开销。
- **Confirmed 处理流程模板 (REQ-2)**：`extension/shared/command-instructions.md`
  新增 confirmed 专用处理流程——Sequential loop 和 Parallel dispatch 按
  suspicion_level 分流（confirmed 走轻量验证路径、suspected/possible 走完整
  推理路径）、批量 confirm 优化、F6 异常读源审计（三分判定：验证性查看 /
  异常读源违规 / 边界待人工复审）。

### 扫描可靠性增强（基于真实扫描会话日志分析）

#### 代码层

- **CLI 子命令 `--help`/`-h` 拦截 (F6)**：`secguard report --help` 等此前
  fallthrough 执行子命令默认逻辑。新增 `usage.go` 为全部 9 个子命令提供独立
  帮助文本，`root.go` 在 dispatch 前拦截 `--help`/`-h`，顶层 `--help` 行为不变。
- **SQLite 并发写端争缓解 (F7)**：`busy_timeout` 从 5000ms 调大至 10000ms；
  `UpsertFinding`/`InsertFinding` 接入 `withBusyRetryID` 指数退避重试（50→100→200ms，
  最多 3 次重试），复用此前未调用的 `isLockedErr()`；`--write-json` 输出新增
  `failed_count`/`failed_details`（含错误分类 `write-busy`/`write-error`）并写
  stderr 审计日志，杜绝静默丢失。
- **断点续扫 per-type 状态查询 (F8)**：新增 `secguard status --per-type
  [--scan-id <id>]`，返回每类型 `candidate_count`/`written_count`/`terminal_state`
  （done/in-progress/pending/unknown），以 DB 实际写入为权威。零 schema 变更
  （复用 `scan_stats` + `findings` 聚合）。

#### 指令层

- **批次容量硬上限 (F2)**：`command-instructions.md` 新增 Batch Capacity Configuration
  配置块（`MAX_TYPES_PER_BATCH=4`、`MAXTURNS=30`、`TURNS_PER_TYPE_ESTIMATE=6`），
  派发前强制校验 `批次类型数×6 < 27`，单类型候选 >500 独占子代理。
- **调度时序合规 (F3)**：要求全部子代理在同一 turn 内连续派发（间隔 ≤10s），
  Monitor 等待期间禁止并行 Bash。
- **长扫描超时策略 (F4)**：>100 文件或预估 >120s 时直接用 Monitor/timeout≥600s，
  禁止 `sleep N; tail`。
- **子代理结构化上报协议 v1 (F5)**：`agent-body.md` 定义 JSON 上报块
  （`format_version`/`processed_types`/`failed_types`），空结果走 DB 二次校验。
- **子代理失败检测与降级 (F1)**：终态三态判定（success/failed/empty）、重试上限 2、
  API 402 标记 missing-type 不重试、Finalize 前置终态确认、报告新增缺失类型章节。

## [0.4.1] - 2026-08-23

### Bug 修复

- **report.md 展示 candidates 而非 findings**：`report.md` 此前仅在扫描阶段从
  `planner.PlanResult.Candidates` 生成（展示 pipeline 疑似级别），`report --audit`
  不会覆写它。AI 分类完成后，用户看到的仍是未分类的候选，与 `findings/` 目录和
  `result.sarif` 矛盾。新增 `WriteReportFromFindings`，在 `report --audit` 时从数据库
  findings 表重新生成 `report.md`，只含 confirmed + suspected（dismissed 排除），
  与 `result.sarif` / `findings/` 对齐。同步更新 extension 指令
  （`command-instructions.md`、`secguard_report.ts`、`agent.cordis.yml`）文档化
  report.md 的双阶段语义。
- **deploy.sh 安装 opencode 到项目级目录**：`sync_project_local` 将 opencode 配置
  写入 `$SCRIPT_DIR/.opencode`（项目级），污染被扫描仓库。移除该函数及其调用，
  仅保留用户级安装（`~/.config/opencode/`）。

## [0.4.0] - 2026-08-22

### 语义图能力补齐 + 区间/锁序/共享访问分析 + 分类并行化

#### 语义图与收敛（补齐 7 个图缺口 + 2 个正确性缺陷）

- **RETURN 传播**：新增 `RETURN` 边，跨函数传播返回空指针/释放态。
- **字段敏感 copy/kill**：`q = p->f` 复制字段级 source；整变量重赋值失效其 `p->*` 事实。
- **区间传播（range propagation）**：新增 `range_flow.go` 前向整数区间分析，含
  **widening**（修复循环不收敛导致的死循环），供除零与整数溢出过滤消费。
- **锁序（lock-order）**：新增 `LOCK_ORDER` 边 + `LockOrderFilter`，检测互斥锁环。
- **共享访问（shared-access）**：新增 `GLOBAL_ACCESS` 边 + `SharedAccessFilter`，
  检测线程函数对同一全局变量的竞争写。
- **对象身份**：别名/所有权转移在 free/use 上的身份区分。
- **宏层（macro）**：识别释放宏、安全释放宏（置 NULL）、宏空指针源。
- **正确性修复**：must-lattice 交汇；`p = f()` copy-kill；for-continue 边指向更新；
  confirmed 降级判定修正。

#### 新过滤器/检测

- `divide-by-zero`（RangeFilter）、`integer-overflow`（IntOverflowGuardFilter）、
  `deadlock`（LockOrderFilter）、`race-condition`（SharedAccessFilter）。

#### DB / CLI

- `edge_type` 枚举扩展（`RETURN`、`LOCK_ORDER`、`GLOBAL_ACCESS`）。
- `UpsertFinding` 幂等写入（scan_id+rule_id+file+line+function 去重）。
- `secguard report --write-json <file|->` 批量写（一次命令写一整类）。
- 扫描开始时清理 `.sgre/.tmp`（临时 JSON 落项目目录，不进 `/tmp`）。

#### Agent 分类并行化 + 平台落库修复

- **规模闸门**：`total_candidates ≤ 200` 串行分类（单上下文更快更省），`> 200` 才
  派并行子代理。
- **瘦身 worker prompt**：子代理只带分类规则 + 置信度分层 + A5 + 写纪律，不再背负
  完整报告格式与 Full-Scan 流程。
- **A5 复用上下文**：复核默认用首轮已读源码 + 已落库 reasoning，仅首轮未读时才开
  文件（计入同一 ≤5 文件预算）。
- **OpenCode 子代理落库修复**：`security-auditor` 改为 `edit: allow` +
  `bash(secguard*)`（plugin 工具不授予子代理），`secguard_report` 工具内部改走
  `--write-json` 单子进程。
- **Claude Code 子代理工具补齐**：`tools` 增加 `Write` + `Skill`。

#### 文档

- README/README-CN/CLAUDE 同步边类型与 range/macro/lock-order/shared-access 说明；
  新增 `docs/classification-parallelism.md`。

## [0.3.6] - 2026-08-21

### 修复样例项目基准验证暴露的回归 + 补齐缺失工具

在 `examples/c-vuln-benchmark`（77 用例 ground truth）上实跑一轮：
precision 100.0% / recall 97.7% / false-pos 0.0%（唯一 miss 是多行 `sprintf` 的
行号差一）。但会话日志自检发现三处真实缺陷，均已修复：

#### 修复

- **A5 复核后 `result.sarif` 停在复核前状态**：`secguard_report` 的 `reviews`
  批次会改变 EffectiveStatus（dismissed/suspected-kept/confirmed），但工具封装
  在 reviews 路径不再跑 audit，导致 `result.sarif` 落后一版（把已 dismiss 的
  条目仍显示为 `warning`）。现在 reviews 批次后统一跑一次 audit，重新生成
  `result.sarif` + `audit-report.md` 并重对账 `findings/`，保证三处口径一致。
- **`secguard_scan` 摘要重建读取已废弃字段**：Go 侧早已不再返回
  `evidence_packages`，TS 包装仍读它来拼"Candidates by Type"，导致该表为空。
  改为读 `candidates_by_type`。
- **缺失 `secguard_types` 工具**：指令要求"先调 `secguard types` 发现类型清单"，
  但 OpenCode 扩展里根本没有这个工具（agent 被迫退回用 skills 目录猜类型）。
  新增 `secguard_types.ts` 包装，并在 `opencode.json` 授权表补上权限。

#### 性能

- `secguard_report` 封装抽取统一的 `runAudit`，避免写路径与 review 路径各复制
  一份 audit 逻辑；audit 仍在写批次与 review 批次后各跑一次，成本可接受。

### 修复生产环境缺失 findings/ 与 result.sarif：强制判定落盘 + 纠正 Agent 误读

本版把 `findings/` 与 `result.sarif` 改为"判定阶段产物"（扫描阶段只产候选）。生产
验证发现 Agent 会"先分析完所有类型、最后再写 findings"，结果**从未调用
`secguard_report`**，于是判定只存在于对话里，`findings/` 与 `result.sarif` 一个都没有。
同时暴露出一批流程/约束缺陷：命令名写错（`secguard_scan` 当 bash 命令）、加载了别的
产品的带前缀技能（`crs-*`）、safe-function 分类规则读反、弱加密被降级为"borderline"、
路径反复试错。本轮只改流程与约束，不动扫描/判定核心逻辑。

#### 变更（extension/shared + deepseek-harness，纯提示词/约束层）

- **强制"边分析边落库"**：全扫描与过滤扫描工作流都明确"分析完一个类型立即
  `secguard_report` 写该类型 findings，再进入下一个类型"，并显式禁止"全部分析完最后
  一起写"——这被标为导致 `findings/`/`result.sarif` 为空的根因。
- **收尾强制验证产物**：所有类型写完后必须读 `<scan_dir>/result.sarif`（非空）并
  列出 `<scan_dir>/findings/`；缺失即视为"判定未落盘"，先修 `per_finding_warning`
  再交付报告。
- **命令名与技能命名空间约束**：明确 OpenCode 工具名带下划线（`secguard_scan`），
  bash 里才是 `secguard scan`；技能只能加载 `secguard types` 里的精确 kebab-case 名，
  `crs-*` 之类前缀属于其它产品，禁止加载，找不到即停。
- **分类规则澄清**：safe function 是默认 false-positive 但要校验本次调用的安全合同
  （size 是否说谎、返回值是否该查）；弱加密（DES/3DES/MD5/SHA-1/RC4/rand）一律
  confirmed，不许以"legacy/可能有意为之"降级。
- **路径处理**：用 candidate 文件 Location 块里的绝对路径直接读源码，禁止试错。


### 修复 findings/ 目录语义：候选与判定分层，误报不再进入复核面

0.3.5 把逐条 markdown 收纳进 `findings/` 时，让**扫描管线**和**AI 判定**写同一个目录：
扫描阶段先按候选写文件，AI 判定阶段再原地重命名/改写。一个目录两个写者、两种语义，
由此派生出三个现场问题：判定后缀丢失、误报仍然写进 `findings/`、候选文件里同时出现
"Suspicion Level: confirmed" 和 "Status: _pending_"。本版本按根因分层重构，不是逐个打补丁。

#### 变更（破坏性：输出目录结构）

- **候选与判定分成两棵树**：扫描阶段的候选证据写入 `candidates/<vuln-type>/NNN_<file>_<line>.md`（Layer 3，唯一写者是管线）；`findings/<vuln-type>/NNN_<file>_<line>_<confirmed|suspected>.md` 只由 AI 判定生成（Layer 4，唯一写者是 DB 投影）。目录语义与 4 层数据模型对齐。
- **findings/ 只收要人处理的结论**：判为 dismissed（误报）的条目**不再生成文件**，判定与理由记入 DB 并标注到对应 `candidates/` 文件的 `## AI Verdict` 小节——排除可审计，但不干扰员工确认。
- **判定后缀不再可能丢失**：`findings/` 里的文件只在有判定时创建，文件名必带 `_confirmed` / `_suspected`。
- **候选文件不再伪装判定**：移除 `- **Status:** _pending_`，suspicion level 明确标注为 `(pipeline prior, not a verdict)`，并给出 `AI Verdict: _unclassified_`。

#### 新增

- **判定文件自包含源码片段**：`## Code Context` 段落嵌入缺陷处上下各 15 行源码（带行号，问题行 `>` 标记），审阅者无需跳回源码即可判断。新增全局 `--context-lines <n>` 调整窗口，`--context-lines 0` 完全关闭源码嵌入（源码不得外流的仓库）。
- **SARIF 携带源码片段**：verdict 阶段的 `result.sarif` 为每条结果补 `region.snippet` 与 `contextRegion.snippet`，IDE/CI 可直接渲染代码。
- **SARIF 按阶段拆成两个文件（破坏性）**：扫描阶段写 `candidates.sarif`（未判定候选，**全部 level=note**，管线先验放进 `properties.suspicion_level`）；`result.sarif` 只由 `report --audit` 从判定生成，**分类前不存在**。CI/IDE 对准 `result.sarif` 即不可能把收敛前候选当缺陷——这是"一个文件两种语义"这个根因在 SARIF 侧的最后一处出口。两个文件均带 `runs[0].properties.stage`。
- **`report --audit` 对账重建**：新增 `report.ReconcileFindings`，按 `findings` 表重建整棵 `findings/` 树并清扫 DB 不认的残留文件——AI 批量排除却没落盘、批次中断、写入漏参数等情况都能自愈。
- **写入不再静默失败**：`report --write` / `--review` 返回 `per_finding_action` 与 `per_finding_warning`（并打到 stderr）；缺 `--scan-id` 时自动继承 `scans/latest` 并回报 `scan_id_source`；`--audit` 报告仍无 scan_id 的 finding 数量。

#### 修复

- **`report --write` 漏传 scan_id 即静默丢判定**：这是 0.3.5 后缀"丢失"的直接原因（OpenCode 工具从不传 `--output-dir`，agent 漏传 `scan_id` 时整条落盘链路无声跳过）。现在 latest 回退 + 显式告警，工具封装也补齐 `--output-dir`。
- **重复扫描留下幽灵文件**：`scan` 写输出前清空 `candidates/` 与 `findings/`（两者完全派生于本次扫描），避免旧序号候选与失效判定残留；已落库的判定由 `report --audit` 重新生成。
- **同一位置多次判定的投影顺序**：`ReconcileFindings` 按位置取最新 finding（最大 id），磁盘状态不再依赖行序。
- **A5 复核降级未清理文件**：`--review` 判为 dismissed 时删除此前的判定文件，`suspected → confirmed` 正确改名，不再出现同一问题两个后缀并存。

## [0.3.5] - 2026-08-21

### 对外文档：5 级收敛管线 + per-finding 目录结构调整

对外叙事从"4 级收敛管线"升级为"5 级收敛管线"，明确 A5 二次审查层（复合补全层）定位；per-finding markdown 统一收纳到 `findings/` 子目录。

#### 文档

- **5 级收敛管线**：README / README-CN 的 hero、Pipeline 图、数据模型表刷新为 5 层叙事——A1–A4 确定性收敛（产不出推理链与修复策略）+ AI 首轮分类对所有发现补全 `summary`/`reasoning`/`exception_check`/`fix_strategy` + A5 复合补全层对疑似逐条二次确认。
- **A5 复合补全层定位**：明确 A5 只接语义图证不了的 suspected 残余，经过 A5 仍留下的 suspected 是真正"需人工判断"的情形，最终报告通过 `EffectiveStatus()` 统计 A5 之后的裁决。

#### 变更

- **per-finding 目录**：逐条证据 markdown 从 `<vuln-type>/` 收纳到 `findings/<vuln-type>/`，新增 `FindingsDir` 常量，同步更新 `markdown.go`、`RewritePerFinding`、测试与全部文档。

## [0.3.4] - 2026-08-21

### 报告输出协议增强 + 隐藏 bug 修复

报告层新增 A5 二次审查与结构化证据链，scan-id 加 `sc_` 前缀；完成一轮隐藏 bug 审计，evidence 层写入错误不再被静默吞掉，消除静默 false-negative。

#### 新增

- **A5 二次审查层**：report 新增第二轮审查，输出自描述状态后缀与结构化 reasoning/fix，状态机接线 A5。
- **SARIF 证据链**：`result.sarif` 丰富化，附结构化 evidence chain；per-finding markdown 幂等重写并裁剪冗余字段。
- **scan-id 前缀**：scan-id 从 `YYYY-MM-DD_HHMMSS_<6-hex>` 改为 `sc_YYYY-MM-DD_HHMMSS_xxxxxx`，保证 `latest` 符号链接排序在前。

#### 修复

- **evidence 写入错误不再静默吞掉（critical）**：22 个 detector 统一迁移到 `emitEvent` helper，`InsertLocation` 失败（locID=0 触发外键违规静默丢事件）与 `InsertEvent` 失败现均上报，杜绝静默 false-negative。
- **injection ConvergeKey**：去重键改用 sink 变量而非 function+category，修复跨 sink 误合并。
- **path-traversal 误报**：收敛 file-operation 洪泛并给出具体修复建议。
- **taint**：丢弃无 tainted caller 的静态参数 sink。
- **convergence**：从源头消除 deterministic suspected，并接线 A5。
- **隐藏 bug 一批**：EffectiveStatus 传播、detector 错误处理、review 状态行更新、legacy-CWE 反查、空 rule_id 保护；`--status` 改用 EffectiveStatus + confidence 截断 + review-status 校验。

#### 文档

- DEVELOPER 补状态机与分层归属说明；`docs/output-protocol.md` 同步 scan-id 与证据链变化。

## [0.3.3] - 2026-08-20

### 轻函数隔离 + 守卫感知误报抑制（Redis 4,837 → 2,931，-39.4%）

新增轻量数值范围分析模块，并修复六类误报根因，Redis 全管线收敛结果从 4,837 降至 2,931（~22× 压缩）。

#### 新增

- **`evidence/range_analysis.go`**：轻量区间传播核心模块（RangeFacts / AnalyzeBounds /
  NonZeroAt / UpperBoundAt / IfsInFunc），识别 `if(x<N)`、`if(x!=0)`、`if(x==0) return`
  等 guard，为下游 detector 提供守卫界查询。

#### 修复

- **null-deref 跨函数隔离（critical）**：`AnalyzeBounds` 接收 per-file 所有 ifs 会跨函数
  混事实（`open_handle` 的 `if(!h) return` 建立 h 非零，`read_handle` 的 `h->fd` 行号更大
  被误抑制）。改用 `IfsInFunc` 按函数隔离，null-deref 972→872（-100）。
- **uninit formB 精确匹配**：if 条件引用赋值变量的判断从子串匹配改为 identifier 精确匹配，
  避免 `rc` 匹配 `rc2` 子串误判。uninit 2347→951（-1396）。
- **free_summary nullGuardedWrite**：去掉 `!p`/`p==NULL`/`p==0` 误判分支（这些条件为真时
  p 是 NULL，写在 if 体内不安全）。
- **buffer_overflow bounds 守卫界**：`detectUnsafeCalls` 算 bounds 传给
  `checkBoundedCopyOverflow`，变量 size 有守卫界 ≤ capacity 则安全。
- **divide_by_zero 反向 early-return guard**：接入 `AnalyzeBounds` 补齐
  `if(d==0) return; a/d;` 模式（-3）。
- **int_overflow filter category 扩展**：switch case 加 `"integer_overflow"` category，
  让一般整数溢出也走守卫界抑制。

#### 文档

- README / README-CN：Redis 收敛数据刷新（4,837→2,931，~13×→~22×），"逼近 CodeQL" 描述
  更新（已实现轻量区间分析）。

## [0.3.2] - 2026-08-19

### 样例基线对齐至 100%（74 用例 · 100% precision / 100% recall）

修复五例存量漂移 + p7 语义图用例，并顺带修复四处检测器缺陷：

- **memcpy 变量长度越界未应用边界检查（回归）**：`checkBoundedCopyOverflow` 对
  caller 可控的变量 size 直接报 `bounded_copy_var_size`，未先查 `hasPrecedingBoundsCheck`，
  导致 `if (n >= sizeof(dst)) return; memcpy(dst, src, n)` 被误报。已补前置边界检查。
- **`_s` 资源泄漏误报**：`if (f) { fclose(f); }` / `if (fd >= 0) { close(fd); }` 正守卫
  包裹释放，失败路径（f==NULL / fd<0）本无资源，却被路径分析判为泄漏。新增
  `isGuardedRelease`/`positiveGuardOn` 识别该模式。
- **注入漏报**：`snprintf(cmd, ..., user_input); system(cmd)` 未把格式化实参的污点
  传播到 dst。新增 `formatCopies`（sprintf/snprintf 变参实参 → dst 的 copy），并让
  非 static 函数形参（外部可控）按"可能被污染"播种为 entry taint。
- **p7 语义图用例**：use-after-free 用 `*p`/`*q`（检测器识别解引用，不识别 `p[0]`）。

基准门禁 `scripts/validate-benchmark.py` 实测：TP=41 / FP=0 / TN=33 / FN=0。

## [0.3.1] - 2026-08-19

### 关键缺陷修复（e2e 自检发现）

- **全管线漏报（critical）**：`connection.go` 的 DSN 用 `_busy_timeout=5000` 设置 busy_timeout，
  但 modernc.org/sqlite 只识别 `_pragma` 参数，`_busy_timeout` 被静默忽略 → busy_timeout 实为 0 →
  并行 detector（4 连接写文件库）触发 SQLITE_BUSY 时立即失败，且 `InsertEvent` 错误被吞 → **大量
  检测事件静默丢失**（1-CFA 污点、`n*4` 溢出等候选在 `secguard scan` 全管线不浮出，聚焦单测却通过）。
  改为 `_pragma=busy_timeout(5000)` 修复。
- **scope-leak（critical）**：`secguard scan <子目录>` 时，累积索引里其它目录的历史文件仍被检测，
  候选泄漏到目标之外。新增 `scopeToTarget` 按 target 路径收窄候选。
- **taint 过滤器 fail-closed**：`computeReturnsParam`/`computeRetTainted`/`computeParamTainted`
  不再吞 DB 错误返回空摘要，改为传播错误并在摘要失败时保留全部候选（宁可不收敛，不可静默漏报）。

### DeepSeek Harness 适配

- 新增 DSH（DeepSeek Harness / Cordis）Agent preset：`extension/deepseek-harness/`
  （`preset.yml` + `agent.cordis.yml`，persona 即"角色"），`release/install-dsh.sh` 安装脚本。
- SecGuard 的 20 个 skill 零改动兼容 DSH 的 SKILL.md 格式；README 新增三平台说明。

### 样例基线增强

- `examples/c-vuln-benchmark/` 新增 `p7_graph_effect.c`（语义图消费）、`p8_value_analysis.c`
  （值分析）、`p9_secure_func.c`（`_s` 契约）、`p10_interproc_taint.c`（1-CFA）四组硬骨头用例。
- 基线纳入 P8-01..06、P9-01..05、P10-01..04 共 15 例（全绿）。
- 门禁脚本 `scripts/validate-benchmark.py` 从读 stdout 的 `evidence_packages`（已移除）改为读 SARIF。

## [0.3.0] - 2026-08-19

对标 CodeQL / Infer / Coverity 的两大差距攻坚：**值分析/区间域（RangeAnalysis lite）** 与
**1-CFA 过程间上下文敏感**。核心打法是"静态分析识别风险形态 + 大模型推理兜底"——静态分析
证明不了的模糊边界（变量 `n` 会不会真的溢出），emit 为 suspected/possible 候选带证据交 AI Agent
推理论证，充分发挥大模型对 API 契约与调用点语义的理解能力。

### 值分析 / 区间域（RangeAnalysis lite）

- **变量界定溢出检测**：`malloc`/`calloc` 的 `n*m`、`n*sizeof(T)`、`n*K`、`n±K` 等 CWE-190 模式，
  以"操作数是否函数形参（caller 可控）"为门控——局部有界变量不误报。
- **守卫常量传播**：`if (n < CONST)` 前置守卫界收敛加法/乘常量溢出候选（区间域轻量版）。
- **strncpy/memcpy/memmove 变量长度越界**：`bounded_copy_overflow`（confirmed）/
  `bounded_copy_var_size`（possible）；memcpy 从 SafeFunctions 分支解耦，strncat 保留 append 保守语义。
- **修复两个静默漏报**：`bounded_copy_overflow` 未入 buffer-overflow 的 seed 允许列表、且被
  SafeFunctionFilter 因 `strncpy` 属 SafeFunctions 误删——此前 strncpy 溢出从未到达 AI Agent。

### Annex K `_s` 安全函数契约分析

业界普遍把 `_s` 函数当"无条件安全"，SecGuard 按契约逐个校验：

- **13 个拷贝类**（memcpy_s/memmove_s/memset_s/strcpy_s/strncpy_s/strcat_s/strncat_s/sprintf_s/
  snprintf_s/vsprintf_s/vsnprintf_s/asctime_s/ctime_s）：三方比对 `declared capacity` vs `真实容量`
  vs `required size`，抓"说谎的 size"（`char buf[10]; memcpy_s(buf, 100, src, 50)`）与约束违约。
- **scanf_s/sscanf_s/fscanf_s 逐转换宽度校验**：解析格式串对齐 `(buffer, size)` 变参对，
  `secure_scanf_overflow`（confirmed）/`secure_scanf_var_size`（possible）。

### 1-CFA 过程间上下文敏感（形参敏感摘要）

- **`returnsParam` 跨函数 fixpoint**：多级 passthrough（`wrap2(s){return id(s);}`）正确传播返回污点。
- **`entrySeeds` 形参污点回流**：由污染形参派生的局部 sink（`char *cmd = s; system(cmd)`）不再漏报。
- **`computeParamTainted` 链式 fixpoint**：`main → A → B → C` 跨任意跳数传播形参污点。

### 测试

- 新增 `tc64`–`tc70` 夹具与 10+ 回归测试（含 `-race` 并发门禁）；`go test -race ./...` 0 数据竞争。

## [0.2.1] - 2026-08-19

### P1 竞品弱项改进（并行化 + 结构化证据链）

基于 `docs/pk/competitive-analysis.md` 的 P1 弱项分析，实施两项改进：

- **并行检测管线**：graph builder（5 个）、detector（21 个独立 + Interprocedural 后置）、planner（20 个）全部并行化，连接池从 1 放宽到 4 + busy_timeout=5000ms。大代码库（redis 11K 函数）扫描时间显著下降。
- **`--timeout <秒>` 超时控制**：`context.WithTimeout` 包 scan 顶层，超时后所有阶段（index/graph/detector/planner/report）协同取消，不再无限挂起。
- **`GetOrCreateGraphNode` 原子化**：`graph_nodes` 加 `UNIQUE(entity_type, entity_id, properties)` 约束 + `INSERT OR IGNORE`，消除并行 builder 的 SELECT-then-INSERT 竞态。
- **SARIF codeFlows 2 步路径**：`Candidate` 加 `SourceLine` 字段，`NullableSourceFilter` 从 `flowResult.nodeIn`（reaching-definitions 源节点）提取源行号，SARIF result 加 `codeFlows` 结构（source→sink 2 步 threadFlow），GitHub Code Scanning 可直接展示"null 引入→解引用"路径。

### 架构清理

- **删除 migration 层**：DB 每次全新创建（`InitSchema` 幂等），不存在旧表迁移场景。移除 `migration.go` 全部代码及对应测试。

### 发布前反向自检修复

并行化改造后的一轮反向自检，发现并修复两个并行引入的回归（均通过 `go test -race ./...` 全量竞态检测）：

- **`parser.ParseCached` 数据竞争（崩溃级）**：并行 graph builder / detector / planner 共享同一 `Parser`，但 `ParseCached` 直接读写 `cache`/`parsers` 两个 map 无锁，多 goroutine 并发解析同一文件时触发 "concurrent map writes" panic。加 `sync.Mutex` 串行化 map 访问与 tree-sitter Language 引用计数；新增 `TestParseCached_Concurrent`（-race）回归门禁。
- **strncpy 有界拷贝溢出双重上报**：`checkBoundedCopyOverflow` 命中溢出后返回 false，回落通用 buffer-overflow 路径，同一调用被上报两次（`bounded_copy_overflow` + `buffer_overflow`）。改为 bounded-copy 大小比对作为权威处理路径，命中即跳过通用路径；`TestBoundedCopyOverflow` 断言单次上报。
- **`GetOrCreateGraphNode` 吞掉 INSERT 错误**：`INSERT OR IGNORE` 的 `ExecContext` 错误曾被 `_, _ =` 丢弃，DB 写入失败会被静默吞掉；改为检查错误（`INSERT OR IGNORE` 下 UNIQUE 冲突不产生错误，任何返回错误都是真实故障）。

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
- **删除 `BRANCH` 边**（声明但从未使用，CFG 分支结构无需落库）。

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
- **删除 migration 层**：DB 每次全新创建（`InitSchema` 幂等），不存在旧表迁移场景。移除 `migration.go` 全部代码（`migrateSchema`/`migrateFindingsTable`/`migrateSecurityEventsTable`/`migrateGraphEdgesTable`/`migrateGraphNodesUnique`）及对应测试。
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
- 去重后的候选仍需 AI Agent 分类确认，流水线自身不产出最终 verdict。

### 本次发布前的版本一致性修复

- 统一版本号为 `0.1.0`：`internal/cli.Version` 改为 `var` 以支持 `-ldflags -X` 注入，`VERSION` 文件、构建脚本 `build_target` 均已同步。
- 修正 OpenCode 扩展层硬编码的「15 种类型 / <=30 候选上限」描述，改为以 `secguard types`（Go 二进制）为唯一权威来源。
