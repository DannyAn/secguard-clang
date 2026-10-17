# secguard-clang round2-evidence-contract 发布前独立代码审计报告

- **审计对象**：分支 `round2-evidence-contract`（HEAD `4e21213`），版本 `0.9.5`
- **审计基线**：`origin/main` = `173cadc`（已推送的 v0.9.5 状态）
- **变更范围**：`origin/main..HEAD` 共 **15 个提交**，**52 个文件**，**+2321 / -79**
- **审计方式**：以实际代码、Git diff、调用链、测试结果与真实 CLI 端到端扫描为依据；未依赖 GLM-5.3 交付报告/注释/自述
- **审计者声明**：本次为发布前审计，未修改任何代码，未打 Tag、未推送

---

## 1. 总体结论

**结论：PASS WITH CONDITIONS**

**主要依据：**

1. 完整证据链在抽样的关键漏洞类型上确实贯通——`Detector → eventProps → Candidate → EvidenceItem/EvidenceFragment → buildHint → 候选文件/索引 → report`，最终候选文件、`_index.md`、`findings/` 与 DB 中都能看到结构化语义事实，且经过了真实 CLI 扫描验证。
2. `go build`、`go test ./...`（14 个包全绿）、`nosqlite` 子集均通过；唯一的 `internal/cli` 失败是审计环境 `TMPDIR` 置于仓库内导致的测试工件，非代码回归（见 §5）。
3. 未发现 P0/P1 级问题：没有证据链断裂、没有系统性漏报/误报、没有关键输出路径失效。
4. 发现的问题均为 P3（非阻断）：hardcoded-secret 脱敏不彻底、一处死写、候选阶段报告的展示歧义、dangerous-function 政策类自动确认量偏大（后两项为基线已有，非 round2 引入）。

**是否建议进入生产实测：** 建议，但须满足下述条件。

**当前最值得警惕的风险：**
- 本轮 135 条 `auto-confirmed` 发现**全部尚未经过 `report --review-json` 复核**（`report --audit` 明确告警）。auto-confirmed 是机器裁决，若某类检测器存在系统性误报，这批会直接落库为 confirmed 而 AI 只做二轮复核，需在灰度中重点观察。
- hardcoded-secret 的完整字面量仍会进入候选文件的 `## Code Context` / `_index.md` Source 列 / SARIF（脱敏只作用于结构化 `secret_value` 片段），扫描产物若被共享/归档会泄露密钥。

---

## 2. 变更范围

### 2.1 基线与分支拓扑（已确认）

- 工作区**无未提交的已跟踪文件修改**（`git diff`/`git diff --cached` 为空）；仅存在未跟踪的 `docs/*.md`、`.DS_Store`、`memory-leak-analysis.json`、`output/` 等，均不在本次 diff 内。
- 本地 `main` 指向 `3f8d221`（已被 GLM-5.3 前移，含 round2 前 7 个提交），`round2-evidence-contract` 在其上再叠 7 个提交。审计基线取 `origin/main=173cadc`，因此审计范围为 **15 个提交**。
- **未发现无关修改混入**：52 个文件全部落在证据契约主题内（planner 证据包装/渲染、report markdown、24 个 SKILL.md、少量 detector 补充 `api` 字段、契约测试）。

### 2.2 核心架构变更（本轮实际做了什么）

本轮**不是**检测器重写，而是**证据包装与渲染层的契约修复**：让检测器在第一轮已算出的语义事实，真正流到 AI 可见的候选文件/索引/报告里。核心改动集中在：

| 模块 | 文件 | 改动 |
|---|---|---|
| 统一事件字段视图 | `planner/props.go` | `eventProps` 集中解码 + `flexInt` 兼容数字字符串 |
| 证据包结构 | `planner/evidence_package.go` | `EvidenceItem` 新增 `SourceLines/Signature/FunctionStartLine/FunctionEndLine/Contract/CalleeDef*/DivisorInterval/DivisorCallers/Expression`；`buildHint` 按类型生成密集 Hint |
| 候选装载 | `planner/planner.go` | `seedCandidatesByType` 补齐七类字段流；`resolveCalleeDefs` 回填 unchecked-return callee 定义位置 |
| 过滤层 | `planner/filter.go`、`filter_lock_order.go`、`filter_range.go`、`filter_taint_source.go`、`range_flow.go`、`call_sites.go` | deadlock reverse 回填、divide-by-zero 区间/调用方裁决传递、taint SourceLine 填充 |
| 类型注册 | `planner/registry.go` | 24 类 `BuildEvidence` 补齐片段（buffer/index/callee_definition/secret_value/reverse_order/divisor_interval/…）；`maskSecret` |
| 渲染层 | `report/markdown.go`、`report/snippet.go` | 候选文件 Failure Contract 段、Taint Source 段、Code Context 整函数/源汇跨度策略 |
| 契约守卫 | `skills/vuln_type_skill_fragments_test.go` 等 | SKILL↔BuildEvidence 片段双向一致性机器守卫 |

### 2.3 重要数据结构变更

- `Candidate` 与 `EvidenceItem` 新增约 30 个字段（`CalleeDefFile/DivisorInterval/SecretValue/LHSKind/ReverseFunc/...`），全部 `omitempty`，序列化向后兼容；`eventProps` 统一了此前散落在各 filter 里的重复字段名。
- `VulnTypeSpec` 新增 `CategoryConfidence`（按 category 覆盖 `DefaultSuspicion`），`out-of-bounds`/`buffer-overflow` 等用其把 detector 已证明的 category 标为 `confirmed`。

---

## 3. 问题清单

### 3.1 [P3] hardcoded-secret 脱敏不彻底：完整字面量仍进入候选文件/SARIF

- **文件与位置**：`sgre/internal/planner/registry.go:1144-1150`（`maskSecret`）、`sgre/internal/report/markdown.go:276-302`（Code Context）、`:471`（Source 列）、`sgre/internal/report/snippet.go:29`（`candidateContextLines=8`）
- **触发条件**：任意 hardcoded-secret 候选。
- **代码证据**：`maskSecret` 只对结构化 `secret_value` 片段做 `"前缀… (N chars)"` 脱敏；但候选文件的 `## Code Context` 与 `_index.md` 的 `Source` 列通过 `readCodeContext`/`sourceLineText` 内嵌原始源码行。实测 `candidates/hardcoded-secret/001_src_crypto_c_17.md` 的 Code Context 中完整出现 `"SuperSecretPassw0rd!"`（第 28 行）、`"sk-abcdef1234..."`（第 23 行）与 JWT `token`（第 29 行）——包括**非本候选的相邻密钥**。
- **影响**：扫描产物（`.codeagent/` 为 gitignore 的本地工件）本身不提交，但若扫描目录/SARIF 被共享、上传 CI 工件或归档，即构成密钥泄露。`--context-lines 0` 只关闭 findings/SARIF 的源码内嵌，**不关闭候选文件的 ±8 窗口**（`candidateContextLines` 未与 `ContextLines` 联动）。
- **是否 round2 回归**：否——Code Context 内嵌源码是既有设计；但 round2 的 `maskSecret`（commit `3f8d221`）声称"full literal is withheld"，实际只做到了片段层脱敏，承诺与实际存在落差。
- **修复建议**：候选文件 `## Code Context` 对 hardcoded-secret 类型复用 `maskSecret` 思路（或对 secret 所在行做掩码），并让 `--context-lines 0` 同时作用于候选窗口；至少在 SKILL/文档中明确"完整字面量仍会出现在 Code Context"。

### 3.2 [P3] injection.go 的 `source` 字段是死写，round2 改动无实际效果

- **文件与位置**：`sgre/internal/evidence/injection.go:266`（`"source": callName`）
- **触发条件**：`detectTaintFlowInjection` 对 CreateProcess/ShellExecute 命令注入族 emit 事件。
- **代码证据**：全仓 grep 确认 `eventProps`（`props.go:36-160`）无 `Source` 字段，`parseEventProps` 不消费 `source`；`filter_taint_source.go` 的 taint 源播种来自 `computeDirectTaintParams`/`computeParamTainted`/`analyzeFlow`，均不读该 prop。round2 把 `"source":"wsprintf"` 改成 `"source":callName`（commit `dfc0bb3`）是**写入后无人读取的无效改动**；taint 源行真正的修复在 `filter_taint_source.go:276`（`flow.sourceLine`）。
- **影响**：无功能影响，但掩盖了真实修复位置，误导后续维护者以为 taint 源靠该 prop 传递。
- **是否 round2 回归**：否（无破坏），属无效/误导性改动。
- **修复建议**：删除死字段，或将注释改为指向 `filter_taint_source.go` 的实际源行填充逻辑。

### 3.3 [P3] 候选阶段 report.md 的 "Candidates by Skill" 对纯 auto-confirmed 类型显示 0，误导读者

- **文件与位置**：`sgre/internal/cli/scan.go:249-291`（`splitBySuspicion` 后 `evidencePackages` 仅装 `needsReview`）、`sgre/internal/report/markdown.go:190-197`（候选表）。
- **触发条件**：某类型所有候选均为 `confirmed`（如 `out-of-bounds` 的 `array_oob_read`/`heap_oob_read` 在 `CategoryConfidence` 里恒为 `confirmed`）。
- **代码证据**：实测 benchmark 扫描中 `out-of-bounds` 候选表为 `0`，但 DB `findings` 表存在 `oob_read_example @ parser.c:86 status=auto-confirmed`（`secguard plan out-of-bounds` 独立运行 `seed=1, final=1`）。根因：`out-of-bounds` 候选被 `splitBySuspicion` 归入 `autoConfirmed`，不进 `needsReview`，故不进候选表/`candidates/`。
- **影响**：读者会误判"out-of-bounds 什么都没检出"，而实际已自动确认 1 条。检测结果本身正确、可追溯，仅是展示歧义。
- **是否 round2 回归**：否（auto-confirm 拆分是既有逻辑；`out-of-bounds` 恒 confirmed 的 `CategoryConfidence` 属 round1/既有）。
- **修复建议**：候选阶段报告增加 `Auto-confirmed per skill` 列，或在 `Candidates by Skill` 并列展示 confirmed 数。

### 3.4 [P3][基线已有] dangerous-function 政策类自动确认量大（附上下文规则澄清）

> **更正（审计后复核检测器本体得出）**：早期版本把 dangerous-function 描述为"不考察上下文"是不准确的。检测器 `sgre/internal/evidence/dangerous_function.go` 实际实现了三类上下文敏感规则：
> - `nonMainOnly`：`exit`/`ExitProcess` 仅在**非入口函数**触发（`isEntryPoint` 识别 main/wmain/WinMain/wWinMain，`dangerous_function.go:189-193`）。
> - `constExempt`：`inet_addr` 首参数为编译期常量时抑制（`:197-199`）。
> - `assert_usage` 映射为 `suspected`，交 AI 判意图（是否用于校验接口入参/运行时结果）。
>
> 覆盖度核对：原始需求中的 C 函数（exit/ExitProcess/pthread_exit/ExitThread/atexit/abort/assert/alloca/realloc/setjmp/longjmp、mem*/str* 族、格式化输出/输入族、gets、atoi 族）**全部覆盖**；C++ 项（reinterpret_cast/const_cast/jsonpickle）按需求"可不管"未实现。

- **文件与位置**：`sgre/internal/planner/registry.go:1009-1031`（`DefaultSuspicion: "confirmed"`，仅 `assert_usage`/`obsolete_api_conditional` 降为 suspected）。
- **触发条件**：任何被禁函数调用（`memcpy/strcpy/gets/atoi/realloc/...`）。
- **代码证据**：benchmark 扫描 dangerous-function 候选表仅 1 条 suspected，但 findings 树出现大量 `*_confirmed.md`（实测 42 条），含 `p2_bounds_checked.c` 等样例。属**设计内的政策发现**——"_s 推荐替换"类（memcpy/strcpy/sprintf 等）按名字匹配、机器确认，且与 buffer-overflow/format-string **有意重叠**（后者答"会不会溢出/注入"，dangerous-function 答"是否用了非 _s API"，两者都报，见 `dangerous_function.go:78-83`）。
- **是否 round2 回归**：否（round1 `e6ae7c5` 引入，在基线内）。
- **建议**：灰度时重点观察 dangerous-function 的政策告警量是否可接受；如需收敛，可在 `secguard.toml` 层面调整或对具体类别改 suspected（这是政策取舍，非正确性缺陷）。

### 3.5 [观察][基线已有] 非静态叶子函数参数注入无 taint 源证据

- **文件与位置**：`sgre/internal/planner/filter_taint_source.go:233-262`、`:263-283`。
- **触发条件**：`windows.c:13` `CreateProcessA(NULL, cmd, ...)`，`cmd` 来自 `wsprintfA(cmd, "...%s", user_input)`，`user_input` 为非静态叶子函数参数、无 tainted caller。
- **代码证据**：实测该 injection 候选 Hint 仅 `api@CreateProcessA cat@command_injection`，无 `tainted`/`src@N`，无 `## Taint Source` 段。这是**正确的保守行为**（未证明的参数不作为 taint 源），AI 依靠 ±8 窗口内的 `wsprintfA` 行自行判断；对比 `path-traversal` 的 `src@23 tainted`（直接 taint 源如 getenv/argv 时确实填充），说明 round2 的 SourceLine 修复对"已证明源"生效、对"未证明参数源"保持留白。
- **是否 round2 回归**：否。

---

## 4. 漏洞类型审计矩阵

采样策略：24 类中，以下逐类做了代码追踪 + 真实候选/单元验证；其余通过 `TestSkillFragmentsMatchBuildEvidence`（SKILL↔BuildEvidence 双向守卫）+ 全量扫描的候选存在性核对。

| 类型 | 证据链贯通 | 端到端验证 | 关键证据（实测） | 未覆盖分支 | 结论 |
|---|---|---|---|---|---|
| integer-overflow | ✅ | ✅ 候选文件 | 整函数 Code Context + `Signature: tp_two_var_product(int n, int m)` | unsigned_sub 的跨文件守卫 | PASS |
| out-of-bounds | ✅ | ✅ findings/ | `array: arr (capacity: 10); index: i` 落库 auto-confirmed | heap_oob_read 分支 | PASS |
| unchecked-return | ✅ | ✅ 候选文件 | `Contract: unknown` + `Callee definition: allocator.c:17 (alloc_entry(size_t size))` | contract@known 分支 | PASS |
| divide-by-zero | ✅ | ✅ 候选文件 | `divisor@compound`；`zz_range_filter_test` 验证 `DivisorInterval="[0,1]"` | 裸标识符+区间实扫（benchmark 无此样本） | PASS |
| null-deref | ✅ | ✅ 索引 | 5 条候选均 `src@N maybe-null`，definite_null/nullable_source 片段 | caller_null 跨文件 | PASS |
| hardcoded-secret | ✅ | ✅ 候选文件 | `secret_value: "Supe… (20 chars)"` + `match_kind` | value-proven 自动确认分支（§3.1 脱敏不彻底） | PASS（带 §3.1 告警） |
| injection | ⚠️ | ✅ 候选文件 | `api@CreateProcessA`；未证明参数源无 taint 证据（§3.5） | 已证明源（getenv/recv）直通 | PASS（带观察） |
| memory-leak | ✅ | ✅ 候选文件 | `allocation of buf via malloc`（`api` 已流） | 所有权转移跨函数 | PASS |
| resource-leak | ✅ | ✅ 候选文件 | `resource m acquired via pthread_mutex_lock` + `api@` | 自定义 acquire/release | PASS |
| format-string | ✅ | ✅ 索引 | `api@printf cat@format_string`，`format_arg` 片段 | taint 直通 | PASS |
| path-traversal | ✅ | ✅ 索引 | `src@23 tainted` / `src@18 tainted`（直接源） | 跨文件 taint | PASS |
| deadlock | ✅ | 单元（zz_lock_order_test） | `locks@m1|m2 reverse@` + `reverse_order` 片段（测试断言） | 真实扫描（benchmark 0 死锁） | PASS |
| crypto-misuse | ✅ | ✅ 候选文件 | `CryptoReason`/`KeySize` 片段 | 多 CWE 分类 | PASS |
| uninit | ✅ | ✅ 候选文件 | `allocation/declaration` 源片段 + `maybe-uninit` Hint | 跨函数输出参数 | PASS |
| use-after-free / double-free | ✅ | 单元/既有 zz 测试 | `free@N` / `free@N,M` Hint（buildHint 代码路径） | 真实扫描（benchmark 0 候选） | PASS |
| race-condition | ✅ | ✅ 索引 | `thread_functions`/`write_line` 片段（props 流测试） | toctou_shared_state | PASS |
| buffer-overflow | ✅ | ✅ 候选 15 条 | `buffer/copy_size/dst_capacity/size_argument` 片段 | var_size 分支 | PASS |
| signed-compare / sizeof-misuse / signal-handler / dangerous-function / argument-type / data-representation / implicit-contract | ✅（BuildEvidence 与 SKILL 双向守卫通过；scan 覆盖若干） | 部分 | — | 多数依赖契约测试而非逐类实扫 | PASS（守卫级） |

**说明**：`implicit-contract`/`deadlock`/`use-after-free`/`double-free` 在 benchmark 中候选数为 0（无对应触发样本），其证据链通过单元测试（`zz_lock_order_test.go` 等）与 SKILL 守卫验证，未做真实模型端到端判定。这是抽样结论，未冒充全量实扫通过。

---

## 5. 测试结果（逐条实际执行）

| 命令 | 结果 |
|---|---|
| `go version` | go1.25.3 darwin/arm64 |
| `gofmt -l .` | 仅 2 个**非 round2** 文件未格式化：`internal/evidence/data_representation_test.go`、`internal/parser/assign_parts_test.go`（均不在 52 文件 diff 内，属基线遗留） |
| `go build -buildvcs=false ./...` | ✅ 通过（需 `GOCACHE=$PWD/.tmpcache`，默认缓存目录被沙箱拒绝） |
| `go test -buildvcs=false ./...` | ✅ 14 个包全绿（`GOCACHE=$PWD/.tmpcache TMPDIR=/tmp`） |
| `go test -buildvcs=false -tags nosqlite ./internal/log/ ./internal/planner/ ./internal/db/` | ✅ 通过 |
| 全量扫描 `examples/c-vuln-benchmark/src`（34 文件） | ✅ 57 候选 + 135 auto-confirmed |
| `report --audit --scan-id ...` | ✅ 投影 135 findings + 告警"135 auto-confirmed 未复核" |
| `secguard plan out-of-bounds` | ✅ seed=1 final=1（确认 OOB 检测未漏） |

**关于首次 `go test ./...` 的 `internal/cli` FAIL**：`TestResolveExistingDBPath_NotExists` 失败，根因是审计命令设 `TMPDIR=$PWD/.tmpcache` 把 `t.TempDir()` 放进了仓库内，使"向上查找无 DB"的测试命中了真实 `.codeagent/.../sgre.db`。改 `TMPDIR=/tmp` 后通过。**属测试环境工件，非代码回归。**

**未执行/未验证**：
- 真实外部 AI 模型的端到端研判（本机未配置模型/凭证）。§6.2 要求的"真实模型端到端"未能验证——本次验证到"候选文件/索引生成正确、证据可读"，未验证"模型实际据此做出正确 confirm/dismiss"。
- `report --write-json` 的幂等 UPSERT 路径本次未手工重跑（由既有 `findings_test.go` 覆盖，该包测试通过）。
- Windows 平台构建（CI 五平台矩阵）未本地验证。

---

## 6. 端到端结果（代表性样本）

| 样本 | 类型 | 预期 | 实际 | 关键候选证据 / 最终状态 |
|---|---|---|---|---|
| `parser.c:86 oob_read_example`（`for i<=10 arr[i]`） | out-of-bounds CWE-125 | finding | ✅ 检出 | auto-confirmed；`array: arr (capacity:10); index: i`；落库 findings 表 |
| `allocator.c:114 alloc_entry(128)` | unchecked-return CWE-252 | 需证明 callee 返回 NULL | ✅ suspected + callee 定位 | `Contract: unknown` + `callee_definition allocator.c:17`（真工厂返回 NULL，AI 可确认） |
| `p8_value_analysis.c:21 malloc(n*m)` | integer-overflow CWE-190 | finding | ✅ suspected | 整函数 Code Context + `Signature: (int n, int m)` |
| `crypto.c:17 password` | hardcoded-secret CWE-798 | finding | ✅ suspected | `secret_value: "Supe… (20 chars)"` 掩码 + `match_kind` |
| `windows.c:13 CreateProcessA` | injection CWE-78 | finding | ⚠️ suspected 但无 taint 源证据 | 无 `tainted`/`src@N`；依赖 ±8 窗口（§3.5） |
| `memory_extra.c:44 malloc` early-return | memory-leak CWE-401 | finding | ✅ suspected（conditional） | `allocation via malloc` + `conditional` 片段 |
| `p11_fp_guards.c:59 oob_sum_bounded`（`i<10`） | 安全对照 | no_finding | ✅ 未报 | 索引严格 <10，正确抑制 |

---

## 7. 生产实测建议

1. **首批实测范围**：选 1-2 个真实中小仓库（含 C 生产代码，非仅 benchmark），先跑全类型，观察候选量/auto-confirmed 量/研判耗时。
2. **重点观察类型**：`dangerous-function`（政策类 auto-confirm 量大，§3.4）、`hardcoded-secret`（脱敏与误报，§3.1）、`out-of-bounds`（恒 confirmed，需复核误报率）、`unchecked-return`（contract@unknown 的 AI 证明负担）。
3. **误报/漏报记录**：用 benchmark 的 `expected-results.json` + `scripts/validate-benchmark.py` 作回归门；真实仓库用人工抽检记录 FP/FN 归因（detector 误报 vs 证据缺失 vs AI 误判）。
4. **异常/超时/上下文不足监控点**：`report --audit` 的 `unreviewed_auto_confirmed` 计数；`secguard status --per-type` 的 `plan_errors`/`detector_errors`；候选文件 `## Code Context` 出现 "Source unavailable" 的比例（文件漂移）。
5. **回滚条件**：若出现 (a) 任一类型系统性漏报（对比 baseline 候选数骤降且无法归因于过滤器收敛）、(b) auto-confirmed 误报率明显升高、(c) AI 研判因上下文超限导致尾部候选未分类，即回退到 `origin/main=173cadc`。

---

## 附：审计边界声明

- 本报告结论基于对 `planner`（`props.go`/`evidence_package.go`/`planner.go`/`registry.go`/`filter*.go`/`range_flow.go`/`call_sites.go`）、`report`（`markdown.go`/`snippet.go`）、`skills/vuln_type_skill_fragments_test.go`、若干 detector 与 SKILL.md 的代码阅读 + 全量测试 + 真实扫描。
- 未对全部 24 类做逐类真实模型端到端判定（§4 已标注哪些是守卫级/单元级验证）。
- `docs/` 下的过程性文档（含 GLM-5.3 交付报告 `docs/round2-evidence-contract-audit.md`）仅用于理解其声称，未作为任何结论依据；全部结论均以源码与运行结果为准。
