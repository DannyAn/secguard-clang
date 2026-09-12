# FP Verification Benchmark — 误报消减基准测试

> 验证多层过滤收敛管道的精度和召回率。
> Ground truth 定义在 [expected-results.json](expected-results.json) 中（每个用例带机器可读的 `expect` 字段）。
> 门禁脚本 `scripts/validate-benchmark.py` 读 SARIF（v0.3.0 起），按 (文件, 行) 交叉比对并计算 precision/recall。
>
> ```bash
> secguard scan --db /tmp/sgbench.db examples/c-vuln-benchmark/src
> python3 scripts/validate-benchmark.py \
>   --sarif .codeagent/secguard-clang/scans/latest/sarif.sarif \
>   --expected examples/c-vuln-benchmark/expected-results.json
> ```
>
> **历史 detector 覆盖缺口（已闭环）**：`PH1-01` 整数溢出 `malloc(count * obj_size)` 与 `PH1-06` 注册表凭据 `RegSetValueExA` 曾未被 detector 捕获，现均已产出候选。

## 测试规模

| 指标 | 数值 |
|------|------|
| 源文件 | 28 |
| 总测试用例 | 118 |
| **覆盖漏洞类型（22 个注册 skill）** | **22 / 22** |
| expect-finding（应报告） | 69 |
| expect-no_finding（应被抑制） | 49 |
| Phase 0（P0-P3/TP 反证骨架） | 18 |
| Phase 1（CWE-190/362/798/667/327） | 12 |
| Phase 2（扩展典型漏洞） | 4 |
| Phase 3（CWE-476 收敛） | 6 |
| Phase 4（uninit 流敏感） | 4 |
| Phase 5（p6 多类型） | 11 |
| Phase 6（resource-leak CWE-404） | 14 |
| Phase 7（语义图消费） | 6 |
| Phase 8（值分析/区间域） | 6 |
| Phase 9（Annex K `_s` 契约） | 8 |
| Phase 10（1-CFA 形参污点） | 4 |
| **Phase 11（补齐 4 个零覆盖 skill + 4 个缺失的 FP 守卫）** | **23** |
| 应完全不产生 Finding (P0: Detector EXCLUDE) | 7 |
| 应产生 Finding 但被 P1 抑制 | 3 |
| 应产生 Finding 但被 P2 抑制 | 4 |

> 每个注册类型都同时具备 `finding` 与 `no_finding` 用例 —— 用 `--coverage` 可复核
> （见「运行方式」）。这是本基准的意图：只测「能不能报」而不测「该不该闭嘴」的类型，
> 其精度主张是没有被验证的。

## 分类定义

| 类别 | 含义 | 期望结果 |
|------|------|---------|
| **P0 — Safe Function** | 使用安全函数 (memcpy_s, execve, PreparedStatement)，Detector EXCLUDE 应直接排除 | 0 Finding |
| **P1 — Semantic** | 看起来像漏洞，但项目安全框架已消除风险 | Finding → P1 exempted → dismissed |
| **P2 — Counter-Evidence** | 看起来像漏洞，但存在 RAII/bounds check/lock guard | Finding → P2 counter_evidence_found → dismissed |
| **P3 — Edge Case** | 有部分保护但不充分 | Finding → P3 suspected → 保留给人工 |
| **TP — True Positive** | 确实存在漏洞 | Finding → P3 confirmed → Certified Finding |

## 用例详情

### P0 — 安全函数 (Detector EXCLUDE 层)

这些用例应被 Detector 的 EXCLUDE 模式在扫描阶段直接排除，**不产生任何 Finding**。

| # | 文件 | 行 | 安全函数 | EXCLUDE 模式 |
|---|------|----|---------|-------------|
| P0-01 | p0_safe_functions.c | 14 | `memcpy_s(dst, sizeof(dst), ...)` | `memcpy_s\(dst,\s*sizeof\(dst\)` |
| P0-02 | p0_safe_functions.c | 18 | `strcpy_s(dst, sizeof(dst), ...)` | `strcpy_s\(dst,\s*sizeof\(dst\)` |
| P0-03 | p0_safe_functions.c | 22 | `sprintf_s(dst, sizeof(dst), ...)` | `sprintf_s\(buf,\s*sizeof\(buf\)` |
| P0-04 | p0_safe_functions.c | 26 | `strcat_s(dst, sizeof(dst), ...)` | `strcat_s\(dst,\s*sizeof\(dst\)` |
| P0-05 | p0_safe_functions.c | 37 | `snprintf + sizeof + 返回值检查` | `snprintf\([^)]*sizeof\([^)]*\).*\n.*if\s*\(.*written` |
| P0-06 | p0_safe_functions.c | 55 | `execve("/bin/ping", argv, NULL)` | `execve\(` |
| P0-07 | p0_safe_functions.c | 86 | `sqlite3_prepare_v2 + sqlite3_bind_text` | `sqlite3_bind_text\|PreparedStatement` |

**期望**: 0 Finding。若 regex 回退精度不足产生 Finding → P2 应作为第二防线抑制。

---

### P1 — Semantic Verification (项目安全框架)

这些用例使用项目自定义的安全包装，Detector 会产出 Finding，但 P1 应识别安全框架并 exempt。

| # | 文件 | 行 | 触发 Detector | 安全机制 | P1 期望 |
|---|------|----|-------------|---------|--------|
| P1-01 | p1_safecopy_wrapper.c | 18 | memory.buffer_overflow | SafeCopy_copy 保证 bounds_checked | **exempted** |
| P1-02 | p1_safecopy_wrapper.c | 28 | memory.buffer_overflow | SafeCopy_strcpy 保证 bounds_checked | **exempted** |
| P1-03 | p1_safequery_wrapper.c | 38 | injection.command_injection | SafeQuery 保证 prepared_statement | **exempted** |

**期望**: 3/3 Finding → P1 exempted → dismissed.

---

### P2 — Counter-Evidence Hunt (反证搜寻)

这些用例看起来像漏洞，Detector 会产出 Finding，P1 no_exemption，但 P2 应找到反证。

| # | 文件 | 行 | 触发 Detector | 反证 | P2 期望 |
|---|------|----|-------------|------|--------|
| P2-01 | p2_raii_memory.c | 16 | memory.memory_leak | ResourceHandle RAII (构造分配+析构释放) | **counter_evidence_found** |
| P2-02 | p2_lock_guard.c | 27 | concurrency.lock | LockGuard mutex 守卫 | **counter_evidence_found** |
| P2-03 | p2_bounds_checked.c | 14 | memory.buffer_overflow | `if (user_len > MAX_MSG_SIZE) return` bounds check | **counter_evidence_found** |
| P2-04 | p2_bounds_checked.c | 30 | memory.buffer_overflow | `if (user_len >= sizeof(dst)) return` sizeof guard | **counter_evidence_found** |

**期望**: 4/4 Finding → P2 counter_evidence_found → dismissed.

---

### P3 — Edge Cases (裁决法庭)

这些用例有部分保护但不充分，P1 no_exemption + P2 counter_evidence_found 但保护不完整。P3 Court 应裁决为 suspected 或 confirmed。

| # | 文件 | 行 | 触发 Detector | 有保护但不充分 | P3 期望 |
|---|------|----|-------------|--------------|--------|
| P3-01 | p3_edge_case.c | 28 | injection.command_injection | is_safe_input 过滤分号但不防御 &&, \|\|, \$() | **suspected** |
| P3-02 | p3_edge_case.c | 49 | concurrency.lock | pthread_mutex_lock 保护了读取但 lock-unlock 间有 TOCTOU 窗口 | **suspected** |

**期望**: 2/2 Finding → P3 suspected → 保留在 Certified Finding 中标记需人工确认。

---

### TP — True Positives (真阳性对照)

这些是确实存在漏洞的对照用例，应通过全部三轮验证不被抑制。

| # | 文件 | 行 | 触发 Detector | 漏洞 | 期望 |
|---|------|----|-------------|------|------|
| TP-01 | p1_safecopy_wrapper.c | 47 | memory.buffer_overflow | `memcpy(buf, user_input, strlen(user_input))` 无 bounds check | P3 **confirmed** |
| TP-02 | p1_safequery_wrapper.c | 49 | injection.command_injection | `sprintf(query, "SELECT ... '%s'", username)` 字符串拼接 SQL | P3 **confirmed** |

**期望**: 2/2 Finding → P3 confirmed → Certified Finding.

---

### Phase 2 — 扩展典型漏洞（本轮新增）

| # | 文件 | 行 | 检测器 | 漏洞 | 期望 |
|---|------|----|--------|------|------|
| OB-01 | memory_extra.c | 15 | buffer-overflow (heap_oob_write) | `malloc(user_len)` 后循环 `i < user_len + 10` 写 `buf[i]` | finding |
| OB-02 | parser.c | 31 | buffer-overflow (format_overflow) | `sprintf(task->command, "Task[%s]: %s", task->name, description)` 写 256 字节字段 | finding |
| RA-01 | concurrency.c | 15 | race-condition (shared_data_race) | 两个 pthread 线程无锁 `g_shared_counter++` | finding |
| OOB-01 | parser.c | 86 | out-of-bounds (CWE-125) | `int arr[10]`，循环 `i <= 10` 读 `arr[i]` | finding |

**说明**：`array_oob_read`/`heap_oob_read` 事件由新增的 `out-of-bounds`（CWE-125）类型消费，写侧事件仍由 `buffer-overflow`（CWE-787）消费。经典数据竞争（至少一次写 + 无锁）为 confirmed；TOCTOU 有部分锁保护（读在锁内、变更在锁外）应为 suspected 人工确认。

---

### Phase 3 — null-deref 收敛（含 sizeof 伪解引用）

| # | 文件 | 行 | 检测器 | 反证 | 期望 |
|---|------|----|--------|------|------|
| ND-01 | null_deref_sizeof.c | 17 | null-deref (CWE-476) | `sizeof(node->value)` 是编译期类型表达式，非运行时解引用 | no_finding |
| ND-02 | p5_null_flow.c | 19 | null-deref (CWE-476) | 真阳性对照：malloc 未检查即解引用 | finding |
| ND-03 | p5_null_flow.c | 26 | null-deref (CWE-476) | `p = &g_fallback` 重赋值杀空 | no_finding |
| ND-04 | p5_null_flow.c | 35 | null-deref (CWE-476) | NULL 守卫内用字符串字面量兜底 | no_finding |
| ND-05 | p5_null_flow.c | 45 | null-deref (CWE-476) | `a = b` 拷贝传播，b 为确定非空地址 | no_finding |
| ND-06 | p5_null_flow.c | 54 | null-deref (CWE-476) | 解引用位于 `return` 之后的不可达代码 | no_finding |

**说明**：`sizeof(p->field)` / `sizeof(p[0])` 对可能为 NULL 的指针求值不会在运行时解引用，
故 `sizeof_pseudo_deref` 过滤规则（null-deref 链第一级）必须抑制该候选。此用例把这条
站点级规则锁进基准门禁，防止后续重构破坏它。

ND-05/ND-06 于 2026-09-12 **从 `examples/nullflow-demo/src/demo.c` 迁入**：该独立样例项目
是 null-deref 流敏感收敛的原型（1 个真阳性 + 4 个误报），其中 `tp_unchecked_malloc` /
`fp_reassign_addressof` / `fp_guard_default_literal` 三个场景与 `p5_null_flow.c` 重复，
只有「拷贝传播」与「return 之后不可达」两个场景是本基准原先没有的。迁移后 demo 目录
（连同其 228K 未跟踪的旧 `zhuque-secguard` 扫描垃圾）已删除，`CLAUDE.md` 的引用同步改指
本节。

> ⚠️ **迁移时的一个坑（已随代码修正消解）**：`fp_copy_nonnull` 与 `fp_dead_after_return` 在
> null-deref 视角下应当静默（它们确实**没有**产生 null-deref 候选），但原 demo 代码都是先
> `malloc` 再丢弃指针，在 memory-leak 视角下是**真泄漏**。迁移后给这三个覆盖指针的用例
> （连同原有的 `fp_reassign_addressof`）补了 `free` 再重赋值/提前返回，使每个 fixture 只测
> null-deref 一件事，泄漏维度不再产生噪声。这也顺带印证了 memory-leak 的「覆盖指针丢分配」
> 检测（`tc110_memory_leak_overwrite.c` 单测已锁）：`malloc; p = NULL; free(p)` 是真泄漏，
> `free(p); p = NULL;` 才正确。

## Benchmark 指标

### 精度 (Precision)

```
Precision = TP / (TP + FP_reported)

Scenario A — 无验证管道 (当前):
  Detector 产出 18 条 Finding → 用户看到 18 条
  实际应报告: 4 (TP-01, TP-02, P3-01, P3-02)
  实际不应报告: 14
  Precision = 4/18 = 22.2%
  误报率 = 14/18 = 77.8%

Scenario B — 三轮验证后 (目标):
  Detector 产出 11 条 Finding (P0 7 条被 EXCLUDE 排除)
    → P1 exempted 3 条 (P1-01~03)
    → P2 counter_evidence_found 4 条 (P2-01~04)
    → P3 裁决: 2 confirmed + 2 suspected
  最终 Certified Finding: 4 条
  Precision = 4/4 = 100% (confirmed 为真阳性基准)
  含 suspected: 2/4 = 50% confirmed rate
  收敛率 = (18-4)/18 = 77.8%
```

### 逐轮收敛

```
18 潜在 Finding
  → P0 (Detector EXCLUDE):  -7  → 11 Finding (38.9% 首轮过滤)
  → P1 (Semantic):          -3  →  8 Finding (16.7% 安全框架)
  → P2 (Counter-Evidence):  -4  →  4 Finding (22.2% 反证)
  → P3 (Court):             确认 2 confirmed + 2 suspected
                              = 4 Certified Finding
```

### 目标指标

| 指标 | 当前 (无验证) | 目标 (三轮验证) |
|------|-------------|---------------|
| Finding 输出数 | 18 | 4 |
| Precision | 22.2% | 100% (confirmed only) |
| 误报率 | 77.8% | 0% |
| 收敛率 | 0% | 77.8% |
| 审计可追溯性 | 0% | 100% (dismissed.json) |

---

## 运行方式

在 `examples/c-vuln-benchmark/` 目录下执行。

```bash
# 1. 扫描（用独立 DB 避免历史索引污染；stdout 只打印摘要）
secguard scan --db /tmp/sgbench.db src

# 2. 收尾：写出 verdict 阶段的 result.sarif / report.md / findings/
secguard report --audit --scan-id <scan_id> \
    --output-dir .codeagent/secguard-clang/scans/<scan_id> --db /tmp/sgbench.db

# 3. 校验（默认自动找最新的 result.sarif）
python3 scripts/validate-benchmark.py              # 退出码 0 = 全通过
python3 scripts/validate-benchmark.py --json       # 机器可读
python3 scripts/validate-benchmark.py --show-pass  # 列出通过用例
python3 scripts/validate-benchmark.py --line-tolerance 0   # 只看精确行匹配

# 4. 覆盖度（不需要 SARIF，也不受上面那轮扫描影响）
python3 scripts/validate-benchmark.py --coverage   # 每个类型的 finding/no_finding 计数
python3 scripts/validate-benchmark.py --selftest   # 校验 detector/cwe → 类型映射是否完整
```

`--coverage` 按注册类型（`CWE_TO_TYPE` 的 22 个值）逐类统计 ground truth，标出
「一个用例都没有」与「有 finding 但缺 no_finding 守卫」两种缺口；前者是硬失败
（退出码 1），后者只告警。`--selftest` 会断言 ground truth 里的每个 `detector` 标签
**和每个 `cwe` 标签**都已映射 —— `cwe` 覆盖曾经是个静默缺口：SARIF 的 `ruleId` 是 CWE
字符串，缺一条映射该类型的 finding 就不再参与比对，召回和精度会同时被悄悄跳过而不报错。

**校验口径（为什么不是单纯的「(文件, 行) 相等」）：**

validator 按 **(漏洞类型, 文件, 行 ± 容差)** 比对，默认容差 ±3，并打印命中偏移。两处必须放宽，都是实测踩出来的：

1. **行号口径不同**：SecGuard 报的是 **sink/调用行**，而部分用例标签写的是**函数定义行**或**格式化行** —— RL-13 标 153 / 实报 155（`mkstemp` 调用）、RL-14 标 163 / 实报 165、TP-02 标 49 / 实报 50（`sqlite3_exec` sink）。纯相等比对会把**已经检出**的算成漏报。
2. **同一行可能有多种漏洞**：P10-02 是 `input.path_traversal` 的 `no_finding`，而 SecGuard 在该行报 unchecked-return (CWE-252) —— 正确且与该用例无关。因此**按类型比对**；命中但类型不同的只作 info 列出。

`detector` → 漏洞类型的映射见 `scripts/validate-benchmark.py` 的 `DETECTOR_TO_TYPE`。注意 **`concurrency.lock` 映射到 `race-condition`**：它的两个用例分别是「加锁保护不该报」(P2-02) 与 TOCTOU (P3-02)，SecGuard 报的是 CWE-362；`deadlock` (CWE-667) 有独立的 detector 标签。未带 `detector` 的用例按「任意类型」比对。

**判定来源**是 verdict 阶段的 `result.sarif`（只含 confirmed + suspected）。被 AI 判为 `dismissed` 的不会出现，因此**不**算误报 —— 这正是本基准的意图。

**退出码**：`0` 全通过；`1` 有误报，或有漏报（`known_gap` 用例的漏报、以及 `--allow-fn` 例外；误报**不**受 `--allow-fn` 抑制）；`2` 找不到 SARIF。

> ⚠️ **答案文件不能进扫描上下文。** 本目录里就躺着 `expected-results.json` / `benchmark.md` / `assignment-baseline.json`，扫描目标旁边还可能有上一轮会话日志。跑基准时只允许把 `src/` 作为目标（`secguard scan ... src`），**不要**读这些答案文件——agent 侧的这条约束已写进 `extension/shared/command-instructions.md` 与 `agent-body.md`，人工跑基准时同样适用。一旦读了，这一轮的 precision/recall 就没有意义了。

## v0.3.0 新增基线（硬骨头场景）

| 文件 | 覆盖 | 状态 |
|------|------|------|
| `p8_value_analysis.c` | 值分析/区间域：`n*sizeof(T)`、`n*m`、`calloc(n,m)`、`n+1`、`n*4`、守卫常量传播 | ✅ 已纳入（P8-01..06） |
| `p9_secure_func.c` | Annex K `_s` 契约：memcpy_s/strcpy_s 说谎 size、约束违约、scanf_s 逐转换宽度、完整签名（errno_t + restrict）count > destsz | ✅ 已纳入（P9-01..08） |
| `p10_interproc_taint.c` | 1-CFA 形参敏感：passthrough、多级 passthrough、链式形参污点 | ✅ 已纳入（P10-01..04） |
| `p7_graph_effect.c` | 语义图消费：污点 source→sink、free→use CFG、别名、所有权转移 | ✅ 已纳入（P7-01..06） |
| `rl_resource_leak.c` | resource-leak (CWE-404)：文件/Socket/FD 工厂/锁泄漏、流敏感条件释放、所有权转移 TN、缺陷修复回归目标 | ✅ 已纳入（RL-01..14，见 Phase 6 节） |

> **当前状态（0.6.1 实测）：VALID — 118/118 用例 PASS · expect-finding 召回 69/69 · `no_finding` 误报 0/49**。
> 复现方式见上方「运行方式」；命中偏移 `+0×66 / +1×1 / +2×2`，即 3 个用例是标签行号口径差（已检出）。
>
> **2026-09-08 更新**：新增 Phase 6 resource-leak 14 用例（77 → 91）。RL-10..14
> 为三个设计缺陷的回归用例（error-return fd 误判、fd 工厂白名单、out-param
> acquirer），0.6.0 后已修复，见下方 Phase 6 节。
>
> **2026-09-12 更新**：新增 Phase 11 共 23 用例、并由已删除的 `examples/nullflow-demo/` 迁入
-> ND-05/ND-06、ML-01/ML-02（91 → 118），补齐
> `dangerous-function` / `double-free` / `format-string` / `signal-handler` 四个
> 此前**一个用例都没有**的 skill，并为 `deadlock` / `hardcoded-secret` /
> `out-of-bounds` / `use-after-free` 补上缺失的 `no_finding` 反证。22 个注册类型
> 至此每个都具备「该报 / 不该报」对照。见下方 Phase 11 节。
>
> ⚠️ **本轮数字的性质**：这轮 118/118 与 Phase 11 用例出自同一次会话，因此它证明的是
> **ground truth 与管线的一致性与可判定性**（TP 落在预期行、TN 全程静默），**不是**
> 一次盲测的 precision/recall —— 作者知道答案。若要作为盲测口径引用，需在未读过
> `expected-results.json` 的会话里重跑（答案文件的约束见本节末尾）。
>
> **v0.3.2 对齐**：五例存量漂移（`P2-04`/`P3-01`/`PH1-03`/`P6-06`/`P6-08`）与
> `p7` 语义图用例全部对齐，修复 4 处检测器缺陷：
> - memcpy 变量长度越界未应用前置边界检查（回归）；
> - `_s` 资源泄漏误报：`if (f) { fclose(f); }` / `if (fd >= 0) { close(fd); }`
>   正守卫包裹释放未被识别为"失败路径无资源"；
> - 注入漏报：`snprintf(cmd, ..., user_input)` 未把格式化实参污点传播到 dst，
>   且非 static 函数形参（外部可控）未按"可能被污染"播种。

---

## Phase 6 — resource-leak (CWE-404)（2026-09-08 新增）

`src/rl_resource_leak.c`，14 用例，Ground truth 见 `expected-results.json` RL-01..RL-14。
来源：v0.6.0 resource-leak 漏报怀疑调查（0.4.3/0.6.0 双版本对照 + 管道层静态检视）。

| 组 | 用例 | 形态 | expect | 当前行为 |
|----|------|------|--------|---------|
| 回归防线 | RL-01..06 | fopen/open/socket+connect/epoll_create1/lock 泄漏、条件释放（流敏感） | finding | ✅ 检出（TP） |
| 防 FP 回潮 | RL-07..09 | fopen+fclose、return f 所有权转移、open 检查+close | no_finding | ✅ 静默（TN） |
| 缺陷修复 | RL-10..14 | error-return fd / dup / sqlite3_open / mkstemp / fopen_s | finding | ✅ 检出（0.6.0 后修复） |

### 缺陷修复用例（回归目标，已修复）

| # | 形态 | 修复 |
|---|------|------|
| RL-10 | `if (fd < 0) return fd;` 正常路径忘 close | detector `hasNonFailureReturn` + graph `isErrorReturn` 排除错误返回 |
| RL-11 | `dup(STDOUT_FILENO)` 无 close | `isResourceAcquirer` 补 dup/dup2/dup3（短名精确匹配） |
| RL-12 | `sqlite3_open(path, &db)` 无 sqlite3_close | `outParamAcquirers` 白名单扫描 `&arg` |
| RL-13 | `mkstemp(tmpl)` 无 close | `isResourceAcquirer` 补 mkstemp/mkostemp（长名子串匹配） |
| RL-14 | `fopen_s(&f, ...)` 无 fclose | `outParamAcquirers` 白名单另一成员 |

**验证**：RL-01..06 守住现有检出（如 4afad45 的 epoll/eventfd fd 工厂修复），
RL-07..09 防止修复缺口时把 FP 再引进来（如 `connect` 误判 acquirer 的回潮），
RL-10..14 锁定三个设计缺陷的修复（error-return fd 误判、fd 工厂白名单、out-param
acquirer），任一回归会翻回 FN、recall 下降。

---

## Phase 11 — 补齐 skill 覆盖缺口（2026-09-12 新增）

### 缺口是什么

22 个注册 skill 里，有 4 个在基准中**一个用例都没有**，另有 4 个只有 `finding` 用例、
没有任何 `no_finding` 反证。对「误报消减」基准来说，后者等于精度主张未被验证：

| 类型 | 补全前 finding / no_finding | 说明 |
|------|---------------------------|------|
| `dangerous-function` | **0 / 0** | 零覆盖 |
| `double-free` | **0 / 0** | 零覆盖 |
| `format-string` | **0 / 0** | 零覆盖（`parser.c:45` 的 `printf(user_msg)` 早已被检出，却从未进 ground truth） |
| `signal-handler` | **0 / 0** | 零覆盖（`concurrency.c:98` 同上） |
| `deadlock` | 1 / **0** | 只有 TP，无「锁序一致不该报」防线 |
| `hardcoded-secret` | 3 / **0** | 只有 TP |
| `out-of-bounds` | 1 / **0** | 只有 TP |
| `use-after-free` | 2 / **0** | 只有 TP |

### 新增文件与用例

| 文件 | 用例 | 形态 | expect |
|------|------|------|--------|
| `p11_dangerous_function.c` | DGF-01..03 | `gets` / `mktemp` / `gethostbyname` —— 名单命中即是缺陷（POLICY 检查） | finding |
| `p11_dangerous_function.c` | DGF-04 | `fgets` + `getaddrinfo` + `mkstemp` + `memmove` 安全替代集群 | no_finding |
| `p11_format_string.c` | FS-01..03 | `printf(user_msg)` / `fprintf(log, fmt)` / `syslog(LOG_ERR, msg)` | finding |
| `p11_format_string.c` | FS-04 | `printf("%s", user_msg)` —— 字面量格式串 | no_finding |
| `parser.c` | FS-05 | 存量已检出缺陷纳入回归防线 | finding |
| `p11_double_free.c` | DF-01..02 | 同一指针两次 free / 结构体字段两次 free | finding |
| `p11_double_free.c` | DF-03..04 | 两次 free 之间重新赋值；free 后置 NULL 再 free | no_finding |
| `allocator.c` | DF-05 | `cleanup_entries` 释放已 release 的全局槽位（存量已检出） | finding |
| `p11_signal_handler.c` | SH-01..02 | 处理器内 `printf` / `malloc`+`free` | finding |
| `p11_signal_handler.c` | SH-03..04 | 只写 `volatile sig_atomic_t`；只用 `write`/`_exit` | no_finding |
| `concurrency.c` | SH-05 | 存量已检出缺陷纳入回归防线 | finding |
| `p11_fp_guards.c` | DL-01 | 两线程始终同序获取两把锁（锁序图无环） | no_finding |
| `p11_fp_guards.c` | HS-01 | 凭据来自 `getenv`，非字面量 | no_finding |
| `p11_fp_guards.c` | OOB-02 | 索引严格 `<` 数组长度 | no_finding |
| `p11_fp_guards.c` | UAF-01 | free 后重新分配，再使用新块 | no_finding |

### 三个构造上的坑（写用例时必须知道）

1. **`deadlock` 的 TN 不能与 TP 共用锁名。** `LockOrderFilter` 消费的是**全局**锁序图
   （`graph/lock_order.go` 按锁名建节点，跨文件同名锁共享节点），找的是强连通分量；
   而且它 **fail-open** —— 非环候选仍以 `suspected` 保留、永不丢弃。所以「锁序一致」的
   TN 只有在**任何地方都不出现反向获取**时才真正静默；`p11_fp_guards.c` 因此用了
   `g_guard_theta` / `g_guard_phi` 两个独占锁名。

2. **`signal-handler` 的处理器里不要写 `if (p) { free(p); }`。** 这个形态会被
   memory-leak 判为泄漏（见下方「顺带发现的问题」），给用例引入与 signal-handler 无关的
   噪声候选。改成早返回式（`if (!p) return; ... free(p);`）即静默。DGF-01 的 `gets(buf)`
   同理会产生一条 buffer-overflow 候选 —— 那是**真阳性**（`gets` 无界），保留。

3. **TN 的行号必须离同类型 TP 至少 4 行**（validator 默认 ±3 容差）。同类 TP/TN 挤在
   一起会让容差窗口互相穿透。

### 顺带发现的问题（写本轮用例时撞上的，均非本基准引入）

三条已全部定位、修复并配了回归测试。逐条记录如下，供追溯。

| # | 层 | 现象 | 根因 | 修复 |
|---|----|------|------|------|
| 1 | **产品：detector**（`memory_leak.go`） | `if (p) { free(p); }` 被判为 memory-leak | 正守卫释放未被识别为释放：`memory_leak.go` 缺 `resource_leak.go` 已有的 `isGuardedRelease` 分支，走了 `cfgValid` 路径后把 NULL 分支跳过 free 当成了泄漏 | `memory_leak.go` 复用 `isGuardedRelease` 补上分支；`TestMemoryLeak_GuardedFreeNoLeak`（fixture `tc111_memory_leak_guarded_free.c`）锁住。`parser.c:102` 现静默 |
| 2 | **产品：pipeline**（`planner.go`） | hardcoded-secret 候选没有位置（`crypto.c:12` 的 `g_api_key`，文件级） | 文件级事件 `EntityID == 0`，候选 `FileID` 只从 `funcsByID[0]`（nil）取，location 里的正确 `FileID` 被丢弃 | `seedCandidatesByType` 在无函数时回退到 location 的 `FileID`；`TestHardcodedSecret_FileScopeCandidateHasLocation` 锁住。`crypto.c:12` 现正常自动确认 |
| 3 | **测试护栏：validator** | `CWE_TO_TYPE` 缺 `CWE-676` / `CWE-479` | 两条映射此前不存在 | 补映射，并把 `cwe` 标签覆盖 + 两套映射一致性纳入 `--selftest` |

> 修复后基准仍为 **118/118**：`memory-leak` 候选 7 → 3（`parser.c:102` 守卫释放消失、
> `p5_null_flow.c` 三处覆盖指针泄漏随代码修正消失），`hardcoded-secret` 候选 3 → 2
> （`crypto.c:12` 转为自动确认），其余不变。

**一条已撤回的判断（留档，避免重复踩）**：曾把 `malloc(64); p = NULL; free(p);` 也当成
memory-leak 误报，复查后**该判定是错的**——`p = NULL` 丢弃了对块的唯一引用，随后
`free(p)` 释放的是 NULL，原块确实泄漏，detector 报得对。对照：`free(p); p = NULL;`
才是正确形态，静默。区别在「置 NULL 在 free 之前还是之后」。

