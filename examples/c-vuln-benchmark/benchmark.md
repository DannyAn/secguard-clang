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
> **历史 detector 覆盖缺口（本轮已全部闭环）**：`PH1-06` 注册表凭据 `RegSetValueExA`、
> `PH1-01` 乘法溢出、`RL-13` mkstemp fd 工厂、`DF-05` 跨函数槽位二次释放均已修复。
> `PH1-01` 的 fixture 从 `size_t` 改为 `unsigned int`（真正的 32 位乘积），并修了
> `sizeCalcExprs` 的 narrow-product 守卫（原先拿乘积和 2^64 比较，但 C 的乘法按操作数
> 公共类型求值，两个 `uint32_t` 在 32 位就回绕）。详见文末「检测器缺口」。

## 测试规模

| 指标 | 数值 |
|------|------|
| 源文件 | 39 |
| 总测试用例 | 202 |
| **覆盖漏洞类型（25 个注册 skill）** | **25 / 25** |
| expect-finding（应报告） | 104 |
| expect-no_finding（应被抑制） | 98 |
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
| Phase 12（v0.7.1 缺陷修复回归） | 6 |
| **Phase 13（v0.7.4 误报修复回归）** | **2** |
| Phase 14（dealloc 启发式误报修复） | 3 |
| **Phase 15（memory-leak 容器逃逸误报修复）** | **2** |
| **Phase 16（divide-by-zero 非零源除数误报修复）** | **2** |
| **Phase 17（补齐 3 个零覆盖 contract 类型：argument-type / data-representation / implicit-contract）** | **12** |
| **Phase 18（P1 调用点实参普查 gate / 净化 kill 回归）** | **5** |
| **Phase 21（unchecked-return 消费点普查误报修复）** | **7** |
| **Phase 22（null-deref 三类误报修复）** | **6** |
| **Phase 23（不完整类型信息 null-deref 检测能力增强）** | **8** |
| **Phase 24（未校验外部索引越界检测能力增强）** | **5** |
| **Phase 26（第三方库 API 语义模型回归）** | **8** |
| 应完全不产生 Finding (P0: Detector EXCLUDE) | 7 |
| 应产生 Finding 但被 P1 抑制 | 3 |
| 应产生 Finding 但被 P2 抑制 | 4 |

> 分 Phase 数字为各阶段新增时的记录，未随之后的补充逐一回填；**总计以 ground truth
> 为准**（`python3 scripts/validate-benchmark.py --coverage`）。
>
> 每个**有 ground truth 的类型**都同时具备 `finding` 与 `no_finding` 用例 —— 用
> `--coverage` 可复核（见「运行方式」）。Phase 17 补齐了 `argument-type`
> （CWE-686）、`data-representation`（CWE-843）、`implicit-contract`（CWE-20）三个
> 此前零覆盖的 contract 类型，25 个注册类型现在全部有「该报」与「不该报」对照；
> `--coverage` 退出码 0。这是本基准的意图：只测「能不能报」而不测「该不该闭嘴」的
> 类型，其精度主张是没有被验证的。

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

`--coverage` 按注册类型（`CWE_TO_TYPE` 的 25 个值）逐类统计 ground truth，标出
「一个用例都没有」与「有 finding 但缺 no_finding 守卫」两种缺口；前者是硬失败
（退出码 1），后者只告警。`--selftest` 会断言 ground truth 里的每个 `detector` 标签
**和每个 `cwe` 标签**都已映射 —— `cwe` 覆盖曾经是个静默缺口：SARIF 的 `ruleId` 是 CWE
字符串，缺一条映射该类型的 finding 就不再参与比对，召回和精度会同时被悄悄跳过而不报错。
注意 ground truth 的 `cwe` 标签只是**用例声称的** CWE；流水线实际能发出的 ruleId 是
`planner.AllCWEs()`（含 `CategoryCWEs`/`LegacyCWEs`，如 injection 的 CWE-89、crypto 的
CWE-326/338），所以 `CWE_TO_TYPE` 必须覆盖整个 `AllCWEs()` 集合 ——
`TestBenchmarkValidatorCWEMap`（`sgre/internal/planner`）会对照 Go 侧的权威清单，
漏一条即构建失败。

**校验口径（为什么不是单纯的「(文件, 行) 相等」）：**

validator 按 **(漏洞类型, 文件, 行 ± 容差)** 比对，默认容差 ±3，并打印命中偏移。两处必须放宽，都是实测踩出来的：

1. **行号口径不同**：SecGuard 报的是 **sink/调用行**，而部分用例标签写的是**函数定义行**或**格式化行** —— RL-13 标 156 / 实报 156（`mkstemp` 调用）、RL-14 标 163 / 实报 165、TP-02 标 49 / 实报 50（`sqlite3_exec` sink）。纯相等比对会把**已经检出**的算成漏报。
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

> **当前状态（0.6.1 实测）：VALID — 118/118 用例 PASS · expect-finding 召回 69/69 · `no_finding` 误报 0/49**。（v0.7.1 新增 Phase 12 七例后为 125 例、expect-finding 76。）
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
| RL-13 | `mkstemp(tmpl)` 无 close | `isResourceAcquirer` 补 mkstemp/mkostemp（0.6.0）+ `SafeFunctionFilter` 对 `resource_acquire` 放行（本轮） |
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
| `p11_dangerous_function.c` | DGF-01..13 | `gets` / `mktemp` / `gethostbyname` + 分层策略：`memcpy` / `strcpy` / `sprintf` / `sscanf` / `atoi` / `abort` / `alloca` / `setjmp` / `longjmp` / `realloc` —— 名单命中即是缺陷（POLICY 检查，按 category 分层） | finding |
| `p11_dangerous_function.c` | DGF-14 | `memset_s` + `memcpy_s` + `strcpy_s` + `snprintf_s` + `sprintf_s` + `fgets` + `getaddrinfo` + `mkstemp` 安全 `_s` 替代集群 | no_finding |
| `p11_dangerous_function.c` | DGF-15 | `exit(0)` 位于 `main` 内 —— 程序入口允许进程退出 | no_finding |
| `p11_format_string.c` | FS-01..03 | `printf(user_msg)` / `fprintf(log, fmt)` / `syslog(LOG_ERR, msg)` —— 树内唯一调用点传字面量，P1 census gate drop（旧保守语义期为 finding） | no_finding |
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

---

## Phase 12 — v0.7.1 缺陷修复回归（2026-09-16 新增）

v0.7.0 打磨时发现一批**逻辑上可证明会漏报**的缺陷（Issue #95），其中五条在
本基准里没有对应 ground truth —— 这些形状此前一直漏报，但 118 例却全绿，说明
「全绿」不等于「召回没漏洞」。本轮把每条修复都锁进一个可回归的用例：

| # | 文件 | 行 | 缺陷 | 修复 |
|---|------|----|------|------|
| ML-03 | memory_extra.c | 119 | 错误路径 `return p` 被判为函数级所有权转移，正常路径从不 free 的泄漏被吞 | memory/resource-leak 的 return-to-caller 改路径敏感（`findReturnVarLines` 进 `hasLostResource` avoid 集，去掉函数级 `isReturned`） |
| ML-04 | memory_extra.c | 129 | `p=malloc(); p=malloc(); free(p)` 第一块覆盖指针泄漏，被 ReleaseFilter 按 (函数,变量) 粗粒度吞掉 | release 事件带 `alloc_line`，ReleaseFilter 按 alloc site 关联 |
| RL-15 | rl_resource_leak.c | 177 | 括号错误返回 `return (fd)` 不被 `isErrorReturn` 识别，误判所有权转移 | `isErrorReturn` / `returnReturnsVar` 解一层括号 |
| RL-16 | rl_resource_leak.c | 188 | `mmap` 是映射工厂但不在 acquirer 白名单（"open"/"create" 子串不命中） | `isResourceAcquirer` 补 `mmap`、`isResourceReleaser` 补 `munmap` |
| SH-06 | p11_signal_handler.c | 62 | 处理器内 `strncpy`：`strncpy` 同时命中 SafeFunctions，SafeFunctionFilter 曾按 VariableName 巧合误杀 | SafeFunctionFilter 不再用 `IsSafeFunction(c.VariableName)` |
| ND-07 | p5_null_flow.c | 80 | getter 返回全局结构体字段（`return g_space.shell_conf`，NULL 初始化），调用方未判空即解引用 | `exprReturnsNullable` 把 field_expression 判为可能为空（fail-open） |
| ND-08 | p5_null_flow.c | 97 | getter 返回外部函数（声明未定义）的调用结果，调用方未判空即解引用 | `exprReturnsNullable` 对 `return 外部调用` 按开放世界 fail-open |

七条均为 `expect: finding`。ML-03/ML-04 同时锁定 planner 层的
`OwnershipTransferFilter`（C2b）与 `ReleaseFilter`（C3）——detector 侧修好后，这两层
粗粒度 filter 仍会二次吞掉候选，因此这两例必须在 **verdict 阶段 result.sarif** 出现才算过。

**顺带补的确定性单测**（不进基准，`go test` 直接跑）：
- `TestResourceLeak_ParenthesizedErrorReturnIsLeak`（fixture `tc92_resleak_defects.c` 增 `rl_paren_return`）—— RL-15 的 detector 级回归。
- `TestSafeFunctionFilter_VariableNameNotDropped`（planner）—— SH-06 的 P3 回归。
- `TestNullDeref_GlobalFieldReturnIsNullable`（planner，inline 源）—— ND-07 的 null-deref 回归。

## Phase 15 — memory-leak 容器逃逸误报修复（2026-10 新增）

`findEscapeLines` 的 pointer_expression 分支曾把 `*container = p`（container 本身是
malloc 分配）无条件判为 `p` 的 escape。但只有当 container **自身**逃逸（被 return /
存入非 local / 交给 escape 函数）时，`p` 的所有权才随之转移；若 container 最终只被
`free(container)`，其成员 `p` 并未释放，`p` 真泄漏会被静默抑制。

| # | 文件 | 行 | 场景 |
|---|------|----|------|
| ML-05 | p15_container_escape_fp.c | 28 | `pchBuf=malloc(100); *pduInfo=pchBuf; return pduInfo` —— 缓冲区写入堆容器后容器 return 转移所有权，不泄漏 |
| ML-06 | p15_container_escape_fp.c | 24 | `pduInfo=malloc(sizeof(char*)); return pduInfo` —— 容器本身通过 return 转移所有权，不泄漏 |

两条均为 `expect: no_finding`。注意行号须按 sink 实际行填写（ML-05=28、ML-06=24），
validator 容差 ±3，写错行会使 no_finding 守卫完全失效。

## Phase 16 — divide-by-zero 非零源除数误报修复（2026-10 新增）

`RangeFilter` 之前只做 function-local 区间传播，对「结构体字段从非零返回函数赋值」
（`graph->gran_time = nlog_get_gran_time_by_flag(...)`）和「全局变量从非零常量赋值」
（`g_thread_count = 4`）这类跨函数非零源不变量无法识别。`global_invariants`
补上非零源赋值扫描 + RangeFilter 的 field-chain invariant 检查后，这两类除数被正确
dismiss。

| # | 文件 | 行 | 场景 |
|---|------|----|------|
| P16-01 | p16_nonzero_source_divisor_fp.c | 32 | `offset / graph->gran_time` —— gran_time 由始终返回 60 的 `nlog_get_gran_time_by_flag` 赋值，field-chain invariant dismiss |
| P16-02 | p16_nonzero_source_divisor_fp.c | 42 | `index % g_thread_count` —— g_thread_count 初始化为非零且只被非零常量赋值，全局 invariant dismiss |

两条均为 `expect: no_finding`。注意：全局变量必须**初始值也非零**才可安全 dismiss ——
若写 `static uint32_t g = 0; g = 4;`，g 在 init 前可为 0，是真除零，`global_invariants`
按「存在任何可能为 0 的来源即不标非零」保守保留为候选（见
`TestGlobalInvariants_ZeroInitNotSuppressed`）。行号须按 sink 实际行填写（P16-01=32、
P16-02=42）。


## Phase 17 — 补齐三个零覆盖 contract 类型（2026-10 新增）

`--coverage` 之前把 `argument-type`（CWE-686）、`data-representation`（CWE-843）、
`implicit-contract`（CWE-20）列为**零覆盖**：这三个类型有 detector、有 skill、有
planner 过滤链，却没有任何 ground truth 用例，等于「召回与精度都未被验证」。
Phase 17 用 `src/p17_contract_types.c` 给每类补 2 个 finding + 2 个 no_finding。

| # | 类型 | 行 | 场景 | 期望 |
|---|------|----|------|------|
| P17-01 | argument-type | 31 | `p17_sink_u32((uint32_t *)&flag)`：`bool`(1B) 对象被当 `uint32_t`(4B) 读 | finding |
| P17-02 | argument-type | 36 | `p17_sink_u64((uint64_t *)&n)`：`uint32_t`(4B) 对象被当 `uint64_t`(8B) 读 | finding |
| P17-03 | argument-type | 41 | `p17_sink_u32((uint32_t *)&n)`：int32/uint32 同尺寸整数重解释，合法边界 | no_finding |
| P17-04 | argument-type | 46 | `p17_sink_void((uint32_t *)&flag)`：`void *` 形参是合法泛型边界 | no_finding |
| P17-05 | data-representation | 67 | `qsort(char buf[], sizeof(char), cmp_ptr)`：char 元素被 comparator 当 `char *` 读 | finding |
| P17-06 | data-representation | 73 | `bsearch(needle, char buf[], sizeof(char), cmp_ptr)`：bsearch base 元素同样是 char | finding |
| P17-07 | data-representation | 78 | `qsort(char *arr[], sizeof(char *), cmp_ptr)`：元素本身就是 `char *`，表示一致 | no_finding |
| P17-08 | data-representation | 83 | `qsort(char buf[], sizeof(char), cmp_scalar)`：标量 comparator 与 char 元素一致 | no_finding |
| P17-09 | implicit-contract | 109 | `p17_contract_partial_guard`：`flag != 0` 路径 null-check，`flag == 0` 路径无守卫解引用 | finding |
| P17-10 | implicit-contract | 121 | `p17_contract_direct_counted`：直接字段下标在 count 循环内无守卫解引用（部分守卫） | finding |
| P17-11 | implicit-contract | 132 | `p17_contract_fully_guarded`：null 守卫支配该解引用，planner guard-dominance 过滤丢弃 | no_finding |
| P17-12 | implicit-contract | 142 | `p17_contract_written_in_scope`：字段在函数内被写，function-controlled，不产生候选 | no_finding |

六条 `no_finding` 都是**确定性抑制**，不是靠 AI 研判放水：argument-type 的同尺寸/
`void *` 在 `compatibleObjectTypes` 直接过滤；data-representation 的 depth 相等在
detector 直接跳过；implicit-contract 的 fully-guarded 被 planner 的
`ContractGapFilter` 守卫支配性分析丢弃、written-in-scope 被 `writtenFields` 排除。
因此这四条在候选阶段就看不到条目，validator 不会出现「无候选 → 误判 PASS」的假阳性
守卫（`no_finding` 的语义是「result.sarif 同类型同位置没有 finding」，与候选存在与否
无关；这里额外保证了候选也不存在，避免浪费 AI 复核预算）。

> 行号以 `src/p17_contract_types.c` 当前内容为准（validator 容差 ±3）。改动该 fixture
> 的任何一行后，务必同步本表与 `expected-results.json` 的 `line`，否则 no_finding
> 守卫会因行号漂移而失效（Phase 15 的教训）。

## Phase 18 — P1 调用点实参普查 / 净化 kill 回归（2026-10 新增）

P1（调用点实参聚合）改变了非 static 函数形参 sink 的保守语义：planner 现在对每个
(callee, param) 做树内调用点实参普查（callsite census，`callsites@N:K-literal,J-var`
token），并识别 basename / strrchr(p,'/') 的路径净化。语义变更的三条影响：

1. **FS-01..03 重定性为 no_finding**：非 static + 树内调用点全部传编译期常量且未被
   取地址 → pipeline gate drop。旧行为（保守播种 → AI 一律 confirmed）在 SSL-VPN
   生产扫描中把 `svn_output_dbg` 类 wrapper 全部误 confirmed，是 P1 的直接动因。
   封闭程序内全字面量调用的形参 sink 不可利用；"变量调用点"的正样本防线由 FS-05
   （parser.c:45，调用点传变量）与 P18-02 继续守卫。
2. **零树内调用点不 gate**：外部 TU 仍可能调用（与所有 reachability filter 的
   scan-tree 边界假设一致）——P18-02 的 wrapper 同族对照。
3. **净化 kill 只作用 path-traversal**：basename / strrchr(p,'/') 派生段不含目录
   组件，但格式指示符仍在（format 流不 kill）。

| 用例 | 类型 | 行 | 形态 | expect |
|------|------|----|------|--------|
| P18-01 | format-string | 24 | `cs_log_wrapper`：非 static wrapper，树内 2 个调用点全字面量 → gate drop | no_finding |
| P18-02 | format-string | 30 | `cs_log_var`：同族 wrapper，但存在 `getenv` 污点调用点 → census 保留 + taint promote | finding |
| P18-03 | path-traversal | 43 | `fopen(basename(user_path))` → 净化 kill | no_finding |
| P18-04 | path-traversal | 46 | `fopen(strrchr(user_path,'/') + 1)` → 净化 kill + 尾部整型指针算术 sink 解析（taintLocKey `seg + 1` → `seg`） | no_finding |
| P18-05 | path-traversal | 35 | `cs_open_config`：非 static path wrapper，树内调用点全字面量 → gate drop | no_finding |

四条 `no_finding` 同样是**确定性抑制**（gate drop / sanitize kill 在候选阶段发生），
不依赖 AI 研判。P18-02 走 paramTainted promote 的 auto-confirm 路径，pipeline 阶段
即写入 findings，无需 AI 复核。

> 行号以 `src/p18_callsite_census.c` 当前内容为准（validator 容差 ±3）。

## Phase 21 — unchecked-return 消费点普查误报修复（2026-10 新增）

IDM 生产环境 AI 复核报告 unchecked-return (CWE-252) 25/25 全误报。三个根因与对应修复：

1. **消费门槛错档**：旧 `indirectGuardedVars` 要求"消费调用的结果被检查 **OR**
   callee 返回 void"，报告模式 A（`(void)filter_add(f, x)` 丢弃结果 + int 返回）
   两条都不满足。修复：消费通道分档 —— 结果被检查 → callee 必须 NULL→失败暴露
   （nullReject，极性陷阱保持报告）；结果被丢弃或 void → callee 只需不解引用 NULL
   （paramNullSafe）。
2. **cast 别名守卫不可见**：`filter_t *ft = (filter_t *)f; if (ft == NULL) return -1;`
   对参数 f 的守卫旧摘要看不见。修复：paramAliases（绑定全一致才算别名）。
3. **字段逃逸无建模**：`para->user_filter = import_strdup(...)` 的判空在下游共享校验
   函数里。修复：fieldNullChecks 摘要（顶层判空 + 失败早退的字段路径集合）。

paramNullSafe = 入口早退（nullReject）∪ 体内正守卫全包裹解引用；零守卫零解引用的
转存（值逃逸）刻意不算。消费点普查为 **AND 语义**：任一不安全消费（直接解引用、
无守卫 callee）保留事件。

| ID | 文件 | 行 | 期望 | 说明 |
|----|------|----|------|------|
| UR-01 | p21_consumer_census_fp.c | 137 | no_finding | 模式 A2：int 消费全丢弃，入口守卫（cast 别名）/正守卫 |
| UR-02 | p21_consumer_census_fp.c | 146 | no_finding | 模式 4.1：void/int 混合消费全 NULL 防御 |
| UR-03 | p21_consumer_census_fp.c | 159 | no_finding | 模式 4.2：字段逃逸 + 下游共享校验 |
| UR-04 | p21_consumer_census_fp.c | 172 | finding | 真阳性控制组：分配结果直接解引用 |
| UR-05 | p21_consumer_census_fp.c | 180 | finding | census AND 负控：一安全消费 + 一直接解引用 |
| UR-06 | p21_consumer_census_fp.c | 197 | finding | 值逃逸负控：无守卫转存全局 |
| UR-07 | p21_consumer_census_fp.c | 212 | no_finding | void 消费 + 体内正守卫全包裹解引用 |

UR-01/02/03/07 在**检测器层**抑制（不发事件），不依赖 AI 研判；UR-04/05/06 保持
candidate（contract@unknown，`_new`/`strdup` 名字启发式）交 AI 研判。单测防线：
`TestUncheckedReturn_ConsumerCensus`（fixture `tc_unchecked_return_consumer_census.c`，
19 函数逐一断言），间接守卫极性陷阱由既有 `TestUncheckedReturn_IndirectGuard` 保持。

> 行号以 `src/p21_consumer_census_fp.c` 当前内容为准（validator 容差 ±3）。

## Phase 22 — null-deref 三类误报修复（2026-10 新增）

生产环境 AI 复核报告 null-deref (CWE-476) 6 项误报（R1×4 / R2×1 / R3×1）。
三个根因与对应修复：

1. **R1 短路守卫行**：`p == NULL || !p->field` 右项解引用发生在守卫条件行
   本身（短路求值保证右操作数仅在 p 非空时求值），而 `paramUnguarded` 的
   守卫区间从 if 行 +1 起，被误判 unguarded → 调用点合成 DEREFERENCE 事件。
   修复：evidence 层短路分析（`||` 右项继承左项 NullCheckedVars、`&&` 右项
   继承左项 GuardedNonnullVars、`?:` 两分支分别继承条件真/假向事实）。
2. **R2 条件非空 getter**：`if (x == NULL) return NULL; return &x->f;` 的
   返回值仅当实参为 NULL 时才可空，`callResultNullSources` 却为 `p = f(x)`
   无条件合成 null source。修复：实参事实记录（六形态分类，不透明形态
   fail-open）+ `retNullGuardContract` paramNullOnly 契约——调用点实参自身
   已判空守卫（无 reaching null source）→ 候选消除。
3. **R3 守卫互斥**：strip 类函数 NULL 路径 = 入参 NULL 检查 + `strlen(p) >= len`
   溢出检查；调用点 `strlen(arg) != 0 && lhs == NULL` 早退守卫与溢出路径互斥
   （溢出蕴含 strlen(arg) >= len > 0，守卫必先命中）→ 残余路径 lhs 非空。
   修复：`retNullGuardContract` 溢出契约（overflowArg/overflowLen）+
   `overflowGuardMutex` 调用点互斥验证。

| ID | 文件 | 行 | 期望 | 说明 |
|----|------|----|------|------|
| P22-01 | p22_null_deref_fp.c | 130 | no_finding | R1：`p == NULL \|\| !p->field` 短路守卫调用点 |
| P22-02 | p22_null_deref_fp.c | 143 | no_finding | R2：实参判空守卫内调用条件非空 getter |
| P22-03 | p22_null_deref_fp.c | 157 | no_finding | R3：strip + strlen 合取守卫互斥 |
| P22-04 | p22_null_deref_fp.c | 163 | finding | TP-1 真阳性控制组：id 范围 getter（NULL 依赖越界而非参数 null 检查）无守卫消费 |
| P22-05 | p22_null_deref_fp.c | 177 | finding | TP-2 真阳性控制组：全局状态 getter（无参数）相邻函数判空不一致 |
| P22-06 | p22_null_deref_fp.c | 187 | finding | TP-3 真阳性控制组：布尔分支 is_all 绕过判空守卫 |

P22-01 在**检测器层**抑制（evidence 不发事件），P22-02/03 在 **planner 层**
dismiss（filter_nullable_source 契约判定），均在 AI 研判之前，不依赖候选
质量。三条抑制均为确定性逻辑；真阳性控制组防止为降误报而整体关停或过度
放宽。单测防线：`TestInterproceduralShortCircuitGuardedParam`（evidence 层
R1 正反例）+ `TestNullDerefGuardContracts`（planner 层 R2/R3 契约正反例 +
TP 控制组 + ND-16 `id == 0` 守卫回归控制组 use_zero_cfg——`pureNullCheckVar`
收紧后 id 范围 getter 不得被误认 paramNullOnly 契约）。

> 行号以 `src/p22_null_deref_fp.c` 当前内容为准（validator 容差 ±3）。

## Phase 23 — 不完整类型信息 null-deref 检测能力增强（2026-10 新增）

生产打回：参数使用第三方 typedef（`Nac_LdapSearchAckMsg_t` 等类型定义不在扫描树内、
项目不要求编译成功）的函数 `import_dn_group_tree_refresh` 产出**零** null-deref 候选。
逐层定位结论：**语法层完全正常**（tree-sitter 对未知 typedef 容错，函数体全部语法
节点恢复、sink 事件齐全），断链在 **null source 播种层**的两条通道：

1. **参数方向**：参数可空性只由 caller_null 检测器从**树内调用点**合成；调用点在
   扫描树外（导出 API / 注册回调）时参数无任何可空性建模。
2. **字段读方向**：`tree = (ldap_usrgroup_node_t *)(resp->group_data)` 的字段值
   可空性（外部结构体的成员契约不可见）无播种通道；链式解引用
   `para->orig->base_dn` 的中间层字段值同样无建模。

修复为两条 **fail-open 播种通道**（全部 suspected 级交 AI 研判，绝不 auto-confirm，
守卫 kill 与非空重赋值 kill 由 planner 既有 guard/non-null 机制统一处理）：
**第二轮补充（树内调用点形态）→ 第三轮重建（调用链开放性 fixpoint）**——第二轮的
「unsafe 调用点 + 类型不可见即播种」在生产现网引爆（null-deref 候选 ≤160 → 1264）：
C 惯例是外层入口判空一次、内层按非空契约直接用，转发链每层实参都"未证明非空"，
该判定等于逐层全播。第三轮以**调用链开放性 fixpoint** 取代：参数可空当且仅当
possibly-null 值真实可达——literal NULL witness（definite）/ 树内零调用点且外部
可调用的开放入口（仅类型布局不可见参数：前向声明 typedef 与未知 typedef；布局
可见类型维持 v0.9.4 契约闭合）/ 转发边传播 caller 自身未守卫参数的开放性；
**守卫在链上任一层即截断整条链**（所有调用方都防护的参数严格不报）；
纯转发参数（体内无解引用/转存消费）不播种（链收敛到解引用处一条）。

- **opaque_param**：非 static 函数 + 树内零调用点（含取地址豁免、main 豁免）+
  指针参数 + 体内有解引用 → 入口播种 assumed source。
- **opaque_field_read**：字段读的 base 参数类型**树内无定义**（未知 typedef/struct，
  基础类型白名单除外）→ 赋值转存（`p = base->f`，cast/下标变体均可）在赋值行播种；
  链式中间层（`base->f1->f2` 读 `base->f1` 字段值）在函数头播种（birth 形态，
  planner 转入 entry seed）。树内已定义类型维持既有行为（字段值流属另一分析层）。

| ID | 文件 | 行 | 期望 | 说明 |
|----|------|----|------|------|
| P23-01 | p23_opaque_type_null.c | 48 | finding | 报告原帖形态（树内调用点版）：转发未证明 + resp 类型不可见 → caller_null + opaque_param 双通道（caller-arg tier） |
| P23-02 | p23_opaque_type_null.c | 56 | finding | 报告原帖形态：tree = (T*)(resp->group_data) 转存后 tree[0].group_name 解引用（opaque_field_read） |
| P23-03 | p23_opaque_type_null.c | 52 | finding | 链式中间层：para->orig->base_dn 的中间字段值解引用（链式 opaque_field_read） |
| P23-04 | p23_opaque_type_null.c | 67 | no_finding | 守卫反例：opaque 参数入口判空早退 → planner guard kill fail-open source |
| P23-05 | p23_opaque_type_null.c | 72 | no_finding | 类型可见反例：树内 typedef + 树内调用点传 &kk → 两通道均不播种 |
| P23-06 | p23_opaque_type_null.c | 50 | finding | 树内调用点形态 para：opaque_param 阻断 onlyUnprovenCallerNullSources dismiss（caller-arg tier） |
| P23-07 | p23_opaque_type_null.c | 94 | no_finding | 体量守卫反例：同样未证明转发但 KnownRec_t 树内定义 → 不加播，dismiss 维持 |
| P23-08 | p23_opaque_type_null.c | 104 | no_finding | 守卫调用者反例：guarded_caller 判空后调用 → classifyArg safe → 无 source |
| P23-09 | p23_opaque_type_null.c | 123 | no_finding | 头文件定义类型反例：P23HdrRec_t 布局在无函数的 p23_header_type.h 可见 + 完整程序扫描 → 类型普查不得误判 opaque |
| P23-10 | p23_opaque_type_null.c | 129 | no_finding | 头文件定义类型反例：从可见类型参数读出的字段指针不得播种 opaque_field_read |

四条 finding 均为 **suspected 级**（fail-open 假设交 AI 研判外部契约，不进
auto-confirmed）：resp/para 走 `null@caller-arg`（detail 标注开放链来源：
witness / 转发链 / 开放入口三形态），para->orig/tree 走 `null@opaque-origin`。
单测防线：`TestOpaqueNullDetectorReportForm` / `TestOpaqueNullDetectorControls` /
`TestOpaqueNullDetectorInTreeCallerReportForm`（evidence 层播种形态、豁免域与
前向声明判定）+ `TestOpaqueNullEndToEndReportForm` / `TestOpaqueNullEndToEndControls` /
`TestOpaqueNullEndToEndInTreeCaller` / `TestOpaqueNullEndToEndAllCallersGuarded`
（planner 端到端红绿：tier/suspected 断言 + 守卫 kill + 非空重赋值 kill +
**全守卫链零候选的灵魂拷问负控** + 类型门控负控）。已知边界：全局变量来源的
opaque 字段读、树内语法 ERROR 吞掉的解引用（缺分号形态）不在覆盖内（后者属
解析层恢复问题，见 CHANGELOG）。

> 行号以 `src/p23_opaque_type_null.c` 当前内容为准（validator 容差 ±3）。

## Phase 24 — 未校验外部索引越界检测能力增强（2026-10 新增）

生产反馈：`maf_rbl` 的 `rbl_profile->svr[rbl_profile->actived_index]` 是
「固定长度数组成员 + 未校验外部配置索引」的教科书形态——`actived_index` 来自外部
配置/输入、入口未做范围校验，越界读到的元素内 `domain` 指针野化，`&svr[idx]` 传入
子函数后解引用 `svr->domain` 触发空指针解引用。**修复前该形态零候选**：OOB 检测
（`checkArrayOOB`）只报**可证明**的越界（常量索引 / 循环上界），未知字段索引既不
可证也不判危险；成员数组（`field_declaration` 里的 `array_declarator`）连容量都
解析不到（`findArraySize` 只认局部/全局 `declaration`），下标基址也被
`subscriptBaseIndex`（只认裸标识符）直接跳过。

修复为 `array_oob_read_unchecked` / `array_oob_write_unchecked` 两条**启发式**
（suspected）事件，交 AI 研判，绝不 auto-confirm：

- **播种条件（全部满足）**：下标基址是**结构体成员数组**且容量可解析（数字字面量
  或对象宏）；索引来自**结构体字段**（直接 `p->idx`/`p.idx` 或一层本地拷贝
  `unsigned idx = p->actived_index`，含 cast 形态）；函数内**没有**与容量相等的
  边界检查支配该访问（`field >= CAPACITY` 且出口，或 `field < CAPACITY` 正分支
  包裹访问；容量符号与数组声明的宏一致，用「更大上界」的伪守卫不算防护）。
- **体积守卫**：只认字段来源索引——普通形参/循环变量索引不播种（普通循环形态是
  C 代码的绝大多数，若播种即重演 null-deref 1264 候选的量级失控）；同一函数内
  相同 (数组, 索引字段, 读写) 的多次访问折叠为一条候选。
- **链条证据（CWE-125 → CWE-476）**：`elem_field` 记录从越界元素读出的指针成员
  （`svr[idx].domain`）；`escape`/`escape_deref` 记录元素（或其地址）逃逸到的子函数
  及该子函数解引用的指针成员（同文件可解析时给出 member@line）。Hint 四 token：
  `idx-src@` / `elem-field@` / `oob-escape@` / `cwe-chain@CWE-125→CWE-476`，AI 无需
  读源码即可给出完整链条与修复建议（入口 `if (idx >= CAP) return;`）。
- **一次 finding、两个 CWE**：越界是根因（可修），空指针是后果。按项目既有
  `ArrayOOBPrecedenceFilter` 的取向不重复上报后果 finding；链条以
  `cwe-chain@` token / 候选文件 `## Vulnerability Chain` 段 / 候选 SARIF
  `properties.cwe_chain` 三处机器可读导出，skill 要求 verdict 的 `reasoning`
  同时陈述两段 CWE。
- **路由**：读形态 `array_oob_read_unchecked` → out-of-bounds（CWE-125）；写形态
  `array_oob_write_unchecked` → buffer-overflow（CWE-787）。共享同一
  `BUFFER_ACCESS` 种子事件，由 `Categories` 分流。

| ID | 文件 | 行 | 期望 | 说明 |
|----|------|----|------|------|
| P24-01 | p24_unchecked_index_oob.c | 29 | finding | 生产形态越界读：`svr[idx].domain` + `&svr[idx]` 传入子函数（out-of-bounds suspected，携带 idx-src/elem-field/oob-escape 链条） |
| P24-02 | p24_unchecked_index_oob.c | 44 | finding | 写形态：`p->svr[p->actived_index].code = 7` 路由 buffer-overflow（写侧 CWE-787） |
| P24-03 | p24_unchecked_index_oob.c | 39 | no_finding | 修复对照：入口 `actived_index >= MAF_RBL_SVR_CFG_COUNT` 早退，容量符号相等 → 不播种 |
| P24-04 | p24_unchecked_index_oob.c | 50 | no_finding | 体量守卫反证：`for (i < MAF_RBL_SVR_CFG_COUNT) dst[i] = p->svr[i]` 循环变量索引 → 不播种 |
| P24-05 | p24_unchecked_index_oob.c | 56 | no_finding | 体量守卫反证：`p->svr[n]` 的 n 是普通形参（非字段）→ 不播种 |
| P25-01 | p25_header_split_oob.c | 11 | finding | 生产现网形态（结构体在 p25_header_split.h、函数在 .c）：`svr[rbl_profile->actived_index]` 越界读 + `&svr[idx]` 传入子函数（CWE-125→CWE-476） |
| P25-02 | p25_header_split_oob.c | 23 | no_finding | 修复对照（头文件拆分版）：入口 `actived_index >= MAF_RBL_HDR_CFG_COUNT` 早退 → 不播种 |

单测防线：evidence 层 `TestUncheckedIndexReadReportForm`（播种形态 + 容量宏 +
链条证据）/ `TestUncheckedIndexGuardedControl`（入口检查零候选）/
`TestUncheckedIndexGuardShapes`（`>=` / `>` / `<` / `<=` 四种守卫惯用法全部抑制，
且「上界大于容量」的伪守卫不抑制）/ `TestUncheckedIndexParameterIndexControl`
（形参/循环/常量索引零候选）/ `TestUncheckedIndexWriteCategory`（写形态路由）；
planner 端到端
`TestUncheckedIndexOutOfBoundsEndToEnd`（单候选 + suspected + Hint 三 token +
VerdictFacts 链条）/ `TestUncheckedIndexGuardedEndToEnd` /
`TestUncheckedIndexOrdinaryShapesEndToEnd` / `TestUncheckedIndexWriteRoutesToBufferOverflow`。
已知边界：索引经跨函数传递（调用方把未校验字段作为形参传入被调方）不在本通道内
——候选收敛到字段读取处，避免逐调用点重复；成员数组的常量/循环越界证明仍走
`array_oob_read` 的既有证明通道（当前只覆盖裸数组，属后续增强）。

> 行号以 `src/p24_unchecked_index_oob.c` 当前内容为准（validator 容差 ±3）。

## 检测器缺口（2026-10 盘点，本轮已全部闭环）

三条 open gap 已回源定位到具体 detector/filter 并修复。结论：**都应在现有 CWE 上增强，
不新增 vuln type / detector / skill**——新增只会把同一 CWE 拆成两套判据。

| ID | 类型 | 根因（已回源） | 本轮修复 | 回归 |
|----|------|----------------|----------|------|
| RL-13 | resource-leak (CWE-404) | `mkstemp` 在 `apikb.SafeFunctions`（临时文件竞态安全），`SafeFunctionFilter` 把整个 acquire 丢弃；但 fd 生命周期与「临时文件名安全」是两回事 | resource-leak 事件补 `category: resource_acquire`；`SafeFunctionFilter` 对该 category 放行（`IsSafeWrapper` 仍可 dismiss） | `TestSafeFunctionFilter_ResourceAcquireNotDropped` + RL-13 实跑 |
| PH1-01 | integer-overflow (CWE-190) | ① fixture 两个形参都是 `size_t`，LP64 下乘积 64 位、不会溢出（ground truth 平台歧义）；② `sizeCalcExprs` 的 narrow-product 守卫拿 `product < 2^64` 判安全，但 C 的乘法按操作数**公共类型**求值——两个 `uint32_t` 在 32 位就回绕，`uint16_t` 提升到 `int` 后也可能溢出 `INT_MAX` | ① fixture 改为 `unsigned int`（保持行 110）；② 守卫按公共类型上限判定（`uint8×uint8` / `uint8×uint16` 可 suppress；`uint16/uint32` 不可） | `TestIntegerOverflow_SizeofProduct`（新增 8/16/32 位四例）+ PH1-01 实跑 |
| DF-05 | double-free (CWE-415) | detector 已有 call summary + 全局槽位聚合，但没有「callee 条件释放参数」的 may-free summary；`main` 里 `release_entry(e1)`（`if (ref_count <= 0)` 才 free）已释放的槽位被 `cleanup_entries()` 再次 free，跨函数不可见 | summary 增加 `ParamMayDirectFrees`/`ParamMayFieldFrees`；全局槽位释放事件带 `may_free`；候选保持 `suspected`（`DoubleFreeFilter` 不因 may-free 升级 confirmed），证据/Hint 明确 `may-free` | `TestDoubleFree_GlobalSlotMayFree` + DF-05 实跑 |

**决策规则（以后遇到同类缺口）**：CWE 已注册、且 pipeline 已能为该缺陷的某些形状产
seed → **增强现有 detector/filter**，不新增 vuln type。只有出现新 CWE 类，或需要独立
研判策略/skill 时，才走 `ADDING_A_VULN_TYPE.md` 的 6 步流程新增类型（同时要过
`TestVulnTypeSkillConsistency` 与 `TestConfirmedTierPolicy` 两个守卫）。

## Phase 26 — 第三方库 API 语义模型回归（2026-10-22 新增）

`docs/secguard-clang支持第三方库函数.md` 首批清单的端到端回归：模型
（`sgre/internal/apikb/external_api.go`）为 libxml2 / cJSON / libc 扩展 API 建立
分配/释放/所有权/可空性四维独立语义，memory-leak 与 null-deref 检测器经既有
`IsDeclaredAllocator` / `IsDeclaredDeallocator` / `IsKnownNullableReturn` /
`IsEscapeFunction` 查询通道消费（不新增 vuln type / detector / skill）。

| ID | 语义 | 期望 |
|----|------|------|
| P26-01 | xmlReadMemory 的 xmlDoc 从不释放也从不转移 → definite 泄漏 | finding |
| P26-02 | xmlReadMemory + xmlFreeDoc 正确配对 | no_finding |
| P26-03 | xmlXPathEvalExpression 的结果对象交给 xmlXPathFreeContext（族错配，释放被拒） | finding |
| P26-04 | cJSON_CreateString 的 item 经 cJSON_AddItemReferenceToObject 添加引用（不转移）且从不 Delete | finding |
| P26-05 | cJSON_Parse + cJSON_Delete 正确配对 | no_finding |
| P26-06 | asprintf 失败早退（`< 0` 守卫）不算泄漏证据 + 成功路径 free | no_finding |
| P26-07 | xmlDocGetRootElement(doc)->name 未判空解引用（可空借用） | finding |
| P26-08 | cJSON_Parse/GetObjectItem 全链判空 | no_finding |

干净目录 A/B（独立 `--db`，CWD=/tmp）：基线 memory-leak 对 P26 全漏报（0/3）、
P26-07 仅为弱证据 suspected 候选；新二进制 4 条 finding 全部检出（3 泄漏
auto-confirmed + 1 null-deref auto-confirmed），候选池 78→76（-1 条 asprintf
失败早退误报修复、-1 条 P26-07 升级出候选池），**post-only 候选为空（零新增
误报）**。P26-01..08 的行号以 `src/p26_external_api_semantics.c` 当前内容为准
（validator 容差 ±3）。注意：A/B 对照必须每轮独立 `--db` 且在干净 CWD 跑——
共享 DB 的第二轮会受第一轮 findings/events 影响（p23/concurrency 曾出现假漂移）。

### Phase 26b — 用户标准 cJSON 用法形态（2026-10-22 追加）

`src/p26b_cjson_lifecycle.c`：用户提供的三个权威形态——标准用法 main
（Create→挂接（失败分支删除）→Print→cJSON_free(json)→Delete(root)，P26-09
no_finding）、借用 item 单独 Delete（P26-10，**free-on-borrow 新通道**：借
用指针（cJSON_GetObjectItem/strstr/getenv 的返回）被释放器调用 → invalid
free/UAF 风险，suspected 候选交 AI，hint `free-on-borrow@<releaseAPI>` +
verdict fact；**不进 ground truth**——validator 只读 verdict 阶段
result.sarif，suspected 候选不在其中，由 tc160 单测锁定）、Detach 正反例
（P26-11 正例 no_finding / P26-12 脱离后不删 definite 泄漏 finding；
`cJSON_DetachItemFromObject/CaseSensitive/FromArray` 建模为 AllocRet——脱离后
归调用方，root 的 Delete 不再覆盖）。A/B（HEAD 基线 vs 本轮）：候选 76→77
（post-only 恰为 P26-10 一条预期新增），auto-confirmed 143→144（+1 =
P26-12），pre-only 为空。


### Phase 27 — 用户 cbwl_tbl.c UAF 样例回归（2026-10-22 追加）

`src/p27_uaf_conditional_release.c`：用户五步审计法的 PATTERN-02（释放后间接
访问）+ PATTERN-07（宏展开隐式 UAF）形态——wrapper 释放
（cbwl_tbl_destory，跨函数释放经 FuncSummary）后使用点经宏 cbwl_nodeinfo
包装（展开为 cbwl_dfx_node_info 解引用 node->key）。P27-01（must 变体，
wrapper 体内无条件 free）为 finding：跨函数释放 summary 直达 + 宏使用点
call 参数 → confirmed 候选（使用点在宏内触发 macro-context 门控，交 AI
复核，非纯 auto-confirm）；P27-02 为用户修复方案对照（先日志后释放）→
no_finding。**防御式条件释放变体**（`if (node != NULL) free(node)`——用户
样例的真实形态）为 may-free suspected 候选：本轮新增 UAF may-free 通道
（findAllFreeSites 消费 ParamMayDirectFrees、事件带 may_free、
LifetimeFilter 对 may 不升 confirmed——对齐 double-free 的 MayFree 先例），
修复前该形态**完全漏报**（红→绿由 tc_uaf_conditional_release_use.c 单测
锁定，suspected 级不进 ground truth）。A/B（HEAD vs 本轮）：候选 78→78、
auto-confirmed 145→145、双向差集均空（benchmark 全量零回归；增量全部由
单测矩阵承载）。