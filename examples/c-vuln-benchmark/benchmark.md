# FP Verification Benchmark — 误报消减基准测试

> 验证多层过滤收敛管道的精度和召回率。
> Ground truth 定义在 [expected-results.json](expected-results.json) 中（每个用例带机器可读的 `expect` 字段）。
> 门禁脚本 `scripts/validate-benchmark.py` 读 SARIF（v0.3.0 起），按 (文件, 行) 交叉比对并计算 precision/recall。
>
> ```bash
> secguard scan --db /tmp/sgbench.db examples/c-vuln-benchmark/src
> python3 scripts/validate-benchmark.py \
>   --sarif .codeagent/zhuque-secguard/scans/latest/sarif.sarif \
>   --expected examples/c-vuln-benchmark/expected-results.json
> ```
>
> **历史 detector 覆盖缺口（已闭环）**：`PH1-01` 整数溢出 `malloc(count * obj_size)` 与 `PH1-06` 注册表凭据 `RegSetValueExA` 曾未被 detector 捕获，现均已产出候选。

## 测试规模

| 指标 | 数值 |
|------|------|
| 源文件 | 16 |
| 总测试用例 | 35 |
| Phase 0（P0-P3/TP） | 18 |
| Phase 1（CWE-190/362/798/667/327） | 12 |
| Phase 2（扩展典型漏洞） | 4 |
| Phase 3（CWE-476 sizeof FP 抑制） | 1 |
| 应完全不产生 Finding (P0: Detector EXCLUDE) | 7 |
| 应产生 Finding 但被 P1 抑制 | 3 |
| 应产生 Finding 但被 P2 抑制 | 4 |
| 应产生 Finding 且 P3 confirmed (真阳性) | 2 |
| 应产生 Finding 且 P3 suspected (需人工确认) | 2 |
| Phase 1 confirmed | 9 |
| Phase 2 confirmed | 4 |
| **总误报应消减数** | **14** |
| **最终 Certified Finding（全 34 用例）** | **17** |

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

### Phase 3 — null-deref sizeof 伪解引用（本轮新增）

| # | 文件 | 行 | 检测器 | 反证 | 期望 |
|---|------|----|--------|------|------|
| ND-01 | null_deref_sizeof.c | 17 | null-deref (CWE-476) | `sizeof(node->value)` 是编译期类型表达式，非运行时解引用 | no_finding |

**说明**：`sizeof(p->field)` / `sizeof(p[0])` 对可能为 NULL 的指针求值不会在运行时解引用，
故 `sizeof_pseudo_deref` 过滤规则（null-deref 链第一级）必须抑制该候选。此用例把这条
站点级规则锁进基准门禁，防止后续重构破坏它。

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

```bash
# 1. 扫描（用独立 DB 避免历史索引污染；stdout 只打印摘要）
secguard scan --db /tmp/sgbench.db examples/c-vuln-benchmark/src

# 2. 校验（validator 读 SARIF，按 (文件, 行) 交叉比对 ground truth）
python3 scripts/validate-benchmark.py \
    --sarif .codeagent/zhuque-secguard/scans/latest/sarif.sarif \
    --expected examples/c-vuln-benchmark/expected-results.json
```

## v0.3.0 新增基线（硬骨头场景）

| 文件 | 覆盖 | 状态 |
|------|------|------|
| `p8_value_analysis.c` | 值分析/区间域：`n*sizeof(T)`、`n*m`、`calloc(n,m)`、`n+1`、`n*4`、守卫常量传播 | ✅ 已纳入（P8-01..06） |
| `p9_secure_func.c` | Annex K `_s` 契约：memcpy_s/strcpy_s 说谎 size、约束违约、scanf_s 逐转换宽度 | ✅ 已纳入（P9-01..05） |
| `p10_interproc_taint.c` | 1-CFA 形参敏感：passthrough、多级 passthrough、链式形参污点 | ✅ 已纳入（P10-01..04） |
| `p7_graph_effect.c` | 语义图消费：污点 source→sink、free→use CFG、别名、所有权转移 | 🚧 已落盘，use-after-free 用例需用 `*p` 而非 `p[0]`（检测器暂不支持下标解引用），待修后纳入 |

> **v0.3.1 修复**：全管线漏报（`busy_timeout` 参数未生效 → 并行 detector 写事件
> 静默丢失）与 scope-leak（scan 子目录候选泄漏到目标之外）已修复。新增 15 例
> （P8/P9/P10）全绿。
>
> **遗留（存量漂移，非本轮引入）**：`P2-04`/`P3-01`/`PH1-03`/`P6-06`/`P6-08`
> 五例因代码演进与 expected-results 未同步而 FP/FN，待单独对齐。
