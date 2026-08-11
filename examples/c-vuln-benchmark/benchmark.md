# FP Verification Benchmark — 误报消减基准测试

> 验证 FEATURE-003 三轮验证管道的精度和召回率。
> Ground truth 定义在 [expected-results.json](expected-results.json) 中。
> **当前状态: INVALID / 不可作为发布门禁。** 源码演进后行号锚点已漂移。已修复 detector ID 引用（web.sql-injection → injection.command_injection; concurrency.race-condition → concurrency.lock; memory.buffer-overflow → memory.buffer_overflow; memory.memory_leak → memory.leak）。P2-03 对未知 `void *dst` 容量也不能证明安全。先运行 `scripts/validate-benchmark.py` 修复基线，再计算 precision/recall。

## 测试规模

| 指标 | 数值 |
|------|------|
| 源文件 | 7 |
| 总测试用例 | 18 |
| 应完全不产生 Finding (P0: Detector EXCLUDE) | 7 |
| 应产生 Finding 但被 P1 抑制 | 3 |
| 应产生 Finding 但被 P2 抑制 | 4 |
| 应产生 Finding 且 P3 confirmed (真阳性) | 2 |
| 应产生 Finding 且 P3 suspected (需人工确认) | 2 |
| **总误报应消减数** | **14** |
| **最终 Certified Finding** | **4** |

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
| P0-01 | p0_safe_functions.c | 24 | `memcpy_s(dst, sizeof(dst), ...)` | `memcpy_s\(dst,\s*sizeof\(dst\)` |
| P0-02 | p0_safe_functions.c | 28 | `strcpy_s(dst, sizeof(dst), ...)` | `strcpy_s\(dst,\s*sizeof\(dst\)` |
| P0-03 | p0_safe_functions.c | 32 | `sprintf_s(dst, sizeof(dst), ...)` | `sprintf_s\(buf,\s*sizeof\(buf\)` |
| P0-04 | p0_safe_functions.c | 36 | `strcat_s(dst, sizeof(dst), ...)` | `strcat_s\(dst,\s*sizeof\(dst\)` |
| P0-05 | p0_safe_functions.c | 44 | `snprintf + sizeof + 返回值检查` | `snprintf\([^)]*sizeof\([^)]*\).*\n.*if\s*\(.*written` |
| P0-06 | p0_safe_functions.c | 65 | `execve("/bin/ping", argv, NULL)` | `execve\(` |
| P0-07 | p0_safe_functions.c | 94 | `sqlite3_prepare_v2 + sqlite3_bind_text` | `sqlite3_bind_text\|PreparedStatement` |

**期望**: 0 Finding。若 regex 回退精度不足产生 Finding → P2 应作为第二防线抑制。

---

### P1 — Semantic Verification (项目安全框架)

这些用例使用项目自定义的安全包装，Detector 会产出 Finding，但 P1 应识别安全框架并 exempt。

| # | 文件 | 行 | 触发 Detector | 安全机制 | P1 期望 |
|---|------|----|-------------|---------|--------|
| P1-01 | p1_safecopy_wrapper.c | 24 | memory.buffer_overflow | SafeCopy_copy 保证 bounds_checked | **exempted** |
| P1-02 | p1_safecopy_wrapper.c | 31 | memory.buffer_overflow | SafeCopy_strcpy 保证 bounds_checked | **exempted** |
| P1-03 | p1_safequery_wrapper.c | 38 | injection.command_injection | SafeQuery 保证 prepared_statement | **exempted** |

**期望**: 3/3 Finding → P1 exempted → dismissed.

---

### P2 — Counter-Evidence Hunt (反证搜寻)

这些用例看起来像漏洞，Detector 会产出 Finding，P1 no_exemption，但 P2 应找到反证。

| # | 文件 | 行 | 触发 Detector | 反证 | P2 期望 |
|---|------|----|-------------|------|--------|
| P2-01 | p2_raii_memory.c | 29 | memory.memory_leak | ResourceHandle RAII (构造分配+析构释放) | **counter_evidence_found** |
| P2-02 | p2_lock_guard.c | 40 | concurrency.lock | LockGuard mutex 守卫 | **counter_evidence_found** |
| P2-03 | p2_bounds_checked.c | 28 | memory.buffer_overflow | `if (user_len > MAX_MSG_SIZE) return` bounds check | **counter_evidence_found** |
| P2-04 | p2_bounds_checked.c | 41 | memory.buffer_overflow | `if (user_len >= sizeof(dst)) return` sizeof guard | **counter_evidence_found** |

**期望**: 4/4 Finding → P2 counter_evidence_found → dismissed.

---

### P3 — Edge Cases (裁决法庭)

这些用例有部分保护但不充分，P1 no_exemption + P2 counter_evidence_found 但保护不完整。P3 Court 应裁决为 suspected 或 confirmed。

| # | 文件 | 行 | 触发 Detector | 有保护但不充分 | P3 期望 |
|---|------|----|-------------|--------------|--------|
| P3-01 | p3_edge_case.c | 40 | injection.command_injection | is_safe_input 过滤分号但不防御 &&, \|\|, \$() | **suspected** |
| P3-02 | p3_edge_case.c | 60 | concurrency.lock | pthread_mutex_lock 保护了读取但 lock-unlock 间有 TOCTOU 窗口 | **suspected** |

**期望**: 2/2 Finding → P3 suspected → 保留在 Certified Finding 中标记需人工确认。

---

### TP — True Positives (真阳性对照)

这些是确实存在漏洞的对照用例，应通过全部三轮验证不被抑制。

| # | 文件 | 行 | 触发 Detector | 漏洞 | 期望 |
|---|------|----|-------------|------|------|
| TP-01 | p1_safecopy_wrapper.c | 62 | memory.buffer_overflow | `memcpy(buf, user_input, strlen(user_input))` 无 bounds check | P3 **confirmed** |
| TP-02 | p1_safequery_wrapper.c | 53 | injection.command_injection | `sprintf(query, "SELECT ... '%s'", username)` 字符串拼接 SQL | P3 **confirmed** |

**期望**: 2/2 Finding → P3 confirmed → Certified Finding.

---

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
# 1. 索引
secguardian-index --path examples/cpp-vuln-demo-no-answers/src \
  --output .codeagent/fp-test/index.json

# 2. 扫描 (AI Agent 执行 Detector)
/secguard examples/cpp-vuln-demo-no-answers/src

# 3. 验证管道 (AI Agent 执行 Step 3.5)
#    → 产出 dismissed.json + verification-audit.json

# 4. 对比 ground truth
diff <(python3 -c "
import json
with open('examples/cpp-vuln-demo-no-answers/expected-results.json') as f:
    expected = json.load(f)
# 提取期望的 dismissed/certified 数量
") <(python3 -c "
import json
with open('.codeagent/.../dismissed.json') as f:
    actual = json.load(f)
# 对比实际结果
")
```
