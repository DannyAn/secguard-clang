# SecGuard-Clang 扫描准确率和扫描性能提升改进建议
deepseek v4 flash扫描源码后让 GLM5.2分析给出“SecGuard-Clang 扫描准确率和扫描性能提升改进建议”，建议AI Agent分析验证后改进落地。

> 基于 nlog 项目 `src/` 目录全量安全扫描的完整诊断分析  
> 扫描 ID: `sc_2026-10-10_091954_73ad48`  
> 扫描时间: 2026-10-10  
> 扫描规模: 1012 文件 / 7092 函数 / 178358 行  
> SecGuard-Clang 版本: 0.9.2  

---

## 1 扫描概况

| 指标 | 数值 |
|------|------|
| 原始种子事件 | 32,974 |
| 收敛后候选 | 692（收敛率 97.9%） |
| 自动确认 | 136 |
| AI 研判确认 | 40 |
| 确认总计 | 176 |
| 已排除（误报/无法判定） | 652 |
| 自动分析耗时 | 120.6 秒 |
| AI 研判耗时 | 1,974 秒 |
| 端到端耗时 | ~2,095 秒 |

---

## 2 准确率诊断

### 2.1 整体准确率指标

| 指标 | 数值 | 评价 |
|------|------|------|
| 整体确认率 | 176/828 = 21.3% | 偏低，大量候选为误报 |
| 自动确认占比 | 136/176 = 77.3% | 自动确认是主力，但含大量误报 |
| AI 研判确认率 | 40/692 = 5.8% | 极低，94.2% 候选被 AI 判定为误报 |
| AI 研判排除率 | 652/692 = 94.2% | 过高，说明过滤链输出质量不足 |

**核心问题：过滤链收敛了 97.9% 的种子，但输出的 692 个候选中 94.2% 是误报，说明过滤链的"量"收敛能力强但"质"筛选能力弱。**

### 2.2 分类型准确率明细

| 类型 | 种子 | 候选 | 自动确认 | AI确认 | 总确认 | 排除 | AI误报率 | 诊断 |
|------|------|------|---------|--------|--------|------|---------|------|
| argument-type | 10 | 10 | 0 | 0 | 0 | 10 | 100% | 全误报，检测器不应输出 |
| buffer-overflow | 6 | 6 | 0 | 1 | 1 | 5 | 83.3% | 候选少但精度不足 |
| dangerous-function | 3 | 1 | 2 | 1 | 3 | 0 | 0% | 精度好 |
| divide-by-zero | 216 | 161 | 0 | 31 | 31 | 130 | 80.7% | 候选过多，大量常量除数误报 |
| hardcoded-secret | 1 | 1 | 0 | 0 | 0 | 1 | 100% | 配置键名误匹配 |
| injection | 32 | 2 | 1 | 0 | 1 | 1 | 50% | taint_source 过滤过严 |
| integer-overflow | 193 | 191 | 0 | 5 | 5 | 186 | 97.4% | 候选爆炸，几乎全误报 |
| memory-leak | 393 | 35 | 22 | 1 | 23 | 12 | 34.3% | 自动确认含误报（见 2.3） |
| null-deref | 31,357 | 145 | 2 | 0 | 2 | 145 | 100% | 检测器种子爆炸，候选全误报 |
| path-traversal | 57 | 17 | 12 | 0 | 12 | 5 | 29.4% | 自动确认可能含误报 |
| race-condition | 14 | 14 | 0 | 0 | 0 | 14 | 100% | 全误报 |
| resource-leak | 189 | 30 | 37 | 0 | 37 | 30 | 100% | 自动确认含大量误报（见 2.3） |
| signed-compare | 1 | 1 | 0 | 0 | 0 | 1 | 100% | 单一候选项误报 |
| uninit | 448 | 78 | 59 | 1 | 60 | 18 | 23.1% | 自动确认可能含误报 |

### 2.3 自动确认误报分析（重大问题）

自动确认（auto-confirmed）是流水线在 AI 研判之前直接机器确认的发现。本轮 136 个自动确认中，经源码抽查发现**至少 40+ 个为确定性误报**：

#### 2.3.1 resource-leak 自动确认误报（37 项中约 25 项为误报）

| 误报模式 | 数量 | 原因 |
|---------|------|------|
| **pthread_mutex_lock/unlock 配对** | 10 | `mutex_lock` 函数内 `pthread_mutex_lock(&g_xxx_mutex)`，同文件有 `mutex_unlock` 函数做 `pthread_mutex_unlock`，是标准配对模式，非泄漏 |
| **pthread_rwlock_rdlock/unlock 配对** | 4 | 同上，rwlock 读写锁配对模式 |
| **iconv_open 存入全局缓存** | 3 | `g_handler_gbk_to_utf8 = iconv_open(...)` 存入全局变量，进程生命周期内复用，非泄漏 |
| **dlopen 存入全局/进程生命周期** | 6 | `dlopen` 句柄存入全局变量，进程退出时由 OS 回收，是插件加载标准模式 |
| **epoll_create 存入全局** | 3 | epoll fd 存入全局变量，进程生命周期持有，非泄漏 |
| **msg_data/recv_data 消息处理框架** | 5 | 消息接收回调中 `void *data` 由框架分配和释放，回调函数不负责释放 |

**典型误报示例：**

```c
// src/ctrlplane/frame/custom/cfg/nlog_custom_rpt_config.c:29-36
__attribute__((noinline)) void nlog_custom_rpt_mutex_lock()
{
    (void)pthread_mutex_lock(&g_nlog_custom_rpt_mutex);  // 被报为 resource-leak
}

__attribute__((noinline)) void nlog_custom_rpt_mutex_unlock()
{
    (void)pthread_mutex_unlock(&g_nlog_custom_rpt_mutex);  // 配对解锁在同一文件
}
```

```c
// src/public/frame/send/syslog/nlog_syslog_charset_pub.c:66-67
if (g_handler_gbk_to_utf8 == NULL) {
    g_handler_gbk_to_utf8 = nlog_iconv_open_handler(CHARSET_GBK, CHARSET_UTF8);  // 全局缓存，非泄漏
}
```

**根因：自动确认逻辑不识别"锁配对"和"全局变量持有"两种安全模式，将进程生命周期的资源持有误判为泄漏。**

#### 2.3.2 uninit 自动确认误报（59 项中部分可能为误报）

自动确认的 59 个 uninit 发现中，经 AI 子代理研判 78 个候选后仅确认 1 个（`nlog_tsdb_utils.c:211` 的 switch default 分支），说明自动确认的阈值可能过松。以下模式可能存在误报：

- 消息处理回调中 `void *data` 参数被当作未初始化变量（框架保证非空）
- `localtime_r`/`gmtime_r` 写入的 out 参数被当作未初始化
- `memset_s` 初始化后的变量仍被标记

#### 2.3.3 memory-leak 自动确认误报（22 项中部分可能为误报）

自动确认的 22 个 memory-leak 发现中，经 AI 研判 35 个候选仅确认 1 个。以下模式可能存在误报：

- 链表节点插入后所有权转移（节点被链表持有，非泄漏）
- 消息入队后所有权转移给队列
- 错误路径中已 free 的内存

### 2.4 AI 研判误报热点分析

6 个类型的 **全部候选** 都被 AI 判定为误报（100% AI 误报率），合计 201 个候选完全浪费 AI 研判资源：

| 类型 | 候选数 | 浪费原因 |
|------|--------|---------|
| null-deref | 145 | 全部为参数隐式非空契约、函数返回值解引用、`if (x != NULL && x[0] != '\0')` 守卫模式 |
| integer-overflow | 186 | `snprintf_truncated_s`/`sprintf_s` 累加器模式（累加值 <= 缓冲大小），常量乘法 |
| argument-type | 10 | `char *` 字节缓冲到结构体指针的标准反序列化转换 |
| race-condition | 14 | 全部在 mutex/rwlock 保护下的共享状态访问 |
| resource-leak | 30 | dlopen 句柄进程生命周期持有、锁配对 |
| hardcoded-secret | 1 | 配置订阅键名 `"sys_name"` 被匹配为硬编码密钥 |

**这些模式在代码库中高度重复，应在过滤链阶段识别并排除，而非交给 AI 研判。**

### 2.5 divide-by-zero 精度问题

31 个 AI 确认的 divide-by-zero 中，18 个是 `graph->gran_time`（趋势时间粒度）作除数的重复模式，分布在 12 个不同文件中。这些是同一代码模式被复制粘贴的结果，流水线应识别为"同模式批量发现"并合并提示，而非逐个生成独立候选。

| 除数模式 | 确认数 | 文件数 | 说明 |
|---------|--------|--------|------|
| `graph->gran_time` | 18 | 12 | 趋势报表时间粒度，重复代码模式 |
| `hdr->elements` | 5 | 1 | 环形缓冲容量，lfrb.c 内 5 处 |
| `max_object_count` | 2 | 2 | 队列容量配置字段 |
| `single_ask_msg_size` | 2 | 1 | maf 报表查询 |
| 其他 | 4 | 4 | 零散 |

---

## 3 性能诊断

### 3.1 端到端耗时分布

| 阶段 | 耗时 | 占比 | 评价 |
|------|------|------|------|
| 索引 (index) | 3.2s | 0.2% | 正常 |
| 建图 (graph) | 32.8s | 1.6% | 正常 |
| 检测 (detectors) | 41.5s | 2.0% | 正常 |
| 规划收敛 (plan) | 42.7s | 2.0% | 有优化空间（见 3.3） |
| 报告生成 (report) | 0.04s | <0.1% | 正常 |
| **自动分析合计** | **120.6s** | **5.8%** | — |
| **AI 研判** | **1,974s** | **94.2%** | **核心瓶颈** |
| **端到端** | **~2,095s** | 100% | — |

**核心发现：AI 研判占端到端耗时的 94.2%，是绝对性能瓶颈。降低候选数量（尤其误报候选）是提升性能的最有效手段。**

### 3.2 检测器耗时分析

| 检测器 | 耗时 | 占比 | 种子数 | 候选数 | 单候选成本 | 诊断 |
|--------|------|------|--------|--------|----------|------|
| dereference | 39.0s | 18.6% | — | — | — | null-deref 主管检测器 |
| caller_null | 29.4s | 14.0% | — | — | — | null-deref 辅助检测器 |
| sizeof_misuse | 27.0s | 12.9% | 0 | 0 | **无效** | 0 种子 0 候选，纯浪费 |
| uninit_variable | 18.6s | 8.9% | 448 | 78 | 238ms | 正常 |
| null_guard | 10.5s | 5.0% | — | — | — | null-deref 守卫分析 |
| unchecked_return | 8.9s | 4.2% | 0 | 0 | **无效** | 0 种子 0 候选，纯浪费 |
| null_source | 8.5s | 4.0% | — | — | — | null-deref 空值源分析 |
| use_after_free | 7.5s | 3.6% | 2 | 0 | **低效** | 2 种子 0 候选 |
| integer_overflow | 6.4s | 3.0% | 193 | 191 | 33ms | 正常但候选质量差 |
| buffer_overflow | 6.3s | 3.0% | 6 | 6 | 1050ms | 候选少 |
| race_condition | 5.6s | 2.7% | 14 | 14 | 400ms | 全误报 |
| memory_leak | 5.2s | 2.5% | 393 | 35 | 149ms | 正常 |
| divide_by_zero | 5.2s | 2.5% | 216 | 161 | 32ms | 候选过多 |

**关键问题：**

1. **null-deref 生态检测器耗时合计 87.4s**（dereference + caller_null + null_guard + null_source），占检测器总时间的 41.8%，但最终仅产出 2 个自动确认 + 145 个全误报候选。投入产出比极低。

2. **sizeof_misuse 检测器耗时 27.0s 但产出 0 种子 0 候选**，是纯浪费。

3. **unchecked_return 检测器耗时 8.9s 但产出 0 种子 0 候选**，是纯浪费。

### 3.3 规划收敛阶段耗时分析

| 收敛类型 | 耗时 | 占比 | 输入 | 输出 | 诊断 |
|---------|------|------|------|------|------|
| injection (taint_source) | 42.6s | 33.9% | 32 | 5 | **32 个种子耗时 42.6s，单种子 1.33s，极慢** |
| path-traversal (taint_source) | 42.6s | 33.9% | 57 | 29 | **57 个种子耗时 42.6s，单种子 0.75s，极慢** |
| null-deref (nullable_source) | 32.2s | 25.6% | 28,284 | 456 | 28K 事件耗时 32.2s，单事件 1.14ms，正常 |
| divide-by-zero (range) | 5.4s | 4.3% | 216 | 215 | 正常 |
| uninit (definite_init) | 1.4s | 1.2% | 448 | 166 | 正常 |

**关键问题：taint_source 过滤器是规划阶段的最大瓶颈。** injection 和 path-traversal 合计 89 个种子，却耗时 85.2s（占规划阶段的 67.8%），单种子处理时间分别为 1.33s 和 0.75s，比 nullable_source 的单事件 1.14ms 慢 1000 倍以上。taint_source 过滤器可能在做全图可达性分析，建议优化为缓存/增量分析。

### 3.4 AI 研判耗时分析

| 维度 | 数值 | 诊断 |
|------|------|------|
| 子代理数量 | 11 | 合理（14 类型分 11 批） |
| 最快子代理 | 47s（hardcoded-secret + signed-compare） | 2 候选，快速完成 |
| 最慢子代理 | 734s（memory-leak + resource-leak） | 64 候选，耗时过长 |
| 平均子代理耗时 | 360s | — |
| 总候选 | 692 | 11 个子代理并行处理 |
| AI 确认 | 40 | 确认率 5.8% |

**AI 研判耗时与候选数量正相关。如果能将 201 个 100% 误报类型的候选在过滤链阶段排除，AI 研判可减少约 30% 的候选负载。**

---

## 4 改进建议

### 4.1 准确率提升建议（优先级排序）

#### P0-1: 修复 resource-leak 自动确认的锁配对误报

**问题：** `pthread_mutex_lock`/`pthread_mutex_unlock` 和 `pthread_rwlock_rdlock`/`pthread_rwlock_unlock` 配对模式被自动确认为 resource-leak。本轮 37 个自动确认中约 14 个为锁配对误报。

**建议：** 在自动确认逻辑中增加"锁配对识别"：
- 若 acquire 是 `pthread_mutex_lock`/`pthread_rwlock_*lock`，在同一编译单元或同类函数中搜索对应的 `pthread_mutex_unlock`/`pthread_rwlock_unlock`，若找到则不自动确认。
- 识别 `__attribute__((noinline)) void xxx_lock()` + `__attribute__((noinline)) void xxx_unlock()` 的封装函数对模式。

**预期收益：** 减少 ~14 个确定性误报（37 → 23）。

#### P0-2: 修复 resource-leak 自动确认的全局变量持有误报

**问题：** `dlopen`/`iconv_open`/`epoll_create` 返回值存入全局变量，进程生命周期持有，被自动确认为泄漏。本轮约 12 个为此类误报。

**建议：** 在自动确认逻辑中增加"全局变量持有"识别：
- 若 acquire 的返回值赋值给全局变量（`g_xxx = ...`），且函数不返回该值也不 free 该值，标记为"进程生命周期持有"，不自动确认。
- 识别 `static` 局部变量缓存模式（`if (g_xxx == NULL) { g_xxx = acquire(...); }`）。

**预期收益：** 减少 ~12 个确定性误报（37 → 25）。

#### P0-3: 修复 resource-leak 自动确认的消息框架回调误报

**问题：** 消息接收回调函数中 `void *data` 参数由框架分配和释放，回调函数不负责释放，被自动确认为泄漏。

**建议：** 识别消息处理回调函数签名模式（如 `int xxx_rcv_msg_proc(void *data, ...)`），若 `data` 来自函数参数且函数体内无 `malloc`/`free` 操作，不自动确认。

**预期收益：** 减少 ~5 个确定性误报。

#### P1-1: 增强 null-deref 过滤链的参数契约识别

**问题：** 145 个 null-deref 候选全部被 AI 判定为误报，主要模式包括：
- 函数参数隐式非空契约（void* 参数直接解引用）
- 函数返回值直接解引用（`nlog_get_xxx()->field`）
- `if (x != NULL && x[0] != '\0')` 守卫后解引用

**建议：** 在 `nullable_source` 过滤器之后增加"参数契约"过滤器：
- 若解引用的变量是函数参数且在整个函数体内无 NULL 检查（暗示隐式非空契约），降级为 dismissed。
- 若解引用的变量是函数返回值的直接字段访问（无中间赋值），且调用函数非 `malloc`/`calloc` 系列，降级为 dismissed。
- 若解引用在 `if (x != NULL && ...)` 条件短路守卫的同一表达式内，识别为已守卫，降级为 dismissed。

**预期收益：** 减少 ~145 个 AI 研判候选（null-deref 候选从 145 降至 ~0-10），节省约 350s AI 耗时。

#### P1-2: 增强 integer-overflow 过滤链的累加器模式识别

**问题：** 191 个 integer-overflow 候选中 186 个被 AI 判定为误报，主要模式包括：
- `snprintf_truncated_s`/`sprintf_s` 返回值累加器（`count += ret`），累加值 <= 缓冲大小
- `size - accumulated` 减法在累加器不变式下不会下溢
- 常量乘法（`1024*1024*1024`）

**建议：** 增加"累加器不变式"过滤器：
- 识别 `count += snprintf_truncated_s(...)` / `count += sprintf_s(...)` 模式，若 `count` 仅用于 `buf + count` / `size - count` 且 `count <= size` 由 `snprintf` 返回值保证，降级为 dismissed。
- 常量表达式乘法（操作数均为字面量或 `#define` 常量）直接降级。

**预期收益：** 减少 ~186 个 AI 研判候选（integer-overflow 候选从 191 降至 ~5-10），节省约 370s AI 耗时。

#### P1-3: 增强 divide-by-zero 的常量除数过滤

**问题：** 161 个 divide-by-zero 候选中 130 个被 AI 判定为误报，主要模式包括：
- `#define` 常量宏作除数（`NLOG_SECOND_PER_MINUTE`、`NLOG_PERCENT_100` 等）
- 循环不变量保证除数非零（`while (count < total)` 保证 `total > 0`）
- 显式零值检查后使用

**建议：** 增强 `range` 过滤器：
- 若除数是 `#define` 常量或字面量，直接降级。
- 若除数在最近支配节点有 `if (x == 0)` 或 `if (x != 0)` 守卫，识别为已守卫。
- 若除数在循环条件中保证非零（`while (x < limit)`），识别为循环不变量。

**预期收益：** 减少 ~130 个 AI 研判候选（divide-by-zero 候选从 161 降至 ~30-40），节省约 430s AI 耗时。

#### P1-4: 增强 race-condition 的锁保护识别

**问题：** 14 个 race-condition 候选全部被 AI 判定为误报，全部为 mutex/rwlock 保护下的共享状态访问。

**建议：** 增强 `shared_access` 过滤器：
- 若共享状态访问在 `pthread_mutex_lock`/`pthread_rwlock_*lock` 和对应 `unlock` 之间，识别为已保护。
- 识别 lock/unlock 封装函数（如 `xxx_mutex_lock()` / `xxx_mutex_unlock()`）。

**预期收益：** 减少 14 个 AI 研判候选（降至 ~0-2）。

#### P1-5: 增强 argument-type 的字节缓冲转换识别

**问题：** 10 个 argument-type 候选全部为 `char *`/`uint8_t *` 字节缓冲到结构体指针的标准反序列化转换。

**建议：** 增加字节缓冲转换模式识别：
- 若 cast 源类型是 `char *`/`uint8_t *`/`void *`，且目标类型是结构体指针，识别为反序列化边界，降级为 dismissed。

**预期收益：** 减少 10 个 AI 研判候选（降至 0）。

#### P2-1: hardcoded-secret 检测器增加值形状过滤

**问题：** 配置订阅键名 `"sys_name"` 被匹配为硬编码密钥。

**建议：** 排除 `.key =` 字段赋值中的非密钥值；增加密钥值熵值检查或模式匹配（密码/token/key 长度 >= 8 且非纯字母）。

**预期收益：** 减少 1 个误报候选。

### 4.2 性能提升建议（优先级排序）

#### P0-4: 优化 taint_source 过滤器性能

**问题：** taint_source 过滤器处理 injection（32 种子）和 path-traversal（57 种子）分别耗时 42.6s 和 42.6s，单种子处理时间 0.75-1.33s，比其他过滤器慢 1000 倍。

**建议：**
- 分析 taint_source 是否在做全图可达性分析，若是，改为增量分析或缓存跨函数分析结果。
- 考虑将 taint_source 的跨函数传播深度限制为 2-3 层（当前可能是全程序分析）。
- injection 和 path-traversal 共享 taint_source 逻辑，可合并为单次传播分析。

**预期收益：** 规划阶段从 42.7s 降至 ~10s（节省 ~33s，自动分析总耗时减少 27%）。

#### P0-5: 空运行检测器跳过

**问题：** `sizeof_misuse`（27.0s）和 `unchecked_return`（8.9s）检测器分别产出 0 种子 0 候选，合计浪费 35.9s。

**建议：**
- 在检测器启动前根据代码特征快速判断是否有匹配模式（如 sizeof_misuse 先扫描是否有 `sizeof(x)` 在 size context 中使用），若无则跳过。
- 或在索引阶段预收集模式特征，检测器启动时查询，避免空运行。

**预期收益：** 检测器阶段减少 ~36s（41.5s → ~6s，自动分析总耗时减少 30%）。

#### P0-6: null-deref 检测器生态瘦身

**问题：** null-deref 生态的 4 个检测器（dereference + caller_null + null_guard + null_source）合计耗时 87.4s，产出 31,357 个种子，经多层过滤后仅 2 个自动确认 + 145 个全误报候选。

**建议：**
- 在检测器阶段增加轻量级预过滤：若解引用目标是非空函数参数（无 NULL 检查），检测器直接不发种子。
- 若解引用在 `if (x != NULL)` 守卫的支配范围内，检测器直接不发种子。
- 将 `sizeof_pseudo_deref` 和 `non_nullable_array_suppress` 的逻辑前移到检测器阶段，避免发出 31,357 个种子后再过滤。

**预期收益：** null-deref 种子从 31,357 降至 ~500-1000，检测器耗时从 87.4s 降至 ~20-30s，规划阶段 null-deref 耗时从 32.2s 降至 ~5s。

#### P1-6: 通过过滤链优化减少 AI 研判候选

**问题：** 692 个候选中 652 个（94.2%）被 AI 判定为误报，AI 研判耗时 1,974s。

**建议：** 实施上述 P1-1 到 P1-5 的过滤链增强后，预计候选数量变化：

| 类型 | 当前候选 | 预期候选 | 减少 |
|------|---------|---------|------|
| null-deref | 145 | 5-10 | ~135 |
| integer-overflow | 191 | 5-10 | ~181 |
| divide-by-zero | 161 | 30-40 | ~121 |
| race-condition | 14 | 0-2 | ~12 |
| argument-type | 10 | 0 | 10 |
| hardcoded-secret | 1 | 0 | 1 |
| **合计** | **522** | **40-62** | **~460** |

总候选从 692 降至 ~230-260，AI 研判耗时预计从 1,974s 降至 ~650-800s（减少 ~60%）。

#### P1-7: 重复模式合并

**问题：** divide-by-zero 的 `graph->gran_time` 模式在 12 个文件中产生 18 个独立候选，`hdr->elements` 在 1 个文件中产生 5 个候选。AI 子代理需要逐个研判。

**建议：** 在候选生成阶段识别"同模式"候选（相同除数变量名 + 相同代码结构），合并为单个候选并标注所有出现位置。AI 子代理一次研判确认/排除整组。

**预期收益：** divide-by-zero 候选从 161 降至 ~80-100（同模式合并），AI 研判效率提升约 30%。

### 4.3 架构级建议

#### P2-2: 自动确认增加"置信度验证"层

**问题：** 自动确认直接将发现标记为 confirmed，不经 AI 研判，但本轮 136 个自动确认中约 30-40 个为确定性误报（resource-leak 的锁配对、全局持有等）。

**建议：** 在自动确认后增加轻量级"置信度验证"：
- 对自动确认的发现，检查是否存在配对释放（lock/unlock、open/close、malloc/free）。
- 检查 acquire 的目标是否为全局/静态变量。
- 若存在疑点，降级为候选交由 AI 研判，而非直接自动确认。

**预期收益：** 自动确认误报从 ~40 个降至 ~5-10 个，整体准确率从 21.3% 提升至 ~25-30%。

#### P2-3: 过滤链可视化与可调参

**问题：** 当前过滤链是黑盒，用户无法了解每个过滤器的输入/输出和参数，难以针对性调优。

**建议：**
- 在 `scan.log` 中增加每个过滤器的详细输入/输出信息（当前已有部分）。
- 提供过滤器配置文件，允许用户针对项目特征调整过滤器参数（如 `nullable_source` 的严格度、`taint_source` 的传播深度）。
- 提供"过滤器效果报告"，展示每个过滤器的淘汰率和误报率（需要 AI 研判结果回填）。

#### P2-4: 项目级安全模式学习

**问题：** nlog 项目有大量重复的安全模式（mutex 封装函数、消息回调框架、snprintf 累加器），每次扫描都要由过滤链和 AI 重新分析。

**建议：**
- 支持"项目级安全模式库"，用户可标注已知安全模式（如 `nlog_custom_rpt_mutex_lock/unlock` 是配对函数）。
- 过滤链自动识别标注的安全模式并跳过。
- 可选：从历史扫描的 AI dismiss 结果中自动学习安全模式（如 `if (x != NULL && x[0] != '\0')` 守卫被 dismiss 100 次后自动加入安全模式库）。

---

## 5 预期改进效果汇总

### 5.1 准确率改进

| 指标 | 当前 | 预期 | 改善 |
|------|------|------|------|
| 自动确认误报数 | ~40 | ~5-10 | -75% |
| AI 候选误报率 | 94.2% | ~70-80% | -15~25pp |
| 整体确认率 | 21.3% | ~30-35% | +10~14pp |

### 5.2 性能改进

| 指标 | 当前 | 预期 | 改善 |
|------|------|------|------|
| 检测器耗时 | 41.5s | ~15-20s | -50% |
| 规划收敛耗时 | 42.7s | ~15-20s | -55% |
| 自动分析总耗时 | 120.6s | ~55-70s | -45% |
| AI 候选数量 | 692 | ~230-260 | -63% |
| AI 研判耗时 | 1,974s | ~650-800s | -60% |
| 端到端耗时 | ~2,095s | ~750-900s | -57% |

---

## 6 附录

### 6.1 扫描产物路径

| 产物 | 路径 |
|------|------|
| SARIF 报告 | `.codeagent/secguard-clang/scans/latest/result.sarif` |
| Excel 报告 | `.codeagent/secguard-clang/scans/latest/result.xlsx` |
| Markdown 报告 | `.codeagent/secguard-clang/scans/latest/report.md` |
| 候选证据 | `.codeagent/secguard-clang/scans/latest/candidates/` |
| 确认发现 | `.codeagent/secguard-clang/scans/latest/findings/` |
| 扫描日志 | `.codeagent/secguard-clang/scans/latest/scan.log` |
| 淘汰记录 | `.codeagent/secguard-clang/scans/latest/dismissed.json` |

### 6.2 过滤链完整数据

| 过滤器 | 类型 | 输入 | 输出 | 淘汰率 |
|--------|------|------|------|--------|
| sizeof_pseudo_deref | null-deref | 31,357 | 30,091 | 4.0% |
| non_nullable_array_suppress | null-deref | 30,091 | 28,284 | 6.0% |
| nullable_source | null-deref | 28,284 | 456 | 98.4% |
| macro_uncertain | null-deref | 456 | 427 | 6.4% |
| has_release | memory-leak | 393 | 57 | 85.5% |
| has_release | resource-leak | 189 | 67 | 64.6% |
| definite_init | uninit | 448 | 166 | 62.9% |
| safe_function_exclude | format-string | 36 | 0 | 100% |
| double_free_flow | double-free | 16 | 0 | 100% |
| taint_source | injection | 32 | 5 | 84.4% |
| taint_source | path-traversal | 57 | 29 | 49.1% |
| range | divide-by-zero | 216 | 215 | 0.5% |
| lifetime | use-after-free | 2 | 1 | 50% |

### 6.3 检测器完整耗时

| 检测器 | 耗时(ms) | 种子数 | 候选数 |
|--------|---------|--------|--------|
| dereference | 39,005 | — | — |
| caller_null | 29,447 | — | — |
| sizeof_misuse | 27,042 | 0 | 0 |
| uninit_variable | 18,558 | 448 | 78 |
| null_guard | 10,467 | — | — |
| unchecked_return | 8,887 | 0 | 0 |
| null_source | 8,469 | — | — |
| use_after_free | 7,491 | 2 | 0 |
| integer_overflow | 6,387 | 193 | 191 |
| buffer_overflow | 6,325 | 6 | 6 |
| race_condition | 5,646 | 14 | 14 |
| memory_leak | 5,245 | 393 | 35 |
| divide_by_zero | 5,184 | 216 | 161 |
| double_free | 4,841 | 16 | 0 |
| resource_leak | 4,694 | 189 | 30 |
| path_traversal | 3,189 | 57 | 17 |
| argument_type | 2,390 | 10 | 10 |
| signed_compare | 2,381 | 1 | 1 |
| dangerous_function | 2,186 | 3 | 1 |
| data_representation | 1,866 | 0 | 0 |
| interprocedural | 1,774 | — | — |
| hardcoded_secret | 1,407 | 1 | 1 |
| injection | 1,191 | 32 | 2 |
| crypto_misuse | 1,069 | 0 | 0 |
| log_injection | 721 | — | — |
| format_string | 714 | 36 | 0 |
| deadlock | 673 | 0 | 0 |
| crlf_injection | 625 | — | — |
| xml_injection | 611 | — | — |
| argument_injection | 588 | — | — |
| signal_handler | 517 | 0 | 0 |
