# SecGuard-Clang 0.9.4 版本扫描审视改进建议

> 本文档基于对 secguard-clang 0.9.4 版本在一次真实 C 语言项目（约 1012 个源文件 / 7092 个函数 / 178358 行代码的安全产品日志系统）上的全量安全扫描结果的人工审视，汇总了扫描会话过程中的编排问题和扫描结果中的误报/漏报问题，并给出针对性的改进建议。
>
> 文档面向 secguard-clang 工具的开发团队，内容自包含，不依赖读者访问被扫描项目的源代码。

---

## 1 扫描概况

| 维度 | 数据 |
|------|------|
| 扫描版本 | secguard-clang 0.9.4 |
| 被扫描项目规模 | 1012 文件 / 7092 函数 / 178358 行 |
| 自动分析耗时 | 约 116 秒（索引+建图+检测+过滤收敛+机器 auto-confirm） |
| AI 研判耗时 | 约 3600 秒（9 个并行子代理） |
| 候选总数 | 591（排除 85 个 auto-confirmed 后） |
| 最终确认 | 51 个（5 个流水线自动确认 + 46 个 AI 研判确认） |
| 已排除 | 545 个 |
| 漏洞类型覆盖 | 24 种类型中 15 种有候选，9 种最终有确认发现 |

### 1.1 确认发现分布

| 漏洞类型 | 确认数 | 严重度分布 |
|----------|--------|-----------|
| divide-by-zero (CWE-369) | 25 | medium 25 |
| integer-overflow (CWE-190) | 11 | high 6 / medium 5 |
| memory-leak (CWE-401) | 4 | high 1 / medium 3 |
| dangerous-function (CWE-676) | 3 | high 3 |
| uninit (CWE-457) | 3 | medium 2 / low 1 |
| injection (CWE-89/117) | 2 | high 1 / medium 1 |
| buffer-overflow (CWE-787) | 1 | high 1 |
| null-deref (CWE-476) | 1 | high 1 |
| signed-compare (CWE-681) | 1 | low 1 |

---

## 2 扫描会话过程问题

### 2.1 子代理上下文溢出导致类型遗漏

**现象**: 编排器（orchestrator）向子代理分发了 4 个类型（memory-leak 32 候选 + format-string 24 候选 + path-traversal 17 候选 + race-condition 13 候选），但该子代理在完成 path-traversal 分类后耗尽了上下文（129 次工具调用），race-condition 类型未被处理，`ai_stage_status` 留在 `pending`。

**根因分析**:
- 子代理在处理 memory-leak 时消耗了大量上下文（32 个候选 + 1 个 auto-confirmed 复核），format-string 和 path-traversal 又各需独立加载 skill 和读取 `_index.md`，累积上下文超过了子代理的有效窗口。
- 编排器的批量容量估算公式 `batch_type_count × TURNS_PER_TYPE_ESTIMATE(12) < 54` 只按类型数估算，没有考虑候选数量的加权。4 个类型 × 12 = 48 < 54 通过了校验，但实际 86 个候选 + 4 次 skill 加载 + 4 次 _index.md 读取远超预算。

**改进建议**:
1. 批量容量估算应加入候选总数维度：`batch_candidate_count × PER_CANDIDATE_OVERHEAD + batch_type_count × PER_TYPE_OVERHEAD < BUDGET`，其中 PER_CANDIDATE_OVERHEAD 应根据实际子代理上下文消耗统计校准。
2. 当一个子代理被分配多个类型时，应在 prompt 中明确优先级顺序，并在每个类型完成后立即写入并 `--complete-type`，而非全部完成后统一写入。这样即使上下文溢出，已完成的类型也不会丢失。
3. 建议增加子代理的"心跳"机制：子代理每完成一个类型后向编排器报告进度，编排器可以实时感知并决定是否需要补充子代理。

### 2.2 injection 类型的 written_count 与实际确认数不一致

**现象**: 子代理报告确认 1 个 injection 发现（CWE-117 日志注入，id=127），但 `secguard status --per-type` 显示 injection 的 `written_count=0`。实际通过 `secguard db` 查询发现该发现确实已写入数据库，但其 `rule_id` 是 `CWE-117` 而非 `CWE-78`，导致 per-type 统计未能正确归类。

**根因分析**:
- `injection` 漏洞类型在 SARIF 中映射到多个 CWE（CWE-78 命令注入、CWE-89 SQL 注入、CWE-117 日志注入），但 per-type 统计可能只按特定 `rule_id` 计数，导致非主 CWE 的发现被遗漏。
- 编排器在 F5 校验阶段依赖 `written_count` 判断子代理是否成功，这个不一致可能导致编排器误判子代理失败并触发不必要的重试。

**改进建议**:
1. `injection` 类型应明确其 CWE 映射范围，per-type 统计应覆盖该类型下所有可能的 `rule_id`（CWE-78/89/117/88 等）。
2. 或者，为 `injection` 类型增加子分类，在 per-type 统计中按子分类聚合而非按 `rule_id` 精确匹配。

### 2.3 自动确认（auto-confirmed）的误报率偏高

**现象**: 本次扫描流水线自动确认了 85 个发现，其中经 AI 复核后被推翻（dismissed）的比例较高：
- null-deref: 37 个 auto-confirmed 全部被 AI 推翻（全是 `memset_s` 清零后使用、out-parameter 初始化模式等误报）
- use-after-free: 1 个 auto-confirmed 被推翻（流水线混淆了两个不同变量 `id_data` 和 `id_del_data`）
- dangerous-function: 2 个 auto-confirmed 维持确认（`inet_addr` 调用，正确）

**根因分析**:
- null-deref 的 auto-confirm 逻辑对 `memset_s(ptr, size, 0, size)` 后解引用 `ptr` 的模式识别不足——`memset_s` 确实写入了 `ptr` 指向的内存，但这不意味着 `ptr` 本身非空。然而流水线似乎把 `memset_s` 的写入语义误判为对指针变量的初始化。实际上这些场景中 `ptr` 是 `nlog_malloc` 的返回值且已做 NULL 检查，auto-confirm 的结论（非空）是对的，但推理路径是错的——它应该基于"malloc 返回值已 NULL 检查"而非"memset_s 初始化了变量"。
- use-after-free 的 auto-confirm 混淆了同名前缀的变量：`id_data`（在第 742 行释放）和 `id_del_data`（在第 748 行释放）。流水线可能基于变量名前缀匹配或定义使用顺序分析出错。

**改进建议**:
1. auto-confirm 的推理路径应可追溯——在 SARIF 的 `reasoning` 字段中记录判定依据（例如"malloc 返回值在第 N 行做了 NULL 检查"），便于 AI 复核时快速定位逻辑错误。
2. 对 use-after-free 检测器，变量身份区分应基于 SSA 值编号或定义点（def-site）而非变量名前缀。同名前缀的不同变量（如 `id_data` vs `id_del_data`）必须被识别为独立对象。
3. null-deref 的 auto-confirm 在"malloc → NULL check → 解引用"这一最常见的安全模式上应当给出正确的推理路径，否则会大量消耗 AI 复核资源。

### 2.4 编排器顺序处理 race-condition 的降级处理

**现象**: race-condition 类型因子代理上下文溢出而未被处理，编排器自行分类了 13 个候选（全部 dismissed），但这个过程是串行的，增加了约 3-5 分钟的墙钟时间。

**改进建议**:
1. 编排器在检测到子代理未完成某类型时，应立即（在收集阶段）为该类型单独派发一个新的子代理，而非自行降级为顺序处理。
2. 或者，编排器应预留一个"兜底子代理"池，专门处理因其他子代理溢出而遗留的类型。

---

## 3 扫描结果误报分析

### 3.1 确认发现中的疑似误报

经人工审视 51 个确认发现，以下几项存在误报嫌疑或准确度问题：

#### 3.1.1 divide-by-zero: `nlog_get_clear_cycle_times()` 返回值作为除数（疑似误报）

**SARIF 描述**: `nlog_check_is_need_clear_mem` 函数中 `entry_times % nlog_get_clear_cycle_times()` 未检查返回值是否为零。

**实际情况**: `nlog_get_clear_cycle_times()` 的函数体为：
```c
return nlog_get_vmrss_state() == NLOG_VMRSS_STATE_NORMAL ? (2 * NLOG_SECOND_FOR_8H) : (2 * NLOG_SECOND_FOR_1MIN);
```
两个分支都返回 `2 * 编译期常量`，**永远不为零**。流水线将函数调用结果作为除数时，未能跨函数体分析返回值的取值范围。

**影响**: 误报 1 个 medium 级发现。
**改进建议**: 对 `divisor@call` 类型的 divide-by-zero 候选，流水线应尝试内联（inline）被调用函数体，分析其所有返回路径的取值范围。如果所有路径都返回非零常量表达式，应直接过滤掉该候选，不进入 AI 研判阶段。

#### 3.1.2 memory-leak: `new_disk_entry` 在 `nlog_db_delete_all_table` 中泄漏（疑似误报）

**SARIF 描述**: `nlog_db_create_new_ctrl_item` 返回的 `new_disk_entry` 在函数返回时未释放，判定为泄漏。

**实际情况**: `nlog_db_create_new_ctrl_item` 内部将分配的内存挂载到全局监控链表（通过 `nlog_set_mon_disk_head`），返回的指针是对全局已注册对象的引用。调用方不需要释放它——它的生命周期由全局链表管理。AI 的推理"never stored, returned, or freed on any path"是错误的——它已经被存储到了全局数据结构中。

**影响**: 误报 1 个 high 级发现。
**改进建议**:
1. memory-leak 检测器需要识别"所有权转移"模式：当被调用函数内部将分配的内存存入全局结构、链表节点、或通过 out-parameter 返回时，调用方不持有所有权，不应判为泄漏。
2. AI 研判时应能访问被调用函数的函数体（或至少其摘要），以判断分配的内存是否在 callee 内部已被接管。当前流水线的 `## Code Context` 只包含候选点周围 ±8 行，无法看到 callee 的实现。

#### 3.1.3 memory-leak: `nlog_db_put.c:317` 中 `tmp_node` 泄漏（正确确认，但路径不完整）

**SARIF 描述**: `nlog_db_put_mem_busy` 中 `tmp_node` 分配后，如果 `nlog_init_wait_list_node` 失败则泄漏。

**实际情况**: 确实是泄漏——`nlog_init_wait_list_node` 返回非 `NLOG_OK` 时，`tmp_node` 既未被加入链表也未被释放。但 SARIF 中的 reasoning 描述不够准确，未明确指出泄漏的具体路径（`nlog_init_wait_list_node` 返回失败的分支）。

**改进建议**: AI 研判的 `reasoning` 字段应明确描述泄漏的具体执行路径（哪些条件分支导致未释放），而非笼统地说"allocation is leaked"。

#### 3.1.4 injection: `nlog_sql_exec` SQL 注入（待商榷）

**SARIF 描述**: `sqlite3_exec(db_handle, sql, NULL, 0, NULL)` 中 `sql` 参数为用户可控值。

**实际情况**: `nlog_sql_exec` 是一个通用 SQL 执行封装函数，`sql` 参数来自各种调用方。流水线判定"user-controlled value reaches the sink"但未展示具体的调用链——哪个调用方传入了用户可控的 SQL 字符串。该函数的大部分调用方传入的是常量 SQL 语句或由内部逻辑拼装的 SQL。

**影响**: 如果确实存在调用方将用户输入拼入 SQL，则为真实漏洞；如果所有调用方都使用参数化查询或常量 SQL，则为误报。当前证据不足以确认。
**改进建议**:
1. injection 检测器的 taint 分析应能展示从 source 到 sink 的完整调用链，至少列出 source 点（如 `recv`、`read`、用户输入接口）和中间传播节点。
2. 对于通用封装函数（如 `nlog_sql_exec`），应标注"此发现基于跨函数 taint 传播，建议人工核实调用方"，而非直接 auto-confirm。

#### 3.1.5 dangerous-function: `inet_addr` 调用（正确确认，但严重度偏高）

**SARIF 描述**: 3 处 `inet_addr()` 调用，severity 标记为 high。

**实际情况**: `inet_addr` 确实是 CWE-676 标记的危险函数（不支持 IPv6，且 INADDR_NONE 与 255.255.255.255 混淆）。但其中 2 处的参数是编译期常量（`NLOG_HOST_IP` 宏），INADDR_NONE 混淆问题不存在。标为 high 过于激进。

**改进建议**: 对 `inet_addr(常量参数)` 的情况，severity 应降为 medium 或 low——危险函数的固有风险存在，但具体的 INADDR_NONE 混淆在该调用点不会触发。

### 3.2 已排除发现中的疑似漏报

#### 3.2.1 format-string 24 个候选全部排除

AI 子代理排除了全部 24 个 format-string 候选，理由是"均为 `snprintf`/`sprintf_s` 等安全格式化函数调用"。但 `snprintf_truncated_s` 是项目自定义的封装函数，其安全性依赖于封装实现的正确性。如果 `snprintf_truncated_s` 内部使用了 `vsnprintf` 且格式字符串参数来自外部，则仍可能存在格式化字符串漏洞。建议流水线对自定义封装函数的安全性给出说明，或在 `_index.md` 的 Hint 中标注"封装函数——需人工确认其实现"。

#### 3.2.2 path-traversal 17 个候选全部排除

全部排除的理由是"路径来源为内部配置或已验证的参数"。但 path-traversal 的关键在于路径参数是否经过规范化（canonicalization）和边界检查。如果内部配置中的路径包含 `../` 或符号链接，仍可能造成路径穿越。建议 path-traversal 检测器在 Hint 中标注路径来源的证明依据，便于 AI 做更准确的判断。

---

## 4 检测器能力改进建议

### 4.1 跨函数分析能力

**当前问题**: 多个误报的根因是流水线无法跨函数分析：
- divide-by-zero: 未内联 `nlog_get_clear_cycle_times()` 的返回值范围
- memory-leak: 未分析 `nlog_db_create_new_ctrl_item()` 内部的所有权转移
- injection: 未展示从 source 到 `nlog_sql_exec` 的完整 taint 路径

**建议**:
1. 对 `divisor@call` 类型的 divide-by-zero，自动内联被调用函数，分析所有 return 语句的取值范围。如果所有路径返回非零常量，直接过滤。
2. 对 memory-leak，增加"callee 所有权转移"分析：如果 callee 内部将分配的内存存入全局结构、链表、或通过 out-parameter/返回值传出，标记为"所有权已转移"并过滤。
3. 对 injection 的 taint 分析，在 SARIF 的 `reasoning` 中附上从 source 到 sink 的路径节点列表（至少列出关键的中转函数）。

### 4.2 严重度分级精细化

**当前问题**: 严重度分级较粗糙：
- `inet_addr(常量参数)` 被标为 high，实际风险为 medium
- divide-by-zero 的 25 个确认全部标为 medium，但其中 `nlog_get_clear_cycle_times()` 返回编译期非零常量的场景实际是误报
- integer-overflow 中 `data_len - copy_len` 无符号下溢（可导致大块 memcpy_s）被标为 high 是正确的，但 `column_info->byte * batch_num`（结构体字段乘参数，溢出需要异常配置）被标为 medium 也合理

**建议**:
1. divide-by-zero 的严重度应考虑除数的可达性：参数/全局变量 → medium；函数返回值（需跨函数分析）→ 根据返回值范围降级或过滤；编译期常量 → 直接过滤。
2. dangerous-function 的严重度应考虑参数是否为常量：`inet_addr(常量)` → medium；`inet_addr(变量)` → high。
3. 增加"可达性"维度：如果触发漏洞需要异常的配置状态（如全局变量被设为零），severity 应降一级。

### 4.3 候选过滤链优化

**当前问题**: 从种子到候选的过滤链存在过度过滤和过滤不足：
- null-deref: 31357 个种子 → 145 个候选，过滤效率高（99.5%），但 145 个候选中 144 个是误报（99.3% 误报率），过滤链的后续质量堪忧
- memory-leak: 444 个种子 → 32 个候选，但 32 个候选中 29 个是误报（90.6% 误报率）
- format-string: 36 个种子 → 24 个候选，24 个全部排除（100% 误报率）

**建议**:
1. null-deref 过滤链应增加"隐式非空契约"过滤：如果一个参数在被调用函数中被直接解引用且无 NULL 检查，这通常意味着该参数有非空契约（caller 保证非空）。这种模式在大型 C 项目中极为常见（尤其是内部 API），应大幅过滤。
2. memory-leak 过滤链应增加"RAII / 所有权转移"模式的识别：`create_xxx` / `init_xxx` 函数通常将分配的内存注册到全局结构中，调用方不持有所有权。
3. format-string 过滤链应识别项目自定义的安全格式化封装（如 `snprintf_truncated_s`、`sprintf_s`），如果这些封装内部使用 `vsnprintf` 且格式参数为字面量，应直接过滤。

### 4.4 auto-confirm 逻辑改进

**当前问题**: 85 个 auto-confirmed 中约 40 个被 AI 推翻（47% 误报率），主要集中在 null-deref（37/37 推翻）和 use-after-free（1/1 推翻）。

**建议**:
1. null-deref 的 auto-confirm 应仅限于"malloc 返回值已 NULL 检查后解引用"这一高置信度模式。对 `memset_s` / `memcpy_s` 写入后解引用的模式，不应 auto-confirm（这些函数写入的是指针指向的内存，不保证指针本身非空）。
2. use-after-free 的 auto-confirm 应基于精确的 SSA 值编号而非变量名匹配。两个不同变量（`id_data` vs `id_del_data`）的 free/use 序列不应被混淆。
3. auto-confirm 的 reasoning 应包含判定依据的关键行号和变量定义点，便于 AI 复核时快速验证。

### 4.5 integer-overflow 的 Code Context 改进

**当前改进有效**: integer-overflow 的 `## Code Context` 嵌入了整个函数体（而非 ±8 行窗口），这是 0.9.4 的一个重要改进。本次扫描中 integer-overflow 的 11 个确认发现质量较高（6 个 high、5 个 medium），人工审视未发现明显误报。特别是 `data_len - copy_len` 无符号下溢的 6 个发现（同一函数族的不同实例），reasoning 准确地指出了 `copy_len` 无条件加 `sizeof(struct)` 的问题。

**进一步建议**:
1. 对于"同一函数族的重复模式"（如同一个文件中多个相似函数的 `data_len - copy_len` 下溢），建议在报告中聚合展示，减少重复信息。
2. integer-overflow 的 `rhs@local` + `rhs-influenced` hint 组合在实际使用中效果良好，AI 能据此判断"累加器被截断安全函数的返回值增长"这一安全模式并正确排除。

### 4.6 SARIF 输出规范性

**当前问题**:
1. `injection` 类型在 SARIF rules 中同时注册了 `CWE-89` 和 `CWE-117` 两个 ruleId，但漏洞类型名都是 `injection`，消费方难以区分。
2. `fixes` 字段的建议过于通用（如"Review the evidence above and apply the appropriate mitigation"），对修复者没有实际指导意义。
3. auto-confirmed 发现的 `review_reasoning` 字段质量参差不齐——dangerous-function 的 review_reasoning 详细且有建设性，但 null-deref 的 auto-confirmed 发现缺乏 review_reasoning（因为 AI 全部推翻了）。

**建议**:
1. 在 SARIF 的 `properties` 中增加 `sub_category` 字段，区分 `sql-injection`、`command-injection`、`log-injection` 等。
2. `fixes` 字段应包含具体的代码修复建议模板（当前只有部分发现做到了，如 integer-overflow 的 `if (num != 0 && size > (UINT32_MAX - sizeof(x)) / num) return NULL;`）。
3. 对所有确认发现统一要求包含 `review_reasoning`，即使 auto-confirmed 发现被 AI 确认维持，也应记录 AI 的复核理由。

---

## 5 编排器（Orchestrator）改进建议

### 5.1 批量容量估算模型

当前模型：`batch_type_count × 12 < 54`（最多 4 个类型/子代理）

建议改为二维模型：
```
estimated_turns = batch_type_count × PER_TYPE_FIXED_TURNS + batch_candidate_count × PER_CANDIDATE_TURNS
if estimated_turns > MAXTURNS × 0.9: split
```

建议参数（基于本次扫描的子代理实际消耗校准）：
- `PER_TYPE_FIXED_TURNS` = 6（skill 加载 + _index.md 读取 + write + complete-type）
- `PER_CANDIDATE_TURNS` = 0.8（大部分候选从 Source+Hint 直接判定，约 20% 需打开 Evidence 文件）
- `MAXTURNS` = 60

### 5.2 子代理进度报告机制

当前子代理在全部完成后才返回结果，编排器无法实时感知进度。

建议：子代理每完成一个类型的分类和写入后，发送一个进度消息（包含已完成类型列表和当前确认计数），编排器据此更新 todo 状态。如果子代理上下文溢出，编排器可以立即为未完成类型派发新子代理。

### 5.3 降级处理策略

当前编排器在子代理未完成某类型时，自行降级为顺序处理。

建议：编排器应优先为遗留类型派发新的子代理（单个类型、完整候选范围），仅在子代理不可用时才降级为顺序处理。降级时应明确记录"降级原因"和"降级处理的类型列表"。

---

## 6 总结

### 6.1 整体评价

secguard-clang 0.9.4 在本次扫描中的整体表现：
- **检测覆盖率**: 24 种漏洞类型全覆盖，15 种有候选产出，9 种有确认发现，覆盖面广。
- **候选质量**: 591 个候选中 51 个确认（8.6% 确认率），545 个排除。候选过滤链的精度有提升空间，尤其是 null-deref（145 候选仅 1 确认）和 format-string（24 候选全排除）。
- **auto-confirm 质量**: 85 个 auto-confirmed 中约 47% 被 AI 推翻，主要集中在 null-deref。dangerous-function 的 auto-confirm 质量较高（100% 正确）。
- **integer-overflow 检测**: 是本次扫描的亮点——全函数体 Code Context + rhs-influenced hint 的组合效果显著，11 个确认发现质量高。
- **divide-by-zero 检测**: 25 个确认中至少 1 个疑似误报（`nlog_get_clear_cycle_times()` 返回编译期非零常量），跨函数分析能力需加强。
- **编排稳定性**: 9 个子代理中 1 个因上下文溢出未完成全部分配类型，编排器降级处理增加了约 5 分钟墙钟时间。

### 6.2 优先改进项排序

| 优先级 | 改进项 | 预期收益 |
|--------|--------|----------|
| P0 | 跨函数返回值范围分析（divide-by-zero 误报消除） | 消除编译期非零常量返回值导致的误报 |
| P0 | memory-leak 所有权转移识别（callee 内部注册到全局结构） | 消除"所有权已转移"类误报 |
| P1 | auto-confirm 的 null-deref 推理路径修正 | 降低 47% 的 auto-confirmed 误报率 |
| P1 | 批量容量估算加入候选总数维度 | 避免子代理上下文溢出导致类型遗漏 |
| P1 | use-after-free 变量身份区分基于 SSA 而非变量名 | 消除同名前缀变量混淆导致的误报 |
| P2 | injection taint 路径完整展示 | 提高注入类发现的可验证性 |
| P2 | 严重度分级精细化（常量参数降级、可达性降级） | 提高严重度评级的准确性 |
| P2 | 子代理进度报告机制 | 实时感知子代理状态，快速恢复溢出类型 |
| P3 | format-string 自定义封装识别 | 减少 100% 误报率的类型 |
| P3 | SARIF 输出规范化（sub_category、统一 review_reasoning） | 提高消费方的可读性 |
