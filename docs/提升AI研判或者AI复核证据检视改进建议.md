# 提升 AI 研判 / AI 复核证据检视改进建议

> 分析对象：`examples/c-vuln-benchmark` 本轮扫描
> （scan `sc_2026-10-17_201510_cf932d`，35 文件 / 261 函数 / 3107 行）
> 分析材料：`scans/latest/candidates/**/*.md`（64 份，排除 `_index.md`）、
> `scans/latest/findings/**/*.md`（148 份）、本轮会话中各子代理的返回、
> 扫描库 `sgre.db`（复核裁决）、以及生成这些文档的 Go 源码。
>
> 结论先行：**候选并不是“无法研判”，而是 5 类决定性事实没有随候选一起生成**，
> 导致 AI 只能回到源码里做“一次符号查找”（caller / consumer / callee / capacity /
> release）。本轮 19 次自报读源、至少 1 次显式 `grep`，几乎全部属于这 5 类。
> 同时，auto-confirmed 层有 34/135（25.2%）被复核推翻，复核本身又制造了
> 第二轮读源。**先把事实随证据发出去，再收紧 auto-confirm，读源会接近 0。**

---

## 1. 本轮客观数据

### 1.1 产出规模

| 指标 | 数值 |
|---|---|
| 候选（AI 待研判） | 64 |
| 有候选的类型 | 20 |
| 仅 auto-confirmed、无候选的类型 | 5（deadlock / out-of-bounds / signal-handler / sizeof-misuse / use-after-free） |
| 机器 auto-confirmed | 135 |
| AI 研判 confirmed | 47 |
| 复核推翻 auto-confirmed | **34（25.2%）** |
| 复核推翻分布 | unchecked-return 20/27、uninit 7/11、resource-leak 3/16、memory-leak 2/7、use-after-free 2/4 |
| `findings/*.md` 缺证据包 | **101 / 101** 个 auto-confirmed 文件都写着 `(no pipeline evidence package recorded for this location)` |

### 1.2 AI 侧的“额外动作”（子代理自报）

| 动作 | 次数 | 说明 |
|---|---|---|
| 读源码 | **19** | buffer 2、format 1、path 1、null-deref 2、uninit 1、memory-leak 2、unchecked-return 3、injection 1、race 1、integer-overflow 1、double-free 1、implicit-contract 1、argument-type 1、data-representation 1 |
| 打开候选 Evidence 文件 | 53 | 多数用于确认调用方 / 消费者 / callee 语义 |
| 显式 grep | ≥1 | 见 §2.2；复核理由 id=95 原文含 `grep: lines 93/99/100/104 only` |

单类型读源都没有超过 `≤5` 的预算，所以这不是“违规读源”，而是**本可以不必读**。

### 1.3 那些“奇怪关键词”的 grep 到底是什么

它们不是模糊搜索，而是 4 类**一跳符号查找**，全部可以预计算：

| 实际查找 | 例子 | 缺的事实 |
|---|---|---|
| 调用方 | `grep -rn "tp_path_traversal\|check_then_open\|toctou_safe"` | `## Call Sites`（谁调用、实参是什么、是否污点） |
| 消费者 | `grep -n "release_entry"`、`grep -n "g_global_ptr"` | `## Consumer`（返回值是否被解引用 / 丢弃 / 比较 / 传给 NULL 安全函数） |
| 定义体 | `grep -n "ResourceHandle_create"`、`p17_cmp_ptr` | `## Callee Definition`（目前只对 unchecked-return 生效） |
| 容量 / 声明 | 全局数组 `g_dst[128]`、结构体字段容量 | `## Definition`（声明行、类型、容量） |

> 复核理由 id=95 的原文：“…which is never read or dereferenced in concurrency.c
> (**grep: lines 93/99/100/104 only**)” —— 这就是一次典型的“文件级使用摘要”缺失，
> 本可以在 auto-confirm 阶段直接写进证据。

---

## 2. 问题定位

### 2.1 五类根因

| 类别 | 本质 | 本轮表现 |
|---|---|---|
| A. 证据事实缺失 | 检测器已经算过，但没写进 event props / 候选证据 | buffer-overflow 13/15 无容量或 copy size；integer-overflow 3/3 无 `lhs@/rhs@`（`_index.md` 图例承诺了但数据没有） |
| B. 一跳关系缺失 | 图里已有（CALL / PARAM_BINDING / alias / macro），但没渲染 | path-traversal 7/7、format-string 5/5 无调用点（path 其中 3 个连 `source` 行也没有）；unchecked-return 4/4 无 consumer；null-deref 1/5 无来源 callee 体 |
| C. 语义层缺失 | 证据只写“在哪”，没写“这说明什么” | resource-leak 锁泄漏写“released on some paths…”，但函数内根本没有 unlock；uninit 写“variable packet allocated at line 51”，实际是 `packet->data` |
| D. auto-confirm 规则太浅 | 只证明了“未检查/未释放”，没证明“有安全后果” | unchecked-return 20/27 被推翻；uninit 7/11；resource-leak 3/16 |
| E. 渲染/裁剪 | 索引 120 字符截断、findings 缺证据、字段名与源码不一致 | 101 个 findings 无证据；hardcoded-secret 声称“literal 已隐藏”但 Code Context 打印全文 |

### 2.2 逐类型缺口清单（本轮）

| 类型 | 候选 | 自报读源 | 缺失的决定性事实 | 具体样例 | 优先级 |
|---|---|---|---|---|---|
| buffer-overflow | 15 | 2 | 目标容量、copy size、是否已有守卫 | `004_src_p11_dangerous_function_c_52.md`：`strcpy(g_dst,g_src)`，`g_dst` 容量不在 ±8 窗口；`013`：`sscanf` | P0-1 |
| unchecked-return | 4 | 3 | 返回值消费者：解引用/比较/丢弃/传入 NULL 安全函数 | `001_src_allocator_c_114.md`：`alloc_entry` 结果传给 `release_entry`，后者 `if(!entry)return`，但证据里没有 | P0-2 |
| path-traversal | 7 | 1 | 调用点、实参表达式、污点状态、链接可见性 | `003_src_p6_new_detectors_c_51.md`、`006`、`007` 无 `source` 行，AI 只能 grep 调用方 | P0-3 |
| format-string | 5 | 1 | 参数是否外部可控/调用点；另有 `snprintf_s` 假候选 | `001_src_p11_dangerous_function_c_98.md` 是 `snprintf_s(..., "%s", ...)`，格式索引错误导致误报 | P0-4 |
| uninit | 2 | 1 | 声明行、初始化写、字段路径 | `001_src_network_c_56.md` 写“variable packet allocated at line 51”，实际是 `packet->data`；AI 需读 42–56 | P0-4 |
| null-deref | 5 | 2 | 来源 callee 的定义体 | `001_src_p2_raii_memory_c_46.md` 需要 `ResourceHandle_create` 体证明返回未检查 malloc | P1-5 |
| memory-leak | 3 | 2 | definite / conditional、释放点、错误路径 | `002_src_memory_extra_c_119.md` 只有 `api@malloc`，condition 在 Evidence 里 | P1-6 |
| resource-leak | 2 | 0 | 释放点、守卫条件、锁的跨函数语义 | `001_src_rl_resource_leak_c_70.md` 文案说“some paths”，实际无 unlock | P1-6 |
| integer-overflow | 3 | 1 | `lhs@/rhs@/rhs-influenced/sink@` 操作数来源 | `_index.md` 图例承诺 `lhs@/rhs@`，实际 hint 只有 `cat@size_calc_overflow` | P1-6 |
| double-free | 1 | 1 | release helper 的 `may-free` 条件体 | 需要在 helper 体内确认“某些路径才 free” | P1-5 |
| implicit-contract | 2 | 1 | `flag` 语义、字段类型/可空性 | `001_src_p17_contract_types_c_109.md` 需要确认 `group_data` 的契约 | P1-5 |
| data-representation | 2 | 1 | 比较器 / API 的指针语义体 | `p17_cmp_ptr` 的定义体不在窗口 | P1-5 |
| argument-type | 2 | 1 | sink 形参类型与对象大小 | 基本可从窗口推出，属可优化 | P2 |
| crypto-misuse | 2 | 0 | 宏定义体（`macro-context`） | `DES_set_key_unchecked` 宏/常量语义 | P1-5 |
| hardcoded-secret | 2 | 0 | 前缀/长度已够；但证据与源码声明矛盾 | `001_src_crypto_c_17.md` 声称 literal 隐藏，Code Context 却打印完整口令 | P2 |
| race-condition | 3 | 1 | TOCTOU 的 check/use 调用点（已较好） | `003` 已有 `check@access→use@fopen` | — |

### 2.3 根因代码位置（可直接定位修改）

| 编号 | 位置 | 现状 |
|---|---|---|
| A1 | `sgre/internal/evidence/buffer_overflow.go:182` | 通用 `buffer_overflow` 事件只写 `function/category/expression`，不写 `copy_size/dst_capacity`（`_s` 分支在 `:407` 才写） |
| A2 | `sgre/internal/planner/registry.go:395` | `BuildEvidence` 已支持渲染容量/拷贝长度，但上游没给值 |
| A3 | `sgre/internal/planner/evidence_package.go:159` | `buildHint` 对 buffer-overflow 没有 `cap@/size@` 分支 |
| B1 | `sgre/internal/planner/filter_taint_source.go:233-260` | 形参直通 sink 时只置/不置 `HasTaintSource`，不记录调用点；非 static 无调用方的情况与 flow 分支语义不一致 |
| B2 | `sgre/internal/planner/filter_taint_source.go:380` | `taintedParamsFor` 对非 static 函数按开放世界播种，但该事实没有回写到候选 |
| B3 | `sgre/internal/evidence/unchecked_return.go:237` | 事件只写 `contract_known`，不写消费者类型 |
| B4 | `sgre/internal/planner/filter_return_check.go:75` | `result=="unchecked" && ContractKnown` 就升级 confirmed，没有消费者语义 |
| B5 | `sgre/internal/report/markdown.go:469` | `calleeDefContext` 只服务 unchecked-return，未推广到“来源 callee / 比较器 / release helper” |
| C1 | `sgre/internal/evidence/resource_leak.go:101-107` | 锁类永不 auto-confirm，但 `definite` 不写，证据文案退化成 “some paths” |
| C2 | `sgre/internal/evidence/uninit_variable.go:1467/1488/1516/1547` | `heap_uninit` 的字段/下标路径与 `destWriteTarget` 的初始化路径没有做前缀包含 |
| D1 | `sgre/internal/evidence/resource_leak.go:261` | `exact[lower]` 用小写名索引含 `CloseHandle/RegCloseKey/FreeLibrary` 的混合大小写 map，永远匹配不到 |
| D2 | `sgre/internal/apikb/apikb.go:754` | `IsAllocator` 用 `contains("alloc")`，把 `alloca` 当堆分配器 |
| D3 | `sgre/internal/evidence/format_string.go:98` | `snprintf_s/vsnprintf_s` 的格式参数索引写成 2；MSVC 签名是 `(buf, size, count, fmt, ...)`，应为 3 |
| D4 | `sgre/internal/evidence/use_after_free.go:316` | 未在 free→use 之间检查“变量被重赋值/别名杀死” |
| E1 | `sgre/internal/report/findings.go:309-316` | auto-confirmed 无候选文件时 Evidence 落成一句占位符 |
| E2 | `sgre/internal/cli/report.go:318-338` | 复核载荷只有 id/rule/file/line/function/variable/summary/reasoning/snippet/±8 context，没有一跳关系 |
| E3 | `sgre/internal/report/markdown.go:557` | `markdownCell` 120 字符截断，长 hint 尾部事实会被吃掉 |

---

## 3. 改进建议

### P0-1 buffer-overflow：把“容量 / 长度 / 守卫”写进事件与候选

**问题**：`strcpy(g_dst,g_src)`、`memcpy(dst,src,len)` 这类候选只告诉 AI“调用了不安全 API”，
不告诉它目标有多大、拷贝多长、函数内是否已有边界检查。AI 只能读源或打开 Evidence。

**改法**（`sgre/internal/evidence/buffer_overflow.go:182`）：

在通用 emit 处补齐检测器**已经算过**的事实，不要新增分析：

```go
args := callNamedArguments(call)
dstName := extractArgName(args[0])
capacity := findArraySize(bc, f, dstName, call.StartLine())
if capacity <= 0 { capacity = constantAllocationSize(bc, f, dstName) }
props := map[string]string{
    "function":   callName,
    "category":   category,
    "expression": call.OriginalText(),
}
if capacity > 0 { props["dst_capacity"] = strconv.Itoa(capacity) }
switch {
case boundedCopySizeIdx(callName) >= 0 && len(args) > boundedCopySizeIdx(callName):
    props["copy_size"] = args[boundedCopySizeIdx(callName)].Text()
case len(args) > 1:
    // 无界字符串拷贝：真正的写入长度是 strlen(src)+1，报告层据此与容量比较
    props["copy_size"] = fmt.Sprintf("strlen(%s)+1", args[1].Text())
}
if hasPrecedingBoundsCheck(bc, f, call, callName) {
    props["guard"] = "present"
} else {
    props["guard"] = "none"
}
```

同时：

1. `sgre/internal/planner/evidence_package.go:159` 的 `buildHint` 增加
   `cap@<n>` / `copy@<expr>` / `guard@none|weak`。
2. 在 `sgre/internal/report/markdown.go` 增加 `## Definition`（见 P1-5），
   把目标变量的声明行与容量放在候选里；对全局/结构体字段尤其重要
   （本轮 `g_dst[128]` 在文件顶部，±8 窗口看不到）。

**验收**：重扫本 benchmark，`buffer-overflow` 的 13 个无 `condition` 候选中
至少有 11 个出现 `cap@` 或 `copy@`；AI 不再需要为容量读源。

**测试**：在 `sgre/internal/report/markdown_test.go` 增加
“generic strcpy into file-scope char[128] renders `destination capacity: 128`”；
在 `sgre/internal/evidence/overflow_sizeof_test.go` 增加 props 断言。

---

### P0-2 unchecked-return：增加“消费者 / 逃逸”一跳分析

**问题**：本轮 27 个 auto-confirmed 里 20 个被推翻，4 个 AI 候选也全部 dismissed。
共同原因是只证明了“返回值没比较”，没证明“这个值随后被危险地使用”。
复核时 AI 为此去 grep `g_global_ptr`、读 `release_entry`。

**改法**：在检测器（`sgre/internal/evidence/unchecked_return.go`，emit 前 `:210-235`）
对赋值变量做**函数内使用分类**，并把结论写入 props：

| 消费者形态 | 结论 | 是否 CWE-252 |
|---|---|---|
| 解引用 (`p->f`, `*p`, `p[i]`) | `consumer=deref` | 是 |
| 传给非 NULL 安全 callee | `consumer=call-unsafe` | 是 |
| 传给 NULL 安全 callee（callee 首句 `if(!p) return`） | `consumer=call-null-safe` | 否 |
| 被比较/truthiness 测试 | `consumer=checked` | 否 |
| `(void)p` / 从未读取 | `consumer=discarded` | 否 |
| 覆盖前未使用 | `consumer=overwritten` | 否 |
| 仅 `free(p)` | `consumer=free-only`（已有 `onlyFreedAfter`） | 否 |
| 仅存入全局 | `consumer=stored-global` | 否（交给 null-deref） |

实现要点：

- 扩展 `sgre/internal/evidence/unchecked_return.go:957 onlyFreedAfter` 为通用
  `classifyConsumer`；
- 在 `sgre/internal/planner/filter_return_check.go:75` 把 auto-confirm 条件从
  `result=="unchecked" && ContractKnown` 改为
  `result=="unchecked" && ContractKnown && consumer in {deref, call-unsafe}`；
- `sgre/internal/planner/registry.go:908` 的 `BuildEvidence` 增加
  `consumer@<line> <kind>`、`consumer-null-safe@yes|no|unknown`；
- `evidence_package.go:159` 增加同名 hint token。

**验收**：本轮 20 个被推翻的 unchecked-return 中，至少 18 个不再进入
auto-confirmed（`discarded/checked/overwritten/free-only/stored-global`），
AI 候选 `allocator.c:114/115/121` 由 `call-null-safe` 直接 dismissed，无需读源。

**测试**：新增 `TestUncheckedReturn_ConsumerClassification`，覆盖
`(void)p`、`f != 0`、`release_entry(p)`（NULL 安全）、`p = malloc(32)` 覆盖、
`g = p` 存全局、`p->x` 解引用六种形态。

---

### P0-3 path / format / injection：补齐“调用点 + 污点状态”

**问题**：`_index.md` 里 3 个 path-traversal、5 个 format-string 候选没有 `src@`/`tainted`，
也没有任何调用点信息。AI 只能 grep 函数名看“有没有人传外部输入”。

**改法**：

1. 在 `sgre/internal/planner/filter_taint_source.go:233-260` 统一三种污点状态，
   不要因为“sink 恰好是形参”而落到不同分支：
   - `tainted`：已证明 source→sink（保留 `src@N`）；
   - `extern-param`：函数非 static、sink 是形参/形参派生值、扫描内无污点调用方
     （开放世界假设），候选要显式标注；
   - `unproven`：static 且无污点调用方 → 丢弃（现有行为）。
   对 `extern-param` 置 `HasTaintSource=false`，但新增 `ExternReachable=true`，
   避免把“可能被外部调用”误写成“已证明污点”。
2. 用已有 `CALL` 边（`sgre/internal/graph/call_graph.go:177` 已存 `call_line`）
   生成 `## Call Sites`：每条 = `caller file:line`、实参表达式、实参污点状态
   （`literal` / `tainted` / `unknown`）。没有调用方时明确写
   `0 in-scan call sites; function is non-static (externally visible)`。
3. 修复 `sgre/internal/evidence/format_string.go:98` 的 `snprintf_s/vsnprintf_s`
   格式参数索引：`2 → 3`。这一处直接消除了本轮
   `p11_dangerous_function.c:98` 的假候选（AI 为它读了源码并 dismissed）。
4. 在 `sgre/internal/report/markdown.go:455` 的 taint 类型集合里继续保留
   `injection/format-string/path-traversal`，并渲染 `## Call Sites` 与
   `## Taint Source`（已有）并列。

**验收**：`003/006/007` 三个 path-traversal 候选在 `_index.md` 里出现
`callers@0 extern@yes`；`fs_log_user_message` 出现
`callers@1 arg="hello" literal extern@yes`。AI 不需要 grep。

**测试**：`filter_taint_source_test.go` 增加
“non-static function, sink is parameter, caller passes literal → `extern-param`”；
`markdown_test.go` 增加 `## Call Sites` 渲染断言。

---

### P0-4 auto-confirm 精度（先修 4 个确定性 bug）

这 4 个 bug 不是“AI 要不要读”的问题，而是**产出了本不该存在的 auto-confirmed**，
复核时必然触发读源。

| # | Bug | 位置 | 本轮代价 | 修法 |
|---|---|---|---|---|
| 1 | `CloseHandle/RegCloseKey/FreeLibrary` 永不匹配 | `sgre/internal/evidence/resource_leak.go:261`：`exact[lower]`，map 键是 camelCase | 3 个 FP（windows.c:23/38/71） | map 键统一小写，或 `if exact[name] || exact[lower]` |
| 2 | `alloca` 被当作堆分配器 | `sgre/internal/apikb/apikb.go:754` `contains("alloc")` | 1 个 FP（dgf_stack） | 在 `IsAllocator` 开头排除 `alloca/_alloca/__builtin_alloca` |
| 3 | uninit 把 malloc 指针当未初始化变量 | `sgre/internal/evidence/uninit_variable.go:1467/1488` | 7 个 FP | 指针值由调用赋值即“已初始化”；`heap_uninit` 只对 payload 字段读保留，并要求字段粒度无初始化写 |
| 4 | uninit 字段/下标路径不共享前缀 | `uninit_variable.go:1516/1547` vs `destWriteTarget:1924` | `packet->data` 写入后 `packet->data[i]` 仍被判未初始化 | 初始化标记做前缀包含（`p->f` 覆盖 `p->f[i]`） |
| 5 | use-after-free 不看 free→use 间重赋值 | `sgre/internal/evidence/use_after_free.go:316` | 2 个 FP（`a=b` / `&g_fallback`） | free 后若变量被非别名值重赋值，杀死该 use |

另外建议补上 `resource-leak` 的状态变量守卫：
`if (status == ERROR_SUCCESS) RegCloseKey(hKey)` 这类“释放由 acquire 的返回状态守卫”
目前不算 release，会继续产生 FP。可在 acquire 事件里记录 `status_var`，
在 `isGuardedRelease`/`positiveGuardOn`（`resource_leak.go:506/542`）里识别。

**验收**：本轮 34 个被推翻的 auto-confirmed 至少减少 30 个（目标 ≤4）。

---

### P1-5 通用“一跳闭包”渲染（架构级，一次解决多类型）

建议在候选文件里统一增加 4 个可选小节，全部来自已有索引/图，不做新分析：

| 小节 | 数据来源 | 服务类型 |
|---|---|---|
| `## Definition` | 变量/字段/数组声明（`findArraySize`、`constantAllocationSize`）、参数类型 | buffer-overflow、uninit、implicit-contract、argument-type |
| `## Call Sites` | `CALL` 边 + 调用点实参文本 + 污点状态 | path-traversal、injection、format-string、null-deref（参数来源） |
| `## Consumer` | 返回值首次使用、是否 NULL 安全、是否丢弃/覆盖 | unchecked-return、memory-leak（ownership） |
| `## Release Sites` | 每个 release 行 + 守卫条件；无 release 时显式说明 | resource-leak、memory-leak、double-free、use-after-free |
| `## Callee Definition`（推广现有实现） | `calleeDefContext`（`markdown.go:469`） | null-deref 来源、data-representation 比较器、double-free helper |
| `## Macro Definition` | `preproc_def` 扫描（parser 已有 `constant_symbols.go:82`） | crypto-misuse、所有 `macro-context` 候选 |

实现上建议抽一个 `CandidatesClosure` 结构，在 `writeCandidates`（`markdown.go:239`）
统一渲染，并对每节做 40 行硬上限（沿用 `maxCalleeDefLines`），避免把候选变成源码转储。

**收益**：这是“让 AI 不再 grep”的核心。以后新增漏洞类型只要声明需要哪几节，
不必各自实现。

---

### P1-6 用 `RequiredEvidence` 做完整性闸门

`VulnTypeSpec.RequiredEvidence`（`sgre/internal/planner/registry.go:59`）目前只是文档：
null-deref `:359`、buffer-overflow `:424`、uninit `:544`、use-after-free `:575`、
implicit-contract `:1137` 都有声明，但没有任何代码读取。

建议：

1. 在生成候选时校验每类 `RequiredEvidence` 是否都有对应 EvidenceFragment；
2. 缺失时渲染 `## Missing Facts`（明确写“pipeline 未能证明 X，需要源码确认”），
   让 AI 的读源是**定向**的，而不是探索式的；
3. 在 `report --metrics`/scan summary 里统计 `evidence_incomplete_by_type`，
   作为下一轮改进的输入。

这条不会直接减少读源，但能消除“AI 不知道自己缺什么”的盲目 grep，并让
“读源”变成可度量的最后手段。

---

### P1-7 Hint 词典补齐（让 AI 只读 `_index.md` 就能分流）

当前 `buildHint`（`evidence_package.go:159`）缺以下 token：

| 类型 | 建议新增 | 用途 |
|---|---|---|
| buffer-overflow | `cap@128`、`copy@len`、`guard@none/weak` | 直接判断是否可能溢出 |
| memory-leak / resource-leak | `definite` / `conditional`、`release@N`、`acquire@N` | 区分“必然泄漏”和“路径相关” |
| resource-leak（锁） | `lock@N`、`unlock@none`、`cross-fn-unlock@maybe` | 解释为什么“无 unlock”仍可能是跨函数释放 |
| path-traversal | `callers@N`、`extern@yes/no`、`arg@<expr>@literal/tainted` | 替代 grep |
| format-string | 同上 + `fmt@<expr>` | 判断形参是否外部可控 |
| integer-overflow | `lhs@param/local/const`、`rhs@...`、`rhs-influenced`、`sink@...` | 图例已承诺，数据缺失 |
| unchecked-return | `consumer@<line> <kind>` | 替代读 `release_entry` |
| uninit | `decl@N`、`init@N|none`、`field@p->data` | 修正“allocated at line 51”的误导 |
| hardcoded-secret | `name-only`、`len@20`、`prefix@Supe` | 不打开 Evidence 也能判占位/真凭据 |

同时把 `markdownCell`（`markdown.go:557`）的 120 字符截断改成
“按 token 边界截断并保留尾部关键 token”，或给 Hint 单独放宽到 200 字符
（`_index.md` 是 AI 的主要输入，长一点比多一次读源便宜）。

---

### P1-8 findings 文档补证据（当前 101/101 缺失）

`sgre/internal/report/findings.go:309-316` 在找不到候选文件时写占位符。
auto-confirmed 没有候选文件，于是所有机器确认项在 `findings/` 里都成了“无证据”。

建议：

1. 写入 finding 时把 `auto_confirm_evidence`（DB `properties` 里已有）反序列化为
   `## Evidence` 段落；
2. 同时写 `## Why Auto-Confirmed`（命中的确定性规则）和
   `## Re-Review`（若有复核结论/理由）；
3. 这样 `findings/*.md` 对人工审计和后续二次复核都是自洽的，不必回查 DB。

---

### P2-9 复核载荷（`--list-auto-confirmed`）增加一跳事实

`sgre/internal/cli/report.go:318-338` 的载荷只有 ±8 `context`。
建议复用 P1-5 的闭包，按类型附加：

```json
{
  "consumer": {"line": 117, "kind": "call-null-safe", "callee": "release_entry"},
  "release_sites": [...],
  "call_sites": [...],
  "definitions": [...],
  "status_guard": "ERROR_SUCCESS"
}
```

这样复核不需要再读源，也不需要 grep。**注意**：这些字段是“事实”，不是“结论”，
不要让它们替 AI 下 verdict。

---

### P2-10 一致性与去重

1. **hardcoded-secret**：证据声称“完整 literal 已隐藏”，但 `## Code Context`
   打印了整行（`001_src_crypto_c_17.md`）。要么在 Code Context 中脱敏，要么删掉
   这句声明——安全工具的文档不应自相矛盾。
2. **跨类型重复**：`p5_null_flow.c:18` 的未检查 malloc 同时产出
   CWE-252（unchecked-return）、CWE-476（null-deref，line 19）、
   CWE-401（memory-leak）三条 finding。若报告目标是“缺陷数”而不是“弱点实例数”，
   建议增加跨类型 dominance 规则（例如 unchecked-return 在“同一变量随后解引用”
   时让位给 null-deref），否则计数会重复。**这是产品口径问题，需先确认期望。**

---

## 4. 候选文件 Schema v2（建议）

```markdown
# <Type> in <Function>

**CWE:** CWE-xxx

## Location
- File / Function / Signature / Variable / Expression

## Code Context            # 保持现状；只在“决定性行不在窗口”时加宽 span

## Definition              # 新增：sink 涉及的变量/字段/数组声明 + 容量/类型
- `g_dst`: `char[128]`, file scope, `src/p11_dangerous_function.c:12`

## Call Sites              # 新增：谁调用、实参是什么、是否污点
- `caller@src/main.c:42` → `arg0="hello" (literal)`, `extern=yes`
- 0 in-scan call sites; function is non-static (externally visible)

## Consumer                # 新增：返回值/资源被谁消费
- `consumer@src/allocator.c:117` → `release_entry(e1)` (`null-safe`)

## Release Sites           # 新增：释放点与守卫
- `release@src/x.c:78` guarded by `if (flag)` → conditional
- no release in function (cross-function unlock possible: yes/no)

## Callee Definition       # 推广：来源 callee / 比较器 / helper（≤40 行）
## Macro Definition        # 新增：macro-context 时给出宏体

## Evidence                # 现有结构化事实（必须完整）
## Missing Facts           # 新增：RequiredEvidence 未满足项，明确“需源码确认”
## Pipeline Assessment
## Fix Suggestion
```

原则：**能由索引/图/已算过的检测器结果得出的事实，一律预生成；不要求 AI 再做
任何一跳符号查找。** 只有“需要人类/模型语义判断”的内容（如业务契约、证书用途）
才留给 AI。

---

## 5. 验证与验收

### 5.1 本轮基准回归

重扫 `examples/c-vuln-benchmark`，对比：

| 指标 | 本轮 | 目标 |
|---|---|---|
| AI 自报读源 | 19 | ≤5 |
| 打开 Evidence 文件 | 53 | ≤20 |
| 显式 grep | ≥1 | 0 |
| auto-confirm 被推翻 | 34/135 (25.2%) | ≤5% |
| `findings/*.md` 缺证据 | 101/101 | 0 |
| buffer-overflow 无容量事实 | 13/15 | 0 |
| path/format 无调用点事实 | 12/12 | 0 |

### 5.2 必加单测

1. `TestBufferOverflow_GenericEmitCarriesCapacity`
2. `TestUncheckedReturn_ConsumerClassification`（6 形态）
3. `TestTaintFilter_NonStaticParamIsExternParam`（不是 `tainted`）
4. `TestResourceReleaser_CloseHandleCamelCase`
5. `TestIsAllocator_ExcludesAlloca`
6. `TestFormatString_SnprintfSFormatIndex`
7. `TestUninit_FieldInitCoversSubscript`
8. `TestUAF_ReassignmentKillsUse`
9. `TestCandidateRendersCallSitesAndConsumer`
10. `TestFindingsDoc_AutoConfirmedCarriesEvidence`

### 5.3 验收口径

- `secguard status --per-type` 仍全部 `done`；
- `report --audit` 的 `summary` 不出现 `unclassified_candidates`；
- 对同一 benchmark，confirmed 集合的变化必须能用“上述修法”逐条解释（增加的是
  之前被证据缺失漏掉的，减少的是误报），不允许“数量对了但原因不明”。

---

## 6. 不要做的事

1. **不要笼统加大 Code Context 窗口。** ±8 已经够用；问题是关键事实（容量、
   调用点、消费者）不在窗口里，加宽只会增加 token，不解决“缺什么”。
2. **不要把整个函数/文件塞进证据。** 目标是把一跳关系结构化，不是转储源码。
3. **不要为了减少 AI 读源而放宽 auto-confirm。** 本轮 25% 的推翻率说明
   auto-confirm 已经偏松；再放宽只会把读源从“研判”搬到“复核”。
4. **不要让 AI 用 grep 做调用图分析。** 调用图在 `CALL/PARAM_BINDING` 里，
   在流水线里算，成本是一次 SQL；让 AI 做是 N 次工具往返 + 不可复现。
5. **不要把“未证明”写成“已证明”。** `extern-param` 不是 `tainted`；
   “跨函数可能 unlock”不是“已释放”。证据的措辞必须与确定性等级一致。

---

## 7. 附：本轮每类“读源/嗅探”的动因（按子代理自报）

| 批次 | 类型 | 自报读源 | 最可能的动因 | 对应建议 |
|---|---|---|---|---|
| 1 | buffer-overflow | 2 | `g_dst/g_src` 容量、`sscanf` 长度 | P0-1 |
| 1 | format-string | 1 | `snprintf_s` 假候选 + 参数可控性 | P0-3/P0-4 |
| 1 | path-traversal | 1 | 无调用方 / 参数是否外部可控 | P0-3 |
| 3 | null-deref | 2 | `ResourceHandle_create` 返回未检查 malloc | P1-5 |
| 3 | uninit | 1 | `decl_line=51` 指向 `packet->data`，需看初始化 | P0-4/P1-7 |
| 3 | memory-leak | 2 | definite/conditional 与错误路径 | P1-6/P1-7 |
| 4 | unchecked-return | 3 | `release_entry` 是否 NULL 安全、值是否被丢弃 | P0-2 |
| 4 | injection | 1 | `cmd` 的污点来源 | P0-3 |
| 5 | race-condition | 1 | 临界区/线程实例已由 hint 给出，属确认性查看 | 可保留 |
| 5 | integer-overflow | 1 | 操作数来源（`lhs@/rhs@` 缺失） | P1-7 |
| 6 | double-free | 1 | release helper 的 may-free 条件 | P1-5 |
| 6 | implicit-contract | 1 | `flag/group_num` 契约 | P1-5 |
| 6 | argument-type | 1 | sink 形参类型 | P1-5 |
| 6 | data-representation | 1 | `p17_cmp_ptr` 比较器体 | P1-5 |

> 注：读源次数来自子代理的 `source_reads` 自报；OpenCode 下编排器看不到子代理
> 内部工具调用，无法逐条核验，但“读源动因”与该类型的证据缺口在候选文件中
> 可一一对应。grep 的直接证据是复核理由 id=95。

---

## 8. 一句话给实施 Agent

> 先把“容量、调用点、消费者、释放点、定义体、宏体”这 6 类一跳事实在流水线里
> 生成并渲染；再修 4 个确定性 auto-confirm bug（CloseHandle 大小写、alloca、
> uninit 字段粒度、UAF 重赋值）和 1 个 API 索引 bug（`snprintf_s`）。
> 做完这两组，本轮 19 次读源与 34 个复核推翻应基本清零。
