# 第二轮：全链路证据契约审计矩阵与问题清单

基线：`3f8d221`（第一轮 E-01~E-11 完成后）· 分支：`round2-evidence-contract`
方法：沿实际调用链核对（detector props 发射 → eventProps 解析 → Candidate 装载 → BuildEvidence/newEvidenceItem/buildHint → markdown 渲染 → SKILL/指令声明），关键项端到端实证。

## 一、全量类型审计矩阵（25 注册类型）

共享链路层（一次性审计，适用于全部类型）：

| 环节 | 现状 | 结论 |
|---|---|---|
| props 解析 | eventProps 60+ 字段，flexInt 双形态解码 | E-02 后健康 |
| Candidate 装载 | planner.go:437-488 单点装载 | 20 个 props 键定义后未装载（其中 4 个 filter 侧直接消费属设计选择，其余为断链，见问题清单） |
| BuildEvidence | registry.go 25 个 spec | 8 个类型存在泛化描述或断链（见下） |
| buildHint | evidence_package.go | 5 个类型 Hint="—"（实证），表头 token 说明漂移 |
| Code Context | ±8 本地窗 + integer-overflow 整函数 + sourceSinkSpan 宽化，maxContextLines=200 预算，超预算回退本地窗 | 符合"最小充分证据"原则，**无需修改** |
| 敏感值 | maskSecret 前 4 字符+长度，confirmed 也脱敏 | 符合最小暴露原则，**无需修改** |
| 状态表达 | definite/conditional（leak）、interval includes 0（dbz）、contract@known/unknown（unchecked-return） | 已证明/未证明区分到位 |
| MCP 工具 | CLI 同源包装（10 工具），report UPSERT 语义与 AGENTS.md 记载一致 | 无新发现 |

逐类型（仅列有发现的；✓=链路健康）：

| 类型 | Detector props | 断链/缺陷 | 严重度 |
|---|---|---|---|
| race-condition | check_function/use_function/path_arg/mutex/lock_line/unlock_line/thread_* /write_line | TOCTOU 分支三键全断链；toctou_shared_state 第三类渲染成泛化 toctou | HIGH |
| crypto-misuse | reason/key_size/crypt | reason+key_size 断链；全 confirmed 走 auto-confirm，Summary=fragments 拼接（scan.go:628）→ confirmed 报告丢"为什么 weak" | HIGH |
| integer-overflow | lhs_influenced | 装载断链（rhs_influenced 有） | MEDIUM |
| format-string | format_arg | 未装载未渲染（Expression 全文兜底） | MEDIUM |
| path-traversal | path | 未装载未渲染（同上） | MEDIUM |
| memory-leak / resource-leak | origin | 装载但不渲染，分配 API 丢失；Hint="—" | MEDIUM |
| deadlock | mutex_a/mutex_b/reverse_function | fragment 渲染 ✓，但 Hint="—" | MEDIUM |
| use-after-free / double-free | free_line/first_free/second_free | fragment ✓ 窗口 ✓，但 suspected 候选 Hint="—" | MEDIUM |
| injection | source/taint（wsprintf 分支） | eventProps 无对应字段，死键 | LOW |
| buffer-overflow | array/index/copy_size/dst_capacity/size_argument | 渲染 ✓；SKILL 无 Evidence Pattern 段 | MEDIUM |
| out-of-bounds | 同上 | 渲染 ✓（E-02）；**SKILL 漏同步 buffer/index** | HIGH |
| unchecked-return | contract_known/expression | 渲染 ✓（E-03 callee_definition）；**SKILL 漏同步 callee_definition** | HIGH |
| null-deref | definite/origin/caller_null | E-01~E-11 后 ✓ | — |
| divide-by-zero | divisor/definitely_zero | E-04 后 ✓（divisor 表达式有 VariableName+Expression 兜底） | — |
| uninit | decl_line/origin/field_path/use_line | ✓ | — |
| implicit-contract | subject/count/missing/evidence | ✓ | — |
| hardcoded-secret | value/value_proven | E-10 后 ✓ | — |
| argument-type | expected/actual/cast | ✓ | — |
| data-representation | expected/actual | ✓ | — |
| signed-compare / sizeof-misuse / signal-handler / dangerous-function | expression/variable/category | ✓（crypto capabilities 声明 unchecked-key 但从不发射——死 capability，LOW） | LOW |

## 二、问题清单（编号 R2-xx，均已源码验证）

### 已确认问题（进入修复）

| 编号 | 根因类 | 问题 | 修复 |
|---|---|---|---|
| R2-01 | 字段流丢失 | race TOCTOU：check_function/use_function/path_arg 不装载不渲染 | 补链+fragment |
| R2-02 | 字段流丢失 | race toctou_shared_state：mutex/lock_line/unlock_line 断链，类别被渲染成泛化 toctou | 补链+分支渲染 |
| R2-03 | 字段流丢失 | crypto reason/key_size 断链 → auto-confirm Summary 不可追溯 | 补链+渲染 |
| R2-04 | 字段流丢失 | integer-overflow lhs_influenced 断链 | 装载+hint 对称 |
| R2-05 | 字段流丢失 | format-string format_arg 未渲染 | fragment |
| R2-06 | 字段流丢失 | path-traversal path 未渲染 | fragment |
| R2-07 | 字段流丢失 | memory/resource-leak origin 不渲染 | fragment 补分配 API |
| R2-08 | Hint 编码 | 5 类 Hint="—"（deadlock/resource-leak 实证；memory-leak/UAF/DF suspected 同构）违反 buildHint 自身承诺 | 类型分支紧凑 token |
| R2-09 | Hint 编码 | _index 表头 token 说明缺 divisor@/uninit 确定性/api@/cat@ | 文案补全 |
| R2-10 | SKILL 漂移 | out-of-bounds SKILL 缺 buffer/index（E-02 遗漏） | 补段 |
| R2-11 | SKILL 漂移 | unchecked-return SKILL 缺 callee_definition（E-03 遗漏） | 补段 |
| R2-12 | SKILL 漂移 | 6 类无 Evidence Pattern 段（buffer-overflow/crypto-misuse/deadlock/injection/integer-overflow/race-condition） | 补段 |
| R2-13 | SKILL 漂移 | memory-leak 声明不存在的 memory_release；double-free 缺 first/second_free；UAF 缺 free_site/use_site；format-string 缺 api/taint_source | 修正 |
| R2-14 | 测试缺失 | 无 Evidence Pattern↔fragment 对齐守卫（E-02/E-03 漂移因此未被发现） | 契约测试 |
| R2-15 | 测试缺失 | 无 props 字段流契约测试（R2-01~07 因此发生） | 契约测试 |
| R2-16 | 测试缺失 | 无 Hint 非空不变量测试（R2-08 因此发生） | 契约测试 |
| R2-17 | 死代码 | crypto capabilities 声明 unchecked-key 从不发射；injection wsprintf 分支 source/taint 死键 | 清理/补字段 |

### 设计正确（无需修改）

- 窗口策略三层（本地±8/整函数/source-sink 宽化）+ 200 行预算 + 超预算回退：符合最小充分证据原则。
- ValueProven/DefinitelyZero/Timed/AllocLine 由 filter 直接读 props 不经 Candidate：分流判定不进 AI 证据，合理。
- maskSecret 脱敏：confirmed 也脱敏，符合 2.4。
- NULL_GUARD props 四键（Condition/Strength/ScopeStart/ScopeEnd）不被消费：guardModel 已 CFG 化自行分析，读取旧 props 反而是倒退；事件本身仍被消费。记为已知遗留，不修。

### 潜在风险（记录，本轮不修）

- resource-leak 把 pthread_mutex_lock 识别为资源获取（hint_case fixture 实证 2 候选）——检测器语义问题，超出证据链范围。
- wsprintf 污点分支无 variable 键 → varName fallback 到 Expression 全文，dedup 键较长。影响低。