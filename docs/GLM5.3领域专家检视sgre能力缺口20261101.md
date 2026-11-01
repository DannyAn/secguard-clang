# 领域专家视角检视：sgre 能力缺口清单（必须要有但我们没有的）

- **基线**：commit `140f4ca`（v0.11.9 之后，含 boundary fail-open / AI 预算强化）
- **日期**：2026-11-01
- **性质**：**能力缺口（capability gap）检视，不是缺陷检视**。回答的问题是"对标 C 安全静态分析领域，哪些'必备能力'我们整体缺失"，而非"已有实现里有哪些 bug"。实现内部缺陷见既有各轮检视清单（GLM5.2检视sgre四子链路20260930.md 等），本文不重复。
- **本轮无任何代码修改**。每项缺口均附代码级证据（file:line 或 grep 确认方式），未经验证的推断一律不写。

## 对标基准

以三类权威基准交叉判定"必须要有"：

1. **CWE 体系**：CWE Top 25 (2025)、CWE-699（平台相关视图）、CWE-1003（C/C++ 视角）
2. **CERT C Coding Standard**：业界 C 安全事实标准（MSC/MEM/ARR/STR/DCL/EXP/FIO 各族）
3. **业界工具标配集**：Coverity、Polyspace、Klocwork、PVS-Studio、Cppcheck、Clang Static Analyzer、Infer、CodeQL 的默认检测面

判据：一项能力同时满足 (a) 出现在 ≥2 类基准中、(b) 缺失会在用户定位场景（企业 C 代码、电信/设备类协议代码）产生系统性漏报或不可用，才定为"必须要有"。

## 现状能力盘点（简）

**检测面**：25 个注册 vuln type，CWE Top 25 中 C 语言相关项基本齐（CWE-78/89/22/798/125/787/416/476/190/401/369/457/415/…），另有 CWE-676/681/686/843/667/479/362/327/467/252/20 等。evidence 层 44 个非测试检测器文件。

**引擎面**：tree-sitter-c fork（typeof + GNU 扩展）、macro 展开与 macro-body 嵌入、semantic graph（CFG + CFGCache、INTERPROC、DATA_FLOW）、区间分析（range_flow）、三态 retNullable fixpoint（proven/assumed）、跨函数 free/use summary、污点传播（injection 六族）、锁原语识别（mutex/rwlock/spin/C11 mtx）、async-signal-safe 函数集、弱密码算法/弱随机/undersized-key。

**工程面**：CLI（index/scan/diff/pr/mr/status/metrics/query/types/plan/report/classify/db/def/schema/config）、SARIF+markdown、SQLite、secguard.toml、c-vuln-benchmark + validator、5 平台发布、MCP 工具、AI 研判/复核/suppression/断点续扫链路。

**结论先行**：检测面的 CWE 广度已是同体量工具中的前列；**系统性缺口集中在四类——地基性检查缺项（栈逃逸/invalid free）、引擎能力盲区（函数指针/编译配置）、高频 C 惯用式检查缺失（fallthrough/移位 UB）、产品化必备件（静态 severity/行内豁免/CI）**。

---

## P0 —— 没有它，产品在定位场景上不成立

### GAP-01 栈地址逃逸（CWE-562：return-of-stack-address 及广义逃逸）

- **领域依据**：C 内存安全的"教科书第一课"检查。Cppcheck（returnAddressOfAutonomousVariable）、Coverity（RETURN_LOCAL）、Clang SA（ret_stack_addr/ret_local_ref）、Polyspace 全部标配；CERT C MEM50-C/MEM51-C 直接对应。
- **现状证据**：evidence 层 44 个检测器文件中无任何栈逃逸判定；`bounded_return.go` 是"资源获取函数返回值边界"语义（bounded_return.go:121 起注释），与栈逃逸无关。
- **覆盖形态**（全部缺失）：
  1. `return &local;`（最简形态）
  2. `&local` 写入全局变量 / 堆对象字段（经函数指针或结构体传出后悬垂）
  3. `&local` 作为实参传给注册回调 / atexit / 线程入口（**用户电信场景高发**：IPC 消息处理函数把局部 buffer 地址挂到异步回调链上）
- **建议落点**：新增 detector（或 uninit 的邻域 category）。所需基建全部已有：locals/globals 符号表、typedefs、CFG；形态 1 是纯 AST 判定（return 表达式为 address-of 且对象在 locals），可直出 confirmed；形态 2/3 需数据流，可先 suspected 留 AI。

### GAP-02 函数指针 / ops-table 间接调用解析（CALL 图完整性）

- **领域依据**：电信与嵌入式 C 代码以 ops 结构体（`dev->open()`、`msg_hdl->dispatch()`）和回调注册表为主干模式。没有 indirect call resolution，CALL 图在这类项目上系统性残缺，**所有跨函数能力连带失效**：retNullable summary、free/use summary、跨函数 size 可大性、调用点实参普查。Coverity/CodeQL 均有函数指针/虚调用目标集分析。
- **现状证据**：全仓无函数指针调用目标解析；`interprocedural.go:511` 的 "indirect-free summary" 是别名推断（q=p; free(q) 场景），不是调用目标解析。调用点 `fp()`/`ops->fn()` 当前要么无目标、要么按名字猜测。
- **建议落点**：保守全集分析即可（不区分上下文，凡取过地址的函数都进候选目标集）：(1) 收集 `&func` / `func` 作为赋值/实参/初始化值的函数名；(2) 收集函数指针类型字段/变量；(3) 调用点若目标集含该名则建 CALL 边。tree-sitter AST 提取无障碍；对 ops-table 项目 CALL 图从"大面积残缺"升到"可用"。目标集宁可过宽（summary 侧按 fail-open 降级），不可为零。

### GAP-03 编译配置消费（compile_commands.json / -I / -D 提取）

- **领域依据**：真实企业 C 项目用 CMake/Autotools，头文件解析与宏环境正确性完全依赖 `-I`/`-D`。没有它：第三方库 typedef 解析不到（类型宽度/容量推断失准）、平台宏（`_WIN32`/`__LP64__`/`-DMODULE_x`）分支解析靠猜、条件编译大门走错分支。Coverity build capture、CodeQL autobuild 均以此为对接根基。**这是与真实世界项目对接的门槛性能力**。
- **现状证据**：全仓（sgre/）grep 无 `compile_commands`/`compiledb` 命中；docs/secguard-clang支持第三方库函数.md 的存在本身证明该痛点已在生产暴露——当前解法是人工配置函数签名表，而非自动消费编译数据库。
- **建议落点**：`secguard index/scan` 增加 `--compile-commands <path>`；解析 JSON 提取每个 TU 的 `-I`（影响头文件定位）与 `-D`（注入预处理器宏环境）。tree-sitter 容错解析保留为无配置时的降级路径，向后兼容。

### GAP-04 invalid free（CWE-761/762：free 非堆指针）

- **领域依据**：free 家族三兄弟——double-free、UAF、invalid-free——sgre 已覆盖前两者，**第三者缺失，家族不对称**。free 栈变量 / free 数组中段（`free(&arr[5])`、`free(arr+2)`）/ free 非分配返回值，全部是 UB 且多为确定性崩溃或可利用堆破坏。Coverity（BAD_FREE）、Cppcheck（deallocinvalid）标配。
- **现状证据**：`double_free.go`/`use_after_free.go` grep 无 non-heap/stack free 判定；free_summary 只汇总"谁 free 了哪个变量"，不判实参指向对象类别。
- **建议落点**：free 实参（剥 cast 后）指向 local 数组 / 栈变量 / subscript 表达式 / 指针算术表达式 → confirmed（纯 AST + locals 判定，无需数据流）；free(全局数组) 同理。与既有 free-summary 管线共用事件流。

---

## P1 —— 业界标配，应尽快补齐

### GAP-05 switch fallthrough（CWE-484）与 missing default（CWE-478）

- **领域依据**：CERT C MSC01-C；GCC `-Wimplicit-fallthrough`/`-Wswitch-default`；Cppcheck/PVS/Klocwork 标配。企业协议/命令字处理代码中 switch 是最高频模式，缺 break 的 fallthrough 是真实高发缺陷源（消息类型错位处理）。
- **现状证据**：evidence 层 grep "fallthrough" 仅命中无关注释（caller_null.go:717 等）；无 switch 结构检查检测器。
- **建议落点**：AST `switch_statement` 遍历：case 末尾无 break/return/continue/goto 且无显式 `/* fallthrough */` 注释 → fallthrough 候选；switch 条件为枚举/命令字且无 default → missing-default 候选。纯 AST，可直出 confirmed（fallthrough 有注释豁免即降级）。

### GAP-06 移位溢出 / 移位 UB（CWE-190 邻域 + CWE-758）

- **领域依据**：`1 << 31`（int 有符号溢出 UB）、`x << 32`/`x << -1`（移位计数 UB）、负值左移（C99/C11 UB）是整数缺陷检测不可分割的部分。Coverity（BAD_SHIFT）、UBSan（shift-base/shift-exponent）标配。
- **现状证据**：integer_overflow.go:402 注释明确 "bit-shift operators have their own token kinds and are excluded" —— **主动排除，非遗漏**，但排除的这批恰是 UB 密度最高的表达式形态。
- **建议落点**：integer_overflow 加 `shift_expression` 分支：左操作数类型宽度（typedefs 基建已有）× 右操作数区间（range_flow 已有）。常量计数可直接 confirmed（`x << 40` 可证 UB）。

### GAP-07 INT_MIN / -1 除法 UB（CWE-190/758 交叉点）

- **领域依据**：除法运算唯一的有符号溢出 UB 点（`INT_MIN / -1`），且是二进制安全/协议代码真实事故来源（长度字段取负后做除法缩放）。UBSan（div-overflow）标配。
- **现状证据**：divide_by_zero 及全部 evidence 文件 grep `INT_MIN` 无命中。
- **建议落点**：divide-by-zero 邻域扩展——definite INT_MIN witness（与既有 definite-zero auto-confirm 完全同模式：区间引擎证明被除数区间=={INT_MIN} 且除数可含 -1）。

### GAP-08 权限设置不当（CWE-732：chmod/umask）

- **领域依据**：C 服务器/设备代码经典缺陷（chmod 0666/0777 于敏感文件、umask 未收紧即创建文件）。Polyspace/Klocwork 有专项；与路径穿越正交。
- **现状证据**：path_traversal.go:40 感知 chmod/chown 但仅作路径操作 sink 上下文，无权限字面量语义；全仓无 0666/0777 检查。
- **建议落点**：path-traversal 新 category `permission_setting`：chmod 实参为常量 0666/0777（或含 world-writable 位）作用于非临时路径 → 候选；open/mkdir 前无 umask 且创建敏感文件 → suspected 留 AI。

### GAP-09 污点长度字段未验证（CWE-1284 邻域：unbounded length-driven allocation/copy）

- **领域依据**：**用户单位电信协议代码最高频真实漏洞形态**——IPC/网络消息的 len 字段直接驱动 `malloc(len)`/`memcpy(dst, src, len)` 而无上界校验。CWE-1284（协议未验证长度）、CWE-789（超大分配）邻域；Snort/Openssl 历史高危多为此形态。
- **现状证据**：integer-overflow 的 size_calc 与 buffer-overflow 的 bounded_copy 各覆盖一角（算术溢出/容量匹配），但没有"污点 len → 分配/复制且无 guard 上界"的端到端语义；taint filter 引擎已有，缺类型化规则。
- **建议落点**：复用 injection 污点引擎 + buffer 容量推断交叉：recv/read/msg 长度字段污点传播至 alloc size 或 copy n，且路径上无 `len > MAX` guard → 独立 category（建议名 `unbounded-length-copy`）。guard 检测复用 guardModel。

### GAP-10 静态 severity 分级

- **领域依据**：按风险排序报告是所有静态分析工具的输出标配；无 severity 则 confirmed 清单无法驱动修复排期（用户此前已将 P2 severity 后置，属已知项，此处正式列入必备清单）。
- **现状证据**：report/findings.go:253 注释明示 Severity "the severity/confidence the AI attached to it" —— 静态管线不产 severity，auto-confirmed 与 AI confirmed 混排。
- **建议落点**：registry per-vuln-type 默认 severity + category 覆盖（如 CWE-787 write 类 > CWE-125 read 类 > CWE-252）；报告层字段已存在（findings.go:39/516），只缺静态侧赋值。

### GAP-11 in-source suppression 标注（`// secguard-disable: <type> <reason>`）

- **领域依据**：企业工程惯例是豁免写在代码旁、走 code review 审计，而非只存工具 DB（DB 换库重扫全部重现、跨团队不可见）。Coverity/Cppcheck/CodeQL（// lint:supress 等）均有行内豁免语法。
- **现状证据**：全仓 grep `secguard-disable`/`nolint`/`nosec` 均无；suppression 仅有 DB 侧 AI index（suppression index）。
- **建议落点**：planner filter 链前置一行注释检查：`// secguard-disable-next-line: <vuln-type> reason=...`；命中即跳过并写入 scan 日志/DB 供审计（与 dismissed 不入库的既有决策对齐：disable 的候选不产 finding）。

### GAP-12 PR 级 CI 集成模板

- **领域依据**：静态分析工具的价值兑现路径是挂进 PR 门禁；diff/pr 命令已有但无部署蓝本，企业用户只能自行摸索。
- **现状证据**：CLI 已有 `diff`/`pr` 命令（root.go:107/148）；仓库无 GitHub Actions/GitLab CI 的用户侧模板；benchmark 本身也无 PR 级自动运行（既有已知问题）。
- **建议落点**：extension 提供 workflow 模板（PR 触发 `secguard pr --sarif` + GitHub code scanning 上传 + 门槛配置示例），随发布包分发。

---

## P2 —— 进阶/差异化，按机会推进

| 编号 | 能力 | 依据 | 现状证据（简） |
|---|---|---|---|
| GAP-13 | 恒真/恒假表达式（CWE-570/572） | PVS/Coverity 标配；`if (x < 0)` 于 unsigned 即恒假 | signed-compare 覆盖比较类型混用，非逻辑恒定 |
| GAP-14 | 赋值当比较（CWE-481 `if (a = b)`） | 老牌检查；GCC -Wall 部分覆盖 | 无 |
| GAP-15 | dead store（CWE-561） | Infer 经典检查 | 无 |
| GAP-16 | 无界递归（CWE-674）/无限循环（CWE-835） | Coverity 有 unbounded recursion | 无（图已有递归边可判） |
| GAP-17 | errno/哨兵语义误用（CWE-253：`==0` 检查返回 -1 的函数） | unchecked-return 邻域精细化 | unchecked-return 只查"未检查"，不查"检查错" |
| GAP-18 | 多字节字符串无界操作（CWE-170） | CERT C STR 章节项 | 无 |
| GAP-19 | 条件编译分支合并（#if 多平台路径全解析） | Coverity/CodeQL macro-model | 现单分支解析 |
| GAP-20 | 修复建议生成（confirmed → fix suggestion） | AI 协同架构的自然延伸、差异化机会 | 报告无 fix 字段 |
| GAP-21 | 合规视图导出（CWE Top 25 命中表 / CERT C 条款映射） | 企业采购侧常见要求 | SARIF 有 CWE 但无合规视图 |

---

## 明确不建议做的（防范围膨胀）

- **符号执行/路径爆炸式引擎**：现有"CFG + 区间 + summary + AI 研判"架构对当前检出目标够用，引入新范式成本/风险不成比例。
- **C++ 全面支持**：单独立项（已有 cpp-agent-integration 规划线索），不得挤占 C 检测质量预算。
- **全量 flow/context-sensitive 指针分析**：渐进增强既有 findAliases（先补 GAP-02 的调用目标集）即可。
- **MISRA C / 汽车功能安全合规全家桶**：与当前"企业安全扫描"定位不匹配。

## 附注（顺带发现的疑点，不属能力缺口，供后续缺陷检视参考）

1. **race-condition category 命名不一致疑点**：race_condition.go:138 发射 `"category": "toctou"`，而 :732 发射 `"toctou_shared_state"`、registry_race_condition.go:32 检查的是 `"toctou_shared_state"`，Capabilities()（:31）自述为 `toctou-filesystem`/`toctou-shared-state`。三套写法并存，:138 的 `"toctou"` 是否被 registry 侧正确分流需另行核实。
2. TOCTOU 检测本身存在（race-condition 的 category），2026-10-16 证据契约审计曾指出其证据链断链问题，见既有 round2 审计文档，本文不重复立项。

## 优先级路线建议

1. **第一批（地基与门槛）**：GAP-01（栈逃逸）→ GAP-04（invalid free）→ GAP-02（函数指针目标集）→ GAP-03（compile_commands）。前两者是纯 AST 级新增检测器，成本最低、可信度收益最大；后两者决定引擎在真实企业代码上的有效性上限。
2. **第二批（高频惯用式 + 产品化）**：GAP-05（fallthrough）→ GAP-06/07（移位/INT_MIN UB）→ GAP-10（静态 severity）→ GAP-11（行内豁免）。
3. **第三批（场景专项 + 生态）**：GAP-08（chmod）→ GAP-09（污点长度）→ GAP-12（CI 模板）→ P2 按机会。

每项落地时按既有纪律执行：新增 vuln type 走 ADDING_A_VULN_TYPE.md 六步清单；修复/新增须构建本地 CLI + benchmark fixture 端到端验证后转正 pinned 回归测试。