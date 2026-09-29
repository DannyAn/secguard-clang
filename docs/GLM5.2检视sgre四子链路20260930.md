# sgre 四子链路检视（null-deref / divide-by-zero / uninit / unchecked-return）

- **日期**：2026-09-30
- **基线**：commit `b14e160`（v0.8.0 + uninit UN-15/apikb SafeFunctions 修复后），工作区 clean
- **模式**：检视与修复分离。本文件是交付物，修复由其他 AI Agent 按编号执行。
- **方法**：4 个并行 agent 静态检视 + 关键 CRITICAL 项逐条回源验证（ND-01/DBZ-01/DBZ-02/CR-01/CR-03/UN-09 均已核实 file:line 属实）。端到端未跑；修复前须按纪律用精确 fixture + 本地 CLI 二进制复现。
- **总量**：57 项 = 8 CRITICAL / 25 MAJOR / 24 MINOR

## 严重度分布

| 子链路 | CRITICAL | MAJOR | MINOR | 小计 |
|---|---|---|---|---|
| null-deref | 2 | 6 | 5 | 13 |
| divide-by-zero | 3 | 6 | 5 | 14 |
| uninit | 0 | 9 | 6 | 15 |
| unchecked-return | 3 | 4 | 8 | 15 |

---

# 一、null-deref（CWE-476）

## 架构级核心结论

1. **guard 主链已 CFG 化（历史 D4-D8 主张不再成立）**：`guard_model.go:10-15` 明示 guardModel 是 "CFG-native replacement for the old line-range GuardFilter"，按 CFG 边（TrueSuccs/FalseSuccs，guard_model.go:38-43）做 path-sensitive kill，旧 GuardFilter 类型已删除。`||` 不 guard、else 分支不泄漏、嵌套 guard 不泄漏 fall-through、`p==NULL` 真分支确立 NULL 而非非空——均有代码+测试钉住。
2. **CFG 数据流已接入但源锚定存在系统性盲区**：null_flow.go 实现了 may（source-ID lattice，null_flow.go:583-637）+ must（boolean intersection，:705-829）+ definite（must-null，:292-323）三层，DATA_FLOW copy 边、killBase、guard 边级 kill、宏写/迭代器 kill 全部在 CFG 上。但 null 源 gen 只锚定显式赋值/调用返回/entry seed，**字段与元素读取不作为源**（ND-02），使循环携带 null 成为当前最大漏报盲区。
3. **guard"非空"语义仍有三套并存**：planner guardModel（CFG，主链）＋ caller_null callerGuardsVar（行号+字节偏移，ND-07）＋ interprocedural paramUnguarded（NULL_GUARD 行号 scope，interprocedural.go:200-226）。主链收敛完成，caller 侧与 interprocedural 侧仍是行号机制，构成残余双引擎。
4. **confirmed/suspected 分层健全，may-null 不会误升 confirmed**：definite 由显式 `p = NULL` 标记（null_source.go:156-176）+ caller 传 NULL literal（caller_null.go:107-119）精确产生；must-null 流节点精确防行碰撞（null_flow.go:286-292）。缝隙仅在 ND-12（strdup 类确定性 API 残留 suspected）与 ND-06（out-of-scan wrapper 无源直接漏报）。
5. **detector↔planner 变量键一致性靠文本约定维系**：deref varName ↔ NULL_VALUE variable ↔ guard LvaluePath 三方字节级对齐，但 dereference.go:106 的 `text[1:]` 捷径在 cast/链式/自增形态断裂（ND-01/09），是漏报的结构性根源。

## 问题清单

- **ND-01｜CRITICAL**｜`evidence/dereference.go:103-106`｜`varName := text[1:]` 提取解引用变量，对 cast/括号/自增形态不做结构性剥离（`*(S*)p`→`"(S*)p"`、`*(p)`→`"(p)"`、`*p++`→`"p++"`），与 NULL_VALUE 源键 `p` 无法匹配（planner `reaching()` 按变量名查 nodeIn，null_flow.go:138-150）｜**漏报**：`p = NULL; *(S*)p = 1;`、`*p++ = 0` 等内核/嵌入式 cast 密集代码全部静默漏报｜修复：pointer_expression 的 varName 递归剥 cast/paren/自增后取 argument 标识符（复用 null_flow.go:905 `rhsVarName` 递归剥离逻辑）。
- **ND-02｜CRITICAL**｜`planner/null_flow.go:924-936`（copySourceKey）+ `planner/zz_null_deref_guard_review_test.go:160-175`｜`p = p->next` 类字段/元素读取赋值只生成 copy 键 `"p->next"`，而 null 源 gen 只锚定显式赋值/调用返回/entry seed（null_flow.go:233-240、null_analysis.go:79-86），`"p->next"` 位置永远无源可传播；字段读取没有 open-world fail-open（对比 exprReturnsNullable 的 fail-open，null_flow.go:1289）｜**漏报**：链表遍历循环携带 `it = it->next` 后解引用 `it->y`（末轮 next=NULL 崩溃）完全无覆盖——D8 测试反而把该行为钉死为 "should NOT be flagged"（错误断言，把漏报固化）｜修复：对存在循环回边的 field/subscript 读取赋值生成 may-null gen（或 suspected），并修正 D8 测试断言。
- **ND-03｜MAJOR**｜`planner/guard_model.go:230-236`｜`isConditionKind` 只认 if/while/for，`conditional_expression` 不产生 guard kill｜**误报**：`p ? p->x : -1` 三元真分支语义保证 p 非 null，仍被 flag｜修复：conditional_expression 纳入条件节点或对其内 deref 打 may-guard 标。
- **ND-04｜MAJOR**｜`parser/guard.go:200-210`（nonNullSideVar）+ `guard.go:101-116`｜cast guard `if ((T)p != NULL)` 的操作数文本 `"(T)p"` 经 `strings.Trim(t,"()")` 产出垃圾名 `"T)p"`，guard kill 键无效｜**误报**：cast-guard 保护的解引用被误报｜修复：nonNullSideVar 走 cast_expression 结构性 operand 提取而非全文 Trim。
- **ND-05｜MAJOR**｜`evidence/null_source.go:223-230`（isNullLiteral）+ `null_flow.go:370-379`｜`p = (T*)NULL` / `p = (T*)0` 的 cast null 赋值不识别，definite 源不发；collectNodeEffects 将该非 copy 重赋值当 kill，把前序 may 源也清空｜**漏报**：`p = get(); p = (S*)NULL; p->x` 完全漏报（definite 与 may 双丢）｜修复：isNullLiteral 对 cast_expression 递归识别 `NULL`/`0` 字面量。
- **ND-06｜MAJOR**｜`evidence/null_source.go:257`｜out-of-scan 的 "alloc"-命名包装函数（`p = xmalloc(n)`，无定义且未声明）被 detectExternalCall 的命名启发 skip，又被 `IsDeclaredAllocator` 精确集（null_source.go:125）拒绝，两边都不发 NULL_VALUE；retNullable fail-open 只对 `definedNames` 生效｜**漏报**：第三方 malloc 包装的解引用无任何源｜修复：detectExternalCall 的 skip 条件改为 `IsDeclaredAllocator`，命名启发只用于 gen 而非 skip。
- **ND-07｜MAJOR**｜`evidence/caller_null.go:272-307`｜caller 侧 guard 判定仍是"字节偏移（:277）+ 行号 scope（:298-303）"机制，与 planner guardModel（CFG 边级）双引擎并存，scope 语义不同｜**误报/漏报**：guard 在循环体内、call 在循环外等多级嵌套场景下行号 scope 与 CFG 语义不一致｜修复：caller_null 改为消费 planner CFG guard 模型或在 evidence 层共享 CFG。
- **ND-08｜MAJOR**｜`evidence/null_guard.go:474-475`｜`assertGuardedVars` 用 `strings.Contains(text,"!=") && (Contains(text,"NULL")||Contains(text,"0"))` 无词边界子串——`assert(p != err0)` 被误判 null check｜**漏报**：误发 guard 被 interprocedural.go:203 消费，caller 侧 deref sink 被错误压制｜修复：改用 parser.IsNullOperand + binary_expression 结构判定。
- **ND-09｜MINOR**｜`evidence/dereference.go:268-275`（isArrowAccess）+ `:289-305`｜`(*p).x` 点号解引用形态既无 `->` 又非 `*` 开头 → 不产生 deref 事件；`p->a->b` 外层回退 `"p->a"` 仅半覆盖｜**漏报**：点号 deref 与多级指针解引用｜修复：isArrowAccess 扩展识别 paren 内 pointer_expression 点号链。
- **ND-10｜MINOR**｜`evidence/null_guard.go:743-755`（classifyGuard）+ `:609`｜guard 分类仍用 condText 子串匹配（`Contains(condText,"0")` 把 `0xFFFF`/`err0` 当 null）→ NULL_GUARD condition 标签不可靠｜DB 证据噪声 + interprocedural 消费者失真（planner 主链已不消费）｜修复：删除或改结构判定。
- **ND-11｜MINOR**｜`evidence/dereference.go:345-357`（firstIdentifier）+ `:80-95`｜ERROR 节点文本宽泛，firstIdentifier 深度优先取第一个 identifier——varName 可能取到非 deref base 的标识符｜宏调用点坏解析场景变量错配｜修复：按 `->` 出现位置取左侧最近 identifier。
- **ND-12｜MINOR**｜`planner/null_analysis.go:117-134`（onlyAllocatorSources）+ `apikb/apikb.go:674`｜confirmed 白名单只有 BuiltinAllocators——`p = strdup(s)` 等确定性返回 NULL 的 libc API 只能 suspected｜**suspected 残留**：确定性 null-deref 无法 auto-confirm｜修复：为确定性 nullable libc API 建 confirmed 白名单。
- **ND-13｜MINOR**｜`planner/planner.go:58-65` + `evidence/null_guard.go:25-59`｜NULL_GUARD 事件流成为半死流：planner 主链已改 guardModel，唯一消费者是 interprocedural.go:203；`planner_test.go:29` 等注释仍称 GuardFilter 匹配 NULL_GUARD（类型已删）｜DB 膨胀 + 注释误导｜修复：废弃 NULL_GUARD 检测或保留最小集，修正注释。

## 测试盲区（null-deref）

cast/括号/自增 deref 形态（ND-01）、`(*p).x` 点号形态、三元 guard 与 cast guard（ND-03/04）、cast null 赋值（ND-05）、循环内字段读取传播（ND-02）、out-of-scan wrapper（ND-06）、assertGuardedVars "0" 子串误判（ND-08）、caller_null 行号 scope 边界——均零覆盖；d8_while 测试把循环携带漏报固化成错误断言。

---

# 二、divide-by-zero（CWE-369）

## 架构级核心结论

1. **detector 与 planner 是两套独立的零值事实系统**：detector 侧（range_analysis.go 线近似 + divisionGuarded AST）与 planner 侧（range_flow.go CFG 区间）串联、方向保守，不产生输出冲突；但 divisionGuarded 的 else 分支盲区（DBZ-02）造成漏报，range_flow mergeInto 的 absent 语义（DBZ-01）造成假 confirmed——一个漏、一个误，恰好落在链路两端。
2. **range_flow 已真实接入除法判定**（filter_range.go:96-107 消费 `flow.at` 区间做 dismiss/confirm，:135-144 接入 return_summary 的 callResult），不再是"AST 模式匹配 + 文本子串"；guard 识别已全面 AST 化（词边界问题已修）；文本启发式仅剩 `isFloatDivisionText` 一处残留（DBZ-05）。
3. **confirmed 通道是当前最大的精准违规面**：definite-zero auto-confirm 有三条真证明通道（字面 0 / 零值常量符号 / 区间 [0,0]），但 DBZ-01（join 语义）、DBZ-03/04（paramVerdict 同名混淆与不可达调用点）都能在无 AI 复核下机器确认一个非确定发现——违反"confirmed 精准"准则，优先级高于一切漏报项。
4. **AI 研判 suspected 通道本身健康**（planner.go splitBySuspicion + macro gate），但 extension 文档三处关于 field/global auto-confirmed 的过时描述（DBZ-09）会让子代理按错误口径理解候选列表。
5. **浮点是链路唯一的类型系统软肋**：range_flow 是纯 int 区间引擎，浮点排除完全依赖 detector 侧类型解析，而后者只覆盖裸标识符（DBZ-06）——pipeline 层对浮点噪声没有确定性过滤能力。

## 问题清单

- **DBZ-01｜CRITICAL**｜`planner/range_flow.go:411-436`（rangeMergeInto）+ `graph/control_flow.go:412-416`｜区间合并缺 bottom/absent 语义——只遍历 src 键，单侧路径有 fact、另一侧无 fact 时直接采纳该 fact，把"另一路径值未知"当"与该路径同值"｜**误报（假 confirmed，auto-confirm 无 AI 复核）**：`if (c) d = 0; x / d;` join 处 fall-through 侧无 d fact → nodeIn 写成 [0,0] → isDefinitelyZero → confirmed；`while (c) d = 0; x/d;` 同理｜修复：merge 要求键两侧都存在才 join，任一侧缺失即回退 top，并补反证 fixture。
- **DBZ-02｜CRITICAL**｜`evidence/divide_by_zero.go:248-254`（divisionGuarded 的 if_statement 分支）｜只检查条件建立 non-zero 就返回 true，不判断除法在 consequence 还是 alternative 分支（同函数 ternary 分支 :241-247 是区分的）｜**漏报**：`if (d != 0) { return 1; } else { return 10 / d; }` else 分支 d 必为 0，condEstablishesNonZero 为真 → divisionGuarded 误判 → 不发事件｜修复：if_statement 复用 ternary 的分支判断，除法在 alternative 内时要求 condEstablishesZero。
- **DBZ-03｜CRITICAL**｜`planner/call_sites.go:38-49,59-78`（paramVerdict 按裸函数名聚合全项目调用点）+ `filter_range.go:145`｜参数零传播按函数名索引，跨文件同名函数（多个 .c 各有同名 static helper 是常态）调用点混在一起；zero 侧无 static 检查、不校验调用点与定义同文件｜**误报（假 confirmed）+ 漏报**：文件 A 的 `helper(0)` 让文件 B 的 `helper(int d)` 中 `x/d` 直接 confirmed；反之误 dismiss｜修复：调用点按 (文件, 函数名) 限定（static 至少同文件），zero 侧补对称保守条件。
- **DBZ-04｜MAJOR**｜`planner/call_sites.go:71-72` + `filter_range.go:153-156`｜zeroReachable 只看是否存在传字面 0 的调用点文本，不验证可达性（死代码、`#if 0` 块内调用仍在 AST）也不验证参数索引语义｜**误报（假 confirmed）**：不可达 `f(0)` 调用把真非零传播路径机器确认为 divide-by-zero｜修复：过滤不可达调用点或要求同调用图可达集。
- **DBZ-05｜MAJOR**｜`evidence/divide_by_zero.go:495-507`（isFloatDivisionText）｜`'e'/'E'` 触发只要求前一字符是数字，无词边界也不要求 e 后跟数字——与注释"followed by digit"矛盾｜**漏报**：`x / (a + 0x1e)`、`x / md5encode` 等被整条误判浮点跳过｜修复：token 化扫描或用 tree-sitter number_literal 判浮点。
- **DBZ-06｜MAJOR**｜`evidence/divide_by_zero.go:451-462`（isFloatDivisionExpr）+ `466-478`｜浮点建模只覆盖裸标识符操作数；字段链（`s->avg`）、数组元素（`farr[0]`）、调用结果（`get_ratio()`）不解析类型｜**误报（suspected 噪声）**：double 字段除法不 trap 但被发事件进 pipeline，planner 纯 int 引擎无浮点过滤｜修复：类型解析扩展到字段链/下标/返回类型摘要。
- **DBZ-07｜MAJOR**｜`evidence/divide_by_zero.go:43`（FindAll binary_expression）+ `:102-109`｜宏包裹的除法完全不可见——`#define DIV(a,b) ((a)/(b))` 函数体是 preproc_arg 文本，调用处是 call_expression，两种形状都不命中｜**漏报**：内核/通信类项目宏算术绕过检测（注意 DBZ-16 测试只覆盖常量体宏作除数，不覆盖宏包裹整个除法）｜修复：call_expression 增加"宏展开近似"路径。
- **DBZ-08｜MAJOR**｜`parser/constant_symbols.go:45-65`（preproc_def 逐条无条件写入，不感知 `#if/#else` 互斥）+ `evidence/divide_by_zero.go:59`｜`#if A #define ZERO 0 #else #define ZERO 1 #endif` 两分支定义都被收集，nonZero[ZERO] 与 zero[ZERO] 同时为 true，detector 先查 NonZero 即跳过｜**漏报（definite-zero 通道失效）**｜修复：env 按"后定义覆盖先定义"，`#if/#else` 分支互斥处理。
- **DBZ-09｜MAJOR**｜`extension/shared/command-instructions.md:420`、`extension/shared/skills/divide-by-zero/SKILL.md:40-42`、`extension/shared/agent-body.md:192-199` vs `planner/filter_range.go:35-40`｜三处扩展文档仍宣称 `divisor@field`/`global` 是 auto-confirmed 不在候选列表；Go 实现已改为 stays suspected｜**架构一致性（架构性误导）**：AI 子代理按错误口径理解候选列表｜修复：同步 shared 文档三处与 filter_range.go:14-21 过时注释、zz_range_filter_test.go:343-349 矛盾注释。
- **DBZ-10｜MINOR**｜`planner/filter_range.go:84-95`｜return summary 能证明 `get_zero()` 恒返 0，但 RangeFilter 无 zero-return confirm 通道，只单向 suppress 非零｜**suspected 残留**：`x / get_zero()` 永远 suspected（tp_zero_return 测试锁死了现状）｜修复：增加 zeroReturn 判定升级 confirmed。
- **DBZ-11｜MINOR**｜`evidence/divide_by_zero.go:248`｜divisionGuarded switch 无 for_statement｜**误报（suspected 噪声）**：`for (; n != 0; n--) { s /= n; }` 不识别｜修复：switch 增加 for_statement。
- **DBZ-12｜MINOR**｜`parser/constant_symbols.go:197-224`（parseConstantInt 只认数字）｜`x / '0'`（'0'=48 非零常量）被当 possibly-zero 变量｜**误报（suspected 噪声）**｜修复：解析字符字面量。
- **DBZ-13｜MINOR**｜`planner/filter_range.go:239-252`（isConfigFieldDivisor）｜死代码——全仓无调用点，field-chain 逻辑与 divisorShape（:259-275）重复维护｜维护成本/漂移风险（未来"恢复调用"会重新引入无证明 confirmed）｜修复：删除或合并。
- **DBZ-14｜MINOR**｜`planner/registry.go:633`｜definite-zero 升级 confirmed 后 Detail 仍写 "possible division by zero"｜报告文案失真｜修复：按 SuspicionLevel 区分文案。

## 测试盲区（divide-by-zero）

`if (c) d = 0; x/d;` 单分支条件赋 0（DBZ-01）、else 分支除法（DBZ-02）、跨文件同名 static（DBZ-03/04）、宏包裹除法（DBZ-07）、`#if/#else` 互斥宏定义（DBZ-08）、`x/(a+0x1e)` 与 `md5encode` 形态（DBZ-05）、double 字段链/数组/调用返回作除数（DBZ-06）、`x/'0'`（DBZ-12）、for-condition guard（DBZ-11）、while 头 join 变体（DBZ-01）——均无反证 fixture。

---

# 三、uninit（CWE-457）

## 架构级核心结论

1. **三层漏斗已贯通但补偿不对称**：heap/struct 现已进入 planner CFG 收敛层（filter_uninit_flow.go:72-79 → refineHeapStruct），但 confirmed 升级通道只有 stack 侧有 output-param 降级护栏（:111-113），heap/struct 的 confirmed 可被外部函数 &s 写入误升（UN-09），这是当前最值得先修的 confirmed 误报通道。
2. **写入白名单是手写字面量 map 且双处维护**：destWriters 在 evidence/uninit_variable.go:1995 与 planner/filter_uninit_heapstruct.go:266 各一份（当前一致但靠人工同步），未进 apikb 单一事实源；read/recv/scanf 输入函数缺口（UN-03）暴露该模式不可扩展。
3. **字段初始化跟踪依赖 path 文本精确匹配**：scopedPath 一级展开 + 全文本键，无法表达"子结构整体已初始化"（UN-06）与"变量下标覆盖"（UN-15），是 heap/struct 误报的系统性来源。
4. **detector 内部两套启发式互相矛盾**："assume write"（&field 传参无条件信任、无 uncond 检查，UN-02/UN-04）与"uncond"（分支内写不算初始化）并存，stack/heap/struct 三侧对 &field 传参处理互不对称（UN-04 vs UN-05）。
5. **planner 侧作用域感知落后于 detector**：detector 已完成 varKey 作用域化，planner 的 heapStructFlow 仍用裸名（UN-11），两层信息模型不一致。

## 问题清单

- **UN-01｜MAJOR**｜`evidence/uninit_variable.go:1442-1449` + `planner/filter_uninit_heapstruct.go:179-189`｜dest-writer 的 whole 分支只对 memset/memset_s/bzero 记 wholeInit/ie.gen，`memcpy/memmove` 整块写入被 whole=true 短路后丢弃｜**误报**：`p = malloc(n); memcpy(p, src, n); v = *p;` 报 heap_uninit｜修复：whole 且为 memcpy/memmove/mempcpy 家族时同样记 wholeInit。
- **UN-02｜MAJOR**｜`evidence/uninit_variable.go:354-360`（记录点）、`505-507`（消费点）｜isDestWriter 的 outputParamInitLines 无 uncond/isConditionalNode 检查，checkUse 对该行之后的使用无条件 skip（先于 CFG 检查）｜**漏报**：`if (c) memcpy(buf, src, 10); use(buf[0]);`——c 为假时 buf 未初始化但被 skip｜修复：条件分支内 dest-writer 不记或让 CFG 先裁决。
- **UN-03｜MAJOR**｜`evidence/uninit_variable.go:1995-2022`（destWriters 表）｜read/recv/fread/scanf/sscanf/getline 等以指针参数**写入**的输入函数不在 destWriters｜**误报**：`char buf[64]; read(fd, buf, n); use(buf[0]);` 报 stack_uninit｜修复：输入函数纳入 destWriters（进 apikb 统一维护）。
- **UN-04｜MAJOR**｜`evidence/uninit_variable.go:1663-1688`｜`&s.f` 传给**任意**函数一律标记 initializedFields，无函数名单/摘要门控｜**漏报**：`memcmp(&s.f, other, n)` 只读却标记已初始化，真未初始化读被吞｜修复：排除 memcmp/strcmp/hash 类只读函数。
- **UN-05｜MAJOR**｜`evidence/uninit_variable.go:1364-1453`｜heap 侧完全没有 `&p->f` 传参即成员写入的识别（struct 侧有且恒信任），两侧不对称｜**误报**：`S *p = malloc(n); getShort(&p->f); use(p->f);` 报 heap_uninit｜修复：与 struct 侧共用 &field output-param 识别（并同步加 UN-04 门控）。
- **UN-06｜MAJOR**｜`evidence/uninit_variable.go:1450-1451`（markField 一级 path）+ `1516-1521`（读路径精确匹配）+ `planner/filter_uninit_heapstruct.go:191-193`｜`memset(p->inner, 0, ...)` 只记 path="p@L->inner"，嵌套字段读 "p@L->inner->len" 文本不匹配，无前缀/子结构归并｜**误报**：清零 inner 子结构后读 `p->inner->len` 仍报｜修复：读路径检查改为"该 path 或任意祖先已初始化即已写"。
- **UN-07｜MAJOR**｜`evidence/uninit_variable.go:238-247`｜带初始化的 shadowing 内层声明（`{ int v; { int v = 0; use(v); } }`）不在 declsByName，resolveVarKey 只解析到外层未初始化声明｜**误报**：use(v) 报 stack_uninit｜修复：declsByName 收录全部声明，uninitVars 单独标记。
- **UN-08｜MAJOR**｜`evidence/uninit_variable.go:864-876`（assignmentLHSName 只认 identifier LHS）+ `planner/filter_uninit_flow.go:229-244,383-393`｜`int *px = &x; *px = 5; use(x);`——`*px = 5` LHS 是 pointer_expression，detector 不进 assignSites[x]，planner 不产生 kill｜**误报且升级 confirmed**：detector 报 stack_uninit，planner mustReaching(x)=true 且 hasOutputParamWrite 看不见 → confirmed｜修复：解引用写若 RHS 链含 `&x` 指针别名，将 x 记入 kill/assignSites。
- **UN-09｜MAJOR（回源已验证）**｜`planner/filter_uninit_flow.go:130-145`（refineHeapStruct）｜heap/struct 的 confirmed 升级（sourceOnEveryPath + 无 initOnAnyPath）无任何 output-param/调用摘要补偿——hasOutputParamWrite 仅作用于 stack_uninit｜**confirmed 误报**：`S s; fill_ext(&s); use(s.f);`（外部函数 &s 写入）→ confirmed 直进报告，AI 不再复核｜修复：refineHeapStruct confirmed 分支复用 hasOutputParamWrite 语义降级 suspected。
- **UN-10｜MINOR**｜`evidence/uninit_variable.go:1322-1327` + `planner/filter_uninit_heapstruct.go:133-137`｜`p = realloc(p, n)` 被当全新未初始化块，忽略 realloc 保留原内容语义｜**误报**：`p = realloc(p, n); use(p[0]);` 原初始化区域被报｜修复：realloc 单独处理为部分初始化。
- **UN-11｜MINOR**｜`planner/filter_uninit_heapstruct.go:35-66` + `filter_uninit_flow.go:92`｜heapStructFlow 的 gen/kill 用裸变量名，detector 侧已 varKey 作用域化（uninit_variable.go:1218-1219）｜同名堆指针 gen/kill 交叉污染（罕见但存在）｜修复：candidate 携带 decl_line，lattice 键带 decl 行。
- **UN-12｜MINOR**｜`evidence/uninit_variable.go:785-796`｜setterMacroName 用 `strings.Contains`，`OFFSET_VALUE`（含 "SET_"）、`ASSET_price` 中招｜**漏报**：`OFFSET_VALUE(x, n)` 第一参被记为写入，后续真未初始化读被 skip｜修复：前缀/后缀边界匹配 + 首参裸标识符确认。
- **UN-13｜MINOR**｜`evidence/uninit_variable.go:1264-1268` + `resource_leak.go:462-472`｜`s->inner = malloc()`（s 为参数）时 extractVarName 返回 base "s"，参数结构体 s 被登记进 mallocVars｜origin/variable 语义错误 + 误报｜修复：malloc 目标提取限定 LHS 为 identifier。
- **UN-14｜MINOR**｜`evidence/uninit_variable.go:1092-1096` + `1035-1038`｜isNullZeroExpr 无 "0.0"/"0.0f"，nullZeroGuardVar 后缀只认 "== 0"｜**误报**：0.0 浮点哨兵 lazy-init 不识别｜修复：isNullZeroExpr 增加浮点零拼写。
- **UN-15｜MINOR**｜`evidence/uninit_variable.go:1389-1392` + `1528-1554`｜循环内 `for (i=0;i<n;i++) p[i] = 0;` 记 "p@L[i]"，读 `p[0]` 的 path 是 "p@L[0]"，变量索引与字面索引互不匹配｜**误报**：写满数组后读 p[0] 仍报｜修复：下标为变量的写视为"未知元素"，读同 base 任意下标降 suspected。

## 已确认修复有效（uninit 历史问题当前不复现）

calloc 零初始化特判（:1248 + heapstruct :127-131）、heap subscript 读（:1528-1554）、三层收敛覆盖 heap/struct（refineHeapStruct）、dest-writer arg-0 四形态统一、safe functions 变体补全（apikb.go:14-44 sprintf_s/snprintf_s 等）、memset 不再依赖文本 sizeof（sizeIsWholeObject/wholeObjectSize 只认 sizeof_expression）、detector 侧 varKey 作用域化、isNullZeroExpr 字面量覆盖（0U/0x0/'\0'/nullptr/false/(void*)0）、宏写汇总跨文件收集。

---

# 四、unchecked-return（CWE-252）——本链路首次检视

## 架构级核心结论

1. **双引擎平行实现、靠顺序耦合保正确**：detector 的 checkedVars（evidence/unchecked_return.go:165-189）与 planner 的 conditionTestsVar（filter_return_check.go:172-209）是两份独立重实现，detector 守卫面严格超集于 filter 守卫面。一切正确性建立在"detector 先豁免、filter 只接手残量"上——detector 任何收紧都会立刻引爆 filter 的 confirmed 误报批量回归（CR-08）。均为 AST kind 判断，无文本子串/词边界问题，但"形状白名单不完整"与 null-deref 链路的守卫缺陷同型不同源。
2. **filter 的形状分类不闭合**（CR-01/02/03）：analyzeCandidate 仅识别裸调用/赋值/声明三形状，实参传递、三目、assert 三类"返回值已被消费或已被守卫"的形状全部双盲落入 confirmed 误报——本链路最高危缺陷。
3. **知识治理违反项目自身原则**：apikb 自我定位 "single source of truth"（apikb.go:1-7），但 unchecked-return 的 API 名单硬编码在 evidence 私有变量（40-44 行），I/O 族漏配、错误码语义族完全未建模（CR-04/05）。
4. **confirmed 通道窄、suspected 证据薄**：auto-confirm 仅覆盖 3 形状且其中实参形状判错；BuildEvidence 不携带赋值目标/使用点，恒 suspected 的 AI 研判缺乏关键证据（CR-11）。
5. **宏不可见性无缓解设施**：macro_summary/macroFreeSummaries 已有能力但 unchecked-return 未接入，注册 allocator 宏内自检场景直接误报（CR-07）；free_summary.go 的 ReturnStores 与 passthrough 检测语义相邻但未复用。

## 问题清单

- **CR-01｜CRITICAL**｜`planner/filter_return_check.go:91-94,116-118` + `evidence/unchecked_return.go:282-284,349-351`｜analyzeCandidate 从 call 向上爬升遇 `expression_statement` 即判 "unchecked"，不区分"裸调用语句"与"实参传递形状"——`foo(malloc(n));` 的 malloc parent 链是 argument_list → call_expression → expression_statement，argument_list/call_expression 落 default 继续爬，最终判 unchecked → confirmed｜**confirmed 级误报**：`consume(malloc(n))`、`register(alloc_buf(sz))` 等返回值作为实参传递的惯用写法被确定性升级 confirmed，绕过 AI 兜底｜修复：爬升遇 argument_list/call_expression 返回 "unknown" 交 AI。
- **CR-02｜CRITICAL**｜`evidence/unchecked_return.go:167`（checkedVars 只收 if/while/for/do condition）+ `planner/filter_return_check.go:62,151`（只 FindAll if_statement）｜三目条件表达式中的判空（`size_t sz = p ? strlen(p) : 0;`）双盲 → "unchecked" → confirmed｜**confirmed 级误报**：三目判空是 C 惯用法｜修复：checkedVars 增加 conditional_expression，filter 同步覆盖。
- **CR-03｜CRITICAL（回源已验证）**｜`evidence/unchecked_return.go:165-189` + `planner/filter_return_check.go:62,147-164`｜`assert(p != NULL)` / `assert(p)` / 项目 CHECK 宏在 AST 中是 call_expression 而非 if_statement，两侧均不识别（grep 确认两文件无任何 assert 处理）→ 检查在场被当无守卫 → detector 发事件 + filter confirmed｜**confirmed 级误报**，高可靠性代码高频形态｜修复：assert/assert_perror/可配置 CHECK 家族纳入两侧共享守卫识别。
- **CR-04｜MAJOR**｜`evidence/unchecked_return.go:40-44`（uncheckedReturnAPIs 硬编码 10 个 API）｜名单仅 malloc/calloc/realloc/fopen/fdopen/opendir/read/recv/write/send；getline/fgets/fread/fwrite/close/open/socket/accept/connect/pipe/pthread_create/scanf 族/snprintf/chmod/unlink/rename 全不在，I/O 类无兜底｜**系统性漏报**：`getline(&l,&c,fp);` 忽略 -1、fread 短读、close 忽略 EINTR、scanf 忽略转换数均检不出｜修复：名单迁入 apikb 作 UncheckedReturnAPIs 单一知识源并补齐。
- **CR-05｜MAJOR**｜`evidence/unchecked_return.go:97-102`｜指针返回类型门控 `strings.HasSuffix(rt, "*")` 排除错误码类 API——posix_memalign/pthread_mutex_lock/pthread_create/getaddrinfo（返回错误码+出参）整体被跳过｜**漏报**｜修复：按 API 建模返回值语义表（sentinel-NULL / sentinel-neg / errno-return）。
- **CR-06｜MAJOR**｜`evidence/unchecked_return.go:165-189`｜checkedVars 以 (函数, 变量名) 全函数范围 map 匹配，无作用域/分支限定——同函数两个分支的同名变量互相豁免｜**漏报**：`if (a) { p = malloc(16); if(!p)...; } else { p = malloc(32); /*未检查*/ }` 第二分支被豁免｜修复：按条件节点行号区间/语句包含关系限定生效范围。
- **CR-07｜MAJOR**｜`evidence/unchecked_return.go:80` + `apikb.go:656-660` + `macro_summary.go:23`｜secguard.toml 注册的 allocator 宏不展开，宏体内已做的 NULL 检查不可见；unchecked-return 不消费任何宏摘要设施（macro_summary 只建模 free 宏）→ 宏调用为语句时 filter 判 unchecked → confirmed｜**误报**（嵌入式 C"宏内自检 allocator"场景），可达 confirmed 级｜修复：为注册 allocator 增加"宏定义体自检"识别或降级 suspected 交 AI。
- **CR-08｜MINOR（当前无触发，高危潜在不一致）**｜`planner/filter_return_check.go:172-227,62` vs `evidence/unchecked_return.go:195-208,216-233,167`｜detector 与 filter 对"检查了"的判定平行重实现（hasCompareOp 与 hasCompareOperator 等价但独立），detector 守卫面严格超集｜detector 任何收紧立即引爆 filter confirmed 误报批量回归｜修复：守卫谓词抽取为两侧共享单一实现。
- **CR-09｜MINOR**｜`evidence/unchecked_return.go:126-142`｜`if (!p) { log(...); }` 后继续使用 p 的"检查了但未处理（log-and-continue）"被视为已检查不发事件｜**漏报**（CWE-252 变体：检查后错误未阻断）｜修复：对"检查体仅含日志且控制流继续使用"降级 suspected 交 AI。
- **CR-10｜MINOR**｜`evidence/unchecked_return.go:179`｜testedOperands 任意比较即注册 checked——`if (n < 0) return;` 之后对 n==0（EOF）或 partial write 的忽略检不出｜**漏报**（需区间分析）｜修复：与 range_analysis.go 联动做长度消费检查。
- **CR-11｜MINOR**｜`evidence/unchecked_return.go:144-148` + `planner.go:338-341` + `registry.go:648`｜事件不含被赋值变量，planner VariableName 退化为调用全文，dedupKey 随之以全文作键；BuildEvidence 不携带赋值目标与使用点｜AI 研判证据链断裂 + dedup 粒度受全文影响｜修复：emitEvent 增加 variable，BuildEvidence 输出赋值目标与首个使用点。
- **CR-12｜MINOR**｜`evidence/unchecked_return.go:390-409`｜funcReturnTypes 全局按函数名合并，跨文件同名 static 函数返回类型互相串扰，影响指针门控判定｜漏报/误报边缘场景｜修复：按 (文件, 名) 键控。
- **CR-13｜MINOR**｜`planner/filter_return_check.go:123-137`｜findCallAtLine 返回行内首个同名调用，同一行多个同名调用时第二个 candidate 形状判定错位；dedupKey 同行合并｜漏报/误判边缘｜修复：event 增加 column 二次定位。
- **CR-14｜MINOR**｜`evidence/unchecked_return.go:115-117`｜`(void)` 显式豁免三值不对称：名单内 API 的 `(void)` 恒报（语义正确——真缺陷），但 ISO C 中 `(void)` 是显式"有意忽略"注解｜suspected 噪声放大 AI 负载｜修复：Detail 标注"程序员已显式忽略"辅助 AI 仲裁。
- **CR-15｜MINOR**｜`apikb.go:688-690`（"alloc" 子串启发）+ `evidence/unchecked_return.go:97-102`｜`alloca`（失败即栈溢出 UB，无需 NULL 检查）等经子串启发 + 指针门控进入检测｜**误报**边缘场景｜修复：apikb 维护排除表。

## 测试盲区（unchecked-return）

实参传递形状（`consume(malloc(n));`，CR-01 无任何反证）、三目判空（CR-02）、assert/自定义断言宏（CR-03）、while/for/do 读循环守卫（checkedVars 这些分支在全部 fixture 中零覆盖）、同名变量跨分支遮蔽（CR-06）、名单外 API 正例（getline/fread/close 应检出的测试不存在，CR-04/05 在测试层面不可见）、宏包裹调用（CR-07）、errno/部分检查（CR-10）、跨文件同名 static 类型串扰（CR-12）——均零覆盖。registry↔skills↔extension 三列表一致性 guard（TestVulnTypeSkillConsistency）健康，但只锁名称/domain/描述，不锁 CategoryCWEs/Confidence 语义。

---

# 五、修复优先级建议

**P0（confirmed 精准违规——违反"confirmed 精准无误"准则，机器确认非确定发现，先于一切漏报）：**
1. DBZ-01（rangeMergeInto absent 语义 → 假 confirmed）
2. DBZ-03 + DBZ-04（paramVerdict 同名混淆 + 不可达调用点 → 假 confirmed）
3. CR-01 + CR-02 + CR-03（unchecked-return 三类双盲形状 → confirmed 误报）
4. UN-09（refineHeapStruct confirmed 无 output-param 护栏）
5. UN-08（指针别名初始化 → confirmed 误报）

**P1（确定性漏报——真实缺陷检不出）：**
1. ND-01（cast deref 形态键断裂）
2. ND-02（循环携带 field 读取无源，含修正 D8 错误断言）
3. DBZ-02（if else 分支除法漏报）
4. CR-04（检测名单系统性缺口——迁 apikb 补齐）
5. ND-05 / DBZ-08（cast null 赋值 / 条件宏互斥）

**P2（MAJOR 漏报/误报 + 文档漂移）：** 其余 MAJOR 项，其中 DBZ-09（shared 文档三处与实现口径漂移）成本低收益高可提前。

**P3（MINOR 项）：** 按模块批量处理；ND-13（NULL_GUARD 半死流）与 DBZ-13（死代码）可顺手清理。

**通用修复纪律**（来自既往轮次教训）：
- 修复须触类旁通系统检视同类问题，禁止单点修复（如 CR-01 修复时须排查 filter_return_check 全部形状分支）。
- 每条问题补 finding/no_finding 对照 fixture 并落 `examples/c-vuln-benchmark`；复现测试全量通过后转正为回归测试。
- confirmed 通道收紧后跑 validate-benchmark.py 全量对照；端到端用本地 CLI 二进制验证（单测绿 ≠ 端到端能检出）。
- 修复 DBZ-09 时注意 release/check-extension-consistency.py 是否需要同步加语义检查。