# PR #229 评审意见处理记录

> 评审来源：PR #229 评论（DannyAn，2026-11-05），结论 **Request Changes**：方向认可，完成 P0/P1 修订后再合入；当前不批准进入 Phase 1。
> 本文逐项记录处理结果、修改位置、设计决策、未解决风险与对后续 Phase 的影响。
> 对应文档：
> - [four-semantic-gaps-analysis.md](four-semantic-gaps-analysis.md)（v2）
> - [four-semantic-gaps-implementation-plan.md](four-semantic-gaps-implementation-plan.md)（v2）
>
> **本轮范围**：只修订设计文档，不修改生产代码，不启动 Phase 1 施工。

---

## 1. 处理结果总览

| 评审项 | 处理 | 主要修改位置 | 对后续 Phase 的影响 |
|---|---|---|---|
| P0-1 Type Layout 不能把 target triple 当 ABI 证明 | **采纳** | 分析 §3.1/§3.2/§5.3–§5.7；计划 Phase 1 §4.1–§4.7 | Phase 1 必须先做 per-TU 配置 + provenance/confidence；`assumed`/`unknown` 不 confirmed |
| P0-2 Guard Witness 必须证明当前访问仍受保护 | **采纳** | 分析 §4.3D/§4.4/§4.5/§4.7；计划 Phase 2 §5.3–§5.6 | Phase 2 只有 `proof_status=must` 才能 dismiss；CFG 支配只是必要条件 |
| P0-3 Global Write Summary 不能直接作为 Consumer 入口 NULL 状态 | **采纳** | 分析 §6.3–§6.7；计划 Phase 3 §6.2–§6.5 | Phase 3 只做 may-only 来源摘要，**不承诺 confirmed** |
| P0-4 Output Parameter 不能假设 0 成功、非 0 失败 | **采纳** | 分析 §7.3–§7.7；计划 Phase 4 §7.3–§7.7 | Phase 4 必须 Return Contract + 字段/子对象覆盖；unknown 合约不 confirmed |
| P0-5 补充 Evidence Completeness 验收 | **采纳** | 分析新增 §3.4；计划 §3.4 + 各 Phase 退出标准 + §8.5/§9/§12 | 每个 Phase 验收必须引用证据表，不以“命中样例”作为完成标准 |
| P1-1 删除按 Phase 预估代码行数 | **采纳** | 计划 §2 表格、§1.2、§12 | 改为“最小必要范围 + 必须通过的证据/测试” |
| P1-2 性能预算要有可复现测量方法 | **采纳** | 计划 §3.6、§8.3、§8.4 | 同机/同数据集/多次/median/P90/冷热增量；token 无采集写“未测量” |
| P1-3 每个 Phase 明确 unsupported cases 与降级 | **采纳** | 计划 Phase 1 §4.6、Phase 2 §5.5、Phase 3 §6.4、Phase 4 §7.6 | 未知/不完整信息降级为 Unknown/Suspected/AI_REQUIRED，不静默乐观 |

**不采纳/本轮不做（不是拒绝评审意见）**：

- **Clang AST Record Layout Dump 集成**：评审明确“本轮不要求为了这一项立即引入 Clang 依赖”。设计保留为未来可选数据源（`compiler_proven`），Phase 1 不实现。
- **代码行数目标**：按 P1-1 删除；不再以行数作为任何交付指标。
- **四类 Gap 同时施工**：按评审 §5 只启动 Phase 1（1038）。

---

## 2. P0 逐项处理

### P0-1：Type Layout 的 TU/编译配置维度

**采纳内容**

1. Layout key 从“类型名”改为 `(TU, Config, Type)`；同名类型跨 TU/宏配置不得无条件合并（分析 §3.2、§5.3）。
2. 新增 layout provenance / confidence 四档：
   - `compiler_proven`；
   - `derived_from_complete_config`；
   - `assumed_default_abi`；
   - `unknown`。
3. 明确 target triple 只是输入之一；补充 `-fpack-struct`、`-fshort-enums`、`#pragma pack`（含 push/pop）、`__attribute__((packed/aligned))`、条件编译、typedef/匿名/嵌套/位域/柔性数组等因素。
4. 缺失编译参数或 pack/alignment 未知 → `assumed_default_abi`/`unknown`；**禁止** ABI-proven Confirmed。
5. `compile_commands.json` 需要逐 TU 的 `File/Directory/Arguments`，当前全局 union `-D/-I` 不足；Phase 1 前置增加 per-TU 配置。
6. 布局算法、字段偏移/大小未知条件、同 TU 冲突处理写入 §5.3；判定边界写入 §5.4。
7. 测试矩阵增加不同 pack/alignment/TU/宏配置、缺失参数、short-enums、bitfield/flexible array、正反例（§5.7、计划 §4.5）。

**设计决策与理由**

- 不把 target triple 当完整 ABI 证明：同一 target 下 pack/alignment 仍可改变偏移；用 `Provenance` 表达“证据来自哪里”，而不是用一个布尔 `Assumed`。
- 不允许全局合并同名类型：同一 struct tag 在不同 TU 可能因宏/编译参数不同而布局不同；全局合并会把一个 TU 的偏移错误应用到另一个 TU。
- Phase 1 默认不新增 confirmed proof class：先把来源/适用范围做可信，等独立评审再决定是否允许 `layout_oob_*` confirmed。

**未解决风险**

- 条件编译的完整求值仍可能不完整；MVP 对无法求值的类型标 unknown，可能漏报。
- `#pragma pack` 作用域、复杂 attributes、编译器扩展的解析成本较高；Phase 1 只覆盖常见情况。
- Clang record layout 作为 `compiler_proven` 数据源未实现；`derived_from_complete_config` 的可信度依赖 per-TU 配置解析的完整性。

### P0-2：Guard Witness 的完整证据

**采纳内容**

1. 明确 `ReachesAvoiding`/CFG 支配只是必要条件，不能替代谓词语义、对象/容量关联、稳定性。
2. 新增结构化字段：`guard_location/access_location/guard_predicate/branch_polarity/index_binding/buffer_object_binding/capacity_binding/index_stable/buffer_stable/length_stable/alias_stability/call_side_effect_status/proof_status`（分析 §4.3D、计划 §5.3）。
3. 要求同时回答 7 个问题：控制流、谓词语义、对象/容量关联、稳定性、alias/副作用、整数语义、路径形状。
4. 只有 `proof_status=must` 才能 dismiss；`may`/`unknown` 保留 suspected/AI_REQUIRED。
5. 评审给出的三个反例全部进入测试矩阵：
   - guard 后 `buffer` 被替换；
   - guard 后 `length` 被重赋值；
   - guard 检查 `other_buffer_length`。
6. 追加 index/buffer/length 重赋值、alias 写入、中间调用副作用、负索引、`<`/`<=`、`&&`/`||`、early return、循环、多分支测试。

**设计决策与理由**

- 不把 guard 做成一个布尔：同一 `index < length` 在不同 buffer/length 生命周期下含义不同；必须把“谓词、对象、容量、稳定性”拆开，才能审计和回归。
- 不把 CFG 支配当保护：支配只说明路径经过 guard 节点，不说明谓词约束了访问对象；反例 1/3 说明这一点。
- `must` 才 dismiss：dismiss 是“证明安全”，必须比“可能安全”更严格；may/unknown 保留给 AI。

**未解决风险**

- alias 分析、函数调用副作用的精度有限；Phase 2 对无法证明的情况只能保留 suspected，可能增加候选量。
- 循环内守卫/多分支短路组合的谓词规范化复杂；MVP 只覆盖常见形态，其他标 unknown。
- `index * elemSize` 的溢出证明依赖 Type Layout；layout unknown 时不能 confirmed。

### P0-3：Global Write Summary 的语义

**采纳内容**

1. 明确 Global Write Summary 是**来源摘要**，不是 Consumer 入口状态；区分四层：writer 存在 / 路径可能写 NULL / 实际调用执行 / Consumer 当前值（分析 §6.3、计划 §6.2）。
2. 禁止把 may-write 直接播种成 Consumer CFG Entry 的确定 NULL；`global_write` 只允许 `ProofStatus=may`，`nullSource.definite=false`。
3. Confirmed 最低条件按评审 5 条写入：来源可确定、调用上下文/顺序可证、无覆盖、无未知外部 writer/escape/并发、可达且无有效 guard。
4. Phase 3 **不承诺** `global_write` confirmed；若未来实现调用点内联/顺序证明，必须满足 5 条并单独评审。
5. static/extern 全局身份区分；同名 static 不合并；`&g` 逃逸、`memcpy(&g,...)`、函数指针/外部 writer、并发/volatile/atomic 均降级。
6. 测试矩阵覆盖单/多 writer、覆盖、条件、writer 未被调用、未知 writer、escape、并发、同名 static（分析 §6.7、计划 §6.3）。

**设计决策与理由**

- “可能写 NULL”是 may 事实，不能变成 Consumer 入口的 must 状态；否则会把路径相关事实错误提升为全局事实。
- Phase 3 不承诺 confirmed 是保守选择：当前 per-function flow engine 不能证明跨函数全局状态；先交付可解释的来源摘要，避免错误确认。
- 保留现有 `detectStaticNullGlobals` 的 static-only 通道：它是“从未被写入”的声明事实，与新的写入来源摘要语义不同。

**未解决风险**

- 完整调用顺序/覆盖证明未实现；Phase 3 只能 suspected。
- 外部 writer、函数指针、escape、并发无法完全建模；只能降级，可能漏报。
- 同名 static/extern 混用、跨 TU 全局身份仍需保守处理。

### P0-4：Output Parameter 的 Return Contract 与字段级覆盖

**采纳内容**

1. 新增 `ReturnContract`：成功集合、失败集合、其他/未知集合、来源、置信度（分析 §7.3、计划 §7.2–§7.3）。
2. 禁止硬编码 `return 0` 成功、非 0 失败；“调用者检查了返回值”不等于“检查了成功”；unknown 合约不得 dismiss/confirmed。
3. 逐 return path 记录 `ReturnClass/WriteLines/WholeParam/Fields/Covered`；字段/子对象覆盖区分 `out->status` 与整个 `Result`。
4. 调用者消费：success 分支只在合约+覆盖完整时不报；error 分支只在 must-uninit + 合约+未覆盖时 confirmed；未检查返回值只 suspected；字段不匹配不得 dismiss。
5. 测试矩阵增加 0 成功、非 0 成功、多成功码、多失败码、负数错误码、枚举、unknown 合约、字段级覆盖（分析 §7.4–§7.6、计划 §7.4）。
6. 保留 `TestUninit_OutputParamUnguarded`，但明确测试期望的变更需要评审批准（分析 §7.5、计划 §7.5）。

**设计决策与理由**

- Return Contract 是“成功/失败”的唯一来源；没有合约时不能用经验猜测，否则会把“检查返回值”误当成“检查成功”。
- 字段级覆盖是防误报关键：`ParamWrites` 参数级事实不能证明整个 struct 已初始化；调用者读取的字段必须匹配。
- 未检查返回值保持 suspected：这是 may 证据，符合仓库 `confirmed=must` 语义。

**未解决风险**

- 项目内显式返回约定/API contract 的覆盖有限；很多函数会落到 unknown，只能 suspected。
- helper/宏/函数指针间接写入的字段覆盖仍可能不完整。
- `TestUninit_OutputParamUnguarded` 的期望变更尚未获最终批准；未批准时 C 场景保持 Remaining Gap。

### P0-5：Evidence Completeness 与 provenance

**采纳内容**

1. 分析新增 §3.4：按 Gap 定义 Confirmed 必须具备的证据（1029/1038/1031/1140）。
2. 明确证据不完整时可以保留候选/AI，但不能仅凭函数名、变量名、注释或模式相似度升级 Confirmed。
3. finding 必须保留 provenance：source / compile-config / repofacts / cfg / contract / heuristic；不得混写。
4. 计划 §3.4、各 Phase 退出标准、§8.5、§9、§12 都引用证据完整性验收。
5. 新增“已支持/部分支持/未支持/未验证”报告分类，禁止把“设计上计划支持”写成“当前已支持”。

**未解决风险**

- 证据完整性的“完整性”需要人工抽查；没有自动化完备性检查器。
- provenance 字段的落库/渲染需要 Phase 实现时确认（候选 evidence token / finding 属性）。

---

## 3. P1 逐项处理

### P1-1：删除代码行数估算

- 计划 §2 表格删除“预计改动量（含测试）”，改为“最小必要范围（非行数目标）”。
- §1.2 明确“不以代码行数作为完成标准”。
- §12 DoD 增加“不以代码行数作为完成标准”。
- 每个 Phase 改为：最小必要实现范围、事实复用说明、必须通过的测试、Evidence Completeness、precision/recall、性能/Token、未解决问题。

### P1-2：性能测量方法

- 计划 §3.6 增加：同机同数据集同编译/扫描参数；同环境；多次运行 median/P90；冷启动/热缓存/增量；wall time/peak RSS/文件数/函数数/事实数；token 无采集写“未测量”。
- §8.3 baseline 命令注明至少 3 次；§8.4 对照表增加 median/P90、TP/FP/FN、证据完整性、provenance 分布、降级验证。
- 明确“性能预算是门槛，不是牺牲准确率的理由”。

### P1-3：每个 Phase 的 unsupported cases 与降级

新增：

- Phase 1 §4.6：无 compile_commands/缺 TU entry、pack/alignment 未解析、条件编译、跨 TU 冲突、bitfield/flexible array、第三方头文件、指针偏移/union/realloc、部分字段。
- Phase 2 §5.5：无容量证据、关联不成立、guard may/unknown、稳定性/alias/副作用未知、间接调用、元素大小/ABI unknown、多调用点冲突、负索引。
- Phase 3 §6.4：writer 集合不完整、调用顺序不可证、覆盖/多 writer、并发、同名 static/extern、escape、仅可能写 NULL。
- Phase 4 §7.6：Return Contract 未知、复杂返回值、字段部分覆盖、未知 helper/宏/函数指针、循环条件写入、caller 分支不匹配、间接/别名写入。

降级统一定义为 `Unknown` / `Suspected` / `AI_REQUIRED`，禁止静默乐观假设。

---

## 4. 两份文档的交叉一致性检查

| 检查项 | 结果 |
|---|---|
| 事实名称 | 两文档统一使用 `TypeLayout`/`LayoutKey`/`Provenance`、`CallSiteBinding`、`GuardWitness`、`GlobalWriteFact`/`GlobalWriteIndex`、`ReturnContract`/`ParamReturnCoverage` |
| Confirmed 语义 | 两文档统一为 must；may 只能 suspected/AI_REQUIRED |
| Layout 判定 | 两文档统一：`compiler_proven`/`derived_from_complete_config` 才可讨论 confirmed；`assumed_default_abi`/`unknown` 不 confirmed |
| Guard 判定 | 两文档统一：只有 `proof_status=must` 才 dismiss；CFG 支配只是必要条件 |
| Global Write | 两文档统一：来源摘要、may-only、Phase 3 不承诺 confirmed |
| Output Param | 两文档统一：Return Contract + 逐 return path + 字段/子对象覆盖；unknown 不 confirmed |
| Evidence Completeness | 分析 §3.4 的表与计划 §3.4/§8.5/§9 引用同一组证据项 |
| 施工顺序/门禁 | 两文档统一：1038 → 1029 → 1031 → 1140；当前只启动 Phase 1 |
| 持久化 | 两文档统一：MVP 不新增表/枚举；layout/callsite/global write 内存；output summary 扩展 `summary_json` |
| 降级 | 两文档统一：unknown/assumed → suspected/AI 或不出；不猜测 |

未发现未处理的矛盾。需要说明的“有意差异”：分析文档给出更多代码路径与事实模型细节，计划文档给出施工/测试/验收；两者引用同一事实与判定边界。

---

## 5. 反例与测试描述复核

评审要求“检查所有示例代码和测试描述，确保反例确实能击穿对应的错误假设”。本轮逐项复核：

| 反例/测试 | 击穿的错误假设 | 结果 |
|---|---|---|
| `buffer = another_buffer` 后 `buffer[index]` | “guard 支配访问 ⇒ 保护成立” | 已加入 1029 反例与测试（buffer 替换） |
| `length = 1` 后 `buffer[index]` | “guard 出现过 ⇒ 检查仍有效” | 已加入 1029 反例与测试（length 重赋值） |
| `other_buffer_length` 保护 `buffer` | “任意 length 都是当前 buffer 容量” | 已加入 1029 反例与测试（对象/容量关联） |
| index 重赋值 / alias 写入 / 调用副作用 | “guard 后变量稳定” | 已加入 1029 稳定性测试 |
| `-fpack-struct` / `#pragma pack` 同一源码 | “target triple 决定布局” | 已加入 1038 不同配置测试 |
| 同名类型不同 TU/宏配置 | “同名类型可以全局合并” | 已加入 1038 TU/宏测试 |
| 无 compile_commands/缺 pack 信息 | “默认 LP64 可以 ABI-proven” | 已加入 1038 assumed/unknown 测试 |
| writer 未被调用 / 先写后覆盖 | “存在 NULL writer ⇒ Consumer 当前 NULL” | 已加入 1031 测试（不承诺 confirmed） |
| `&g` 逃逸 / 函数指针 / 外部 writer | “writer 集合完整” | 已加入 1031 unknown/降级测试 |
| 0 成功 / 非 0 成功 / 多成功码 | “0 成功、非 0 失败” | 已加入 1140 Return Contract 测试 |
| `out->status` 写入、caller 读 `out->data` | “参数级写入 = 整体初始化” | 已加入 1140 字段/子对象测试 |
| unknown 返回合约 + caller 检查返回值 | “检查返回值 = 检查成功” | 已加入 1140 unknown 合约测试（不得 dismiss/confirmed） |

---

## 6. 未解决风险与开放问题

1. **Phase 1 是否新增 `layout_oob_*` confirmed proof class**：默认不新增，Phase 1 只 suspected；需要独立评审决定。
2. **`TestUninit_OutputParamUnguarded` 期望**：改为“不 confirmed、允许 suspected”还是保持完全静默；需评审批准。
3. **1029 常量越界确认语义**：是否沿用“常量边界 + 已知容量”的 confirmed；前提是 Guard Witness 完整。
4. **Type Layout 落点**：算法放 `internal/typeinfo` + census 扩展 `repofacts`，还是全部塞进 `repofacts`。
5. **无 compile_commands 时**：只出 suspected 还是直接不报。
6. **宽度表收敛时机**：Phase 1 前置（推荐）还是 Phase 5。
7. **持久化策略**：MVP 不新增表/枚举；是否需要为 layout/global write 做跨扫描持久化。
8. **性能预算**：+10% / +50MB 是否接受为初始预算（方法论已按 P1-2 补齐）。
9. **Clang Record Layout Dump**：未来可选数据源，Phase 1 不实现；如果后续引入，需要重新评估依赖/构建成本。
10. **证据完整性自动化**：当前依赖人工抽查；后续可考虑机器校验器。

---

## 7. Phase 1 严格施工边界

按评审 §5/§7：

**只做**：

- 1038 Type Layout 基础层；
- per-TU 编译配置（至少 target/pack/short-enums/defines 的提取与 `ConfigKey`）；
- layout provenance/confidence；
- 独立 `layout_oob_*` 候选（默认 suspected）；
- 正反测试 + Evidence Completeness + 性能测量；
- 文档/token/边界登记（仅当新增 confirmed proof class 并获批准）。

**不做**：

- 不启动 1029/1031/1140；
- 不修改现有 `confirmed` 门槛；
- 不新增 SQLite 表/事件类型/边类型；
- 不引入未测量的全局缓存；
- 不把 assumed/unknown layout 升级为 confirmed；
- 不以代码行数作为完成标准。

**门禁**：Phase 1 独立 PR、独立测试、独立评审；通过后才允许启动 Phase 2。若 Phase 1 的 layout 来源/适用范围仍不可信，应停在 suspected-only，并把剩余风险写入 Remaining Gap，而不是进入 1029。
