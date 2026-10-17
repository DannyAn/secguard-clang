# null-deref 候选给 AI 研判过多：分析改进方案

> 本文档面向 SecGuard / sgre 检测链路的维护方，目的：通过**可机械判定的特征规则**，在 AI 研判阶段之前把可确定为误报（dismissed）的 null-deref 候选批量过滤掉，把 AI 研判资源集中到真正有证据链的候选上。
>
> 分析基线：secguard-clang v0.9.0，对 NLOG 项目 `src/` 目录的一次完整扫描（scan_id `sc_2026-10-08_100940_8434dc`，1012 文件 / 7057 函数 / 177082 行）。所有结论均来自扫描产物 `candidates.sarif`（候选证据）与 `result.sarif`（确认结果），特征为**模式级**，不依赖本项目的具体业务代码。
>
> 文中所附代码均为**脱敏示意代码**（为展示特征模式而构造），非任何项目生产代码。

---

## 1 问题现状

### 1.1 数量失衡

| 指标 | 值 |
|------|-----|
| null-deref 收敛候选总数 | 2161 |
| 进入 AI 研判阶段的候选 | 2161（100%） |
| AI 研判后确认 | 2 |
| 流水线 auto-confirmed（不占 AI 预算） | 2 |
| 最终确认问题总数 | 4 |
| AI 研判有效率 | 2 / 2161 ≈ **0.09%** |

**即：2161 个候选交给 AI，只有 2 个是真的；99.9% 的 AI 研判工作量消耗在误报上。**

### 1.2 目标

让 sgre 在**收敛/过滤阶段**（AI 分发之前）就识别出可确定为误报的候选并标记 dismissed，将本次扫描的 AI 候选量从 2161 降至 **50 条以内**，且**不遗漏任何一条真实确认**（当前 4 条确认必须全部保留）。

---

## 2 候选特征规律（核心发现）

candidates.sarif 中每条候选都带一条结构化 `message.text`（由检测器预计算），这是规则化判定的最佳输入。按 message 文本模式可将 2161 个候选分成 3 类：

| 类别 | 判定依据（message.text 模式） | 数量 | 占比 | 其中最终确认 |
|------|-------------------------------|-----:|-----:|------------:|
| **A. 参数 not-proven** | `parameter <X> can be NULL: caller <C> passes <X> (not proven non-null)` | 1936 | 89.6% | **0** |
| **B. 赋值后解引用** | `variable <X> is assigned a possibly-null value at line <N> before the dereference` | 224 | 10.4% | **4** |
| **C. certain-null** | `variable <X> is assigned NULL at line <N> ... (certain null-deref)` | 1 | 0.05% | 1（流水线已处理） |

### 2.1 结论一：类别 A 是纯误报，且占绝对多数

- 1936 条（89.6%）候选的消息文本是 **"参数可能为 NULL：调用方传入 X，未证明非空"**。
- 该类候选**没有一条**被最终确认（4 条确认全部落在类别 B）。
- 根因：分析器只证明了 **"调用点实参的 NULL 可达性未知"**（`maybe-null`），并未证明 **"实参真的会为 NULL"**。这类候选在语义上只是"分析器跨函数推断能力不足"，不是缺陷证据。
- 分布特征：被点名的函数高度集中在**内部辅助函数族**（TOP25 函数族覆盖约 1/3 候选，如 `nlog_sqlbind_*`、`nlog_custom_rpt_*`、`nlog_tsdb_*`、`nlog_url_*`、`nlog_thrt_*`、`nlog_cache_set_*` 等），被点名的参数名也高度集中（TOP25 参数名覆盖约 1000 条，如 `log`、`thrt_log`、`cond`、`msg_head`、`sql_cond`、`stmt`、`index` 等业务对象/输出参数）。

### 2.2 结论二：类别 B 才有证据链，应保留给 AI

- 224 条（10.4%）候选带**具体的 NULL 来源行**（`assigned ... at line N`），是真实的"赋值→解引用"数据流。
- 当前全部 4 条确认都来自这一类，说明**只有带具体来源行的候选才有研判价值**。
- 类别 B 还可细分：
  - **B-local（136 条）**：NULL 来源是本地赋值语句（`var = foo();`），确认 3 条。
  - **B-line0（88 条）**：NULL 来源是**函数返回值**（`at line 0`），确认 1 条。

### 2.3 结论三：带来源行的候选里，还有一半是"判空守卫"误报

对带 `src@N` 来源行的候选（共 137 条）按其解引用语句（Source 列）再分类：

| 子类 | Source 语句形态 | 数量 | 说明 |
|------|----------------|-----:|------|
| **判空守卫** | 解引用发生在 `if (<X> == NULL \|\| <X>->...)` 判空表达式的**短路分支内** | 118 | 判空守卫已生效，属误报 |
| **直接解引用** | `X->field = ...;`、`msg.x = *X;` 等无守卫访问 | 19 | 其中 2 条为 AI 确认，1 条为流水线确认 |

**规律：Source 语句以 `if (` 开头的判空候选 → 误报；Source 语句是直接字段解引用 → 有确认价值。**

### 2.4 结论四：Hint 体系已具备规则化基础

`_index.md` 的 Hint 列（pipeline 预计算事实）分布：

| Hint | 数量 | 语义 |
|------|-----:|------|
| `maybe-null` | 1827 | 无具体 NULL 来源行（= 类别 A 主体） |
| `maybe-null macro-context` | 197 | 宏上下文（最高假阳性风险） |
| `src@N maybe-null` | ~133 | 有具体 NULL 来源行（= 类别 B 主体） |
| `src@N certain-null` | 1 | 确定性 NULL（流水线已确认） |

---

## 3 规则化 dismissed 方案（在 sgre 过滤链实现）

### 3.1 规则总览

| 规则 | 触发条件 | 本次命中 | 误杀确认 | 建议实现位置 |
|------|----------|--------:|:--------:|--------------|
| **R1** 参数 not-proven 抑制 | message 匹配 `parameter <X> can be NULL: caller <C> passes <X> (not proven non-null)`，且 Hint 不含 `src@N`、不含 `certain-null` | ~1936 | 0（该集合 0 确认） | 过滤链，`nullable_source` 之后、AI 分发之前 |
| **R2** 弱守卫抑制 | Hint 含 `src@N`，且 Source 语句以 `if (` 开头（判空短路表达式） | 118 | 0 | 过滤链或 Hint 生成阶段 |
| **R3** 宏上下文抑制 | Hint 为 `maybe-null macro-context`，且宏展开后语义为访问器/迭代器/非空守卫 | 197 | 0 | 过滤链，需宏展开校验 |

> 三条规则命中集合存在少量重叠（如 R1 与 R3 都命中的 `maybe-null macro-context` 参数候选），实际**去重后可覆盖 >99% 的候选**。剩余给 AI 的候选约 40~50 条，全部带 `src@N` 证据链。

### 3.2 规则语义与实现要点

**R1 —— 参数 not-proven 抑制**

- 判定完全基于 message 文本与 Hint 维度，无需源码读取。
- 语义依据：`not proven non-null` 是"分析器无法证明非空"，不是"证明可为空"。对内部辅助函数族（函数名符合 `模块前缀 + 业务操作`，被多调用点复用），实参由上层业务逻辑保证非空。
- 可配置开关（默认 on，可降级）：`suppress_unproven_caller_param: true/false`。
- 补充建议：对命中 R1 的函数，如检测器后续能在**任一调用点**证明实参非空，可将该函数整体加入"内部契约非空"白名单，避免后续重复上报。

**R2 —— 弱守卫抑制**

- 判定依据：`src@N` 来源行对应语句（即候选的 Source）为 `if (<X> == NULL || ...)` 判空表达式，解引用发生在短路守卫之后。
- 注意区分：Source 是**直接字段解引用**（如 `X->field = ...`）的候选**不得**被 R2 命中——那正是真实缺陷（本次 2 条 AI 确认 + 1 条流水线确认都属于此类）。

**R3 —— 宏上下文抑制**

- Hint 为 `macro-context` 时，候选证据可能来自宏展开，分析器的流证明可能失真。
- 需对宏做一次展开/语义校验：若宏为**非空守卫**（`*CHECK*`/`*ASSERT*`）、**访问器/迭代器**（`ITEM_FIRST`、`LIST_FOR_EACH`），或无法推断宏语义 → 一律 dismissed（不得 confirmed）。

### 3.3 Hint 体系增强建议

在现有 `src@N` / `certain-null` / `maybe-null` / `macro-context` 基础上，新增两个显式维度，让规则化判定下沉到 Hint 生成阶段：

| 新增 Hint 维度 | 含义 | 对应规则 |
|----------------|------|----------|
| `param-not-proven` | 参数空值来源为"调用方未证明非空" | R1 |
| `weak-guard` | NULL 来源行的解引用受判空短路守卫保护 | R2 |

---

## 4 特征样例（脱敏示意代码）

以下代码为展示特征模式而构造，与任何生产代码无关。**规则应基于 message/hint 契约判定，不依赖具体代码内容。**

### 4.1 模式 P1：参数 not-proven（R1 应抑制）

```c
/* 内部辅助函数：入参由上层业务逻辑保证非空 */
static int fill_log_item(log_item_t *item, sqlite3_stmt *stmt, int *idx)
{
    /* 检测器在此上报：parameter stmt / idx can be NULL: caller ... (not proven non-null) */
    int ret = sqlite3_bind_int(*stmt, (*idx)++, item->id);  /* deref 行 */
    return ret;
}

int handle_query(query_ctx_t *ctx)
{
    sqlite3_stmt *stmt = prepare_stmt(ctx->db);
    if (stmt == NULL) {
        return -1;              /* 调用点已判空 */
    }
    int idx = 1;
    log_item_t item = {0};
    return fill_log_item(&item, stmt, &idx);  /* 实参实际非空，但跨函数推断失败 */
}
```

- **message 特征**：`parameter stmt can be NULL: caller handle_query passes stmt (not proven non-null)`；`parameter idx can be NULL: ... (not proven non-null)`
- **Hint 特征**：`maybe-null`（无 `src@N`）
- **规则**：R1 → dismissed。

### 4.2 模式 P2：本地赋值 NULL 后无守卫解引用（保留给 AI，可确认）

```c
channel_t *get_channel(int module, int chan)
{
    if (module >= MODULE_MAX || chan >= CHAN_MAX) {
        return NULL;            /* 越界返回 NULL */
    }
    return &g_channels[module][chan];
}

void recover_channel(void)
{
    channel_t *ch = get_channel(g_module, g_chan);  /* src@150：可能为 NULL */
    g_msg.enable = ch->enable;                      /* 无判空，直接解引用 → 真实缺陷 */
}
```

- **message 特征**：`variable ch is assigned a possibly-null value at line 150 before the dereference at line 153`
- **Hint 特征**：`src@150 maybe-null`；Source 为**直接字段解引用** `ch->enable`
- **规则**：不命中 R1/R2/R3 → 保留给 AI → AI confirmed。

### 4.3 模式 P3：判空守卫短路解引用（R2 应抑制）

```c
void set_user_name(char *name)
{
    name = lookup_user_name();                     /* src@51：可能为 NULL */
    if (name == NULL || name[0] == '\0') {         /* 判空短路：name[0] 不会在 NULL 上求值 */
        return;
    }
    save(name);
}
```

- **message 特征**：`variable name is assigned a possibly-null value at line 51 ...`
- **Hint 特征**：`src@51 maybe-null`；但 **Source 以 `if (` 开头**（判空表达式）
- **规则**：R2 → dismissed。

### 4.4 模式 P4：宏上下文（R3 应抑制）

```c
#define ITEM_FIRST(list)  ((list)->head)   /* 访问器宏：调用方保证 list 非空 */
#define ITEM_NEXT(it)     ((it)->next)

void walk_list(list_t *l)
{
    for (item_t *it = ITEM_FIRST(l); it != NULL; it = ITEM_NEXT(it)) {
        process(it);
    }
}
```

- **Hint 特征**：`maybe-null macro-context`
- **规则**：宏展开校验语义为访问器/迭代器，或无法推断宏语义 → R3 → dismissed（不得 confirmed）。

---

## 5 验证与验收标准

厂商实现后，请在本扫描产物（candidates.sarif + result.sarif）上做回归验证：

1. **数量目标**：R1+R2+R3 生效后，null-deref AI 候选 ≤ 50 条（原 2161 条）。
2. **零误杀**：规则命中集合与 4 条已确认 finding 的交集必须为空（4 条确认全部保留）。
3. **幂等**：规则重复执行不改变已写结果（dismissed 不覆盖 confirmed）。
4. **可观测**：每个被规则抑制的候选应记录触发规则（如 `suppressed_by: R1`）与理由，便于抽样审计。
5. **可配置**：R1 提供开关，默认开启；关闭后回退到原行为。

建议在 CI 中加入"AI 候选量/确认率"监控：若某类型 AI 候选量显著高于确认数（如 >50:1），自动提示检测器过宽，触发规则审计。

---

## 6 推广价值（其他类型复用）

本次扫描的其他类型同样存在"候选量大、确认率低"的结构，message 模式归类思路可复用：

| 类型 | 候选 | 确认 | 疑似可规则化的 message 模式 |
|------|-----:|-----:|------------------------------|
| integer-overflow | 191 | 0 | `caller passes ... (not proven)` 类参数推断、`+1 % N` 模式 |
| divide-by-zero | 159 | 3 | 除数来源为全局计数/容量字段（未配置时可为 0） |
| uninit | 95 | 0 | 分配后字段初始化推断（allocated at line N） |
| buffer-overflow | 6 | 0 | `fread(buffer, size, 1, fp)` 读文件大小与缓冲区不匹配推断 |

统一思路：**优先从 message.text 提取可机械判定的结构特征，将"证据链不足"的候选在过滤链阶段 dismissed，而非交给 AI。**

---

## 7 风险与边界

1. **R1 的理论漏报**：极端情况下，内部函数某参数确实可为 NULL 且调用点全部无守卫——本扫描 0 例，但 R1 应做成可配置开关而非硬编码，便于厂商在其它代码库按需关闭。
2. **R3 依赖宏语义**：无法推断宏契约时保持 dismissed（符合"存疑即 dismiss"原则），不会误报。
3. **规则基于 message/hint 契约**：只要 message/hint 格式稳定，规则即跨项目通用；若格式变更，需同步更新规则匹配器。
4. **不建议**：直接按函数名/参数名硬编码（本项目的 `nlog_*` 前缀不具备跨项目通用性）——应采用本文 R1/R2/R3 的**结构特征**，而非名称特征。
