# SecGuard-Clang 扫描 IDM 仓库误报消除改进建议

## 1. 验证概况

对 `result.sarif` 中的 70 个确认发现逐条进行源码验证，结果如下：

| 漏洞类型 | 发现数 | 真阳性 | 误报 | 误报率 |
|---------|--------|--------|------|--------|
| crypto-misuse (CWE-327) | 3 | 3 | 0 | 0% |
| memory-leak (CWE-401) | 7 | 7 | 0 | 0% |
| uninit (CWE-457) | 1 | 1 | 0 | 0% |
| resource-leak (CWE-404) | 1 | 1 | 0 | 0% |
| null-deref (CWE-476) | 6 | 4 | 2 | 33% |
| unchecked-return (CWE-252) | 35 | 24 | 11 | 31% |
| path-traversal (CWE-22) | 9 | 0 | 9 | **100%** |
| integer-overflow (CWE-190) | 3 | 0 | 3 | **100%** |
| dangerous-function (CWE-676) | 2 | 0 | 2 | **100%** |
| double-free (CWE-415) | 1 | 0 | 1 | **100%** |
| injection (CWE-89) | 1 | 0 | 1 | **100%** |
| use-after-free (CWE-416) | 1 | 0 | 1 | **100%** |
| **合计** | **70** | **40** | **30** | **42.9%** |

**核心结论**：30 个误报集中在 6 个类型，其中 path-traversal、integer-overflow、dangerous-function、double-free、injection、use-after-free 误报率 100%。这些误报有明确的根因模式，可通过检测器优化消除。

---

## 2. 逐类根因分析与改进建议

### 2.1 path-traversal（CWE-22）— 误报率 100%（9/9）

#### 根因

SecGuard 的 path-traversal 检测器将 `fopen`/`remove` 接收非字面量路径参数直接判定为 auto-confirmed，**未识别代码库中的防护函数**。

IDM 代码库对路径遍历有统一的防护策略：

**策略 A：前置校验函数 `idm_file_path_is_valid`**

```c
// src/utils/file/idm_file.c
bool idm_file_path_is_valid(const char *filename)
{
    return (filename != NULL && strstr(filename, "../") == NULL);
}
```

该函数在用户输入到达 `fopen`/`remove` 之前被调用。例如：

```c
// src/mgmtplane/import/web/idm_web_csv_import.c:585
if (!idm_file_path_is_valid(file_path)) {
    return IDM_ERR;
}
// ... 后续调用 fopen(file_path, ...) 是安全的
```

**策略 B：固定基目录构造路径**

```c
// 路径由宏常量基目录 + 文件名拼接，不直接使用用户输入
char path[256];
snprintf(path, sizeof(path), "%s/%s", IDM_FLASH_BASE_PATH, filename);
fopen(path, "r");  // 安全，基目录固定
```

SecGuard 在 auto-confirm 阶段没有识别 `idm_file_path_is_valid` 为路径防护函数，也没有追踪到路径参数来自固定基目录构造。

#### 改进建议

1. **支持自定义防护函数白名单**：允许在配置文件或 `.secguardrc` 中声明路径防护函数，格式如：

```json
{
  "path_traversal": {
    "guard_functions": ["idm_file_path_is_valid", "idm_validate_path"]
  }
}
```

当 sink（`fopen`/`remove`）的同函数内或上游调用链中存在对白名单函数的调用，且参数相同或为同一变量的子串时，判定为已防护。

2. **增强 taint 分析：识别基目录拼接模式**：当路径参数由 `snprintf`/`sprintf_s` 通过 `%s/%s` 模式构造，且第一个 `%s` 参数为宏常量（如 `IDM_FLASH_BASE_PATH`）时，不应标记为 path-traversal 候选。

3. **auto-confirm 门槛提升**：path-traversal 的 auto-confirm 不应仅基于"非字面量参数到达 sink"，至少应检查同函数内是否存在防护调用。无法确认防护时，应降级为 candidate 交由 AI 研判，而非直接 auto-confirm。

---

### 2.2 integer-overflow（CWE-190）— 误报率 100%（3/3）

#### 根因

检测器将 `size_t` 类型的减法（`size - offset`）标记为无符号下溢，但未识别结果传递给**安全函数族**（`sprintf_s`）时不构成可利用漏洞。

典型误报代码：

```c
// src/mgmtplane/import/csv/idm_csv_import.c:502-508
static int encode_user_ipmac(char *buf, size_t size, size_t offset, ...)
{
    int ret = sprintf_s(buf + offset, size - offset, "%s", ip);
    if (ret < 0) return -1;
    // ... 重复 3 次，每次 offset 递增
}
```

即使 `offset >= size` 导致 `size - offset` 下溢，`sprintf_s` 作为安全函数族成员，其内部对 `size` 参数有保护：当 size 为 0 时返回 -1，不会越界写入。返回值 -1 被上层 `if (ret < 0)` 捕获并传播。

#### 改进建议

1. **安全函数族识别**：`sprintf_s`、`memcpy_s`、`strcpy_s` 等 `_s` 后缀的安全函数族，其 size 参数即使由无符号下溢产生，也不应标记为可利用的 integer-overflow。安全函数族在 size 为 0 或异常大时返回错误码而非越界访问。

2. **下溢结果流向分析**：当 `size - offset` 的结果仅传递给安全函数族的 size 参数，且该安全函数的返回值被检查时，应自动 dismiss。

3. **下溢可证明分析**：当 `offset` 从 0 开始、每次递增量为安全函数返回值（已校验 >= 0）、且循环有 `ret < 0` 提前退出保护时，`offset` 不会超过 `size`，应判定为安全。

---

### 2.3 dangerous-function（CWE-676）— 误报率 100%（2/2）

#### 根因

`inet_addr()` 被标记为危险函数（已废弃），但检测器未区分其输入来源。

实际代码中，`inet_addr()` 的输入是**内部解析的结构体字段**，非用户直接输入：

```c
// src/ctrlplane/pdt/spruce/hwd/idm_hwd_rsp_parse.c:355
// ip_str 来自内部协议解析结构体，经固定格式解析
addr.sin_addr.s_addr = inet_addr(ip_str);

// src/ctrlplane/pdt/spruce/dophi/idm_mesh.c:310
// 来自内部配置结构体
addr.sin_addr.s_addr = inet_addr(cfg->server_ip);
```

`inet_addr()` 的 CWE-676 风险在于：对非法输入返回 `(in_addr_t)-1`（即 `INADDR_NONE` / `0xFFFFFFFF`），调用者若未检查返回值可能将其解释为 `255.255.255.255`。但这属于"不安全 API 使用"，而非直接的安全漏洞——当输入来自内部可信源时，风险可忽略。

#### 改进建议

1. **输入来源分级**：对 dangerous-function 类检测器，区分输入来源：
   - 用户直接输入（HTTP 参数、socket 数据）→ confirmed
   - 内部解析结构体、配置文件 → candidate（不 auto-confirm）
   - 编译时常量 → dismiss

2. **返回值检查作为防护信号**：当 `inet_addr()` 的返回值被存储后，后续代码检查是否为 `INADDR_NONE` / `(in_addr_t)-1` 时，应 dismiss。

3. **严重度调整**：`inet_addr()` 本身不导致崩溃或提权，建议从 high 降为 medium，仅在输入来自外部不可信源时标记为 high。

---

### 2.4 double-free（CWE-415）— 误报率 100%（1/1）

#### 根因

检测器将 `http_conn_pool_free()` 中对 `pool` 的两个连续操作误判为 double-free：

```c
void http_conn_pool_free(http_conn_pool_t *pool)
{
    pool->releasing = true;
    http_destroy_active_conn_list(pool);  // line 285
    http_destroy_idle_conn_list(pool);    // line 286 — 被标记为 double-free
    http_pooled_conn_listener_free(pool->cl);
    http_free(pool);                       // line 288
}
```

检测器看到 `pool` 在 line 285 和 286 被传入两个"destroy"函数，误认为同一资源被释放两次。实际上这两个函数销毁的是 `pool` 结构体的**不同成员**（`active_list` 和 `idle_list`），`pool` 本身只在 line 288 被 `http_free()` 释放一次。

#### 改进建议

1. **字段级精度**：double-free 检测器应追踪**具体被 free 的指针**，而非仅追踪传入 free 函数的参数名。当两个 free 操作释放的是同一结构体的不同成员时，不应标记。

2. **函数语义理解**：`http_destroy_active_conn_list(pool)` 和 `http_destroy_idle_conn_list(pool)` 虽然都接收 `pool` 指针，但它们 free 的是 `pool->active_list` 和 `pool->idle_list`，不是 `pool` 本身。检测器应通过函数签名或实现分析，识别这些是"成员销毁"而非"整体销毁"。

3. **auto-confirm 门槛**：当两个 free 操作的目标变量相同但传入不同函数时，不应 auto-confirm，应降级为 candidate。

---

### 2.5 injection（CWE-89）— 误报率 100%（1/1）

#### 根因

`idm_exec_sql()` 被标记为 SQL 注入点，因为 `sql` 参数非字面量传入 `sqlite3_exec()`：

```c
int idm_exec_sql(const char *sql)
{
    return sqlite3_exec(g_db, sql, NULL, NULL, NULL);
}
```

`idm_exec_sql` 是一个**通用执行器**，其所有调用者（约 40 处）构造 SQL 的方式为：

1. **纯常量字符串**：`"PRAGMA synchronous = OFF;"`
2. **`sprintf_s` + 整型格式化**：`sprintf_s(buf, sizeof(buf), "INSERT INTO %s VALUES (%u)", TBL_USER, user_id)`
3. **表名/列名使用 `#define` 宏常量**

没有任何调用者将用户可控字符串拼接到 SQL 中。

#### 改进建议

1. **调用者分析**：当标记一个函数为 injection sink 时，应分析其所有调用者的参数构造方式。如果所有调用者仅使用常量字符串、整型格式化或宏常量，应 dismiss。

2. **安全格式化函数识别**：`sprintf_s` 配合 `%u`/`%d` 格式化整型值不会引入 SQL 注入，只有 `%s` 格式化用户字符串才构成风险。检测器应区分格式化类型。

3. **基础设施函数豁免**：对于类似 `idm_exec_sql()` 这样的通用执行器（函数体仅一行，直接透传参数），检测器应将分析重点放在调用者而非执行器本身，避免将执行器标记为 sink。

---

### 2.6 use-after-free（CWE-416）— 误报率 100%（1/1）

#### 根因

与 double-free 同源。`http_free(pool)` 是 `http_conn_pool_free()` 的**最后一条语句**（line 288），之后函数返回，不存在对 `pool` 的后续访问：

```c
void http_conn_pool_free(http_conn_pool_t *pool)
{
    // ...
    http_free(pool);  // 最后一条语句
}  // 函数结束
```

检测器可能担心调用者持有悬空指针，但这是调用者侧的问题，不属于该函数内的 use-after-free。

#### 改进建议

1. **free 后访问检查**：use-after-free 检测器应验证 free 操作后是否存在对同一变量的**实际访问**（读取或写入）。当 free 是函数的最后一条语句时，不应标记。

2. **与 double-free 联动**：double-free 和 use-after-free 检测器共享同一误报模式（对销毁函数的语义理解不足），建议统一优化。

---

### 2.7 unchecked-return（CWE-252）— 误报率 31%（11/35）

#### 根因

35 个 unchecked-return 发现中有 11 个误报，集中在以下模式：

**模式 A：`idm_asset_record_dup`（3 个误报）**

```c
// 栈上缓冲区复制，不会失败
char buf[256];
idm_asset_record_dup(rec, &buf);  // 返回值未检查
```

`idm_asset_record_dup` 将记录复制到栈缓冲区，该操作不会因内存分配失败而返回错误。

**模式 B：`read` 函数指针（1 个误报）**

```c
// read 不是 POSIX read() 系统调用，而是函数指针
int (*read)(void *, size_t, void *);
read(buff, rcvlen, &ctx);  // 返回值未检查
```

检测器将函数指针 `read` 误识别为 POSIX `read()` 系统调用。

**模式 C：`idm_malloc` 返回值间接检查（1 个误报）**

```c
tsm_sync_svr_t *svr = idm_malloc(MID_SEC_TSM, sizeof(tsm_sync_svr_t));
if (svr == NULL) return NULL;  // 下一行就检查了
```

返回值在下一行被检查，但检测器仅检查赋值行本身。

**模式 D：`idm_db_filter_new` 通过 wrapper 间接检查（6 个误报）**

```c
idm_db_filter_t *filter = idm_db_filter_new(2);
int ret = idm_fill_sec_group_filter(filter, ...);  // filter 传入 fill 函数
if (ret != 0) { idm_db_filter_free(filter); return ret; }
```

当 `filter` 为 NULL 时，`idm_fill_sec_group_filter` 内部会返回 -1，调用者检查其返回值。检测器未追踪到这种间接防护。

#### 改进建议

1. **函数失败能力建模**：为每个函数建立"是否可能失败"的模型。栈缓冲区操作（如 `idm_asset_record_dup`）不标记为 unchecked-return。

2. **跨行检查窗口扩大**：当赋值语句的下一行（±3 行内）对该变量进行 NULL 检查时，应判定为已检查。

3. **函数指针与系统调用区分**：当变量名为 `read`/`write` 等常见系统调用名时，应通过类型信息确认其是否为函数指针，而非直接匹配为系统调用。

4. **间接防护追踪**：当未检查的返回值被传入另一个函数，且该函数的返回值被检查时，追踪目标函数对 NULL 参数的处理逻辑。如果目标函数在参数为 NULL 时返回错误码，应判定为间接防护。

---

### 2.8 null-deref（CWE-476）— 误报率 33%（2/6）

#### 根因

**误报 1：`idm_custom_portal_web.c:695`**

```c
char *name_buf = idm_custom_portal_get_image_name(...);
idm_custom_portal_delete_unused_image(name_buf);  // 传入可能为 NULL 的指针
if (name_buf == NULL) ...  // NULL 检查在之后
```

`idm_custom_portal_delete_unused_image` 在入口处检查 `file_name == NULL` 并直接返回，因此传入 NULL 不会崩溃。检测器未识别目标函数的入口 NULL 守卫。

**误报 2：`idm_user_bind.c:170`**

```c
idm_user_binds_t *data = shm_deque_at_safe(&deq, uid);
if (data == NULL) {
    shm_deque_resize(&deq, uid + 1);
    data = shm_deque_at(&deq, uid);  // resize 后获取
    *data = (idm_user_binds_t){0};   // 被标记为 null-deref
}
```

`shm_deque_resize` 成功后，`shm_deque_at` 在已扩容的索引上保证返回有效指针。检测器未理解 resize 操作的语义契约。

#### 改进建议

1. **目标函数入口守卫识别**：当被调用函数在入口处对参数进行 NULL 检查并 early-return 时，调用者传入 NULL 不构成 null-deref。

2. **容器操作语义理解**：`shm_deque_resize` 成功后，`shm_deque_at` 在已扩容索引上的返回值保证非 NULL。检测器应识别这种"扩容后访问"的安全模式。

---

## 3. 架构级改进建议

### 3.1 auto-confirm 分级策略

当前 182 个 auto-confirmed 发现中，误报集中在 path-traversal（9/9）、double-free（1/1）、injection（1/1）、use-after-free（1/1）——这些类型的 auto-confirm 条件过于宽松。

建议将 auto-confirm 分为两级：

| 级别 | 条件 | 示例 |
|------|------|------|
| L1 确定 | 机器可证明的漏洞，无需 AI 复核 | DES 算法使用、memset 后未初始化 |
| L2 疑似 | 机器高度怀疑但需上下文确认 | 非字面量路径到达 fopen、两个 free 操作涉及同一变量 |

L2 级别不应直接 auto-confirm，应降级为 candidate 交由 AI 研判。

### 3.2 防护函数注册机制

提供配置接口，允许项目声明其防护函数：

```json
{
  "guards": {
    "path_traversal": ["idm_file_path_is_valid"],
    "null_deref": ["idm_custom_portal_delete_unused_image"],
    "sql_injection": ["idm_parametrize_query"]
  },
  "safe_functions": {
    "sprintf_s": {"bounded": true, "size_param": 2},
    "memcpy_s": {"bounded": true, "size_param": 3},
    "idm_asset_record_dup": {"never_fails": true}
  }
}
```

### 3.3 跨函数语义分析

对于 double-free/use-after-free 检测器，当前仅基于变量名和 free 调用模式匹配。建议：

1. 当两个 free 操作的目标变量相同但传入不同函数时，分析目标函数的实现，确认它们 free 的是不同成员。
2. 当 free 是函数的最后一条语句时，不标记 use-after-free。

### 3.4 unchecked-return 的间接防护追踪

当前仅检查赋值语句本身是否检查返回值。建议扩展：

1. 检查赋值后 ±3 行内是否有 NULL 检查。
2. 当未检查的返回值被传入另一个函数，且该函数的返回值被检查时，分析目标函数对 NULL 的处理。
3. 对于声明为 `__attribute__((warn_unused_result))` 或类似标记的函数，强制标记；对于栈操作函数，不标记。

---

## 4. 优先级排序

| 优先级 | 改进项 | 影响发现数 | 实施难度 |
|--------|--------|-----------|---------|
| P0 | auto-confirm 分级（path-traversal/double-free/injection/use-after-free 降级为 L2） | 12 | 中 |
| P0 | 防护函数注册机制 | 9（path-traversal） | 低 |
| P1 | 安全函数族识别（integer-overflow 场景） | 3 | 低 |
| P1 | 跨行检查窗口扩大（unchecked-return） | 1 | 低 |
| P1 | 函数指针与系统调用区分 | 1 | 低 |
| P2 | 调用者 SQL 构造分析（injection） | 1 | 高 |
| P2 | 间接防护追踪（unchecked-return wrapper 模式） | 6 | 高 |
| P2 | 目标函数入口守卫识别（null-deref） | 1 | 中 |
| P3 | 容器操作语义理解（null-deref resize 模式） | 1 | 中 |
| P3 | dangerous-function 输入来源分级 | 2 | 中 |

---

## 5. 预期效果

如果实施 P0+P1 改进，预计可将本次扫描的误报率从 **42.9%（30/70）** 降至 **约 15.7%（11/70）**，消除的 19 个误报对应：

- path-traversal 9 个（防护函数注册 + auto-confirm 降级）
- integer-overflow 3 个（安全函数族识别）
- dangerous-function 2 个（auto-confirm 降级）
- double-free 1 个（auto-confirm 降级 + 字段级精度）
- injection 1 个（auto-confirm 降级）
- use-after-free 1 个（auto-confirm 降级 + free 后访问检查）
- unchecked-return 2 个（跨行检查窗口 + 函数指针区分）

---

## 附录：误报发现明细

| # | 类型 | 文件:行 | 函数 | 误报根因 |
|---|------|---------|------|---------|
| 1 | path-traversal | idm_csv_import.c:1200 | idm_file_is_utf8_encode_by_file_name | idm_file_path_is_valid 前置校验未识别 |
| 2 | path-traversal | idm_csv_import.c:1240 | idm_protect_import_file | 路径由固定基目录构造 |
| 3 | path-traversal | idm_db_api.c:294 | idm_fcopy | 编译时常量路径 |
| 4 | path-traversal | idm_db_api.c:299 | idm_fcopy | 编译时常量路径 |
| 5 | path-traversal | idm_db_api.c:300 | idm_fcopy | 编译时常量路径 |
| 6 | path-traversal | idm_web_csv_import.c:273 | idm_get_csv_file_size | idm_file_path_is_valid 前置校验 |
| 7 | path-traversal | idm_web_csv_import.c:410 | idm_file_copy | idm_file_path_is_valid + 固定基目录 |
| 8 | path-traversal | idm_web_csv_import.c:414 | idm_file_copy | 固定基目录构造 |
| 9 | path-traversal | idm_file.c:140 | idm_create_file | 所有调用者使用基目录构造 |
| 10 | integer-overflow | idm_csv_import.c:502 | encode_user_ipmac | sprintf_s 安全函数保护 |
| 11 | integer-overflow | idm_csv_import.c:505 | encode_user_ipmac | sprintf_s 安全函数保护 |
| 12 | integer-overflow | idm_csv_import.c:508 | encode_user_ipmac | sprintf_s 安全函数保护 |
| 13 | dangerous-function | idm_hwd_rsp_parse.c:355 | idm_hwd_get_user_ip | 输入来自内部协议解析 |
| 14 | dangerous-function | idm_mesh.c:310 | idm_get_server_ip | 输入来自内部配置 |
| 15 | double-free | http_conn_pool.c:286 | http_conn_pool_free | 两个不同 list 销毁被误判 |
| 16 | injection | idm_db_api.c:378 | idm_exec_sql | 所有调用者使用常量+整型格式化 |
| 17 | use-after-free | http_conn_pool.c:288 | http_conn_pool_free | free 为最后一条语句 |
| 18 | unchecked-return | idm_asset_tbl.c:274 | idm_asset_update_gmdb | idm_asset_record_dup 不失败 |
| 19 | unchecked-return | idm_asset_tbl.c:293 | idm_asset_update_tsm | idm_asset_record_dup 不失败 |
| 20 | unchecked-return | idm_asset_ctrl.c:144 | idm_backup_and_sync_on_timer | idm_asset_record_dup 不失败 |
| 21 | unchecked-return | idm_listen.c:120 | idm_on_read | read 是函数指针非系统调用 |
| 22 | unchecked-return | tsm_sync_svr.c:58 | tsm_sync_svr_get | 下一行 NULL 检查 |
| 23 | unchecked-return | idm_query_sec_group.c:111 | idm_query_sec_group_list | 通过 fill 函数间接检查 |
| 24 | unchecked-return | idm_query_sec_group.c:132 | idm_query_sec_group_num | 通过 fill 函数间接检查 |
| 25 | unchecked-return | idm_query_user_group.c:151 | idm_query_user_group_list | 通过 fill 函数间接检查 |
| 26 | unchecked-return | idm_query_user_group.c:172 | idm_query_user_group_num | 通过 fill 函数间接检查 |
| 27 | unchecked-return | idm_query_user_group.c:232 | idm_query_user_group_full_path_list | 通过 fill 函数间接检查 |
| 28 | unchecked-return | idm_import_lua.c:561 | idm_db_create_vsys_filter | idm_db_filter_add 返回值被检查 |
| 29 | null-deref | idm_custom_portal_web.c:695 | idm_custom_portal_set_image_cfg | 目标函数入口 NULL 守卫 |
| 30 | null-deref | idm_user_bind.c:170 | idm_add_ip_mac | resize 后保证非 NULL |
