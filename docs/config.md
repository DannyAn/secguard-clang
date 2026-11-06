# SecGuard 配置文件（secguard.toml）

SecGuard 支持一个**可选**的 TOML 配置文件 `secguard.toml`，用于覆盖默认行为。
配置文件独立于二进制和扩展（extension），**卸载/重装 secguard 不会删除它**，
因此适合存放环境相关的配置（例如本团队的访问宏白名单）。

## 宏问题的处理策略（v0.7.0 起，重要）

SecGuard 已经**不再依赖「配例外 → 重扫」的循环**来消宏误报。新的默认策略是
**精度优先**：

1. **宏上下文自动交 AI**：候选的报错行或其 ±8 行上下文里出现函数式宏调用时，
   pipeline 会给它打上 `macro-context` 标记，**即使机器证明是 confirmed 也不会
   auto-confirm**，一律转交 AI 研判。
2. **拿不准就丢**：AI 裁决是**二元**的——`confirmed`（可证缺陷）才进入面向用户的
   `result.sarif` / `result.xlsx` / `report.md` / `findings/`；其余（含"拿不准"）
   一律 `dismissed`（丢弃，带 reasoning 落 DB）。**没有 `suspected` 第三态**。

因此，遇到宏误报时，**首选不是在本文件加例外**，而是让它走 AI 研判；AI 看到
`DBM_CHECK_RET(ctrl == NULL, FALSE)` 这类判空宏、迭代宏、访问宏后会正确判为
`dismissed`（排除）。只有下面这些**确定性事实**才值得写进本文件：

- **`[trusted_macros]` / `[iterator_macros.macros]`**：访问宏/迭代宏的定义落在扫描
  范围之外，且你希望确定性过滤器**在 AI 之前就 kill 掉空源**（减少 AI 工作量、
  让真正确定的项仍可 auto-confirm）。
- **`[allocators]` / `[deallocators]` / `[ownership_transfer_calls]` /
  `[nullability.non_null_returns]`**：项目自有的分配/释放/所有权转移/永不返回 NULL
  的函数契约（定义落在扫描范围之外）。
- **`[integer_overflow.truncating_wrappers]`**：项目声明的返回值上界契约。
- **`[uninit] initialization_macros`**：树外初始化宏白名单（宏体不可见时按契约初始化
  调用前声明的局部变量）。
- **`[banned_functions]` / `[exclude]` / `[disabled_types]`**：策略与扫描范围开关。

一句话：**本文件的配置现在是「确定性前置优化」，不是「误报兜底」**。兜底由
「宏上下文 → AI 研判 → 拿不准直接 dismissed」这条链负责。

## 位置

配置文件统一在 `.codeagent` 命名空间下（与运行时数据目录
`.codeagent/secguard-clang/` 保持一致），按优先级探测第一个存在的：

| 层级 | 路径 | 用途 |
|------|------|------|
| 项目级 | `<cwd>/.codeagent/secguard.toml` | 团队/仓库的例外配置（随 git 走） |
| 项目级 | `<cwd>/.codeagent/secguard-clang/secguard.toml` | index 生成建议配置 `secguard.toml.suggested` 后，去掉 `.suggested` 后缀原地采纳 |
| 用户级 | `~/.codeagent/secguard.toml` | 个人默认配置（全局生效） |

安装时会自动在 `~/.codeagent/secguard.toml` 生成一个带注释的模板（若文件不存在）。

> 运行时查看：`secguard config` 显示当前生效的配置文件与值，`secguard config --help`
> 查看完整配置说明，`secguard config --example` 打印可直接复制的示例模板。

## 读取顺序

1. `--config <path>` 显式参数（最高优先级）
2. `SECGUARD_CONFIG` 环境变量
3. 项目级 `<cwd>/.codeagent/secguard.toml`
4. 项目级 `<cwd>/.codeagent/secguard-clang/secguard.toml`
5. 用户级 `~/.codeagent/secguard.toml`

均未命中时，使用内置默认行为（无配置文件）。

> 说明：项目级优先于用户级，且是**整文件覆盖**语义——项目级存在时完全使用
> 它，不合并用户级。

### 建议配置自动生成（`secguard.toml.suggested`）

`secguard index` 建库收尾阶段会自动发现项目自定义的分配/释放函数，并把建议写进
`<cwd>/.codeagent/secguard-clang/secguard.toml.suggested`。文件结构与本配置兼容，
条目带 `confidence`/`reason` 注释；低置信度候选标为 `needs review` 且**以注释形式
给出**（不会进入生效的 `names` 列表，避免未审视的猜测被当作已声明的
分配/释放函数而自动确认误报）。该建议文件**不覆盖**已存在的同名文件，也**从不修改**
`secguard.toml` 本体。

采纳方式：

- 若项目级 `<cwd>/.codeagent/secguard.toml` **不存在**，去掉 `.suggested` 后缀原地
  改名即可生效（`secguard.toml` 的整文件覆盖语义意味着它只提供建议文件里的
  章节，其他章节使用内置默认值）。
- 若 `<cwd>/.codeagent/secguard.toml` 已存在，它**优先于**本文件，原地改名不会生效；
  且项目级配置是**整文件覆盖**，只含 `[allocators]`/`[deallocators]` 的建议文件会
  让用户级配置里的 `[trusted_macros]`/`[scan]` 等设置失效。此时应把需要的条目
  **合并进**已有的 `.codeagent/secguard.toml`，不要用建议文件整体替换它。

## 配置项

### `[trusted_macros]` — 可信访问宏白名单

```toml
[trusted_macros]
names = [
    "YOUR_ACCESSOR_MACRO",
]
```

`names` 里列出的宏，其返回的指针被当作**默认可信**：调用方直接解引用、
不判空，SecGuard 不报空指针解引用。

适用场景：第三方/内部 SDK 的访问宏，其宏定义落在扫描范围之外（例如 SDK
头文件被排除目录跳过），导致 SecGuard 无法通过宏定义自动识别「字段 + 指针
偏移」的可信访问模式。把宏名列在这里即可。

> 说明：宏定义可见时（在扫描范围内的头文件/源码里），SecGuard 会自动识别
> 展开为「字段 + 指针偏移」的可信访问宏，无需手动配置；`names` 只是对
> 定义不可见场景的补充。

### `[iterator_macros.macros]` — 项目迭代器宏声明

```toml
[iterator_macros.macros]
SAMPLE_Scan = [1]
POOL_FOR = [1]
LIST_FOR_EACH_SAFE = [0, 1]
```

声明**定义在扫描范围之外**的项目自定义迭代器宏。每个键是宏名，值是该宏
**迭代器参数**的 0-based 下标列表——即在 `for` 初始化子句中被写入、且被循环
条件判空的参数位置。声明后，SecGuard 会在调用点 kill 迭器实参的 null 源，
从而抑制循环体内解引用的空指针误报。

适用场景：第三方/内部 SDK 的链表/池遍历宏（如 `SAMPLE_Scan(list, iter, type)`
写入 `iter`），其宏定义落在扫描范围之外，导致 SecGuard 无法通过宏定义自动
识别迭代器写入模式。把宏名和迭代器参数下标列在这里即可。

> 说明：
> - 标准 Linux 内核遍历宏（`list_for_each_entry`、`list_for_each_entry_safe`
>   等）已内建于知识库（`apikb.IteratorMacros`），**无需**在此重复声明。
> - 宏定义在扫描范围内时（如项目自己的 `.h` 头文件），SecGuard 会跨文件
>   自动收集宏写入摘要并 kill 迭代器 null 源，同样**无需**手动配置。
> - 此配置仅用于定义在扫描树之外的 SDK 头文件中的项目自定义迭代器宏。

### `[banned_functions]` — 禁用函数策略清单扩展（CWE-676）

`dangerous-function`（CWE-676）检测器内置了一份**分层**的禁用函数策略清单，
`[banned_functions] names` 用于向这份清单**追加**企业自定义的禁用项。

```toml
[banned_functions]
names = [
    "my_legacy_alloc",
    "legacy_strcpy_wrapper",
]
```

内置清单（始终生效，`names` 只能追加、不能移除），按 category 分层：

| category | 内置函数 | 建议替代 |
|----------|----------|----------|
| `process_exit` | `exit` `ExitProcess`（仅非入口函数）、`pthread_exit` `ExitThread`（仅非入口函数）、`atexit` `abort` | 返回错误 / 优雅退出 |
| `stack_allocation` | `alloca` | `malloc`/`free` 或定长缓冲 |
| `nonlocal_jump` | `setjmp` `longjmp` | 返回值错误传播 |
| `unsafe_memory` | `memcpy` `wmemcpy` `memmove` `wmemmove` `memset` `bcopy` `bzero` | `memcpy_s` `memmove_s` `memset_s` … |
| `unsafe_string` | `strcpy` `wcscpy` `strncpy` `wcsncpy` `strcat` `wcscat` `strncat` `wcsncat` `bcmp` | `strcpy_s` `strncpy_s` `strcat_s` … / `memcmp` |
| `unsafe_format` | `sprintf` `swprintf` `vsprintf` `vswprintf` `snprintf` `vsnprintf` | `sprintf_s` `snprintf_s` `vsnprintf_s` … |
| `unsafe_scan` | `scanf`/`wscanf`/`vscanf`/`vwscanf`/`fscanf`/`fwscanf`/`vfscanf`/`vfwscanf`/`sscanf`/`swscanf`/`vsscanf`/`vswscanf` `gets` | `scanf_s` `sscanf_s` … / `fgets` |
| `unchecked_conversion` | `atoi` `atol` `atoll` `atof` | `strtol` `strtoll` `strtod` |
| `unsafe_alloc` | `realloc` | `malloc` + 拷贝 + `free` |
| `assert_usage` | `assert` | 校验入参并返回错误 |
| `insecure_temp` | `mktemp` `tmpnam` `tmpnam_r` | `mkstemp` |
| `obsolete_api` | `gethostbyname` `gethostbyaddr` `inet_addr` | `getaddrinfo` `getnameinfo` `inet_pton` |
| `config_banned` | `names` 追加的项目自定义名 | 项目自定义 |

> 说明：
> - **策略检查**，非上下文敏感：调用即报，不看调用点是否做了边界检查——企业禁用的是函数本身，检测健全、无数据流误报。
> - 除 `assert_usage` 外，所有 category 由管线自动 **confirmed**；`assert` 是否用于校验入参需意图判断，交 AI 研判（**suspected**）。
> - `exit`/`ExitProcess`/`pthread_exit`/`ExitThread` 仅在**非入口函数**（main/wmain/WinMain/wWinMain 之外）报。
> - `unsafe_memory`/`unsafe_string`/`unsafe_format`/`unsafe_scan` 与 `buffer-overflow`/`injection`/`format-string` **刻意重叠**：后者回答「这一次调用会不会溢出/注入」，前者回答策略维度「是否使用了非 `_s` API」，两个维度都会报。

### `[exclude]` — 索引阶段排除目录

```toml
[exclude]
paths = [
    "./svc/src/bak/",
    "src/generated",
]
```

`paths` 列出的目录在**建立索引时**就被整棵剪枝（`filepath.SkipDir`），完全不进入
语义图、检测器和收敛管线——不是扫描后过滤，而是根本不被索引。

关键语义：**相对路径相对于「扫描目标」解析，而不是当前工作目录或配置文件位置**。

| 命令 | `paths` 里的 `"./svc/src/bak/"` 实际排除 |
|------|------------------------------------------|
| `secguard scan ./src` | `./src/svc/src/bak/` |
| `secguard scan .` | `./svc/src/bak/` |
| `secguard index ./svc` | `./svc/svc/src/bak/`（如有） |

- 条目既可以是相对路径（相对扫描目标），也可以是绝对路径；末尾 `/` 会被忽略。
- 匹配的是**完整路径前缀**，与 `--exclude`（按目录**基名**匹配，如 `deps`、`vendor`）
  不同：因此同名 `bak` 目录可以只排除特定那一个，不影响其他 `bak`。
- 排除目录会被完全跳过，`files_indexed` / `functions_indexed` 统计里不含其内容。

### `[disabled_types]` — 漏洞类型开关（关闭整类问题）

```toml
[disabled_types]
types = [
    "path-traversal",
    "divide-by-zero",
]
```

`types` 里列出的漏洞类型（kebab-case，与 `secguard types` 一致）在**扫描源头就被关闭**：
收敛规划（plan）阶段根本不为其运行，因此**不产出任何 candidate**——AI Agent 的
skill 拿不到它，也就自动被过滤掉；同时省下该类型收敛/研判的端到端耗时。

适用场景：某类问题告警过多、逐条甄别误报成本高、或拖慢端到端扫描速度（例如
`path-traversal`、`divide-by-zero`），而团队当前只关心内存/资源类问题时，把它
整个关掉。

> 说明：
> - 关闭是**扫描级**的：被关闭类型在 `candidates_by_type` / `seeds_by_type` /
>   `result.sarif` / `result.xlsx` 中都不出现，也不会被 `status --per-type` 误报为
>   `unknown`（它是有意关闭，不是漏扫）。
> - `secguard types` 仍列出全部类型（那是「能检测什么」的权威清单）；关闭只影响
>   本次扫描是否产出候选。
> - 未知类型名会被忽略并打印一条 warning（拼写错误不会静默关错类型）。

### `[scan] skip_detectors` — 检测器开关（跳过指定证据检测阶段）

```toml
[scan]
skip_detectors = ["unchecked_return", "memory_leak"]
```

`skip_detectors` 里列出的**证据检测器**（`secguard scan` 日志里 `detector timing`
的 `detector` 名称）本次扫描整个不运行：既不产出 `security_events`，也不消耗该阶段
耗时。它是 `[disabled_types]` 在检测阶段的对应物——`[disabled_types]` 关掉的是
「收敛规划」，检测器本身仍会跑；`skip_detectors` 关掉的是「证据检测」，连事件都不再
产生。

适用场景：某些检测器在特定仓库上耗时高但产出为零（例如生产环境实测
`unchecked_return` 空转 20s 产出 0 候选），按仓库关掉它，端到端扫描即可省下这段时间。

> 说明：
> - 被跳过检测器所供给的漏洞类型会得到 **0 candidate**：这是**开关**，不是「干净」。
>   实际生效的名单回写到扫描 JSON 的 `detectors_skipped` 字段（以及 `scan.log` 的
>   `detectors_total` 行），供编排器区分「关掉了」与「没找到」。
> - 未知名字会被忽略并打印一条 warning（拼写错误不会静默关错检测器）。
> - CLI 也有一次性覆盖开关：`secguard scan <path> --skip-detectors=a,b`（逗号分隔，
>   覆盖配置文件里的列表）。
> - 与 `[disabled_types]` 一样，这是**扫描级**配置：`scan` / `diff` / `pr` / `mr`
>   共用同一套流水线，因此都生效。

### `[scan]` 大仓内存 / 并发预算（v0.12.1+）

```toml
[scan]
# 进程内存超过 high 后，新任务最多只准入 1 个；降到 low 后恢复。
memory_pressure_enabled = true
memory_high_watermark_mb = 26000
memory_low_watermark_mb = 20000

# AST / CFG 预算：两者要一起调（CFG 条目会持有 AST 引用）。
max_cached_trees = 1000
cfg_cache_max_entries = 1000
cfg_cache_max_total_nodes = 200000

# Go heap 预算：只约束 Go 侧（事件/候选/临时结构），不约束 tree-sitter/SQLite。
go_mem_limit_mb = 24000
go_gc_percent = 50

# SQLite page cache / mmap（计入 cgroup，但不被 go_mem_limit_mb 约束）
sqlite_cache_mb = 64
sqlite_mmap_mb = 256

# 阶段并发（默认 8 / 7 / 8）；大仓可先降到 4 观察峰值。
graph_builders_concurrency = 4
detector_concurrency = 4
plan_concurrency = 4
```

| 配置 | 默认 | 作用 |
|---|---|---|
| `memory_pressure_enabled` | `false` | 开启 cgroup/RSS 回压；超过 high 后并发降到 1（不是只暂停准入），低于 low 恢复 |
| `memory_high_watermark_mb` | `0` | 回压触发阈值；`0` = 有 cgroup 内存上限时自动取上限的 70%，无上限时不启用 |
| `memory_low_watermark_mb` | `0` | 恢复阈值；`0`/非法值归一化为 high 的 75% |
| `max_cached_trees` | `4000` | parser AST 缓存条目上限；负数保留无界旧行为 |
| `cfg_cache_max_entries` | `4000` | 语句级 CFG 缓存条目上限；只淘汰无 lease 的条目 |
| `cfg_cache_max_total_nodes` | `400000` | CFG 缓存总节点上限，防止单个巨型函数吃满预算 |
| `go_mem_limit_mb` | `0` | Go 运行时软内存上限（GOMEMLIMIT）；`0` = 检测到 cgroup 内存上限时自动取上限的 85%，否则不设 |
| `go_gc_percent` | `0` | 覆盖 GOGC；`0` = 运行时默认 |
| `sqlite_cache_mb` | `0` | 每个 SQLite 连接的 page cache 上限（MB）；`0` = SQLite 默认 |
| `sqlite_mmap_mb` | `0` | SQLite mmap_size（MB）；`0` = 默认；mmap 页计入进程 RSS |
| `graph_builders_concurrency` | `7` | 并行图构建器数量 |
| `detector_concurrency` | `8` | 并行检测器数量 |
| `plan_concurrency` | `8` | 并行漏洞类型收敛数量 |

> 注意：
> - `go_mem_limit_mb` **不约束** tree-sitter 的 C AST 和 SQLite page cache；这两部分仍计入 cgroup。要压 C 侧请调 `max_cached_trees` / `cfg_cache_*`。
> - 只压 `max_cached_trees` 可能因 CFG 条目仍持有 AST 而无效，甚至因重解析抬高 RSS；必须同时压 CFG 预算。
> - 1700 文件仓建议先 `max_cached_trees=1000`、`cfg_cache_max_entries=1000`；如果实测 Go heap 是主因，优先用 `go_mem_limit_mb`/`go_gc_percent`，不要把 AST 压得过低。

### `[allocators]` / `[deallocators]` — 项目分配/释放函数（v0.7.4）

```toml
[allocators]
names = ["nat_malloc", "VOS_MALLOC", "VOS_MALLOC_F"]

[deallocators]
names = ["nat_free", "VOS_FREE"]
```

CLI 启动时注册进 `apikb` 的**精确层**：被登记的名字与内置 `malloc`/`calloc`/`realloc`、
`free` 完全等价——调用结果可能为 NULL（需判空）、分配必须被释放（否则 memory-leak），
且可参与 `confirmed` 判定。

> 说明：未登记时仍有**宽松层**兜底（名字含 `alloc` 视为分配、以 `free` 结尾视为释放），
> 但宽松层只出 `suspected` 交 AI。本项仅用于**定义落在扫描树之外**的包装
> （SDK 头文件、被 `[exclude]` 跳过的目录）；定义在扫描范围内的包装，SecGuard 会
> 通过函数体自动识别。

### `[ownership_transfer_calls]` — 所有权转移函数（v0.9.1）

```toml
[ownership_transfer_calls]
names = ["list_push_back", "dict_set", "buffer_append"]
```

`names` 里的函数视为**接管其指针参数的所有权**：指针传入即算「已逃逸」，释放责任
转移到被调方，memory-leak / resource-leak 不再报泄漏。

适用场景：定义在扫描范围之外的容器插入类 helper，其命名不匹配内置的逃逸启发式
（`_put` / `_push` / `_add` / `_insert` 等）。

### `[nullability.non_null_returns]` — 永不返回 NULL 的函数（v0.9.0）

```toml
[nullability.non_null_returns]
names = ["xmalloc", "g_malloc", "g_new", "sdsnew"]
```

`names` 里的函数返回值被判定为**保证非 NULL**（失败即 abort/退出）。null_source
检测器不会为它们播种空源，因此对调用结果直接解引用不再报 null-deref。

适用场景：定义在扫描范围之外的「分配即断言」函数（glib 的 `g_malloc`、`sdsnew`、
`xmalloc` 这类）。

### `[integer_overflow.truncating_wrappers]` — 返回值有界的包装函数（v0.9.4）

```toml
[integer_overflow.truncating_wrappers]
nlog_syslog_add_pri = 1          # 返回值 <= 实参 1（缓冲区大小）
nlog_syslog_add_hostname = 1
```

每个键是函数名，值是它的**容量/长度实参的 0-based 下标**。声明后，由该返回值累加而
成的累加器被视为**不超过**这个容量，因此后续 `size - total` 减法不可能无符号下溢，
`integer-overflow` 不再报。

适用场景：定义在扫描范围之外、契约已知的截断式追加函数。

### `[uninit]` — 初始化宏白名单（Issue #214）

```toml
[uninit]
initialization_macros = ["CMD_MSG_INIT", "msg_ctx_fill"]
```

命令处理器常见「声明后紧跟命令消息初始化宏」的写法，宏体给**不以实参传入**的调用方
局部变量赋值（`#define CMD_MSG_INIT(recv) do { execId = get(recv); paraNum = 0; }
while (0)`）。宏体在扫描树内时，uninit 检测器/planner 会读到这些自由标识符赋值，
把变量视为已初始化；宏体在扫描树之外（排除头文件、第三方 SDK）时，在此声明宏名，
该调用即按契约初始化**调用前已声明**的局部变量，不再产生 `init@none` 的 auto-confirm
误报。

未声明的树外初始化宏：候选会降级为 `suspected` 交 AI 复核（不直接标 confirmed）。

适用场景：命令/消息处理器初始化宏、协议上下文填充宏。

## 完整示例

```toml
# SecGuard 配置文件（可选）。卸载/重装不会删除此文件。

[trusted_macros]
names = [
    "YOUR_ACCESSOR_MACRO",
]

# 项目自定义迭代器宏（定义在扫描范围外的 SDK 头文件中）。
# 值为迭代器参数的 0-based 下标。
# 标准 list_for_each_entry 等已内建，无需在此声明。
[iterator_macros.macros]
# SAMPLE_Scan = [1]
# POOL_FOR = [1]

# 企业自定义禁用函数（追加到内置危险函数清单，CWE-676）。
[banned_functions]
# names = [
#     "my_legacy_alloc",
# ]

# 索引阶段排除的目录（相对路径相对于「扫描目标」解析，绝对路径原样使用）。
[exclude]
# paths = [
#     "./svc/src/bak/",
#     "src/generated",
# ]

# 漏洞类型开关：关闭整类问题（kebab-case，见 secguard types）。
# 关闭的类型不产出 candidate，skill 拿不到、也就自动过滤。
[disabled_types]
# types = [
#     "path-traversal",
#     "divide-by-zero",
# ]

# 项目自有的分配/释放包装（定义在扫描范围之外）：与 malloc/free 等价。
[allocators]
# names = [
#     "nat_malloc",
# ]

[deallocators]
# names = [
#     "nat_free",
# ]

# 接管指针参数所有权的函数：指针传入即视为已逃逸，不算泄漏。
[ownership_transfer_calls]
# names = [
#     "list_push_back",
# ]

# 保证永不返回 NULL 的函数：对其结果直接解引用不报 null-deref。
[nullability.non_null_returns]
# names = [
#     "xmalloc",
# ]

# 返回值有界的包装函数：键是函数名，值是其容量实参的 0-based 下标。
# 由这些返回值累加而成的累加器不会超过该容量，`size - total` 不会下溢。
[integer_overflow.truncating_wrappers]
# nlog_syslog_add_pri = 1
```

## 与扩展的关系

- **二进制**：`secguard` 可执行程序，安装在 `PATH`（默认 `/usr/local/bin`，
  不可写时回退 `~/.local/bin`）。AI Agent 通过 `PATH` 调用它。
- **扩展**：各平台的扩展目录（指令 / 技能 / MCP 工具），不含二进制。
- **配置**：`secguard.toml`，在 AI Agent 配置目录，独立持久。

三者职责分离：二进制随版本更新，扩展随版本更新，配置跨版本持久。
