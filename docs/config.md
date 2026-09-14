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
`dismissed`（排除）。只有下面两类场景才需要本文件配置：

- **`[trusted_macros]`**：访问宏的定义落在扫描范围之外，且你希望确定性过滤器
  **在 AI 之前就 kill 掉空源**（减少 AI 工作量、让真正确定的项仍可 auto-confirm）。
- **`[iterator_macros.macros]`**：迭代宏定义在扫描范围外，且你希望确定性过滤器
  **在 AI 之前就 kill 迭代子空源**（同上，是优化而非必需）。

一句话：**本文件的配置现在是「确定性前置优化」，不是「误报兜底」**。兜底由
「宏上下文 → AI 研判 → 拿不准直接 dismissed」这条链负责。

## 位置

配置文件统一在 `.codeagent` 命名空间下（与运行时数据目录
`.codeagent/secguard-clang/` 保持一致），按优先级探测第一个存在的：

| 层级 | 路径 | 用途 |
|------|------|------|
| 项目级 | `<cwd>/.codeagent/secguard.toml` | 团队/仓库的例外配置（随 git 走） |
| 用户级 | `~/.codeagent/secguard.toml` | 个人默认配置（全局生效） |

安装时会自动在 `~/.codeagent/secguard.toml` 生成一个带注释的模板（若文件不存在）。

> 运行时查看：`secguard config` 显示当前生效的配置文件与值，`secguard config --help`
> 查看完整配置说明，`secguard config --example` 打印可直接复制的示例模板。

## 读取顺序

1. `--config <path>` 显式参数（最高优先级）
2. `SECGUARD_CONFIG` 环境变量
3. 项目级 `<cwd>/.codeagent/secguard.toml`
4. 用户级 `~/.codeagent/secguard.toml`

均未命中时，使用内置默认行为（无配置文件）。

> 说明：项目级优先于用户级，且是**整文件覆盖**语义——项目级存在时完全使用
> 它，不合并用户级。

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

### `[banned_functions]` — 危险/废弃函数禁用扩展（CWE-676）

`dangerous-function`（CWE-676）检测器内置了一份**保守**的危险/废弃函数清单，
`[banned_functions] names` 用于向这份清单**追加**企业自定义的禁用项。

```toml
[banned_functions]
names = [
    "my_legacy_alloc",
    "legacy_strcpy_wrapper",
]
```

内置清单（始终生效，`names` 只能追加、不能移除）：

| 内置函数 | 废弃/危险原因 |
|----------|----------------|
| `gets` | 无边界检查，C11 已移除 |
| `mktemp` `tmpnam` `tmpnam_r` | 不安全的临时文件 API |
| `gethostbyname` `gethostbyaddr` | 废弃，改用 `getaddrinfo` |
| `inet_addr` | 废弃，改用 `inet_pton` |
| `bcmp` `bcopy` `bzero` | 废弃 BSD API，改用 `memcmp`/`memmove`/`memset` |

> 说明：
> - **策略检查**，非上下文敏感：调用即报，不看调用点是否做了边界检查——企业禁用的是函数本身，检测健全、无数据流误报。
> - `strcpy`/`sprintf`/`system` 等无界字符串/格式化函数**故意不内置**（`buffer-overflow`/`injection` 已上下文敏感地处理，内置会重复噪音）；企业若要一刀切禁用，把它们加进 `names` 即可。

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
```

## 与扩展的关系

- **二进制**：`secguard` 可执行程序，安装在 `PATH`（默认 `/usr/local/bin`，
  不可写时回退 `~/.local/bin`）。AI Agent 通过 `PATH` 调用它。
- **扩展**：各平台的扩展目录（指令 / 技能 / MCP 工具），不含二进制。
- **配置**：`secguard.toml`，在 AI Agent 配置目录，独立持久。

三者职责分离：二进制随版本更新，扩展随版本更新，配置跨版本持久。
