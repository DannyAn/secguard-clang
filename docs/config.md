# SecGuard 配置文件（secguard.toml）

SecGuard 支持一个**可选**的 TOML 配置文件 `secguard.toml`，用于覆盖默认行为。
配置文件独立于二进制和扩展（extension），**卸载/重装 secguard 不会删除它**，
因此适合存放环境相关的配置（例如本团队的访问宏白名单）。

## 位置

配置文件是**用户级共享一份**（不是每个 AI Agent 平台各一份），按顺序探测
第一个存在的：

1. `~/.config/secguard.toml`（首选，XDG 标准配置目录）
2. `~/.codeagent/secguard.toml`（次选，兼容旧约定）

安装时会自动在 `~/.config/secguard.toml` 生成一个带注释的模板（若文件不存在）。

## 读取顺序

1. `--config <path>` 显式参数（最高优先级）
2. `SECGUARD_CONFIG` 环境变量
3. 上述默认路径（按顺序探测，第一个存在的生效）

三个来源都未命中时，使用内置默认行为（无配置文件）。

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

## 完整示例

```toml
# SecGuard 配置文件（可选）。卸载/重装不会删除此文件。

[trusted_macros]
names = [
    "YOUR_ACCESSOR_MACRO",
]
```

## 与扩展的关系

- **二进制**：`secguard` 可执行程序，安装在 `PATH`（默认 `/usr/local/bin`，
  不可写时回退 `~/.local/bin`）。AI Agent 通过 `PATH` 调用它。
- **扩展**：各平台的扩展目录（指令 / 技能 / MCP 工具），不含二进制。
- **配置**：`secguard.toml`，在 AI Agent 配置目录，独立持久。

三者职责分离：二进制随版本更新，扩展随版本更新，配置跨版本持久。
