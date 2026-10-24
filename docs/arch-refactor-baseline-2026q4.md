# 架构重构基线（2026-10-23，main @ db2f184e）

> 在 `feature/arch-refactor-2026q4` 上的重构以本表为对比基准。

## 工作负载

- 目标：`examples/c-vuln-benchmark/src`
- 文件 53 / 函数 366 / 代码行 4598
- 扫描 ID：`sc_2026-10-23_223525_d1b6d2`

## 阶段耗时（ms）

| 阶段 | 基线 |
|---|---|
| index | 50 |
| graph | 261 |
| detectors | 644 |
| plan | 273 |
| report | 33 |
| **total** | **1307** |

## 候选与发现

- seed_count = 681
- final_count = 84（收敛率 87.7%）
- auto_confirmed = 149
- tokens_est = 96773

## 候选按类型分布

| vuln_type | candidates |
|---|---|
| argument-type | 2 |
| buffer-overflow | 16 |
| crypto-misuse | 2 |
| dangerous-function | 2 |
| data-representation | 2 |
| divide-by-zero | 2 |
| double-free | 2 |
| format-string | 1 |
| hardcoded-secret | 2 |
| implicit-contract | 4 |
| injection | 1 |
| integer-overflow | 3 |
| memory-leak | 4 |
| null-deref | 11 |
| out-of-bounds | 2 |
| path-traversal | 7 |
| race-condition | 3 |
| resource-leak | 2 |
| signed-compare | 1 |
| unchecked-return | 5 |
| uninit | 9 |
| use-after-free | 1 |

## extension 使用面盘点

- `extension/opencode/tools/` 下 10 个 MCP wrapper（scan / plan / report / review / status / types / schema / db / metrics / index）全部通过 `execFile("secguard", [...])` 调 CLI
- `extension/shared/` 仅持有 prompt / SKILL.md（静态文本）
- **结论**：sgre 内部重构只要不改 CLI 命令名 / 参数 / stdout JSON schema，对 extension 完全透明