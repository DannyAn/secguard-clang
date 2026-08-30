已完成检视。先说结论：这两个目录本身是迁移分叉后的兼容层（commit bbc7a36 今天 18:01 "OpenCode 扩展迁移到插件机制 (#18)" 把 opencode.json + plugins/ 从旧 opencode/ 挪到了 opencode-nga/，.cac/ 是 Claude Code 的另一种宿主布局）。工作区当前是干净的，改动已提交，没有未提交的意外残留。

目录定位（先厘清，避免误判）
目录	定位	事实源
opencode/	新版 OpenCode 插件机制	index.ts（{ id, server } 注册工具/命令/代理/技能）
opencode-nga/	旧版 OpenCode fork 兼容层（nga 分叉）	opencode.json 声明式 + plugins/
claude-code/	Claude Code 标准宿主	.claude/
claude-cac/	Claude Code 另一宿主布局（cac）	.cac/
核心问题：批次容量模型与平台 steps 参数严重脱节（重点）

批次设计唯一事实源在 shared/command-instructions.md:137-155，其硬约束是：

MAXTURNS = 30，注释明确写 security-auditor.md maxTurns (must match)（command-instructions.md:145）
预分派校验：batch_type_count × TURNS_PER_TYPE_ESTIMATE(6) ≥ MAXTURNS × 0.9(27) 即拒绝批次（:155）

但各平台实际生效的 turns/上限不一致：

平台	文件	实际值	与模型是否一致
claude-code	.claude/agents/security-auditor.md:5	maxTurns: 30	✅
claude-cac	.cac/agents/security-auditor.md:5	maxTurns: 30	✅
opencode（新插件）	index.ts:68 loadAgent() 硬编码	steps: 200	❌
opencode（新插件）	agents/security-auditor.md:6 frontmatter	steps: 30（死值）	表面 ✅
opencode-nga（fork）	opencode.json:8	steps: 200	❌

这有三层不合理：

opencode 平台存在双事实源。index.ts:61-80 的 loadAgent() 只从 frontmatter 读了 description，其余全部硬编码（mode/temperature/steps:200/permission）。于是 agents/security-auditor.md frontmatter 里的 steps: 30、mode: all、permission 全是误导性的死值，真正生效的是代码里的 steps: 200。这是典型的 "source of truth 不一致"，且 30 恰好是正确值（匹配批次模型），200 是错的。

200 与批次模型冲突。MAXTURNS × 0.9 = 27 这套预算推导完全建立在 30-turn 上限上；OpenCode 侧实际给到 200，等于这套 batch_type_count × 6 < 27 约束在 OpenCode 上被架空——要么模型失效（一个 batch 可塞进远超预算的类型），要么 200 是笔误。两者必有一个错。

失败原因语义也依赖该值。command-instructions.md:392-393 定义 maxturns-exceeded 为"由 security-auditor.md 的 steps/maxTurns 参数定义"，而 OpenCode 的 steps 是 200（且来自代码非 md），导致该诊断在两个平台含义不一致。

其他合理性问题（次要，但值得记录）

opencode-nga 的工具声明悬空：opencode.json:24-34 声明了 secguard_scan/index/plan/report/status/db/schema/types 八个权限和 plugin: ["secguard-context"]，但该目录下没有任何东西注册这八个工具（plugins/secguard-context.ts 只做 tool.execute.before 注入 path + 文件改动提示）。这些工具的实现是靠外部环境/旧宿主注入的；新版 index.ts 才真正用 tool hook 注册它们。这属于 fork 层的环境耦合，可接受但要意识到它是"只读声明"而非"自包含"。

逻辑重复：opencode-nga/plugins/secguard-context.ts:5-43 与 opencode/index.ts:82-140 的 resolveWorkDir/tool.execute.before/event 三段逻辑完全一致。分叉后两份 drift 风险。

claude-cac vs claude-code 是纯复制：仅目录名 .cac vs .claude 不同 + hooks.json 尾换行差异（diff -r 验证）。宿主名不同是合理的 thin wrapper，但注意 .cac/settings.json:17-29 与 hooks/hooks.json 同时定义了 PostToolUse Edit|Write hook（claude-code 里也同样重复），存在 hook 双重触发的隐患，且这是既有问题不是今天引入的。

建议:[注：我建议是否按此落地需要评估，不要完全遵循，要保持最佳设计]
把 OpenCode 平台的 steps 收敛回 30（或至少与批次模型重算）：统一 index.ts 硬编码与 frontmatter，二者择一为唯一事实源。若确需放宽 turn 上限，则应同步修订 command-instructions.md 的 MAXTURNS/MAXTURNS_SAFETY_RATIO 及预分派公式（batch_type_count × 6 < 27），不能只改平台。
index.ts 的 loadAgent() 应改为读取 frontmatter 的 steps/mode/permission，而不是硬编码，消除死值误导。
决定 opencode-nga/ 去留：若 fork 仍需维护，把 plugins/secguard-context.ts 与新 index.ts 的重复逻辑抽到共享；若不再需要，尽快归档，避免继续产生 drift 假象。
