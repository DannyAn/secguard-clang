你的理解里有一个关键误区：**OpenCode 的 agent 不是通过自然语言“自动匹配触发”的**。

你输入：

> analyzes code for vulnerabilities

**大概率不会触发你的 `security-auditor` agent。**

它只会被当作普通用户任务，让当前主 agent（默认 agent）自己决定怎么处理。除非你的主 agent 的 system prompt 或配置明确告诉它“遇到安全分析要调用 security-auditor”。

---

## OpenCode Agent 的正常触发方式

你的文件：

```
extension/opencode/agents/security-auditor.md
```

定义的是一个 **subagent**：

```yaml
mode: subagent
```

意味着：

> 它不是用户直接聊天入口，而是被其他 agent 调用的专用推理角色。

类似：

```
User
 |
 | "帮我扫描漏洞"
 |
Main Agent
 |
 | decide delegation
 |
security-auditor subagent
 |
 | analysis
 |
result
```

---

# 方法1（最直接）：显式指定 agent

OpenCode 一般支持 slash command / agent 切换。

你可以尝试：

```
@security-auditor analyze this code for vulnerabilities
```

或者：

```
/agent security-auditor
```

不同 OpenCode 版本命令可能略有变化。

你可以在 TUI 输入：

```
/
```

看 autocomplete。

正常会看到：

```
/agents
```

或者 agent 列表。

---

# 方法2（推荐）：让主 Agent 自动委派

这是现在 Agentic Coding 更推荐的模式。

你的 agent：

```
security-auditor
```

应该不是用户入口，而是一个 capability。

例如主 agent 配置：

```
You are a software engineering agent.

Available specialists:

- security-auditor:
  Use when:
    - vulnerability analysis
    - CWE detection
    - security review
    - memory safety issues

Delegate security tasks.
```

然后用户：

```
Review this repository for security issues
```

流程：

```
Main Agent
    |
    | classify intent
    |
    +--> security-auditor
```

这才是类似：

* Claude Code Agent
* Cursor Background Agent
* Devin sub-agent
* OpenAI Codex agent

的设计方式。

---

# 方法3：通过 Skill 触发（更适合你的 SecGuardian）

结合你之前设计的 SecGuardian，我反而不建议让用户直接调用：

```
security-auditor
```

因为你的架构明显已经接近：

```
User Request
      |
Repository Intelligence Engine
      |
Planner
      |
Execution Plan
      |
Dispatcher
      |
Skills
      |
Agents
```

那么应该：

```
用户:
scan repository for vulnerabilities


Main Agent:
  ↓
Repository Planner

发现:
  memory safety audit

  ↓

Dispatcher

  ↓

security-auditor agent

  ↓

skills:
  null_dereference
  use_after_free
  buffer_overflow
```

也就是说：

**Agent 是执行者，不应该成为入口。**

---

# 你的 agent 定义还有一个问题

这里：

```yaml
model: anthropic/claude-sonnet-4-20250514
```

我建议不要固定模型。

原因：

Agent 应该描述：

> 能力

不是：

> 运行环境

例如：

```yaml
model:
```

最好交给 OpenCode 全局配置。

否则以后：

```
security-auditor
       |
       +-- Claude Sonnet
       |
       +-- GPT-5
       |
       +-- DeepSeek
```

切换困难。

---

# 另外一个重要点：你的路径可能不对

OpenCode 官方 agent 目录通常是：

```
.opencode/
   agents/
       security-auditor.md
```

而不是：

```
extension/opencode/agents/
```

除非你是在开发 OpenCode extension。

确认：

```bash
find . -name security-auditor.md
```

然后：

```bash
opencode --debug
```

看它加载 agent 的日志。

---

# 我建议你的验证方法

不要猜，直接测试。

进入项目：

```
opencode
```

输入：

```
/agents
```

看是否出现：

```
security-auditor
```

如果出现：

```
@security-auditor
```

测试：

```
@security-auditor analyze src/ for null pointer vulnerabilities
```

如果没有出现：

你的 agent 没被加载。

---

结合你之前 SecGuardian 的设计，我认为你的方向应该是：

```
/secguard
      |
      v
Security Orchestrator Agent
      |
      +-- security-auditor
      |
      +-- memory-agent
      |
      +-- concurrency-agent
      |
      +-- resource-agent
```

而不是让用户记：

```
@security-auditor
```

因为你的目标不是一个聊天机器人，而是一个安全分析系统。

你现在这个 `security-auditor.md` 更像 **底层 Specialist Agent**，不是用户入口。你需要再设计一个 **Security Orchestrator Agent** 作为入口。这个和你之前的 Repository Planner / Dispatcher 思路是一致的。
