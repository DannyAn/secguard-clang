# SecGuard-Clang：C++ 端到端安全扫描与 Commands / Agents / Skills 对接重构任务书

> **目标：在完成 sgre C/C++ language-neutral 数据模型升级之后，把 C++ 能力完整贯通到 Repository Facts → Semantic Graph → Security Skills → Agents → Commands → SARIF 的整条链路。**

---

## 1. 任务背景

项目：

```text
https://github.com/DannyAn/secguard-clang
```

当前 sgre 已经支持 C，并已有以下 20 个 security skills：

```text
buffer-overflow
crypto-misuse
deadlock
divide-by-zero
double-free
format-string
hardcoded-secret
injection
integer-overflow
memory-leak
null-deref
out-of-bounds
path-traversal
race-condition
resource-leak
signed-compare
sizeof-misuse
unchecked-return
uninit
use-after-free
```

前一阶段任务是：

```text
C-oriented sgre
        ↓
Language-neutral semantic model
        ↓
C + C++ Repository Facts
        ↓
Unified Semantic Graph
```

本任务是在此基础上继续完成：

```text
C / C++ Source
       ↓
sgre
       ↓
Repository Facts
       ↓
Semantic Graph
       ↓
Security Evidence
       ↓
Skills
       ↓
Security Agent
       ↓
Commands
       ↓
SARIF / Findings
```

**最终要求不是“C++ 能被 parser 解析”，而是用户执行现有 SecGuard command 时，可以无感地扫描 C、C++、以及 mixed C/C++ repository。**

---

# 2. 最重要的架构原则

## 2.1 不建立 C++ 专用的一套 Agent / Command / Skill

禁止：

```text
/secguard-c
/secguard-cpp

skills/c-buffer-overflow
skills/cpp-buffer-overflow

agents/c-security-auditor
agents/cpp-security-auditor
```

除非实际业务确实需要语言专用分析，否则必须采用：

```text
/secguard
    ↓
language-aware sgre
    ↓
unified security skills
```

也就是说：

> **语言差异应该尽量消化在 sgre Facts / Graph / Skill evidence layer，而不是污染 Commands 和 Agent routing。**

---

# 3. 先审计，不准直接修改

首先完整阅读：

```text
commands/
agents/
skills/
sgre/
docs/
```

以及所有 command / agent / skill 的：

```text
frontmatter
trigger
input contract
output contract
evidence contract
```

重点查找：

```text
C-specific assumption
function-only assumption
pointer-only assumption
C AST node assumption
C type assumption
C source extension assumption
```

输出：

```text
docs/cpp-agent-integration-audit.md
```

必须回答：

| 层 | 当前问题 | C++影响 | 修改方案 |
|---|---|---|---|
| Commands | 是否写死 C | 高/中/低 | |
| Agents | 是否假定 C facts | 高/中/低 | |
| Skills | 是否只认识 C event | 高/中/低 | |
| Evidence | 是否缺 C++ facts | 高/中/低 | |
| SARIF | 是否依赖 function | 高/中/低 | |
| Tests | 是否只有 `.c` | 高/中/低 | |

---

# 4. Skills 不应该全部增加 C++ 版本

这是本次重构的关键判断。

正确方式：

```text
existing skill
      ↓
language-neutral security intent
      ↓
C evidence
+
C++ evidence
```

而不是：

```text
buffer-overflow
cpp-buffer-overflow
```

---

# 5. 现有 20 个 Skills 的处理矩阵

## 5.1 第一类：必须深度修改

这些 skill 与 C++ object/lifetime/type/dispatch 高度相关。

### memory-leak

必须支持：

```text
new
new[]
constructor
destructor
exception path
ownership transfer
smart pointer facts
```

特别增加：

```text
object lifetime
allocation origin
release responsibility
```

---

### resource-leak

这是 C++ 升级中最重要的 skill 之一。

必须从：

```text
acquire → release
```

扩展为：

```text
acquire
    ↓
ownership
    ↓
RAII object
    ↓
constructor
    ↓
destructor
    ↓
exception path
```

重点处理：

```cpp
class Resource {
public:
    Resource();
    ~Resource();
};
```

以及：

```cpp
try {
    Resource r;
    ...
}
```

资源生命周期不能只靠 `free()` / `close()` 识别。

---

### use-after-free

必须支持：

```text
delete
delete[]
destructor
object lifetime end
reference invalidation
iterator invalidation
moved-from object
```

C++ 中：

```cpp
delete p;
p->foo();
```

只是最简单情况。

还要为：

```cpp
std::vector<int> v;
auto &r = v[0];
v.push_back(1);
use(r);
```

这种 iterator/reference invalidation 留出 evidence model。

---

### double-free

必须支持：

```text
delete
delete[]
free
ownership transfer
smart pointer
move
```

尤其防止：

```cpp
std::unique_ptr<T> a;
std::unique_ptr<T> b = std::move(a);
```

被错误判断为 double ownership。

---

### null-deref

C++ 必须同时考虑：

```text
raw pointer
nullable pointer
reference
this
smart pointer
optional-like state
```

注意：

> reference 不是 nullable pointer。

不能把：

```cpp
T& r
```

直接标记成 pointer。

---

### uninit

C++ 需要新增：

```text
constructor initialization
member initialization
default initialization
value initialization
delegating constructor
base-class initialization
```

例如：

```cpp
class A {
    int x;
public:
    A() {}
    int get() { return x; }
};
```

这里 `x` 的初始化状态必须能够进入 facts。

---

### out-of-bounds

需要增加：

```text
array
pointer
std::array
vector
string
iterator
operator[]
operator.at()
```

第一阶段不要求完整 STL knowledge，但必须让 container abstraction 可以扩展。

---

### buffer-overflow

必须区分：

```text
raw array
heap array
stack object
class member buffer
new[]
container-backed buffer
```

不要把所有 C++ object 都当成 C struct + byte array。

---

### race-condition

必须支持：

```text
class member
object identity
reference
this
mutex member
shared object
```

例如：

```cpp
class Counter {
    int value;
public:
    void inc();
};
```

多个线程调用：

```cpp
counter.inc();
```

应该能够识别：

```text
same object
same member
concurrent access
```

---

### deadlock

需要支持：

```text
std::mutex
std::recursive_mutex
std::lock_guard
std::unique_lock
scoped_lock
RAII lock lifetime
```

特别重要：

> C++ lock/unlock 经常不以显式 `unlock()` 出现，而是通过 destructor 自动释放。

因此 deadlock 的 lock-set / lock-lifetime 必须使用新的 object lifetime facts。

---

# 6. 第二类：需要适配 C++ type / call model

以下 skills 不一定需要大规模重写，但必须验证 C++ facts 能正确进入。

```text
divide-by-zero
integer-overflow
signed-compare
sizeof-misuse
unchecked-return
format-string
injection
path-traversal
crypto-misuse
```

重点：

```text
method
overload
namespace
operator
template
return type
parameter binding
```

例如：

```cpp
foo(int)
foo(std::string)
```

不能因为函数名相同而混淆 evidence。

---

# 7. 第三类：基本可以复用

### hardcoded-secret

主要依赖：

```text
literal
identifier
data flow
```

如果现有 evidence pipeline 已 language-neutral，则无需 C++ 专用版本。

---

# 8. 建议新增 Skills

这部分不要盲目照搬 CERT C++ 的所有规则。

目标是：

> **优先增加那些只有 C++ object model 才能可靠检测、且具有真实安全价值的能力。**

CERT C++ 本身已经把 memory management、exceptions、OOP、concurrency、containers 等作为独立规则域；例如 `EXP54-CPP` 专门处理 object lifetime，`MEM50-CPP` 处理 freed memory，`OOP52-CPP` 涉及 polymorphic deletion，`ERR57-CPP` 涉及 exception path resource leak。 citeturn1search0turn1search1

---

## 8.1 object-lifetime

**建议新增，优先级：P0**

覆盖：

```text
use before lifetime begins
use after lifetime ends
dangling reference
dangling pointer
object destruction
temporary lifetime
placement-new lifetime transition
```

这是 C++ security semantic model 的核心。

---

## 8.2 cpp-cast

**建议新增，优先级：P0**

覆盖：

```text
static_cast
reinterpret_cast
const_cast
dynamic_cast
C-style cast
```

重点：

```text
invalid downcast
unsafe reinterpretation
const violation
wrong object type
alignment/type punning
```

---

## 8.3 virtual-destructor

**建议新增，优先级：P0**

典型：

```cpp
class Base {
public:
    virtual void foo();
};

class Derived : public Base {
};

Base *p = new Derived();
delete p;
```

如果 Base destructor 非 virtual，就存在典型 C++ polymorphic deletion 风险。

CERT C++ 将其定义为 `OOP52-CPP`。 citeturn1search14

需要依赖：

```text
inheritance
virtual
override
dynamic type
delete
destructor
```

---

## 8.4 iterator-invalidation

**建议新增，优先级：P1**

覆盖：

```text
container mutation
iterator invalidation
reference invalidation
pointer invalidation
```

典型：

```cpp
auto it = v.begin();
v.push_back(x);
use(*it);
```

CERT C++ 的 CTR51-CPP 明确关注 pointers/references/iterators 对 container element 的有效性。 citeturn1search0

---

## 8.5 moved-from

**建议新增，优先级：P1**

覆盖：

```text
std::move(x)
use(x)
```

但不要把所有 moved-from object 都直接判漏洞。

需要：

```text
type contract
operation contract
known-safe state
```

作为 evidence。

CERT C++ 有 `EXP63-CPP` 专门讨论 moved-from object 的状态。 citeturn1search1

---

## 8.6 exception-safety

**建议新增，优先级：P1**

覆盖：

```text
throw
catch
destructor
RAII
cleanup
exception edge
```

尤其：

```text
acquire
    ↓
operation throws
    ↓
resource not released
```

CERT C++ 将 exception safety 和 exception-path resource leak 分别作为 `ERR56-CPP`、`ERR57-CPP`。 citeturn1search0

---

## 8.7 lambda-lifetime

**建议新增，优先级：P1**

重点：

```cpp
int *p;

auto f = [&p]() {
    use(p);
};
```

以及：

```cpp
auto make() {
    int x;
    return [&]() { return x; };
}
```

重点依赖：

```text
lambda
capture
capture mode
referent lifetime
lambda lifetime
```

CERT C++ 有 `EXP61-CPP` 对 lambda reference capture 生命周期进行明确约束。 citeturn1search0

---

## 8.8 polymorphic-type

**建议新增，优先级：P1**

覆盖：

```text
unsafe downcast
object slicing
polymorphic misuse
virtual dispatch mismatch
```

依赖：

```text
inheritance
virtual
override
dynamic type
```

---

## 8.9 resource-raii

这个 skill 是否独立，需要根据现有 `resource-leak` 的职责决定。

如果：

```text
resource-leak
```

已经升级成：

```text
resource lifecycle + RAII
```

则**不要重复创建 `resource-raii`**。

优先保持：

```text
resource-leak
```

成为统一资源生命周期 skill。

---

# 9. 推荐最终 Skill 架构

不要形成：

```text
20 C skills
+
20 C++ skills
```

推荐：

```text
skills/
├── memory/
│   ├── buffer-overflow
│   ├── double-free
│   ├── memory-leak
│   ├── null-deref
│   ├── out-of-bounds
│   ├── object-lifetime
│   └── use-after-free
│
├── resource/
│   ├── resource-leak
│   └── exception-safety
│
├── type/
│   ├── cpp-cast
│   ├── virtual-destructor
│   ├── polymorphic-type
│   └── moved-from
│
├── concurrency/
│   ├── deadlock
│   └── race-condition
│
└── ...
```

**但是否真的重排目录，必须先根据当前项目 skill discovery / command loading 机制决定。**

如果现有 marketplace/package contract 依赖：

```text
skills/<skill-name>
```

就不要为了目录漂亮而破坏现有接口。

---

# 10. Skill Contract 必须升级

每个 skill 必须明确：

```yaml
name:
description:
languages:
required_facts:
required_edges:
candidate_granularity:
evidence_contract:
output_schema:
```

例如：

```yaml
name: use-after-free

languages:
  - c
  - c++

required_facts:
  - allocation
  - deallocation
  - object_lifetime
  - pointer
  - reference

required_edges:
  - ALLOCATES
  - DEALLOCATES
  - REFERS_TO
  - ALIASES

candidate_granularity:
  - dereference_site

output_schema:
  - source_location
  - allocation_site
  - lifetime_end
  - invalid_use
```

这样 skill 不需要猜数据库结构。

---

# 11. Skill 与 sgre 的边界

严格遵守：

```text
sgre
    = facts + graph + semantic evidence

skill
    = security reasoning over evidence

agent
    = orchestration / interpretation

command
    = user-facing entry point
```

禁止：

```text
skill 自己查询 SQLite
skill 自己解析 Tree-sitter AST
agent 自己重新解析 C++
command 自己判断 .cpp
```

正确：

```text
command
   ↓
agent
   ↓
skill
   ↓
sgre API
   ↓
facts / graph / evidence
```

---

# 12. Agent 重构

当前 security agent 如果类似：

```text
security-auditor
```

必须改成：

```text
language-agnostic security auditor
```

Agent 不应该写：

```text
If this is C code...
```

而应该读取：

```text
repository.language
repository.languages
translation_units
available_skills
```

例如：

```text
languages = [c, c++]
```

然后决定：

```text
enable C/C++ compatible skills
```

---

# 13. Agent 不应该直接决定 detector

Agent 不应该自己判断：

```text
这是 use-after-free
所以调用 use-after-free skill
```

应该由：

```text
planner / dispatcher
```

根据：

```text
candidate facts
security event
skill applicability
```

进行调度。

Agent 的职责：

```text
orchestration
evidence interpretation
finding synthesis
confidence reasoning
```

而不是重新实现 scanner。

---

# 14. Commands 重构

现有：

```text
/secguard
/secreview
/secaudit
```

原则上都不增加 C++ 专用 command。

保持：

```text
/secguard
```

即可扫描：

```text
.c
.cpp
.cc
.cxx
.h
.hpp
.hh
.hxx
```

并自动识别：

```text
C
C++
Mixed C/C++
```

---

# 15. Command contract

Command 应明确向 Agent 提供：

```text
repository path
scan mode
language scope
compile database
severity
output format
```

例如：

```text
language = auto
```

默认：

```text
auto
```

而不是：

```text
language = c
```

必要时允许：

```text
--language c
--language cpp
--language auto
```

但：

> 默认必须是 `auto`。

---

# 16. Mixed C/C++ 是一级测试场景

必须测试：

```text
project/
├── src/
│   ├── foo.c
│   ├── bar.cpp
│   └── baz.cc
├── include/
│   ├── foo.h
│   └── bar.hpp
└── compile_commands.json
```

Command：

```text
/secguard
```

必须能够：

```text
detect repository languages
build correct index
build unified graph
dispatch compatible skills
produce one SARIF
```

而不是生成：

```text
c-result.json
cpp-result.json
```

再由 Agent 拼起来。

---

# 17. Evidence Contract 必须升级

原来的：

```text
function
line
variable
pointer
```

不足以描述 C++。

建议 Evidence 至少可以表达：

```text
symbol_id
qualified_name
signature
language
source_location
scope
type
owner_type
allocation
deallocation
lifetime
reference
alias
call_target
dynamic_targets
inheritance
exception_path
```

例如一个 finding：

```text
Base::foo()
```

不能只输出：

```text
foo()
```

必须尽可能输出：

```text
ns::Base::foo()
```

以及：

```text
dispatch target:
    ns::Derived::foo()
```

---

# 18. Candidate Granularity

C++ 会进一步证明：

> function 不是最好的 security candidate abstraction。

优先：

```text
security event
dereference site
allocation site
deallocation site
call site
object lifetime event
```

例如：

```text
delete p
```

candidate：

```text
deallocation_event
```

而不是：

```text
function containing delete
```

对于：

```cpp
p->foo();
```

candidate：

```text
member_call_event
```

而不是：

```text
foo function
```

---

# 19. SARIF 输出

SARIF 应保持稳定。

不要因为 C++ 引入另一套 schema。

重点确保：

```text
ruleId
message
artifactLocation
region
level
properties
```

可以增加：

```json
"language": "c++",
"symbol": "ns::Derived::foo",
"qualifiedName": "ns::Derived::foo",
"dispatchTarget": "ns::Derived::foo"
```

但不要破坏已有 SARIF consumers。

---

# 20. Skill applicability

每个 skill 增加：

```text
supports_language
required_fact
```

例如：

```text
buffer-overflow
    C:    yes
    C++:  yes

virtual-destructor
    C:    no
    C++:  yes

hardcoded-secret
    C:    yes
    C++:  yes
```

Dispatcher 自动过滤：

```text
language × skill capability
```

---

# 21. C++ Skill Priority

建议实施顺序：

## P0

```text
object-lifetime
virtual-destructor
cpp-cast
```

同时深度升级：

```text
memory-leak
resource-leak
use-after-free
double-free
null-deref
uninit
```

## P1

```text
exception-safety
iterator-invalidation
moved-from
lambda-lifetime
polymorphic-type
```

同时升级：

```text
out-of-bounds
buffer-overflow
deadlock
race-condition
```

## P2

```text
container-contract
temporary-lifetime
object-slicing
unsafe-downcast
```

这些可以在第一版 C++ 支持稳定后继续增加。

---

# 22. Database → Skill → Agent 一致性矩阵

最终必须生成：

```text
docs/cpp-security-integration-matrix.md
```

表格：

| Fact | Graph | Skill | Agent | Command |
|---|---|---|---|---|
| language | | | | |
| class | | | | |
| method | | | | |
| constructor | | | | |
| destructor | | | | |
| inheritance | | | | |
| override | | | | |
| reference | | | | |
| allocation | | | | |
| deallocation | | | | |
| lifetime | | | | |
| virtual dispatch | | | | |
| exception | | | | |
| lambda capture | | | | |
| move | | | | |

每一行必须能够追踪：

```text
DB fact
  ↓
graph/evidence
  ↓
skill
  ↓
agent
  ↓
command
  ↓
SARIF
```

这张矩阵就是整个升级的 architecture traceability。

---

# 23. End-to-End Tests

必须建立：

```text
tests/e2e/c/
tests/e2e/cpp/
tests/e2e/mixed/
```

---

## C

验证：

```text
/secguard
```

结果与升级前一致。

---

## C++

至少覆盖：

```text
class
method
namespace
inheritance
virtual
constructor
destructor
reference
new/delete
lambda
template
exception
```

以及：

```text
UAF
double-free
memory leak
resource leak
null deref
buffer overflow
out-of-bounds
race
deadlock
cast
virtual destructor
```

---

## Mixed

验证：

```text
C source
+
C++ source
+
C header
+
C++ header
```

最终：

```text
one repository
one graph
one finding model
one SARIF
```

---

# 24. Agent invocation test

不能只测试：

```text
go test
```

必须测试真实 command：

```text
/secguard
```

然后验证：

```text
command
 → agent
 → planner
 → skill
 → sgre
 → evidence
 → finding
 → SARIF
```

每一层都必须有 traceable identifier。

---

# 25. Debug / Observability

增加一个 debug 模式，使 Agent 能看到：

```text
Repository languages:
  c
  c++

Translation units:
  12

C++ classes:
  42

C++ methods:
  187

Inheritance edges:
  23

Virtual dispatch edges:
  31

Object lifetime events:
  891

Enabled skills:
  ...
```

这样出现：

```text
C++ 漏报
```

时可以定位究竟是：

```text
parser
→ fact
→ graph
→ candidate
→ skill
→ planner
→ agent
```

哪一层丢失。

---

# 26. Performance Gate

C++ 项目通常比 C 项目更复杂。

必须比较：

```text
C only
C++ only
Mixed
```

指标：

```text
index time
graph build time
DB size
memory
skill execution
agent execution
```

禁止：

```text
为了支持 C++，每个 skill 都扫描整个 AST
```

必须继续保持：

```text
Repository Facts
+
shared evidence
+
candidate filtering
+
skill reuse
```

---

# 27. 不允许的架构

禁止：

```text
cpp-agent
cpp-command
cpp-skill copy
cpp-db
cpp-scan pipeline
```

形成第二套系统。

也禁止：

```text
Agent 看到 .cpp
→ 自己调用 grep / AST
→ 自己分析漏洞
```

这会绕开 sgre，是架构倒退。

---

# 28. 最终目录目标

实际目录必须以当前仓库为准，不要机械照搬。

概念目标：

```text
commands/
├── secguard.md
├── secreview.md
└── secaudit.md

agents/
└── security-auditor.md

skills/
├── buffer-overflow/
├── double-free/
├── memory-leak/
├── null-deref/
├── object-lifetime/
├── virtual-destructor/
├── cpp-cast/
├── exception-safety/
├── iterator-invalidation/
├── moved-from/
├── lambda-lifetime/
├── polymorphic-type/
└── ...

sgre/
├── parser/
├── db/
├── facts/
├── graph/
├── evidence/
├── planner/
└── dispatcher/
```

不要因为这个示例改变当前项目已经稳定的目录/API contract。

---

# 29. 完成标准

必须同时满足：

## Database

```text
[ ] C++ facts available
[ ] language-aware
[ ] object lifetime
[ ] inheritance
[ ] overload
[ ] references
[ ] new/delete
[ ] exception
```

## Graph

```text
[ ] method call
[ ] constructor/destructor
[ ] override
[ ] virtual dispatch
[ ] reference/alias
[ ] lifetime
[ ] allocation/deallocation
[ ] exception flow
```

## Skills

```text
[ ] existing 20 skills audited
[ ] C++ capability declared
[ ] memory/resource skills upgraded
[ ] P0 C++ skills implemented
[ ] P1 roadmap established
```

## Agent

```text
[ ] language-neutral
[ ] no direct AST parsing
[ ] no direct SQLite access
[ ] uses evidence contract
[ ] dispatches skills correctly
```

## Commands

```text
[ ] /secguard works for C
[ ] /secguard works for C++
[ ] /secguard works for mixed
[ ] /secreview works for C++
[ ] /secaudit works for C++
```

## Output

```text
[ ] SARIF remains compatible
[ ] C findings unchanged
[ ] C++ findings include qualified symbol information
```

---

# 30. Required documentation

最终必须生成：

```text
docs/cpp-agent-integration-audit.md
docs/cpp-security-integration-matrix.md
docs/cpp-skill-migration.md
docs/cpp-e2e-validation.md
```

其中 `cpp-skill-migration.md` 必须明确：

```text
Skill
Status
C support
C++ support
Required facts
Required graph edges
Required modifications
New skill dependency
Test coverage
```

---

# 31. 执行顺序

严格按照：

```text
1. Audit commands
2. Audit agents
3. Audit all skills
4. Map database facts to skills
5. Map graph edges to skills
6. Define evidence contract
7. Upgrade dispatcher
8. Upgrade skill manifests/contracts
9. Upgrade P0 skills
10. Add P0 C++ skills
11. Upgrade Agent
12. Upgrade Commands
13. Add C++ fixtures
14. Add mixed C/C++ fixtures
15. Run real /secguard
16. Run /secreview
17. Run /secaudit
18. Validate SARIF
19. Validate C regression
20. Validate performance
21. Generate architecture traceability documents
```

---

# 32. 最终架构验收

最终系统应该变成：

```text
                       User
                        │
             ┌──────────┼──────────┐
             │          │          │
         /secguard  /secreview  /secaudit
             │          │          │
             └──────────┼──────────┘
                        ↓
                Security Agent
                        ↓
                  Planner/Dispatcher
                        ↓
              ┌─────────────────────┐
              │ Security Skills     │
              │                     │
              │ C + C++ unified     │
              └──────────┬──────────┘
                         ↓
                 Evidence API
                         ↓
              ┌─────────────────────┐
              │       sgre          │
              │                     │
              │ Repository Facts    │
              │ Semantic Graph      │
              │ Lifetime Model      │
              │ Call Graph          │
              │ Type Model          │
              └──────────┬──────────┘
                         ↓
                   C / C++ Source
```

最重要的验收标准：

> **Agent 不知道如何解析 C++。Skill 不知道如何解析 C++。Command 也不应该知道如何解析 C++。**
>
> **C++ 的复杂性必须被 sgre 的 Facts / Graph / Evidence 层吸收，然后以统一的 Security Evidence 提供给 Skills。**

只有做到这一点，`secguard-clang` 才是真正完成了从 **C security scanner → C/C++ semantic security scanner** 的架构升级，而不是简单增加一个 C++ parser。
