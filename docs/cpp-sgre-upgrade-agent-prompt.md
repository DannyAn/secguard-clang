# SecGuard-Clang：sgre C++ 语言支持架构升级任务书

## 1. 任务目标

你现在负责对 `DannyAn/secguard-clang` 的 `sgre` 引擎进行一次**架构级语言扩展**：

> 在不破坏现有 C 语言扫描能力、数据库兼容性和 20 个现有 security skills 的前提下，使 sgre 能够正确建立 C++ 项目的 Repository Facts / Semantic Graph，并让现有检测框架能够逐步复用这些事实完成 C++ 安全分析。

项目地址：

- https://github.com/DannyAn/secguard-clang

当前项目的核心定位是：

```text
Source Code
    ↓
Tree-sitter / Parser
    ↓
Repository Facts
    ↓
Semantic Graph
    ↓
Security Events
    ↓
Planner / Evidence Convergence
    ↓
AI Agent
```

当前支持的 skills：

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

当前主要支持 C；本次升级的重点不是简单增加 `.cpp` 后缀，而是把 `sgre` 的数据模型从：

```text
C-oriented semantic model
```

升级为：

```text
C/C++ language-neutral semantic model
        +
C++-specific semantic facts
```

---

# 2. 最重要的架构原则

## 2.1 不允许简单复制一套 C++ 数据库

禁止设计：

```text
c_functions
cpp_functions

c_variables
cpp_variables

c_types
cpp_types
```

这种方案会迅速导致 graph / detector / planner 全部出现 language-specific 分支，最终形成：

```go
if language == "c" {
    ...
} else if language == "cpp" {
    ...
}
```

大量散落代码。

正确方向应该是：

```text
                 ┌─────────────────────┐
                 │ Language-neutral    │
                 │ Repository Facts    │
                 └─────────┬───────────┘
                           │
          ┌────────────────┴────────────────┐
          │                                 │
       C facts                         C++ facts
   function/variable                 class/method
   pointer/array                     inheritance
   struct                            template
   typedef                           namespace
   enum                              overload
   macro                             lambda
          │                                 │
          └────────────────┬────────────────┘
                           ↓
                  Unified Semantic Graph
                           ↓
                     Security Skills
```

核心原则：

> **C++ 是对现有语义模型的扩展，而不是另一套并行数据库。**

---

# 3. 第一阶段：必须先审计现有代码

不要直接修改数据库。

首先完整阅读以下模块：

```text
sgre/internal/db/
sgre/internal/indexer/
sgre/internal/parser/
sgre/internal/graph/
sgre/internal/detector/
sgre/internal/planner/
sgre/internal/evidence/
sgre/testdata/
```

以及：

```text
go.mod
README.md
DEVELOPER.md
AGENTS.md
docs/
```

重点回答：

1. 当前 SQLite schema 是什么？
2. 哪些表表达 Repository Facts？
3. 哪些表表达 Semantic Graph？
4. function / variable / type / parameter / call / CFG node 的身份如何建立？
5. symbol ID 如何生成？
6. 文件 checksum / incremental indexing 如何工作？
7. parser 如何区分 C 与其他语言？
8. Tree-sitter grammar 当前如何加载？
9. C-specific 假设具体散落在哪里？
10. detector 是否直接依赖数据库 schema？
11. graph builder 是否假定只有：
   - C function
   - C pointer
   - C struct
   - C call
12. planner / evidence 是否假定 function 是唯一的分析主体？

先形成一份：

```text
docs/cpp-architecture-audit.md
```

列出：

```text
Current assumption
Affected module
Why it is C-specific
Required abstraction
C++ requirement
Migration strategy
```

**不要在没有完成这个审计之前修改 schema。**

---

# 4. 数据库设计目标

## 4.1 language 必须成为 Repository Fact

至少需要明确记录：

```text
language
language_standard
```

建议支持：

```text
c
c++
```

以及标准：

```text
c89
c99
c11
c17
c23

c++98
c++11
c++14
c++17
c++20
c++23
```

但不要把标准硬编码成大量数据库枚举限制。

推荐：

```text
files.language
files.language_standard
```

例如：

```text
/path/foo.c
language = c
language_standard = c17

/path/bar.cpp
language = c++
language_standard = c++20
```

---

# 5. 不要把 `.cpp` 扩展名当作语言识别的唯一依据

必须支持：

```text
.cpp
.cc
.cxx
.C
.hpp
.hh
.hxx
```

以及项目实际 build configuration。

但是：

> 文件扩展名只是 fallback，不是完整语言判定机制。

如果项目提供：

```text
compile_commands.json
```

应优先利用编译命令中的：

```text
-x
-std=
-I
-isystem
-D
-U
```

等信息。

特别是：

```text
-std=c++17
-std=gnu++20
```

必须能够正确进入 parser/indexer 的语言配置。

---

# 6. 建议的数据模型

以下不是要求机械照抄，而是要求 Agent 根据现有 schema 进行最小侵入式演进。

## 6.1 files

建议增加：

```text
language
language_standard
```

必要时：

```text
compile_command_hash
```

用于增量索引。

---

# 7. symbols：统一符号模型

如果当前数据库已经存在 function / variable / type 等独立表，不要为了 C++ 重构成巨型 polymorphic table。

优先考虑：

```text
symbols
```

作为统一身份层：

```text
symbol_id
kind
name
qualified_name
file_id
line
column
scope_id
language
```

其中：

```text
kind
```

可以扩展为：

```text
function
method
constructor
destructor
operator
variable
field
parameter
type
class
struct
enum
namespace
template
lambda
enum_constant
```

但是要注意：

> 如果当前数据库已经有稳定的 function / variable 表，不要为了理论上的统一而进行高风险大重构。

优先采用兼容演进：

```text
existing tables
        +
symbol identity / language-neutral metadata
        +
C++ extension tables
```

---

# 8. C++ 最关键的新事实：qualified name

C 中：

```c
foo()
```

通常可以使用：

```text
foo
```

作为较简单的函数身份。

C++ 中必须支持：

```cpp
foo()
A::foo()
ns::foo()
ns::A::foo()
A<T>::foo()
```

因此数据库至少需要：

```text
name
qualified_name
```

例如：

```text
name           = foo
qualified_name = ns::A::foo
```

不要让 detector 自己重新拼接 namespace / class 名称。

---

# 9. scope 模型

C++ 对 scope 的依赖远大于 C。

建议建立或增强：

```text
scopes
```

例如：

```text
global
namespace
class
struct
function
block
lambda
```

关系：

```text
scope
  ├── parent_scope
  └── child_scope
```

symbol：

```text
symbol.scope_id
```

这样可以表达：

```cpp
namespace ns {
    class A {
    public:
        int foo(int x);
    };
}
```

形成：

```text
global
  └── namespace ns
        └── class A
              └── method foo
```

---

# 10. C++ class / struct

必须能够表达：

```cpp
class Base {};
class Derived : public Base {};
```

因此至少需要：

```text
types
classes
inheritance_edges
```

或者在现有 type 模型上扩展：

```text
type.kind
```

支持：

```text
struct
class
union
enum
typedef
using
alias
```

继承关系建议进入图模型：

```text
Derived
   │
   └── INHERITS
          ↓
        Base
```

并保留：

```text
access
```

例如：

```text
public
protected
private
```

---

# 11. method 必须和 function 统一处理

C++：

```cpp
class A {
public:
    void foo();
};
```

数据库不能只记录：

```text
function = foo
```

而应该知道：

```text
kind = method
owner_type = A
qualified_name = A::foo
```

同时 graph 中：

```text
A::foo
```

仍然应该作为一个可调用实体参与：

```text
CALLS
RETURNS
PARAMETER_BINDING
RETURN_VALUE
DATA_FLOW
```

这样现有 security skills 才能最大程度复用。

---

# 12. constructor / destructor

必须专门建模：

```cpp
A();
~A();
```

建议：

```text
kind = constructor
kind = destructor
```

因为 resource-lifecycle / memory-lifetime 分析会高度依赖它们。

例如：

```cpp
class A {
public:
    A();
    ~A();
};
```

数据库必须能够表达：

```text
A::A
A::~A
```

不要把 destructor 当成普通名字为 `~A` 的 function 后再让 detector 猜。

---

# 13. operator overload

必须支持：

```cpp
operator=
operator+
operator[]
operator*
operator->
operator()
```

至少能够正确建立：

```text
method/function identity
CALLS
RETURN
PARAMETERS
```

否则大量 C++ operator-based memory / pointer 操作无法进入现有 graph。

---

# 14. overload 是 C++ 数据库升级的核心问题

C 中：

```c
foo(int)
```

基本可以使用：

```text
foo
```

C++：

```cpp
foo(int);
foo(char*);
foo(double);
```

不能使用：

```text
name = foo
```

作为唯一 identity。

必须有稳定的：

```text
symbol_id
```

必要时增加：

```text
signature
```

例如：

```text
foo(int)
foo(char*)
foo(double)
```

以及：

```text
qualified_name
```

推荐：

```text
stable internal symbol_id
+
qualified_name
+
signature
```

而不是让 detector 依赖人工拼接的 mangled name。

---

# 15. 模板

C++ 模板不能简单当普通 function。

需要至少能够识别：

```cpp
template<typename T>
T foo(T x);
```

以及实例：

```cpp
foo<int>(1)
foo<std::string>("x")
```

数据库模型至少需要区分：

```text
template declaration
template parameter
template specialization / instantiation
```

但第一阶段不要求实现完整 C++ template semantic engine。

最低要求：

> 不允许 parser 因 template syntax 导致 symbol / call graph 崩溃或丢失大量事实。

可以采用：

```text
template metadata
+
best-effort symbol resolution
```

逐步增强。

---

# 16. namespace

必须建立：

```text
namespace
namespace parent-child
symbol -> namespace
```

例如：

```cpp
namespace foo {
namespace bar {
void baz();
}
}
```

得到：

```text
foo
 └── bar
      └── foo::bar::baz
```

---

# 17. lambda

C++ 中：

```cpp
auto f = [](int x) {
    return x + 1;
};
```

至少需要保证 lambda body：

1. 可以进入 AST/CFG
2. 不会破坏 enclosing function 的 CFG
3. 捕获变量信息尽可能保留
4. lambda 内部 call 能进入 graph

建议内部建模：

```text
lambda symbol
lambda scope
capture facts
```

第一阶段可以不追求完美 lambda naming。

---

# 18. references 是 C++ 安全分析的关键

这是本次升级不能偷懒的地方。

C++：

```cpp
int &r = x;
int *p = &x;
```

不能只使用 C pointer 模型。

数据库 / facts 至少要区分：

```text
pointer
lvalue reference
rvalue reference
```

例如：

```text
type_category:
    pointer
    lvalue_reference
    rvalue_reference
    value
```

否则：

```cpp
int &r = x;
*r
```

以及：

```cpp
T&& x
```

的生命周期、alias、nullability 分析会产生错误模型。

---

# 19. const / volatile / noexcept / attributes

类型信息必须尽可能保留：

```text
const
volatile
restrict (C)
noexcept (C++)
```

不要把：

```cpp
const int*
int*
```

当成完全相同的 type。

至少保证 type canonicalization 不丢失影响安全分析的 qualifier。

---

# 20. C++ pointer / reference / ownership facts

对于现有：

```text
null-deref
use-after-free
double-free
memory-leak
buffer-overflow
out-of-bounds
resource-leak
```

数据库必须逐步支持：

```text
pointer -> pointee
reference -> referent
object -> lifetime
constructor -> object initialization
destructor -> object destruction
move -> source invalidation / transfer
```

尤其关注：

```cpp
std::move()
```

以及：

```cpp
std::unique_ptr
std::shared_ptr
std::weak_ptr
```

第一阶段不要求完整 STL semantics，但数据库设计不能把这些信息堵死。

---

# 21. C++ object lifetime 是数据库升级的重点

例如：

```cpp
A *p = new A();
delete p;
```

应该能够形成：

```text
ALLOCATE(new A)
    ↓
OBJECT
    ↓
DESTRUCTOR
    ↓
DELETE
```

而不是只把：

```text
new A()
```

当作普通 call。

---

# 22. new / delete

必须显式支持：

```cpp
new T
new T[n]

delete p
delete[] p
```

数据库 / graph 至少应该区分：

```text
allocation kind:
    malloc
    calloc
    realloc
    new
    new_array
```

以及：

```text
release kind:
    free
    delete
    delete_array
```

这样：

```text
new → free
malloc → delete
new[] → delete
new → delete[]
```

等 mismatch 才有可能被准确分析。

如果当前没有 `allocator_kind` / `release_kind`，应在本次升级中补齐。

---

# 23. C++ exception model

C++ 的：

```cpp
throw
try
catch
```

会改变 CFG。

因此数据库 / CFG 模型不能假设只有：

```text
if
while
for
switch
return
```

至少需要支持：

```text
THROW
CATCH
EXCEPTION_EDGE
```

第一阶段可以使用保守模型，但必须保证：

```text
try → catch
```

不会导致 CFG 构建失败。

---

# 24. C++ call graph

call graph 是这次升级的核心。

必须支持：

```text
free function
method call
constructor call
destructor call
operator call
virtual call
function object
lambda call
```

尤其注意：

```cpp
Base *p = new Derived();
p->foo();
```

此时：

```text
static target = Base::foo
dynamic target = Derived::foo
```

第一阶段可以 conservative over-approximation：

```text
CALLS
 ├── Base::foo
 └── Derived::foo
```

但绝对不能错误地认为只有一个普通：

```text
foo
```

---

# 25. virtual dispatch

建议增加：

```text
DISPATCHES_TO
OVERRIDES
```

或者等价的 edge kind。

例如：

```cpp
class Base {
public:
    virtual void foo();
};

class Derived : public Base {
public:
    void foo() override;
};
```

应该存在：

```text
Derived::foo
    └── OVERRIDES → Base::foo
```

调用：

```cpp
p->foo();
```

至少能够得到保守 dispatch set。

---

# 26. type system 不要过度设计

不要试图在本次任务中实现完整 C++ type checker。

目标不是：

```text
Clang semantic compiler
```

而是：

```text
Security-oriented repository semantic database
```

因此优先级应该是：

```text
安全分析所需的类型信息
    >
完整 C++ 类型系统
```

---

# 27. schema migration

数据库升级必须满足：

```text
old C database
    ↓
new sgre
    ↓
still readable
```

如果现有数据库不是严格 schema-versioned，必须增加：

```text
schema_version
```

或等价机制。

推荐：

```text
schema_migrations
```

或者：

```text
metadata.schema_version
```

Migration 必须是：

```text
idempotent
transactional
```

不能让扫描中途失败后留下半迁移数据库。

---

# 28. backward compatibility

必须保证：

```text
纯 C 项目
```

升级后：

```text
扫描结果不发生无理由变化
```

特别关注：

```text
candidate count
security event count
finding count
SARIF result
```

对于已有 C regression fixtures：

```text
go test ./...
go test -race ./...
```

必须继续通过。

---

# 29. Parser architecture

不要在业务层写：

```go
if strings.HasSuffix(file, ".cpp") {
    ...
}
```

应该建立：

```text
Language
LanguageConfig
ParserConfig
```

例如概念上：

```go
type Language string

const (
    LanguageC   Language = "c"
    LanguageCPP Language = "c++"
)
```

再由：

```text
file → language detection → parser configuration
```

决定：

```text
Tree-sitter grammar
language standard
preprocessor configuration
```

---

# 30. Tree-sitter C++

必须验证当前项目实际使用的 Tree-sitter 版本及 grammar API。

不要凭记忆写：

```go
tree_sitter_cpp.New()
```

必须：

1. 查看 go.mod
2. 查看当前 parser abstraction
3. 查看现有 C grammar 的加载方式
4. 根据当前依赖版本确认 C++ grammar 的正确 API
5. 统一接入 parser factory

不要升级 Tree-sitter 版本，除非确实必要。

**本次任务优先做语言扩展，而不是顺便升级整个 parser stack。**

---

# 31. Detector 层要求

本次任务不是要求立刻重写 20 个 detector。

正确策略：

```text
Phase 1
    ↓
C++ parsing
    ↓
C++ Repository Facts
    ↓
C++ graph
    ↓
现有 detector 尽可能复用
```

然后逐 detector 判断：

| Skill | C++ 第一阶段要求 |
|---|---|
| buffer-overflow | 支持 object / array / pointer 基础模型 |
| crypto-misuse | 支持 namespace / method / overload |
| deadlock | 支持 class method / mutex object |
| divide-by-zero | 复用 expression/value facts |
| double-free | 支持 new/delete + ownership |
| format-string | 支持 method / overload |
| hardcoded-secret | 基础支持即可 |
| injection | call graph / taint |
| integer-overflow | C++ integral type |
| memory-leak | new/delete/object lifetime |
| null-deref | pointer/reference |
| out-of-bounds | array/container 基础模型 |
| path-traversal | call / taint |
| race-condition | object / member / synchronization |
| resource-leak | RAII / destructor 是重点 |
| signed-compare | C++ integral types |
| sizeof-misuse | class/object/pointer |
| unchecked-return | method/function |
| uninit | constructor/member initialization |
| use-after-free | object lifetime |
| resource-leak | RAII / destructor |

---

# 32. 特别重要：不要把 C++ STL 一次性全部建模

第一阶段不要试图完整实现：

```text
std::vector
std::string
std::map
std::unordered_map
std::shared_ptr
std::unique_ptr
std::weak_ptr
std::optional
std::variant
std::function
...
```

应该先设计 extensible API：

```text
API Knowledge
Type Facts
Ownership Facts
Contract Facts
```

之后逐步增加：

```text
std::unique_ptr → ownership transfer
std::shared_ptr → shared ownership
std::vector → bounds/container
std::string → string source/sink
```

否则本次升级会失控。

---

# 33. Repository Facts 推荐增加的 C++ Facts

建议最终可以表达：

```text
LanguageFact
TypeFact
ScopeFact
NamespaceFact
ClassFact
InheritanceFact
MethodFact
ConstructorFact
DestructorFact
OperatorFact
TemplateFact
LambdaFact
ReferenceFact
QualifierFact
OverrideFact
VirtualDispatchFact
ObjectLifetimeFact
AllocationFact
DeallocationFact
ExceptionFact
```

注意：

> Facts 是安全分析需要的原子事实，不是 AST 的一对一镜像。

---

# 34. Semantic Graph 推荐 edge

在已有 edge model 基础上，根据实际代码决定是否增加：

```text
DECLARES
MEMBER_OF
INHERITS
OVERRIDES
INSTANTIATES
CONSTRUCTS
DESTRUCTS
REFERS_TO
ALIASES
DISPATCHES_TO
THROWS
CATCHES
EXCEPTION_FLOW
ALLOCATES
DEALLOCATES
MOVES_FROM
```

不要为了“完整”增加大量永远不用的 edge。

每个新 edge 必须回答：

```text
哪个 detector 使用？
为什么 database fact 不够？
为什么 graph edge 更合适？
```

---

# 35. Candidate identity

C++ overload / template / method 会暴露一个严重问题：

```text
file + line
```

不能作为唯一 candidate identity。

建议 candidate identity 至少能够区分：

```text
symbol_id
event_id
source_location
semantic context
```

尤其是：

```cpp
foo(1);
foo("x");
```

两个 overload call 不能因为都叫 `foo` 而合并。

---

# 36. Incremental indexing

C++ header 是重点。

例如：

```text
include/a.hpp
include/b.hpp
src/main.cpp
```

多个 translation unit 都可能引用同一个 header。

因此不能简单：

```text
file changed → only parse file
```

必须分析：

```text
header dependency
translation unit
compile configuration
```

至少不要破坏当前 checksum/incremental indexing 机制。

第一阶段如果无法做到完整 TU-aware incremental rebuild：

> 宁可对受影响 C++ translation unit 做保守重建，也不要产生错误 graph。

---

# 37. Translation Unit 概念

C++ 项目不是简单的“文件 = 编译单元”。

应该逐步引入：

```text
translation_unit
compile_command
source_file
included_file
```

关系：

```text
compile_command
      ↓
translation_unit
      ↓
source_file
      ↓
included headers
```

这是后续 C++ 精确语义分析的基础。

---

# 38. Compile database

如果项目存在：

```text
compile_commands.json
```

优先使用。

需要提取：

```text
directory
file
command / arguments
compiler
language
standard
include paths
defines
```

因为 C++：

```text
#ifdef
template
macro
platform headers
compiler extensions
```

高度依赖编译配置。

---

# 39. 测试策略

不能只增加：

```text
hello.cpp
```

必须增加至少以下类别：

## 基础

```cpp
int main() {
    int x = 1;
    return x;
}
```

## class / method

```cpp
class A {
public:
    void foo();
};
```

## inheritance

```cpp
class Base {};
class Derived : public Base {};
```

## overload

```cpp
void foo(int);
void foo(char*);
```

## constructor / destructor

```cpp
class A {
public:
    A();
    ~A();
};
```

## pointer / reference

```cpp
int *p;
int &r = x;
```

## new/delete

```cpp
int *p = new int;
delete p;
```

## new[]

```cpp
int *p = new int[10];
delete[] p;
```

## namespace

```cpp
namespace foo {
void bar();
}
```

## template

```cpp
template<typename T>
T foo(T x);
```

## lambda

```cpp
auto f = [](int x) { return x + 1; };
```

## virtual

```cpp
Base *p = new Derived();
p->foo();
```

## exception

```cpp
try {
    foo();
} catch (...) {
}
```

---

# 40. Security regression fixtures

必须增加真实 C++ vulnerability fixtures，而不仅是 parser fixtures。

最低建议覆盖：

```text
cpp-buffer-overflow
cpp-null-deref
cpp-use-after-free
cpp-double-free
cpp-memory-leak
cpp-resource-leak
cpp-format-string
cpp-integer-overflow
cpp-out-of-bounds
cpp-unchecked-return
cpp-race-condition
```

尤其：

## new/delete mismatch

```cpp
int *p = new int;
free(p);
```

## delete[] mismatch

```cpp
int *p = new int[10];
delete p;
```

## use-after-free

```cpp
int *p = new int;
delete p;
*p = 1;
```

## RAII resource leak

设计至少一个：

```cpp
class Resource {
public:
    Resource();
    ~Resource();
};
```

测试 destructor / exceptional path。

---

# 41. C regression gate

这是硬门禁。

在所有修改完成后必须证明：

```text
C fixtures before
=
C fixtures after
```

至少比较：

```text
detector result
security event
candidate
SARIF
```

不能接受：

> “C++ 支持了，所以 C 的一些结果发生变化也没关系。”

这是错误的升级方式。

---

# 42. 不允许的实现方式

禁止：

### 方式 1

```go
if cpp {
   fake C representation
}
```

### 方式 2

```text
C database
C++ database
```

完全分裂。

### 方式 3

只识别：

```text
.cpp
```

而忽略 compile_commands。

### 方式 4

把：

```cpp
class
```

直接扁平化成普通 function / variable。

### 方式 5

把：

```cpp
reference
```

强行转换成 pointer。

### 方式 6

把：

```cpp
new/delete
```

当普通函数调用。

### 方式 7

为了支持 C++ 大规模升级所有依赖。

### 方式 8

为了支持 C++ 一次性重写全部 detector。

### 方式 9

没有测试就修改 schema。

### 方式 10

直接修改数据库文件格式而不提供 migration。

---

# 43. 推荐实施阶段

## Phase 0 — Architecture Audit

输出：

```text
docs/cpp-architecture-audit.md
```

完成：

```text
schema audit
parser audit
indexer audit
graph audit
detector audit
incremental-index audit
```

---

## Phase 1 — Language Abstraction

实现：

```text
Language
LanguageConfig
C parser
C++ parser
language detection
language standard
```

目标：

```text
.c / .h
.cpp / .cc / .cxx / .C / .hpp / .hh / .hxx
```

都能正确进入 parser pipeline。

---

## Phase 2 — Database Evolution

增加：

```text
language
language_standard
scope
qualified_name
signature
symbol identity
```

以及必要的 C++ extension facts。

完成：

```text
schema migration
```

---

## Phase 3 — C++ Repository Facts

支持：

```text
namespace
class
struct
method
constructor
destructor
operator
inheritance
override
template
lambda
reference
qualifier
```

---

## Phase 4 — Semantic Graph

支持：

```text
method call
constructor/destructor
inheritance
override
virtual dispatch
reference/alias
new/delete
exception
```

---

## Phase 5 — Detector Reuse

逐个验证 20 个 skills：

```text
Can current detector consume C++ facts?
```

能复用的：

```text
reuse
```

不能复用的：

```text
extend narrowly
```

不要全部重写。

---

## Phase 6 — Security Regression

建立：

```text
testdata/cpp/
```

覆盖核心漏洞类型。

---

## Phase 7 — Performance

比较：

```text
C project
C++ project
mixed C/C++ project
```

指标：

```text
parse time
index time
graph time
DB size
memory
detector time
planner time
```

---

# 44. Definition of Done

只有全部满足以下条件才算完成。

## Parser

```text
[ ] C parser unchanged
[ ] C++ parser works
[ ] C/C++ mixed repository works
[ ] C++ standard detected
[ ] compile_commands supported
```

## Database

```text
[ ] schema version exists
[ ] migration exists
[ ] old C DB remains readable
[ ] language recorded
[ ] qualified name recorded
[ ] overload identity preserved
[ ] scope model exists
[ ] C++ semantic facts persisted
```

## Graph

```text
[ ] method call
[ ] constructor
[ ] destructor
[ ] inheritance
[ ] override
[ ] virtual dispatch
[ ] reference
[ ] new/delete
[ ] exception
```

## Security

```text
[ ] existing C detectors remain functional
[ ] C++ basic memory vulnerabilities detected
[ ] new/delete mismatch detected
[ ] use-after-free supported
[ ] double-free supported
[ ] resource lifetime supported
```

## Regression

```text
[ ] go test ./...
[ ] go test -race ./...
[ ] all existing C security fixtures pass
[ ] C++ fixtures pass
[ ] mixed C/C++ fixture passes
```

---

# 45. 最终输出要求

不要只提交代码。

必须输出：

```text
docs/cpp-architecture-audit.md
docs/cpp-database-design.md
docs/cpp-migration.md
docs/cpp-security-coverage.md
```

其中：

### cpp-architecture-audit.md

回答：

```text
现有 C-specific assumption
在哪里
为什么
如何解除
```

### cpp-database-design.md

给出：

```text
旧 schema
新 schema
migration
entity
relationship
index
```

### cpp-migration.md

给出：

```text
migration version
upgrade path
backward compatibility
rollback strategy
```

### cpp-security-coverage.md

逐 skill 标记：

```text
FULL
PARTIAL
NOT_SUPPORTED
```

并解释：

```text
C++ dependency
missing fact
required follow-up
```

---

# 46. 最终工程原则

你不是在给 sgre “增加 C++ 文件支持”。

你是在完成一次更重要的架构升级：

```text
                 Before

          C Source Code
                ↓
          C-oriented Facts
                ↓
          C-oriented Graph
                ↓
           Security Skills


                 After

          C / C++ Source
                ↓
       Language-aware Parser
                ↓
      Unified Repository Facts
          /              \
     C Facts          C++ Facts
          \              /
           Unified Graph
                ↓
        Security Evidence
                ↓
          Security Skills
```

最终目标：

> **sgre 的核心数据模型不再是 C-specific，而是 language-neutral security semantic model；C++ 只是这个模型的第一个重要扩展。**

如果未来增加：

```text
Objective-C
CUDA
OpenCL
```

应该能够继续扩展：

```text
Language Facts
```

而不是再次复制：

```text
C database
C++ database
Objective-C database
...
```

---

# 47. 给执行 Agent 的最后指令

请严格遵循以下顺序：

```text
1. 阅读整个 sgre
2. 阅读现有 schema
3. 阅读 parser/indexer/graph
4. 阅读至少 5 个代表性 detector
5. 阅读全部现有 C++/language-related tests
6. 输出 architecture audit
7. 提出 schema migration
8. 等价验证 C regression
9. 实现 language abstraction
10. 实现 C++ facts
11. 实现 C++ graph
12. 扩展 detectors
13. 增加 C++ security fixtures
14. 运行 go test ./...
15. 运行 go test -race ./...
16. 检查性能和数据库增长
17. 更新文档
```

**不要跳过 audit。**

**不要因为“代码能编译”就认为架构升级完成。**

最终验收标准不是：

```text
.cpp 能解析
```

而是：

```text
C/C++ mixed repository
        ↓
correct Repository Facts
        ↓
correct Semantic Graph
        ↓
correct Security Events
        ↓
existing C skills remain stable
        ↓
C++ security analysis becomes extensible
```

这才是本次升级的完成标准。
