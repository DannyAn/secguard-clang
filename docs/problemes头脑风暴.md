# 头脑风暴现状问题和未来发展

## 管线未覆盖的额外发现问题分析与建议
本内容是与Chat GPT沟通聊天的部分摘录，可以算是头脑风暴的一些关键信息。

### network.c:52 uint32 溢出绕过包大小检查（CWE-125 越界读）、

建议检测技能：integer-overflow

覆盖：
```
size = count * sizeof(struct item);

if(size < count)
    return error;

malloc(size);
```
以及：
```
uint32_t len;

len += header;

memcpy(buf,len);
```
验证：
```
range analysis
arithmetic propagation
boundary influence
```
这是必须有的。


### system.c:44 TOCTOU、
建议检测技能：race-condition ⭐⭐⭐⭐⭐

覆盖：

TOCTOU

增加：

race-condition

测试：
```
if(access(file,F_OK)==0)
{
    open(file);
}
```
需要模拟：
```
check
 |
time gap
 |
use
```
这是传统规则很难覆盖的。

### crypto.c 硬编码密钥、
建议检测技能：hardcoded-secret

不要叫 crypto。

测试：
```
char *key =
"123456789abcdef";
```
覆盖：
```
password
API key
private key
token
```
这是企业扫描非常重要的一类。


### concurrency.c 死锁/信号处理器中 malloc、
建议检测技能：deadlock

测试：
```
lock(a)
lock(b)

lock(b)
lock(a)
```
核心不是 AST。

需要：

Lock Graph

验证你的多层过滤：
```
第一层:
发现 mutex

第二层:
建立 lock order

第三层:
cycle detection
```

### memory_extra.c:43 漏检的内存泄漏。
建议检测技能：


## 保持 skill 合并思想？
保持skills现状, 例如：
```
buffer-overflow
memory-leak
resource-leak
```
不要拆 CWE。

但是 skill 内部必须有 capability matrix：

例如：
```
buffer-overflow

Capabilities:

[x] stack write overflow
[x] heap write overflow
[x] out-of-bound read
[x] integer derived overflow
[x] pointer arithmetic overflow
```

## 合并skill的风险

一个 skill 太胖。

比如：

buffer-overflow

最后变成：

buffer-overflow/
    SKILL.md

    rules:
       strcpy
       memcpy
       memset
       scanf
       packet parser
       serialization
       image parser
       compression
       integer arithmetic
       pointer arithmetic

最后 3000 行。

这会违反 Agent skill 的一个原则：

skill 应该有明确 reasoning boundary。

## skill 应该是面向漏洞类型（CWE），还是面向安全语义域（Security Reasoning Domain）？

### 阶段一、面向漏洞类型（CWE）

这个路线非常容易复制 Coverity / CodeQL 的组织方式。

优点：

工程师容易理解
初期实现快
baseline 好管理

缺点：

Agent 推理能力被切碎
skill 数量增长失控
Repository Facts 无法复用

按照这个模式，则建议 secguard-clang v2 最终结构

不要 20 个散 skill。

建议分类管理：

```
skills/

memory/
├── null-deref
├── use-after-free
├── double-free
├── memory-leak
└── ownership

boundary/
├── buffer-overflow
├── out-of-bounds
├── integer-overflow

input/
├── injection
├── command-injection

resource/
├── resource-leak

concurrency/
├── race-condition
├── deadlock

crypto/
├── hardcoded-secret
├── crypto-misuse

semantic/
├── api-misuse
├── contract-violation

initialization/
└── uninit
```

大约： 20 skills

### 阶段二、面向安全语义域（Security Reasoning Domain）

核心思想：一个 skill 是一个安全领域专家，而不是一个漏洞检测器。
建议这个阶段要在阶段一的基础上，再做一次 skill 合并。如果阶段一功能验证通过，那么这个阶段是完全可行的。

面向安全语义域的比较完整的 secguard-clang v2 skill taxonomy。

目标：

不超过 20~25 个 skill
覆盖 CWE Top 25 大部分 C/C++问题
每个 skill 有清晰 reasoning boundary
能映射回具体 CWE
Repository Facts 可复用 

secguard-clang Security Reasoning Skills
```
skills/

├── memory/
│
│   ├── pointer-safety
│   └── lifetime-analysis
│
├── boundary/
│
│   ├── buffer-boundary
│   └── integer-range
│
├── input/
│
│   └── injection
│
├── resource/
│
│   └── resource-lifecycle
│
├── concurrency/
│
│   ├── race-condition
│   ├── deadlock
│   └── async-safety
│
├── trust/
│
│   ├── secret-management
│   └── trust-boundary
│
├── crypto/
│
│   └── crypto-usage
│
├── initialization/
│
│   └── initialization-state
│
├── contract/
│
│   ├── api-contract
│   └── validation-contract
│
└── control-flow/
    │
    └── unsafe-control-flow
```

总共：21 skills

下面逐一展开几个，去穿刺验证架构可行性。

#### 1. memory

pointer-safety

替代：

null-deref

负责：

空指针
p->x

但是核心不是 NULL。

而是：

Pointer Validity

包括：

null pointer
dangling pointer
invalid pointer
uninitialized pointer

输出：

CWE-476
CWE-824
lifetime-analysis

替代：

use-after-free
double-free
memory-leak
ownership

核心：

Object Lifecycle

状态：
```
create
 |
alive
 |
release
 |
dead
```
检测：

问题	本质
UAF	dead object used
double free	dead object released again
leak	lost ownership

输出：

CWE-401
CWE-415
CWE-416

#### 2. boundary

buffer-boundary

替代：

buffer-overflow
out-of-bounds

覆盖：

stack overflow
heap overflow
global overflow
OOB read
OOB write

核心：

Memory Spatial Safety
integer-range

替代：

integer-overflow

但是不要理解成数学问题。

核心：

Integer value affects security boundary

例如：

size=count*element_size;
malloc(size);

覆盖：

overflow
truncation
sign conversion

#### 3. input
injection

统一：

SQL injection
Command injection
LDAP injection
Path injection

核心：

Untrusted Data -> Interpreter

模型：
```
source
 |
transform
 |
sink
```

#### 4. resource

resource-lifecycle

这个非常重要。

不要只叫：

resource-leak

因为资源不只有 memory。

覆盖：

open()
close()

socket()
close()

lock()
unlock()

thread()
join()

核心：

Resource ownership

#### 5. concurrency
race-condition

覆盖：

TOCTOU
data race

模型：

check
 |
time gap
 |
use
deadlock

模型：

Lock Dependency Graph

覆盖：

A->B
B->A
async-safety

专门覆盖：

signal handler malloc

模型：

Execution Context Contract

例如：

signal handler:

禁止：

malloc
printf
pthread_mutex

#### 6. trust

这个是很多传统 SAST 没有的。

secret-management

替代：

hardcoded-secret

覆盖：

password
token
key
certificate
trust-boundary

非常重要。

例如：
```
user input
 |
kernel
 |
network
 |
database
```
检测：

missing validation
privilege crossing

#### 7. crypto

crypto-usage

不要叫 crypto-misuse。

覆盖：

weak algorithm
bad mode
weak random
bad key usage

#### 8. initialization

initialization-state

替代：

uninit

覆盖：

declared
 |
assigned?
 |
used

#### 9. contract

api-contract

覆盖：

例如：

free(NULL)
pthread_mutex_unlock()
signal()

API 使用规则。

validation-contract

覆盖：

例如：

函数：
```c
foo(char *p)
{
 p->x;
}
```
隐含：

p != NULL

调用者违反。

#### 10. control-flow
unsafe-control-flow

这个是高级能力。

覆盖：

unreachable security branch
bypass check
missing authorization path

例如：
```c
if(auth)
{
}
do_sensitive();
```