# Semantic Graph Builder 原理和用途

> 本文档以 secguard-clang 项目 `sgre/internal/graph` 包为蓝本，系统讲解**语义图构建器（Semantic Graph Builder）**到底构建什么、根据什么构建、在什么时机构建、如何被消费，并给出可被另一个项目直接参考的设计清单与示例。
>
> 蓝本实现语言：Go；解析器：tree-sitter（C 语法）；存储：SQLite。

---

## 0. 如何使用本文档（导读）

本文档有**双重身份**：既是 secguard-clang 蓝本的解剖说明，也是写给"另一个 Python 版 sgre"的实践指导。第 1–11 章是蓝本解剖（"它怎么做的"），第 12–18 章是给你的 Python 项目的指导（"你该怎么做、怎么判断做对了"）。

### 按角色阅读

| 你是 | 重点读 | 用途 |
|---|---|---|
| Python sgre 的架构师 | 第 0、12、14、18 章 | 决策取舍、阶段路线图、蓝本到你的项目的映射 |
| Python sgre 的实现者 | 第 4、5、13、15、17 章 | 具体怎么写、对照清单、反模式、可运行骨架 |
| Python sgre 的测试/质量 | 第 13、16 章 | 验收标准、度量指标、fixture 设计 |
| 想理解 secguard-clang 本身 | 第 1–11 章 | 蓝本实现细节 |

### 三条核心忠告（如果你只记三句话）

1. **先做 CALL + DATA_FLOW + 递归 CTE 可达性，跑通端到端，再加别的边。** 蓝本 6 种边只实现了 2 种，照样支撑了 14 种漏洞类型的检测。边类型贪多是最常见的过度工程。
2. **图是检测器和收敛管线的共享查询层，不是检测器本身。** 图只产生关系，不产生安全结论。如果你发现自己在图构建器里写"判断这里有没有漏洞"，你把职责放错了位置。
3. **每一条边都要有明确的消费方。** 没有下游查询的边是死边，只会增加构建成本和去重负担。蓝本预留的 4 种边至今没有构建代码——预留可以，但别先实现再找用途。

### 一个判断你做对了的快速信号

如果你的 Python sgre 能做到这三件事，说明语义图这一层基本立住了：

- 能回答"函数 X 是否从入口函数可达"（call-graph 可达性，用于过滤不可达候选）；
- 能回答"变量 V 的值是从哪条赋值/返回流过来的"（data-flow 反向溯源）；
- 能回答"free 在第 L1 行、use 在第 L2 行，两者在同一函数内是否路径可达"（CFG 近似）。

如果三件都做不到，说明图还不够"语义"；如果三件都做到了但检测器还在自己重新遍历 AST，说明图没被消费、白建了。

---

## 1. 它是什么、解决什么问题

### 1.1 一句话定义

**语义图构建器**位于"程序事实索引"和"安全证据检测"之间，把分散在多文件、多函数中的**程序事实（Layer 1）**提升为一张可查询的**语义关系图（Layer 2）**：节点是程序实体（函数、变量引用、返回槽），边是它们之间的语义关系（调用、数据流）。

### 1.2 为什么需要它

安全检测器（如 use-after-free、memory-leak、null-deref）需要回答的问题本质上是**关系型**的：

- "函数 A 是否调用了函数 B？"（call graph）
- "这个指针的值是从哪里流过来的？"（data flow）
- "free 之后的那次 use，在控制流上真的可达吗？"（CFG / 可达性）
- "这个被调函数从 main 入口是否可达？"（call-graph 可达性）

如果每个检测器都自己重新遍历 AST 去回答这些问题，会产生三个问题：

1. **重复解析**：N 个检测器 × M 个文件 = N×M 次 AST 遍历。
2. **跨函数能力缺失**：单文件 AST 无法回答"A 调用 B 吗"这种跨函数关系。
3. **不可复用**：每个检测器各自实现一遍图遍历，逻辑分散、难以优化。

语义图把这些关系**物化到数据库**，检测器和下游的收敛管线只需查询 `graph_nodes` / `graph_edges` 两张表即可，且可达性可由 SQL 递归 CTE 在 DB 端高效计算。

### 1.3 在整体管线中的位置

```
┌─────────────┐    ┌──────────────────────┐    ┌──────────────────┐    ┌─────────────┐    ┌──────────────┐
│  indexer    │ -> │  Semantic Graph      │ -> │  evidence        │ -> │  planner    │ -> │  AI agent    │
│  (Layer 1)  │    │  Builder (Layer 2)   │    │  detectors (L3)  │    │  (Layer 4)  │    │  (findings)  │
│ files,      │    │ graph_nodes,         │    │ security_events  │    │ converged   │    │              │
│ functions,  │    │ graph_edges,         │    │                  │    │ candidates  │    │              │
│ variables,  │    │ (+ 补写 variables)   │    │                  │    │             │    │              │
│ expressions │    │                      │    │                  │    │             │    │              │
└─────────────┘    └──────────────────────┘    └──────────────────┘    └─────────────┘    └──────────────┘
   程序事实            语义关系图                  原始候选              收敛后的证据         分类结果
```

**关键定位**：语义图是**检测器和收敛管线的共享查询层**。它不直接产生安全结论，只产生关系；安全结论由下游基于这些关系推断。

---

## 2. 构建时机

### 2.1 管线中的精确顺序

以 `secguard scan <path>` 为例（`sgre/internal/cli/scan.go`）：

| 步骤 | 代码位置 | 作用 |
|---|---|---|
| 1. 索引 | `scan.go:73-78` `idx.Index(ctx, absPath)` | 写 Layer 1：`files`/`functions`/`variables`/`expressions`/`types`/`locations` |
| 2. **构建调用图** | `scan.go:80-81` `cgBuilder.Build(ctx)` | 写 Layer 2：`graph_nodes`(function/external_function) + `graph_edges`(CALL) |
| 3. **构建数据流** | `scan.go:83-84` `dfBuilder.Build(ctx)` | 写 Layer 2：`graph_nodes`(variable_ref/return_slot) + `graph_edges`(DATA_FLOW)；**并补写 Layer 1 的 `variables` 表** |
| 4. 清空旧证据 | `scan.go:86-88` `store.ClearSecurityEvents` | 清 Layer 3，避免脏数据 |
| 5. 跑检测器 | `scan.go:91` `evidence.RunAllDetectors` | 写 Layer 3：`security_events` |
| 6. 收敛 | `scan.go:96-128` 对 14 种 vulnType 逐个 `pl.Plan` | 写 Layer 4：`findings`（由 AI agent 完成） |

### 2.2 关键时机结论

- **在 indexer 之后、检测器之前**。检测器依赖图，所以图必须先建好。
- **`secguard index` 命令也会建图**（`index.go:48-63` 与 scan 前 5 步一致），不只是 scan 才建。
- **`secguard plan` 命令不建图**，它只消费已存在的图。
- **CFG 不在此时构建**——`BuildCFG` 是纯内存函数，由检测器/过滤器在自己需要时按函数即时构建（见 §4.3）。这是图构建器中唯一"惰性"的部分。

### 2.3 增量构建

**当前实现没有增量构建能力。** 每次 `Build` 都全量遍历所有函数并重新解析源文件。`graph_edges` 的插入是纯 `INSERT`，没有 `ON CONFLICT` 去重，也没有 `ClearGraph` 之类的方法——重复跑 scan 会导致 CALL/DATA_FLOW 边重复累积。

> **给参考项目的警示**：要么在 builder 里实现"先删后插"，要么在 `InsertGraphEdge` 上加 `UNIQUE(src_id, dst_id, edge_type)` 约束 + `INSERT OR IGNORE`，否则增量场景会出问题。

---

## 3. 输入：根据什么构建

### 3.1 混合输入模式（重要设计决策）

语义图构建器采用**混合输入**：

| 输入来源 | 提供什么 | 怎么拿 |
|---|---|---|
| **DB（Layer 1）** | 函数清单：`functions(id, name, file_id, start_line, end_line)`；文件路径：`files(id, path)` | `store.ListFunctions(ctx)`、`store.GetFileByID(ctx, f.FileID)` |
| **源文件 + tree-sitter** | 语法细节：调用表达式、赋值、return、声明、if/for/while 等 | `os.ReadFile(file.Path)` → `parser.Parse(source, path)` |

**为什么不全用 DB？** 因为 indexer 写入的 `expressions` 表是扁平的、按需索引的，重建跨语句关系（如"这个赋值的 RHS 是哪个变量的引用"）从扁平表反查很别扭；直接对源文件跑一遍 tree-sitter 拿到 AST 最直接。

**为什么不全用源文件？** 因为需要 DB 提供权威的函数清单（哪些是已索引的内部函数、各自的 ID 和行范围），才能把 AST 中的调用名解析到具体的 `functions.id`。

### 3.2 不读取的 Layer 1 表

构建器**不读取** `expressions`、`types`、`locations` 表。它只读 `functions` 和 `files`。这意味着 indexer 写入的很多事实在图构建阶段被"绕过"——这是已知的重复解析开销，但简化了实现。

---

## 4. 输出：构建哪些内容

### 4.1 写入的表

| 表 | 写入方 | 备注 |
|---|---|---|
| `graph_nodes` | `store.GetOrCreateGraphNode` | 按 `(entity_type, entity_id)` 去重 |
| `graph_edges` | `store.InsertGraphEdge` | **不去重**，纯 INSERT |
| `variables`（Layer 1！） | `store.InsertVariable` | **跨层副作用**：data_flow builder 把发现的指针声明补录到 Layer 1 |

> **设计争议点**：data_flow builder 往 Layer 1 写数据，破坏了"层只往下写"的单向性。蓝本中这么做是因为 indexer 没有完整索引所有指针变量，data_flow builder 顺手补齐。**参考项目应避免这种跨层写**，让 indexer 一次性把 variables 写全。

### 4.2 `graph_nodes` 表结构

```sql
CREATE TABLE IF NOT EXISTS graph_nodes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id   INTEGER NOT NULL,
    properties  TEXT
);
```

`entity_type` 没有枚举约束，实际使用的 4 种节点类型：

| entity_type | entity_id 含义 | properties | 语义 |
|---|---|---|---|
| `function` | `functions.id` | `""` | 已索引的内部函数 |
| `external_function` | `0`（所有外部函数共享！） | `{"external":true}` | 未索引的外部/库函数 |
| `variable_ref` | `functions.id` | `{"name":"p","line":10}` | 函数内某行的变量引用 |
| `return_slot` | `functions.id` | `""` | 函数的返回值槽 |

> **已知缺陷**：所有外部函数共享同一个节点（`entity_id=0`），无法区分 `printf` 和 `malloc`。参考项目应让外部函数按名字去重，`entity_id` 用名字的 hash 或单独的 `external_functions` 表。

### 4.3 `graph_edges` 表结构

```sql
CREATE TABLE IF NOT EXISTS graph_edges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    src_id      INTEGER NOT NULL,
    dst_id      INTEGER NOT NULL,
    edge_type   TEXT NOT NULL CHECK (edge_type IN (
        'CALL', 'DATA_FLOW', 'OWNERSHIP_TRANSFER', 'RELEASE', 'BRANCH', 'ALIAS'
    )),
    properties  TEXT,
    FOREIGN KEY(src_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
    FOREIGN KEY(dst_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
);
```

### 4.4 六种边类型 vs 实际构建情况

| edge_type | 实际构建 | 语义 | 边方向 | properties |
|---|---|---|---|---|
| `CALL` | ✅ | 函数调用 | caller → callee | `{"call_line":N}` |
| `DATA_FLOW` | ✅ | 数据流（赋值 / 返回） | 源 → 目标 | `{"variable":"name"}` |
| `OWNERSHIP_TRANSFER` | ❌ 预留 | 所有权转移（如 `return p;`） | — | — |
| `RELEASE` | ❌ 预留 | 资源释放（如 `free(p)`） | — | — |
| `BRANCH` | ❌ 预留 | 控制流分支 | — | — |
| `ALIAS` | ❌ 预留 | 别名（如 `q = p;`） | — | — |

**只有 2/6 种边被实际构建**。其余 4 种是 schema 预留枚举，当前版本未实现。它们对应的语义通过其他途径表达：

- 所有权转移 / 释放：由 `internal/evidence` 检测器直接写成 `security_events`（如 `MEMORY_RELEASE` 事件），不经过 graph 边。
- 分支：由 CFG 的作用域树隐式表达（见 §4.3），不作为 graph 边。
- 别名：未实现，当前 data flow 只处理直接赋值，不做别名传播。

> **给参考项目的建议**：如果是从零实现，建议**先只做 CALL + DATA_FLOW**，覆盖 80% 的检测需求；ALIAS 和跨函数 data flow 是后续增量。OWNERSHIP_TRANSFER/RELEASE 用边表达会比用事件表达更利于跨函数分析，可以考虑直接用边。

---

## 5. 构建算法详解

### 5.1 调用图（Call Graph）

**入口**：`CallGraphBuilder.Build` (`sgre/internal/graph/call_graph.go:28`)

**算法**：

```
1. funcs = store.ListFunctions()                  // 从 DB 拿全部函数
2. funcMap = { f.Name -> f.ID for f in funcs }    // 按名字建索引（重名会冲突！）
3. for each f in funcs:
   a. callerNode = GetOrCreateGraphNode("function", f.ID)
   b. file = store.GetFileByID(f.FileID)
   c. source = readFile(file.Path)
   d. tree = parser.Parse(source, file.Path)      // 重新解析源文件
   e. for each call_expression in tree where f.StartLine <= line <= f.EndLine:
      i.  callName = extractCallName(callNode)    // 取第一个 identifier/field_expression
      ii. if callName in funcMap:
            calleeNode = GetOrCreateGraphNode("function", funcMap[callName])
          else:
            calleeNode = GetOrCreateGraphNode("external_function", 0, {"external":true})
      iii.InsertGraphEdge(callerNode, calleeNode, "CALL", {"call_line": f.StartLine})
```

**支持的调用形式**：`foo()`、`obj->method()`（通过 `field_expression`）。

**不支持的调用形式**：函数指针调用 `(*fp)()`（会落到 `external_function`）。

**已知近似**：
- `call_line` 用的是**函数起始行**而非实际调用行（`call_graph.go:73`），定位不准。
- 同名函数互相覆盖（`funcMap` 按名字建）。
- 所有外部函数合并为一个节点。

### 5.2 数据流（Data Flow）

**入口**：`DataFlowBuilder.Build` (`sgre/internal/graph/data_flow.go:24`)

对每个函数重新解析源码后，依次跑三个子检测器：

#### 5.2.1 `detectPointerDeclarations`（不建边，补写 variables 表）

```
for each declaration in func where it has pointer_declarator:
    name = 提取声明名
    type = 提取类型 + "*"
    isHeap = 文本是否含 malloc/calloc/realloc
    store.InsertVariable({
        FunctionID, Name, Type,
        StorageClass: isHeap ? "heap" : "auto",
        IsPointer: true,
        IsNullable: isHeap
    })
```

#### 5.2.2 `detectPointerAssignments`（建 DATA_FLOW 边）

```
for each assignment_expression in func:
    lhs = children[0]   // 必须是 identifier
    rhs = children[1]   // identifier 或 call_expression
    lhsNode = GetOrCreateGraphNode("variable_ref", f.ID, {"name":lhs, "line":N})
    rhsNode = GetOrCreateGraphNode("variable_ref", f.ID, {"name":rhs, "line":N})
    InsertGraphEdge(rhsNode, lhsNode, "DATA_FLOW", {"variable":lhs})
    // 方向：RHS → LHS（数据从源流向目标）
```

#### 5.2.3 `detectPointerReturns`（建 DATA_FLOW 边）

```
for each return_statement in func:
    if returned child is identifier:
        retNode = GetOrCreateGraphNode("return_slot", f.ID)
        varNode = GetOrCreateGraphNode("variable_ref", f.ID, {"name":child, "line":N})
        InsertGraphEdge(varNode, retNode, "DATA_FLOW", {"variable":child})
        // 方向：变量 → 返回槽
```

**未实现的流**：
- 参数流（形参 → 函数体内使用）
- 跨函数流（调用者实参 → 被调用者形参）
- 字段流（`p->field`）
- 别名传播（`q = p` 后 q 和 p 互为别名）

当前 data flow 是**函数内、语句级、赋值/返回 only** 的近似。

### 5.3 控制流图（CFG，实为作用域树）

**入口**：`BuildCFG(root parser.Node, funcStart, funcEnd int) *CFG` (`sgre/internal/graph/cfg.go:20`)

**这是纯内存函数，不写 DB**，由检测器/过滤器在自己需要时按函数即时构建。

**它构建的不是传统 CFG，而是"作用域树"**：

```go
type Scope struct {
    StartLine int
    EndLine   int
    HasExit   bool      // 是否有 return/break/continue
    ExitLine  int
    Children  []*Scope
    Parent    *Scope
}
```

**构建规则**：
- 为每个 `if_statement` 的 consequence 和 alternative 各建一个子 scope。
- 为每个 `for`/`while`/`do` 的循环体建一个子 scope。
- 递归处理嵌套。
- `HasExit` = scope 内是否有 `return`/`break`/`continue`。

**`CanReach(freeLine, useLine)`**（`cfg.go:126`）——路径敏感性近似：

```
freeScope = findInnermostScope(freeLine)
if freeScope.HasExit and not freeScope.Contains(useLine):     return false  // free 后提前退出，use 在别的分支
if freeScope.HasExit and freeScope.Contains(useLine) and useLine > freeScope.ExitLine:
    return false  // free 后 return，use 在 return 之后
return true
```

这是一个**保守的过近似**（偏向报告漏洞），不是完整的路径敏感 CFG。不考虑循环回边、不考虑条件谓词、不做路径合并。

### 5.4 可达性（Reachability）

**入口**：`graph.IsReachable` / `graph.ReachableSet` (`sgre/internal/graph/reachability.go`)

可达性通过 **SQLite 递归 CTE** 在 DB 端计算：

```sql
-- sgre/internal/db/crud_graph.go:113
WITH RECURSIVE reach(node) AS (
    SELECT ?                                              -- 起点
    UNION
    SELECT ge.dst_id
    FROM graph_edges ge
    JOIN reach r ON ge.src_id = r.node
    WHERE ge.edge_type = ?                                -- 边类型过滤
)
SELECT DISTINCT node FROM reach
```

**用法**：传入一个函数节点 ID 和边类型（如 `"CALL"`），返回从该函数出发沿该类型边可达的所有节点。用于回答"这个可疑函数从 main 入口是否可达"等问题。

**性能注意**：`IsReachable` 取出整个可达集再线性查找目标，是 O(N) 内存。大图上应改为 SQL 端直接判断 `EXISTS`。

---

## 6. 如何使用（消费方）

语义图被以下消费方查询：

| 消费方 | 文件 | 使用的图 API | 用途 |
|---|---|---|---|
| memory_leak 检测器 | `evidence/memory_leak.go` | `BuildCFG`、`CFG.CanReach`、`Scope.HasExit` | 判断 free 后 use 是否可达、return 是否转移所有权 |
| uninit_variable 检测器 | `evidence/uninit_variable.go` | `BuildCFG`、`FindInnermostScope` | 判断变量在所有路径上是否被赋值 |
| LifetimeFilter（planner） | `planner/filter_lifetime.go` | `BuildCFG`、`CFG.CanReach` | 去除 use-after-free 假阳性 |
| CallReachFilter（planner） | `planner/filter_call_reach.go` | `store.ReachableFromEntry(..., "CALL")` | 从 main/非 static 函数可达性过滤候选 |
| DataFlowFilter（planner） | `planner/filter_data_flow.go` | `store.ListGraphEdgesByType("DATA_FLOW")` | 标记候选是否有数据流支撑 |

**典型查询模式**：

```go
// 模式 1：从入口函数出发，哪些函数可达（用于过滤不可达的候选）
reachable, _ := store.ReachableFromEntry(ctx, mainNodeID, "CALL")
reachableSet := make(map[int64]bool)
for _, id := range reachable { reachableSet[id] = true }
if !reachableSet[suspectFuncNodeID] { /* 丢弃这个候选 */ }

// 模式 2：函数内 free 后 use 是否可达（用于去假阳性）
cfg := graph.BuildCFG(rootNode, funcStart, funcEnd)
if !cfg.CanReach(freeLine, useLine) { /* free 后不可达 use，不是 UAF */ }

// 模式 3：列出所有 DATA_FLOW 边，看候选是否有数据流支撑
edges, _ := store.ListGraphEdgesByType(ctx, "DATA_FLOW")
```

---

## 7. 完整示例

### 7.1 输入代码

`sgre/testdata/tc05_memleak_no_free.c`：

```c
#include <stdlib.h>

int tc05_memleak_no_free(int n) {
    int *arr = (int *)malloc(sizeof(int) * n);   // line 10: 指针声明 + 堆分配
    if (!arr) {
        return -1;                               // line 12: early exit
    }
    for (int i = 0; i < n; i++) {
        arr[i] = i * 2;
    }
    return arr[0];                               // line 17: 返回 arr 解引用（未 free）
}
```

### 7.2 Layer 1（indexer 写入）

```
files:    {id=1, path="tc05_memleak_no_free.c", checksum="..."}
functions:{id=1, name="tc05_memleak_no_free", file_id=1, start_line=9, end_line=18}
```

### 7.3 Layer 2（语义图构建器写入）

**Call Graph 构建产物**（重新解析源码，找 `call_expression`）：

```
节点:
  graph_nodes(id=1, entity_type="function",          entity_id=1)               // tc05_memleak_no_free
  graph_nodes(id=2, entity_type="external_function", entity_id=0, {"external":true})  // malloc（所有外部函数共享）

边:
  graph_edges(src=1, dst=2, edge_type="CALL", properties={"call_line":9})
  // 注意：call_line 用的是函数起始行 9，而非 malloc 实际调用行 10（已知近似）
```

**Data Flow 构建产物**：

```
(a) detectPointerDeclarations → 补写 variables 表:
    variables(function_id=1, name="arr", type="int*", storage_class="heap",
              declaration_line=10, is_pointer=true, is_nullable=true)

(b) detectPointerAssignments → DATA_FLOW 边:
    // line 10: arr = (int*)malloc(...)  →  RHS 是 call_expression "malloc"
    graph_nodes(id=3, entity_type="variable_ref", entity_id=1, {"name":"arr","line":10})
    graph_nodes(id=4, entity_type="variable_ref", entity_id=1, {"name":"malloc","line":10})
    graph_edges(src=4, dst=3, edge_type="DATA_FLOW", properties={"variable":"arr"})
    // 方向：malloc → arr（malloc 的返回值流向 arr）

(c) detectPointerReturns → DATA_FLOW 边:
    // line 17: return arr[0];  →  返回的是 arr（实际是 arr[0]，但 identifier 提取拿到 arr）
    graph_nodes(id=5, entity_type="return_slot", entity_id=1)
    graph_nodes(id=6, entity_type="variable_ref", entity_id=1, {"name":"arr","line":17})
    graph_edges(src=6, dst=5, edge_type="DATA_FLOW", properties={"variable":"arr"})
    // 方向：arr → return_slot（arr 的值流向返回槽）
```

**CFG 构建产物**（纯内存，不写 DB；由 memory_leak 检测器按需构建）：

```
Scope(root, line 9-18)
├── Scope(cons of "if (!arr)", line 11-13, HasExit=true, ExitLine=12)   // return -1
└── Scope(body of "for", line 14-16, HasExit=false)
```

### 7.4 下游如何用这张图

memory_leak 检测器结合上述事实推断：

1. `variables` 表显示 `arr` 是 `storage_class="heap"`、`is_nullable=true` → 候选堆分配。
2. 没有找到 `free(arr)` 调用 → 没有 `MEMORY_RELEASE` 事件。
3. CFG 显示 `if (!arr)` 分支有 early exit（line 12 return），所以 line 17 的 `return arr[0]` 只在 `arr != NULL` 路径上执行 → 不是空指针解引用，但**确实漏 free**。
4. DATA_FLOW 边 `arr → return_slot` 表明所有权转移给调用者 → 严格说这不是 leak（调用者负责 free），但当前检测器仍报告为候选，由 AI agent 最终分类。

---

## 8. 关键文件清单（蓝本）

| 文件 | 行数 | 职责 |
|---|---|---|
| `sgre/internal/graph/call_graph.go` | 124 | Call graph 构建，写 CALL 边 |
| `sgre/internal/graph/data_flow.go` | 199 | Data flow 构建，写 DATA_FLOW 边 + 补写 variables |
| `sgre/internal/graph/cfg.go` | 138 | 作用域树（CFG 近似），纯内存 |
| `sgre/internal/graph/reachability.go` | 33 | 可达性查询包装，委托 SQL 递归 CTE |
| `sgre/internal/graph/helpers.go` | 9 | `readFile` 辅助 |
| `sgre/internal/db/crud_graph.go` | 143 | graph_nodes/graph_edges 的 CRUD + `ReachableFromEntry`（递归 CTE） |
| `sgre/internal/db/schema.go:80-97` | — | `graph_nodes`/`graph_edges` 表 DDL |

**注意**：`internal/graph` 包**没有单元测试**（无 `_test.go`），全部由下游 `evidence`/`planner` 的集成测试间接覆盖。

---

## 9. 已知局限与设计争议

| 项 | 现状 | 影响 | 参考项目建议 |
|---|---|---|---|
| 无增量构建 | 每次全量重解析，边重复累积 | 重复 scan 性能差、数据脏 | builder 先 `DELETE FROM graph_edges WHERE ...` 再插，或加 UNIQUE 约束 + `INSERT OR IGNORE` |
| 外部函数合并为一个节点 | `entity_id=0` 共享 | 无法区分 `printf` 和 `malloc` | 外部函数按名字去重，单独建 `external_functions` 表或用名字 hash 做 entity_id |
| 函数名重名冲突 | `funcMap` 按名字建 | 同名函数互相覆盖 | 用 `(file_id, name)` 或签名做键 |
| `call_line` 用函数起始行 | 而非实际调用行 | 定位不准 | 用 `callNode.StartLine()` |
| data flow 不含参数流/跨函数流/别名 | 函数内、语句级、赋值/返回 only | 跨函数数据流分析无法做 | 先做参数流（形参节点 + 入口 DATA_FLOW 边），再做跨函数拼接 |
| 4/6 种边未实现 | OWNERSHIP_TRANSFER/RELEASE/BRANCH/ALIAS 预留 | 所有权/释放语义靠事件表达，不利于跨函数 | 直接用边表达，更利于图查询 |
| CFG 是作用域树非真 CFG | 不考虑循环回边、条件谓词、路径合并 | 路径敏感性弱 | 如需强路径敏感，做真 CFG + 谓词抽象 |
| 跨层写 variables | data_flow builder 写 Layer 1 | 破坏层单向性 | 让 indexer 一次写全 variables |
| 重复解析源码 | indexer 已解析过，graph builder 再解析一遍 | 性能 2x 开销 | indexer 把 AST 序列化存 DB，或 graph builder 复用 indexer 的解析结果 |
| 可达性 O(N) 内存 | 取整个可达集再线性查找 | 大图慢 | SQL 端 `EXISTS` 判断 |

---

## 10. 给参考项目的设计清单

如果你要在另一个项目（Python 或其他语言）里实现类似的语义图构建器，建议按以下顺序：

### 10.1 最小可用集（先做这些）

1. **两张表**：`graph_nodes(id, entity_type, entity_id, properties JSON)` + `graph_edges(id, src_id, dst_id, edge_type, properties JSON)`。`edge_type` 加 CHECK 约束枚举。
2. **CALL 边构建器**：遍历所有函数，对每个函数找调用表达式，建 caller→callee 边。内部函数解析到 `functions.id`，外部函数按**名字**去重建节点（不要全合并为一个）。
3. **DATA_FLOW 边构建器**（函数内）：赋值 `a = b` 建 `b → a`；`return x` 建 `x → return_slot`。
4. **可达性查询**：用递归 CTE（SQLite/PostgreSQL 都支持）或 BFS/DFS。先支持按 edge_type 过滤的可达集。
5. **去重**：builder 开头 `DELETE FROM graph_edges WHERE edge_type IN ('CALL','DATA_FLOW')` 或 UNIQUE 约束。

### 10.2 进阶（按需加）

6. **参数流**：为每个形参建 `param_slot` 节点，函数入口建 `param_slot → first_use` 的 DATA_FLOW 边。
7. **跨函数数据流**：在调用点建 `actual_arg → param_slot` 的 DATA_FLOW 边（跨函数）。
8. **ALIAS 边**：`q = p` 时除了 DATA_FLOW 还建一条 `q ↔ p` 的 ALIAS 边，做别名传播。
9. **OWNERSHIP_TRANSFER / RELEASE 边**：`return p` 建 `p → return_slot` 的 OWNERSHIP_TRANSFER；`free(p)` 建 `p → free_call` 的 RELEASE。比用事件表达更利于图查询。
10. **真 CFG**：如果路径敏感性重要，建带分支和回边的真 CFG，用数据流分析框架（如 worklist 算法）做可达性。

### 10.3 时机原则

- **在 indexer 之后、检测器之前**，一次性建好整张图。
- **CFG 惰性构建**：如果 CFG 按函数独立、且检测器只对少数函数需要，就做成纯内存按需构建（像蓝本的 `BuildCFG`），不写 DB。
- **可达性不预计算**：用递归 CTE 按需查询，不预存传递闭包（闭包 O(N²) 存储）。

### 10.4 输入原则

- **函数清单从 DB 拿**（权威的已索引函数 ID 和行范围）。
- **语法细节从源码 + 解析器拿**（最直接，避免从扁平表反查关系）。
- **避免跨层写**：builder 只写 Layer 2，不往 Layer 1 补数据。如果 Layer 1 缺数据，修 indexer。

### 10.5 Python 实现提示

如果用 Python 实现：

- 解析器：C 用 `tree-sitter`（py-tree-sitter），Python 用 `ast` 或 `tree-sitter-python`，Java 用 `tree-sitter-java`。
- 存储：SQLite（`sqlite3` 标准库）即可，递归 CTE 原生支持。
- 递归 CTE 写法和蓝本完全一样：
  ```sql
  WITH RECURSIVE reach(node) AS (
      SELECT :entry
      UNION
      SELECT ge.dst_id FROM graph_edges ge
      JOIN reach r ON ge.src_id = r.node
      WHERE ge.edge_type = :edge_type
  )
  SELECT DISTINCT node FROM reach
  ```
- 节点去重：`INSERT INTO graph_nodes ... ON CONFLICT(entity_type, entity_id) DO NOTHING RETURNING id`（SQLite 3.35+）。
- 边去重：`UNIQUE(src_id, dst_id, edge_type)` 约束 + `INSERT OR IGNORE`。

---

## 12. 架构决策经验谈（为什么这么做）

这一章解释蓝本每个关键决策背后的取舍，以及替代方案的利弊。**移植时不要照抄结论，要理解权衡**——你的项目规模、目标语言、性能要求可能让最优解不同。

### 决策 1：关系型 DB + 递归 CTE，而非图数据库

**蓝本选择**：SQLite 两张表 + 递归 CTE 算可达性。

**替代方案**：Neo4j / Dgraph / networkx 图库。

**为什么选 SQLite**：
- 安全分析管线本就是 SQLite 4 层数据模型的一部分（Layer 1/2/3/4 都在同一个 `sgre.db`），图跟事实/证据/发现同库，跨层 JOIN 方便（如"列出所有从 main 可达且产生了 NULL_VALUE 事件的函数"一条 SQL 就能写完）。
- 递归 CTE 对可达性这种"沿边类型过滤的传递闭包"足够用，SQLite/PostgreSQL 都原生支持，无需额外服务。
- 部署零依赖：单文件 `sgre.db`，CI 里随便跑。

**什么时候该换图库**：
- 节点 > 10⁶ 且需要频繁做全图 PageRank/社区检测等图算法 → 上 networkx（内存图）或 Neo4j。
- 只做可达性 + 按类型列边 → SQLite 完全够，别引入图库的运维成本。

**给 Python 项目的建议**：MVP 用 `sqlite3`，递归 CTE 一行 SQL 搞定可达性。等性能真成瓶颈再考虑 networkx 做内存缓存层，DB 仍是持久化。**不要一开始就上 Neo4j**——你 90% 的查询是"沿 CALL 边可达吗"，SQL 写起来比 Cypher 简单且可跟其他层 JOIN。

### 决策 2：边类型只实现 2/6 种（YAGNI）

**蓝本选择**：schema 定义 6 种 edge_type，但只构建 CALL 和 DATA_FLOW，其余 4 种（OWNERSHIP_TRANSFER/RELEASE/BRANCH/ALIAS）预留空枚举。

**为什么**：
- CALL + DATA_FLOW 已能支撑 14 种漏洞类型检测的候选过滤需求。
- OWNERSHIP_TRANSFER/RELEASE 的语义当前由 evidence 检测器直接写成 `security_events`（如 `MEMORY_RELEASE` 事件），不经过图边，也能跑通。
- BRANCH 由 CFG 作用域树隐式表达，ALIAS 未做别名传播。

**这是不是"偷懒"？** 部分是，部分是合理的 YAGNI。预留枚举的好处是 schema 稳定（不用 ALTER TABLE 加枚举值），坏处是容易让人误以为"已经实现"。

**给 Python 项目的建议**：
- **schema 里只声明你真要实现的边类型**，别学蓝本预留一堆。预留枚举在 Go 里是 `CHECK` 约束，Python 项目里更容易写成"动态 edge_type 字符串"，那更不该预留。
- 每加一种边类型，先问："哪个检测器/过滤器会查这条边？" 答不上来就别加。
- **但 OWNERSHIP_TRANSFER 和 RELEASE 建议你比蓝本更进一步直接用边表达**（见决策 3 后的"你可以比蓝本做得更好的地方"）。

### 决策 3：CFG 用作用域树，而非真 CFG

**蓝本选择**：`BuildCFG` 构建的是 if/for/while 嵌套的**作用域树**，`CanReach` 只看 early-exit，不考虑循环回边、条件谓词、路径合并。

**替代方案**：带分支节点和回边的真 CFG + worklist 数据流分析。

**为什么选作用域树**：
- 安全检测最需要的路径敏感性问题是"free 后 return 了，use 还能执行吗"——这种 early-exit 模式作用域树就能回答。
- 真 CFG 实现成本高一个数量级（基本块划分、回边处理、谓词抽象、不动点迭代），但对当前 14 种漏洞类型的边际收益有限。
- 投入产出比：作用域树 ~100 行代码，覆盖 ~80% 的路径敏感需求；真 CFG ~1000 行，覆盖 ~95%。

**什么时候该上真 CFG**：
- 你要检测的漏洞强依赖条件谓词（如"if (x > 0) free(p); if (x > 0) use(p);" 这种相关条件分支）。
- 你要做区间分析/抽象解释。

**给 Python 项目的建议**：MVP 阶段直接抄作用域树思路——遍历 if/for/while 建嵌套 scope，标记 HasExit，`can_reach(free_line, use_line)` 看 free 所在 scope 是否提前退出。**别一上来就写基本块和 worklist**，那是 Phase 3+ 的事。

### 决策 4：混合输入（DB 函数清单 + 重新解析源码）

**蓝本选择**：从 DB 拿 `functions`/`files`，但语法细节用 tree-sitter 重新解析源文件。

**替代方案 A**：全从 DB 拿（读 indexer 写好的 `expressions` 表反查关系）。
**替代方案 B**：全从源码拿（不依赖 DB，自己扫所有 .c 文件）。

**为什么选混合**：
- 全 DB：indexer 写入的 `expressions` 是扁平的，重建"这个赋值的 RHS 是哪个变量引用"要从扁平表反查，SQL 写起来别扭，且 indexer 不一定索引全了所有语法结构。
- 全源码：拿不到权威的 `functions.id`，无法把调用名解析到具体函数节点；且会跟 indexer 重复"发现函数"的逻辑。
- 混合：DB 给权威函数清单和 ID，源码给语法细节，各取所长。

**代价**：每个文件被 tree-sitter 解析两遍（indexer 一遍，graph builder 一遍）。蓝本接受这个开销。

**给 Python 项目的建议**：混合输入是对的，但**可以比蓝本做得更好**——让 indexer 把每个函数的 AST 子树序列化（如 pickle / JSON）存进 `functions.ast` 字段，graph builder 直接反序列化，省掉重新读文件和重新解析。如果嫌复杂，至少在 graph builder 里加一个**按文件路径缓存的解析结果**（一个函数被多次 Build 时复用）。

### 决策 5：可达性按需 CTE，不预计算传递闭包

**蓝本选择**：不存闭包表，每次查询跑递归 CTE。

**替代方案**：预计算 `reachability_closure(src, dst, edge_type)` 表，O(N²) 空间但查询 O(1)。

**为什么按需**：
- 安全分析的可达性查询是**稀疏的**——只对少数候选函数问"从 main 可达吗"，不是对所有节点对问。
- 闭包表对 N=10⁴ 函数就是 10⁸ 行，写入和增量维护成本高。
- 递归 CTE 在 SQLite 上对万级节点 + 稀疏查询是毫秒级，够用。

**什么时候该预计算**：
- 你要做"所有不可达函数"这种全量枚举 → 预计算一次闭包比逐个 CTE 快。
- 图频繁变 + 查询极密集 → 闭包增量维护（如 semi-naive）可能值得。

**给 Python 项目的建议**：按需 CTE 起步。如果发现 planner 对每个候选都查一次可达性且候选很多，再加一层"本次 scan 内 memoize 可达集"的内存缓存（key = (entry_node, edge_type)），不要急着落库。

### 决策 6：节点用 `(entity_type, entity_id)` 外键，而非每种节点一张表

**蓝本选择**：所有节点塞进 `graph_nodes(entity_type, entity_id, properties)`，`entity_id` 指向 Layer 1 对应表的 ID。

**替代方案**：`function_nodes`、`variable_ref_nodes`、`return_slot_nodes` 各一张表。

**为什么选单表 + 类型字段**：
- 边的 `src_id`/`dst_id` 只需要一个外键列，否则要 polymorphic 关联。
- 加新节点类型不用建表。
- 缺点：失去类型安全，`entity_id` 的语义靠 `entity_type` 解释。

**给 Python 项目的建议**：单表 + 类型字段是对的。**但加一个约束**：`entity_type` 用 CHECK 枚举（蓝本漏了这个），或者 Python 侧用 `enum.StrEnum` 限定。蓝本最大的节点设计缺陷是**所有外部函数共享 `entity_id=0`**——你一定要让外部函数按名字去重，要么单独 `external_functions(name)` 表，要么 `entity_id` 用名字的稳定 hash。

### 决策 7：properties 用 JSON 字符串，而非强 schema

**蓝本选择**：`graph_nodes.properties` 和 `graph_edges.properties` 都是 `TEXT`，存 JSON 字符串。

**为什么**：不同节点/边类型有不同的附加属性（CALL 有 call_line，DATA_FLOW 有 variable 名），用 JSON 灵活；强 schema 要么多列稀疏（大部分 NULL），要么分表。

**代价**：无法在 SQL 端高效按属性过滤（要 `json_extract`），类型不安全。

**给 Python 项目的建议**：JSON 字符串可以，但**Python 侧用 dataclass / pydantic 模型封装**，序列化/反序列化走模型，别到处手拼 `{"name":"%s","line":%d}` 字符串（蓝本就这么拼，容易出 bug）。SQLite 3.38+ 的 `json_extract` 可以在 SQL 端取属性，需要时用。

### 决策 8：builder 分散（CallGraphBuilder + DataFlowBuilder），而非统一 Builder

**蓝本选择**：两个独立 builder，各自 `Build()`，CLI 分别调用。没有聚合的 `GraphBuilder.BuildAll()`。

**替代方案**：一个 `GraphBuilder` 内部组合 call graph 和 data flow。

**为什么分散**：
- 各自独立可测试、可单独重跑。
- 失败隔离：call graph 挂了不影响 data flow。

**代价**：CLI 要写两行调用，且两者都遍历一遍所有函数 + 重新解析源码（**两次重复解析**）。

**给 Python 项目的建议**：分散可以，但**加一个 `build_all()` 聚合函数**做两件事：(1) 只解析每个文件一次，传给两个子 builder；(2) 统一去重/清理。这样既保持子 builder 独立，又避免蓝本的"两次解析"开销。

---

## 13. Python 项目对照检查清单

逐项对照你的 Python sgre，勾选确认。分四档：**必须做 / 应该做 / 可以做 / 别做（反模式）**。

### 13.1 必须做（缺一项图就立不住）

- [ ] **两张表 `graph_nodes` / `graph_edges`**，`edge_type` 有 CHECK 枚举或 Python enum 限定。
- [ ] **CALL 边**：对每个函数找调用表达式，建 caller→callee 边；内部函数解析到 `functions.id`。
- [ ] **DATA_FLOW 边**（函数内）：赋值 `a = b` 建 `b → a`；`return x` 建 `x → return_slot`。**方向是源→目标**。
- [ ] **可达性查询**：递归 CTE 或 BFS，支持按 `edge_type` 过滤。
- [ ] **构建时机**：在 indexer 之后、检测器之前；图建好后检测器才能查。
- [ ] **节点去重**：`GetOrCreateNode` 语义（按 `(entity_type, entity_id)` 查存在则复用）。
- [ ] **边方向有文档**：每条边类型的 src/dst 语义写清楚（如"CALL: caller→callee"）。

### 13.2 应该做（蓝本的缺陷你别重犯）

- [ ] **边去重**：builder 开头 `DELETE FROM graph_edges WHERE edge_type IN (...)` 或 `UNIQUE(src_id, dst_id, edge_type)` + `INSERT OR IGNORE`。蓝本没做，重复 scan 边会累积。
- [ ] **外部函数按名字去重**，不要全合并成一个 `entity_id=0` 节点。蓝本的合并导致无法区分 `printf` 和 `malloc`。
- [ ] **函数名重名处理**：用 `(file_id, name)` 或签名做键，不要只用名字。蓝本按名字建 `funcMap`，重名互相覆盖。
- [ ] **call_line 用实际调用行**（`call_node.start_line`），不要用函数起始行。蓝本用了函数起始行，定位不准。
- [ ] **不跨层写**：graph builder 只写 Layer 2，不往 Layer 1 的 `variables` 表补数据。蓝本 data_flow builder 往 Layer 1 写了，破坏层单向性。如果 Layer 1 缺数据，修 indexer。
- [ ] **每个文件只解析一次**：graph builder 内部按文件路径缓存 tree-sitter 解析结果。蓝本 call graph 和 data flow 各解析一遍。
- [ ] **CFG 惰性构建**：`build_cfg(func_node)` 纯内存，不写 DB，由检测器按需调用。

### 13.3 可以做（进阶，按需）

- [ ] **OWNERSHIP_TRANSFER 边**：`return p` 建 `p → return_slot` 的 OWNERSHIP_TRANSFER（比蓝本用事件表达更利于图查询）。
- [ ] **RELEASE 边**：`free(p)` 建 `p → free_call` 的 RELEASE。
- [ ] **参数流**：形参节点 + 入口 DATA_FLOW 边。
- [ ] **跨函数 data flow**：调用点 `actual_arg → param_slot`。
- [ ] **ALIAS 边**：`q = p` 建 `q ↔ p` 别名边 + 传播。
- [ ] **真 CFG**：带分支和回边，worklist 可达性。
- [ ] **可达性内存缓存**：scan 内 memoize `(entry, edge_type) → reachable_set`。
- [ ] **properties 用 dataclass/pydantic 模型**，别手拼 JSON 字符串。

### 13.4 别做（反模式）

- [ ] **别在图构建器里写"判断有没有漏洞"**。图只产生关系，安全结论由检测器/agent 下。
- [ ] **别先实现边再找用途**。每条边类型上线前先确认有消费方。
- [ ] **别让图构建器读 `expressions` 表反查关系**。从源码 + 解析器拿 AST 更直接。
- [ ] **别预计算全图传递闭包表**。稀疏查询用按需 CTE。
- [ ] **别一上来就上 Neo4j/图库**。SQLite + 递归 CTE 够用很久。
- [ ] **别一上来就写真 CFG + worklist**。作用域树覆盖 80% 路径敏感需求。
- [ ] **别把所有外部函数合并成一个节点**。
- [ ] **别用函数名做唯一键**（重名冲突）。
- [ ] **别让 builder 跨层往 Layer 1 写数据**。
- [ ] **别在 `InsertGraphEdge` 上不加任何去重就允许重复 Build**。

---

## 14. 分阶段实施路线图

给你的 Python sgre 的推荐节奏。每个阶段都有**验收标准**和**常见卡点**——卡点是我根据蓝本实现预判你大概率会踩的坑。

### Phase 0：MVP——CALL + DATA_FLOW + 可达性

**目标**：端到端跑通"索引 → 建图 → 一个最简检测器查图 → 输出"。

**该有什么**：
- `graph_nodes` / `graph_edges` 两张表 + DDL。
- `CallGraphBuilder.build()`：遍历函数，tree-sitter 找 `call_expression`，建 CALL 边。
- `DataFlowBuilder.build()`：找 `assignment_expression` 和 `return_statement`，建 DATA_FLOW 边。
- `reachable_from(entry_id, edge_type)`：递归 CTE。
- 一个测试 fixture：两个函数 A 调 B，B 里 `p = malloc(); return p;`，验证能查到 A→B 的 CALL 边和 B 内的 DATA_FLOW 边。

**不该有什么**：CFG、增量、跨函数流、alias、真 CFG、图库。**忍住别加**。

**验收标准**：
- 对一个 10 函数的小代码库，`graph_edges` 行数 = 调用数 + 赋值数 + return 数。
- `reachable_from(A, "CALL")` 返回 {A, B, B 调的所有函数...}。
- 重复跑两次 build，边数不翻倍（去重生效）。

**常见卡点**：
- tree-sitter 的节点类型名跟目标语言有关（C 是 `call_expression`，Python 是 `call`）。**先 print 一遍 AST dump 确认节点类型名**，别照抄蓝本的 C 节点名。
- `assignment_expression` 在 Python 里没有等价物（Python 是 `Assign` 节点，且是语句不是表达式）。**Python 目标语言的话 data flow 要按 Python AST 重新设计**，不能照抄。
- 递归 CTE 在 SQLite 默认 `sqlite3` 连接上能用，但如果用了 ORM（SQLAlchemy）可能要开 `PRAGMA` 或裸连接。

### Phase 1：CFG + 检测器接入

**目标**：让检测器真正用上图，而不只是图自娱自乐。

**该有什么**：
- `build_cfg(func_root_node)`：作用域树，标记 HasExit。
- `cfg.can_reach(line1, line2)`：基于 early-exit 的近似。
- 至少一个检测器查 `graph_edges`（如 memory_leak 检测器查"有没有 free 调用"）。
- 至少一个 planner filter 查 `reachable_from(..., "CALL")`（如过滤不可达候选）。

**不该有什么**：真 CFG、跨函数流。

**验收标准**：
- 一个"free 后 return，use 在 return 之后"的 fixture，`can_reach(free_line, use_line)` 返回 False。
- 一个"main 调 A，A 调 B，B 有候选"的 fixture，planner 能通过 call-graph 可达性保留 B 的候选；一个"孤立函数 C 有候选"的 fixture，planner 过滤掉 C。

**常见卡点**：
- 作用域树的 `Contains(line)` 用闭区间 `[start, end]`，注意 tree-sitter 行号是 0-based 还是 1-based，跟 DB 里存的 `start_line` 对齐。**蓝本这里踩过坑**。
- `can_reach` 是过近似（偏向报漏洞），别拿它去"证明安全"——它说不可达才真不可达，说可达可能其实不可达。

### Phase 2：增量 + 去重 + 质量度量

**目标**：能重复 scan 不脏数据，且能量化图质量。

**该有什么**：
- builder 开头清空相关边：`DELETE FROM graph_edges WHERE edge_type IN ('CALL','DATA_FLOW')`（或按文件删）。
- 文件级增量：按 checksum 跳过未变文件的图重建（需要按文件删旧边）。
- 质量度量：节点数、边数、外部函数节点数、每函数平均边数、重复边数（应为 0）。

**验收标准**：
- 连续跑 3 次 scan，`graph_edges` 行数稳定不涨。
- 改一个文件只重建该文件相关的边，其他文件边不动。
- 度量脚本输出"外部函数节点数 = 实际不同外部函数数"（验证没合并成一个）。

**常见卡点**：
- 按文件删边要先记录"该文件涉及哪些节点和边"，否则删不干净。蓝本完全没做增量，你要做就得自己设计 `DELETE FROM graph_edges WHERE src_id IN (该文件函数的节点)`。
- 增量跟"全量清空再建"的复杂度差异巨大。**如果代码库不大（< 1000 文件），直接全量清空再建，别做增量**——增量正确性很容易出 bug。

### Phase 3：跨函数流 / alias / 进阶边

**目标**：提升分析精度，支持跨函数漏洞。

**该有什么**（按需选）：
- 参数流 + 跨函数 data flow。
- ALIAS 边 + 别名传播。
- OWNERSHIP_TRANSFER / RELEASE 边。
- 真 CFG（如果路径敏感性不够）。

**验收标准**：
- 一个"调用者传 NULL，被调用者解引用"的跨函数 fixture，能通过跨函数 data flow 追到 NULL 源。
- alias：`q = p; free(p); use(q);` 能识别 q 是 p 的别名，报 use-after-free。

**常见卡点**：
- 跨函数 data flow 的边数会爆炸（每个调用点 × 每个参数）。**先加开关，默认关，只对可疑函数开启**。
- alias 传播要算不动点，别无限循环。设个传播深度上限。

---

## 15. 常见误区与反模式

**如果你发现自己正在写下面这些，停下来想想。**

1. **在 graph builder 里写 `if is_vulnerable(...)`** → 你把检测器逻辑混进了图构建。图只建关系，漏洞判断放检测器。

2. **为了"完整性"加了 6 种边类型但只有 2 种有消费方** → YAGNI。删掉没消费方的边类型，等真有需求再加。

3. **`graph_nodes` 里外部函数全是同一个节点** → 你复刻了蓝本的缺陷。按名字去重。

4. **builder 不清空旧边直接 INSERT，第二次跑边数翻倍** → 加去重。最简单：builder 开头 `DELETE FROM graph_edges WHERE edge_type = ?`。

5. **用函数名做 `func_map` 的 key** → 重名冲突。用 `(file_id, name)` 或 mangled name。

6. **`call_line` 存成函数起始行** → 定位不准。用调用表达式的实际行号。

7. **graph builder 往 `variables`/`functions` 表写数据** → 跨层写。Layer 1 缺数据修 indexer，别在 Layer 2 补。

8. **每个检测器自己 `parser.parse(file)` 一遍** → 重复解析。在 builder 里按文件缓存解析结果，或 indexer 存 AST。

9. **预计算 `reachability_closure` 表存所有节点对** → O(N²) 空间。用按需 CTE。

10. **CFG 建了基本块和回边但检测器只用 `can_reach`** → 过度工程。作用域树就够，真 CFG 等有谓词敏感需求再做。

11. **properties 手拼 `f'{{"name":"{n}","line":{l}}}'`** → 引号/转义 bug。用 `json.dumps` 或 dataclass。

12. **递归 CTE 忘了 `UNION`（写成 `UNION ALL`）** → 可达集有重复元素。用 `UNION` 去重（蓝本用的是 `UNION`，对的）。

13. **`can_reach` 返回 True 就断定"漏洞真发生"** → 它是过近似（偏向报）。True 不代表真可达，False 才真不可达。拿 False 去假阳性，别拿 True 去确认真阳性。

14. **图构建器读 `expressions` 表反查"这个赋值的 RHS 是谁"** → 从源码 AST 拿更直接。扁平表反查关系是反模式。

15. **加了 `entity_type` 但没 CHECK 约束也没 enum** → 拼错字符串静默写入脏数据。加 CHECK 或 `StrEnum`。

---

## 16. 验证你做对了

### 16.1 图构建正确性的单元测试

为每种边类型写一个最小 fixture，断言建出的边正好符合预期。模板：

```python
def test_call_graph_simple():
    code = """
    void a() { b(); }
    void b() { c(); }
    void c() {}
    """
    build_index_and_graph(code)
    edges = list_graph_edges(edge_type="CALL")
    assert {(e.src_name, e.dst_name) for e in edges} == {("a", "b"), ("b", "c")}
    assert reachable_from(node_id("a"), "CALL") == {node_id("a"), node_id("b"), node_id("c")}
    assert not is_reachable(node_id("c"), node_id("a"), "CALL")  # 反向不可达
```

**关键断言模式**：
- 边集合精确匹配（不是"至少包含"）——抓多余边。
- 可达性正反都测（a 到 c 可达，c 到 a 不可达）。
- 重复 build 后边数不变（去重生效）。

### 16.2 度量图质量的指标

建一个 `graph_stats()` 函数输出：

| 指标 | 健康值 | 异常信号 |
|---|---|---|
| `node_count` / `function_count` | ~1（每个函数一个 function 节点） | >>1 说明节点重复创建 |
| `external_node_count` vs 实际不同外部函数数 | 相等 | external_node_count=1 说明全合并了 |
| `edge_count` / `call_count`（CALL 边） | ~1 | >>1 说明边重复 |
| `duplicate_edge_count` | 0 | >0 说明去重没生效 |
| `avg_data_flow_per_function` | 跟代码风格相关 | 异常高说明把表达式拆太细 |
| `unreachable_function_count` / `function_count` | 项目相关 | 偏高说明 call graph 漏边（很多函数本该可达却没连上） |

**把这些指标加进 scan 输出**，每次 scan 自动打印，异常时一眼看出。

### 16.3 端到端 fixture 设计

蓝本有 `tc01-tc17` 共 17 个 fixture，每个针对一个检测器。建议你的 Python sgre 也建一套，**每个 fixture 同时验证图构建和检测结论**：

```
fixtures/
  call_chain_reachable.c      # main→a→b→c，验证可达性
  call_chain_unreachable.c    # 孤立函数，验证不可达过滤
  dataflow_assign.c           # p = q; 验证 DATA_FLOW 边方向
  dataflow_return.c           # return p; 验证 return_slot 边
  cfg_early_exit.c            # if (!p) return; use(p); 验证 can_reach
  cfg_no_exit.c               # 普通顺序执行，验证 can_reach=True
  external_func_distinct.c    # 调 printf 和 malloc，验证两个不同外部节点
  ...
```

每个 fixture 配一个 `expected.json` 声明应该建出哪些边、哪些可达关系。CI 跑一遍比对。

### 16.4 回归测试

蓝本 `internal/graph` 包**没有单元测试**，全靠下游集成测试间接覆盖——这是缺陷，别学。你的 Python sgre 应该：
- `tests/graph/test_call_graph.py` — call graph 构建正确性。
- `tests/graph/test_data_flow.py` — data flow 边方向和数量。
- `tests/graph/test_reachability.py` — 递归 CTE 正确性（含环、含不可达）。
- `tests/graph/test_cfg.py` — 作用域树和 can_reach。
- `tests/graph/test_idempotent.py` — 连续 build 两次结果一致（去重生效）。

**`test_idempotent` 是蓝本缺、你必须有的**——它直接抓住"边重复累积"这个蓝本缺陷。

---

## 17. Python 实现具体指引

### 17.1 库选择

| 用途 | 推荐 | 备选 | 备注 |
|---|---|---|---|
| C 源解析 | `tree-sitter` + `tree-sitter-c` | pycparser | tree-sitter 跟蓝本一致；pycparser 纯 Python 但只支持 C |
| Python 源解析 | `ast`（标准库） | `tree-sitter-python` | 分析 Python 项目用 `ast` 够；要跨语言统一用 tree-sitter |
| 存储 | `sqlite3`（标准库） | SQLAlchemy | MVP 用裸 sqlite3；ORM 后期再加 |
| 递归 CTE | sqlite3 原生 | — | `WITH RECURSIVE` 直接写 |
| AST dump 调试 | tree-sitter 的 `node.sexp()` | — | 先 dump 确认节点类型名 |

### 17.2 与 Go 蓝本的语义差异

| 点 | Go 蓝本 | Python 你的项目 |
|---|---|---|
| 节点类型名 | C 的 `call_expression`/`assignment_expression` | 目标语言不同，**先 dump 确认** |
| 赋值表达式 | C 有 `assignment_expression` | Python 是 `ast.Assign` 语句，多对一（`a = b = c`） |
| return | C `return_statement` | Python `ast.Return` |
| 函数定义 | C `function_definition` | Python `ast.FunctionDef` |
| 行号 | tree-sitter 0-based | `ast` 1-based，**跟 DB 存的对齐** |
| 并发 | Go goroutine 可并行建图 | Python GIL，别想并行，串行即可 |

### 17.3 可运行骨架（Call Graph Builder）

```python
import sqlite3, json
from tree_sitter import Parser, Language

class CallGraphBuilder:
    def __init__(self, db: sqlite3.Connection, parser: Parser):
        self.db = db
        self.parser = parser

    def build(self):
        # 清空旧 CALL 边（蓝本没做，你必须做）
        self.db.execute("DELETE FROM graph_edges WHERE edge_type = 'CALL'")
        funcs = self.db.execute(
            "SELECT id, name, file_id, start_line, end_line FROM functions"
        ).fetchall()
        func_map = {(f[1]): f[0] for f in funcs}  # TODO: 用 (file_id, name) 避免重名冲突

        for fid, name, file_id, sline, eline in funcs:
            path = self._file_path(file_id)
            source = open(path, "rb").read()
            tree = self.parser.parse(source)
            caller_node = self._get_or_create_node("function", fid, None)
            for call_node in self._find_calls(tree.root_node, sline, eline):
                callee_name = self._extract_call_name(call_node)
                if not callee_name:
                    continue
                if callee_name in func_map:
                    callee_node = self._get_or_create_node("function", func_map[callee_name], None)
                else:
                    # 外部函数按名字去重，不要全合并成 entity_id=0
                    callee_node = self._get_or_create_external(callee_name)
                self.db.execute(
                    "INSERT INTO graph_edges (src_id, dst_id, edge_type, properties) VALUES (?,?,?,?)",
                    (caller_node, callee_node, "CALL",
                     json.dumps({"call_line": call_node.start_point[0] + 1})),  # 用实际调用行，不是函数起始行
                )
        self.db.commit()

    def _get_or_create_node(self, entity_type, entity_id, properties):
        row = self.db.execute(
            "SELECT id FROM graph_nodes WHERE entity_type=? AND entity_id=?",
            (entity_type, entity_id),
        ).fetchone()
        if row:
            return row[0]
        cur = self.db.execute(
            "INSERT INTO graph_nodes (entity_type, entity_id, properties) VALUES (?,?,?)",
            (entity_type, entity_id, json.dumps(properties) if properties else None),
        )
        return cur.lastrowid

    def _get_or_create_external(self, name: str):
        # 外部函数按名字去重：用 entity_type='external_function' + entity_id=名字 hash
        # 或单独 external_functions 表。这里用 hash 演示。
        import hashlib
        eid = int(hashlib.md5(name.encode()).hexdigest()[:8], 16)
        return self._get_or_create_node("external_function", eid, {"name": name, "external": True})
```

**可达性查询**：

```python
def reachable_from(db: sqlite3.Connection, entry_id: int, edge_type: str) -> set[int]:
    rows = db.execute("""
        WITH RECURSIVE reach(node) AS (
            SELECT ? UNION
            SELECT ge.dst_id FROM graph_edges ge
            JOIN reach r ON ge.src_id = r.node
            WHERE ge.edge_type = ?
        ) SELECT DISTINCT node FROM reach
    """, (entry_id, edge_type)).fetchall()
    return {r[0] for r in rows}
```

### 17.4 性能注意

- **tree-sitter 解析是热点**：按文件路径缓存 `(path, mtime) -> tree`，避免 call graph 和 data flow 各解析一遍。
- **批量插入**：Python `sqlite3` 默认每条 INSERT 一次事务。用 `executemany` 或显式 `BEGIN/COMMIT` 包住整个 build，快 10–100x。
- **`ListFunctions` 一次拿全表**，别在循环里逐个查。
- **递归 CTE 对万级节点毫秒级**，别过早优化。真慢了再加 scan 内 memoize。

---

## 18. 从蓝本到你的 Python 项目——映射表

移植时按这张表找对应。

| 蓝本（Go） | 你的 Python 项目 | 移植要点 |
|---|---|---|
| `sgre/internal/graph/call_graph.go` | `sgre/graph/call_graph.py` | 节点类型名换成目标语言的；外部函数按名字去重 |
| `sgre/internal/graph/data_flow.go` | `sgre/graph/data_flow.py` | Python 的赋值是 `ast.Assign` 不是表达式，重写 |
| `sgre/internal/graph/cfg.go` | `sgre/graph/cfg.py` | 作用域树思路通用，if/for/while 节点名换 |
| `sgre/internal/graph/reachability.go` | `sgre/graph/reachability.py` | 递归 CTE 直接抄 |
| `sgre/internal/db/crud_graph.go` | `sgre/db/graph_crud.py` | `GetOrCreate` 用 `ON CONFLICT DO NOTHING RETURNING` |
| `sgre/internal/db/schema.go` graph 部分 | `sgre/db/schema.py` | 加 `entity_type` CHECK 约束，蓝本漏了 |
| `BuildResult{EdgesCreated,ExternalFuncs}` | `@dataclass class BuildResult` | 加 `external_node_count` 等度量字段 |
| `funcMap map[string]int64` | `dict[str, int]` | key 用 `(file_id, name)` 元组，别只用 name |
| `InsertGraphEdge` 纯 INSERT | 加 `UNIQUE(src_id,dst_id,edge_type)` + `INSERT OR IGNORE` | 蓝本没去重，你要修 |
| `internal/graph` 无单元测试 | `tests/graph/test_*.py` 必须有 | 别学蓝本无测试 |
| `secguard scan` 调 `cgBuilder.Build` + `dfBuilder.Build` | `scan` 命令调 `build_all()` | 加聚合函数，只解析每文件一次 |

**蓝本的 3 个缺陷你务必修掉**：(1) 边不去重 → 加 UNIQUE + IGNORE；(2) 外部函数合并 → 按名字去重；(3) `call_line` 用函数起始行 → 用调用行。

**蓝本的 3 个优点你要保留**：(1) 混合输入（DB 函数清单 + 源码解析）；(2) CFG 惰性纯内存；(3) 可达性按需递归 CTE。

---

## 11. 一页速查

### 蓝本速查

```
何时构建：  indexer 之后、检测器之前（scan 流程第 2-3 步）
根据什么：  DB 的 functions/files 表 + 源文件 tree-sitter 重新解析
构建什么：  graph_nodes（function/external_function/variable_ref/return_slot）
            graph_edges（CALL、DATA_FLOW；其余 4 种预留）
            + 补写 variables 表（跨层副作用，不建议模仿）
怎么用：    检测器查 graph_edges 回答"谁调用谁""数据从哪来"
            planner 用 ReachableFromEntry("CALL") 过滤不可达候选
            检测器用 BuildCFG + CanReach 做函数内路径敏感性近似
关键局限：  无增量、外部函数合并、重名冲突、data flow 不跨函数、CFG 非真 CFG
最小实现：  CALL + DATA_FLOW + 递归 CTE 可达性，约 300 行代码
```

### Python 移植速查

```
必做：      两张表 + CALL + DATA_FLOW + 递归 CTE 可达性 + 去重 + 节点去重
必避：      外部函数合并、重名 key、跨层写、无去重、手拼 JSON、预计算闭包
必加测试：  test_idempotent（连跑两次边数不变）——蓝本没做你必须做
阶段：      Phase 0 MVP(CALL+DF+可达) → Phase 1(CFG+检测器接入) → Phase 2(去重+度量) → Phase 3(跨函数流)
判断做对：  能回答"X 从入口可达吗""V 的值从哪来""free 后 use 路径可达吗"三问
```