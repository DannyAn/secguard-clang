# sgre 设计实现检视报告(2026-08-26)

> 检视范围:`sgre/internal/graph` 全部、`db` 存储层、`planner` 流引擎与过滤器、`evidence` 编排、`parser`、`cli/scan`。
> 检视主题:semantic graph 的利用率、影响性能与稳定性的关键点。
> 性质:问题清单 + 修复方案,未做任何代码修改。
>
> **总评**:CFG/数据流引擎本身设计质量高(may/must 双格、field-sensitive kill、收敛保证齐全),
> 但"持久化语义图"写入端存在严重的累积性缺陷(边表/variables 表永不清理、每次扫描全量重复插入),
> 消费端存在多个 O(rounds×F) 不动点热点与静默退化点。持久化图目前实质上只是一个
> 弱加速器 + 跨函数 join 索引,而非 CLAUDE.md 定位的"单一事实源"。

---

## 问题总表

| # | 问题 | 严重度 | 类别 | 定位 |
|---|------|--------|------|------|
| 1 | graph_edges 每扫描全量重复插入,永不清理 | 高 | 稳定性+性能 | scan.go:157-186, crud_graph.go:93 |
| 2 | variables 表只写不读,每扫描重复累积 | 高 | 稳定性 | data_flow.go:58 |
| 3 | call_graph 同名函数坍缩 → 假阴性 | 高 | 正确性 | call_graph.go:36-39 |
| 4 | PARAM_BINDING 跨文件前向引用丢失 | 中 | 正确性 | interproc.go:50-90 |
| 5 | 外部函数身份丢失 + call_line 属性错位 | 中 | 利用率+潜伏 | call_graph.go:66-68, 74 |
| 6 | RETURN 边零消费方(死数据)+ 注释误导 | 中 | 利用率 | filter_nullable_source.go:123 |
| 7 | LockOrderBuilder 按行序而非 CFG 追踪持锁 | 中 | 正确性(FP) | lock_order.go:42-70 |
| 8 | ALIAS 边忽略 field 属性 → UAF 假阳性路径 | 中 | 正确性(FP) | alias.go:103-117, null_flow.go:753-798 |
| 9 | 静默退化面广(无日志) | 中 | 稳定性/观测 | helpers.go:38-46 等 |
| 10 | planner 不动点每轮全量重跑函数内数据流 | 高(性能) | 性能 | filter_nullable_source.go:202-221 等 |
| 11 | 写入零批量化,全部 autocommit | 高(性能) | 性能 | crud_graph.go, crud_events.go |
| 12 | CFG 每扫描重复构建 6+ 次 | 中(性能) | 性能 | evidence 6 处 + planner filters |
| 13 | N+1 查询族 | 中(性能) | 性能 | planner.go:235-249 等 |
| 14 | ParseCached 全量常驻 + indexer 双重解析 | 中(性能) | 性能/内存 | parser.go:82-95, indexer.go:34 |

---

## 一、高严重度(稳定性/正确性)

### 问题 1:graph_edges 每次扫描全量重复插入,永不清理【最严重】

**证据**
- `scan.go:157-186`:每次 scan 无条件重跑 7 个 graph builder(并行);
- `cli/index.go:69-105`:`index` 命令同样重跑;
- `crud_graph.go:93` `InsertGraphEdge` 是裸 INSERT,`graph_edges` 表无 UNIQUE 约束;
- 全代码库 grep 确认:没有任何 `DELETE FROM graph_edges` / `graph_nodes`
  (唯一的 DELETE 是 `ClearSecurityEvents` 与 `DeleteFunctionsByFile`);
- DB 设计上是跨扫描持久化的(`.codeagent/.../.sgre/sgre.db`,findings 历史/baseline 都在里面)。

**影响**
- N 次扫描后边表 N 倍膨胀;所有 `ListGraphEdgesByType` 消费者
  (null_flow 的 DATA_FLOW/ALIAS/RELEASE 加载、filter_ownership、filter_lock_order、
  filter_shared_access、call_reach)都做全表扫描 → plan 阶段耗时与内存随扫描次数线性恶化;
- 变更文件重索引后,旧函数 ID 对应的 node/edge 永久残留
  (`graph_nodes.entity_id` 无 FK,不随 functions 的 ON DELETE CASCADE 级联),成为永久死数据;
- 好消息:现有消费者全部以 map/set 吸收重复,正确性暂未受损,纯粹是资源问题——
  但这是悬在头上的 cliff(大库 + 多次扫描后某个 plan 阶段会突然变慢一个数量级)。

**修复方案(高把握)**
图是每次扫描全量重建的(没有增量逻辑),所以最简单、最干净的修复是 **scan/index 开头先清空再重建**:

1. `db.Store` 新增方法(带 schema 层接口声明):
   ```go
   // crud_graph.go
   func (s *store) ClearGraph(ctx context.Context) error {
       // 先删边再删节点(graph_edges 对 graph_nodes 有 FK)
       if _, err := s.exec.ExecContext(ctx, `DELETE FROM graph_edges`); err != nil { ... }
       if _, err := s.exec.ExecContext(ctx, `DELETE FROM graph_nodes`); err != nil { ... }
       return nil
   }
   ```
2. 在 `scan.go` 调用 7 个 builder **之前**(index 完成、builders 启动前)调用 `store.ClearGraph(ctx)`;
   `cli/index.go` 同样处理;
3. 顺带做一次 `PRAGMA wal_checkpoint(TRUNCATE)` 或 VACUUM 可选(不必需)。

为什么不选"给 edge 加 UNIQUE + INSERT OR IGNORE":边的业务唯一键是
(src_id, dst_id, edge_type, properties),加 UNIQUE 后 stale 数据仍会留存,
且 properties 里含行号等易变字段,去重键脆弱。清空重建一并解决 stale 残留。

**验证**
- 对同一 fixture 连跑 2 次 `secguard scan`,断言 `SELECT COUNT(*) FROM graph_edges` 两次一致;
- 现有回归测试(`zz_p0p1_regression_test.go` 等)+ `go test ./...` 全绿。

---

### 问题 2:variables 表只写不读,每扫描重复累积

**证据**
- `data_flow.go:58` `detectPointerDeclarations` 对每个指针声明 `InsertVariable`
  (注意:这是 graph builder 在写 Layer-1 表,层级本身就混乱);
- variables 无唯一约束、无清理(仅当文件变更、functions 被级联删除时才随函数消失);
- grep 确认:`ListPointerVariables` / `ListVariablesByFunction` / `GetVariableByID` 在
  db 包外**零消费方**(过滤器用的是 event props 里的 `NonNullable`,不查这张表);
- 附带缺陷:`isHeapAllocation`(data_flow.go:172)对整段声明文本做子串匹配,
  `char *my_malloc_log;` 会被标为 heap/is_nullable——污染的恰恰是"最稳定的程序事实层"。

**修复方案(高把握)**
直接删除 `detectPointerDeclarations` 的写路径(方法与 `isHeapAllocation` 一并移除),
`DataFlowBuilder.Build` 只保留 DATA_FLOW 边构建。理由:无消费方 = 无行为变化;
表中已有数据可留可清(建议在 ClearGraph 同一版本顺手 `DELETE FROM variables`,
或留一条 release note 说明废弃)。

**验证**
- `go test ./...` 全绿(无测试依赖该表内容);
- `secguard scan` 输出的 candidates/findings 数量与改前一致(diff 两次扫描的 report)。

---

### 问题 3:call_graph 同名函数坍缩 → 假阴性

**证据**
- `call_graph.go:36-39`:`funcMap[f.Name] = f.ID`,同名后者覆盖前者;
- C 里 static 函数跨文件同名合法且常见。被遮蔽函数的 graph node 无 CALL 入边、
  又非入口函数 → `computeCallReach` 判其不可达 → `call_reach` 过滤器**丢弃该函数全部候选**;
- 对比:interproc.go:44 正确使用了 `map[string][]int64`;evidence/interprocedural.go 也正确。

**修复方案(高把握)**
与 interproc.go 对齐:

```go
funcByName := make(map[string][]int64)
for _, f := range funcs {
    funcByName[f.Name] = append(funcByName[f.Name], f.ID)
}
// 调用点处理:对每个同名 callee 各发一条 CALL 边
for _, calleeID := range funcByName[callName] {
    calleeNodeID, err = b.store.GetOrCreateGraphNode(ctx, "function", calleeID, "")
    ...
}
```

注意:多 callee 会让 CALL 边数量增加(每调用点 × 同名函数数),在问题 1 修复
(清空重建)的前提下可控;call_reach 的 BFS 语义不变。

**验证**
- 新增回归测试:两个文件各含同名 `static void helper(...)`,扫描后断言
  两个 function node 都在 reachable 集合中、候选不被 call_reach 丢弃。

---

## 二、中严重度(正确性/精度)

### 问题 4:PARAM_BINDING 跨文件前向引用系统性丢失

**证据**
- `interproc.go:50-90`:`paramsByFunc` 在 forEachFile 回调里**边遍历文件边累积**;
  调用点文件在 filepath.Walk 字典序上先于被调函数所在文件时(如 `a.c` 调 `z.c` 的函数),
  `paramsByFunc[calleeID]` 为空 → `if i >= len(params)` break → 绑定边静默丢失;
- 约一半跨文件参数绑定缺失(取决于文件名字典序),削弱 taint / 可空性跨过程传播;
- 讽刺:被它"替代"的 `evidence/interprocedural.go` 是两阶段实现(先全文件收集 params,
  再扫调用点),没有此问题。

**修复方案(高把握)**
改为两阶段,结构照抄 evidence/interprocedural.go:

```
阶段一:遍历所有文件,收集 paramsByFunc(全部函数)+ 各文件 AST 缓存(已有 ParseCached,代价低);
阶段二:遍历所有文件,对每个调用点发 PARAM_BINDING / RETURN 边。
```

实现上把 forEachFile 跑两遍即可(解析有缓存,第二轮不重复 parse),
或者把 Build 拆成两个闭包分别传给 forEachFile。

**验证**
- 测试:文件 A(字典序靠前)调用文件 B(靠后)中函数的参数,断言 PARAM_BINDING 边存在;
- taint 现有测试(`filter_taint_source_test.go`)全绿。

---

### 问题 5:外部函数身份丢失 + call_line 属性错位

**证据**
- `call_graph.go:66-68`:所有外部函数共用一个节点
  (`entity_id=0, props={"external":true}`)→ 图无法回答"这里调用了谁",
  malloc/strcpy/free 的 CALL 边不可区分;消费方被迫重新解析 AST;
- `call_graph.go:74`:`call_line` 属性写的是 `f.StartLine`(函数起始行)而非调用行。
  目前全库无消费方,属潜伏错误。

**修复方案(高把握)**
1. external_function 节点以函数名区分:
   ```go
   props, _ := json.Marshal(map[string]bool{"external": true}) // 改为
   props, _ := json.Marshal(map[string]string{"name": callName, "external": "true"})
   ```
   `GetOrCreateGraphNode` 按 (entity_type, entity_id, properties) 去重,
   改 props 后每个外部函数自然获得独立节点;
   `persistRelease`(ownership.go:151)同步修改,RELEASE 边的语义随之完整
   (指向具体的 free/fclose 而非匿名节点);
2. `call_graph.go:74`:`"call_line": f.StartLine` → `"call_line": callNode.StartLine()`。

**验证**
- 断言 `malloc` 与 `strcpy` 的 CALL 边 dst 是不同 node;node properties 里 name 正确;
- 现有测试全绿(call_line 无消费方,改动无回归面)。

---

### 问题 6:RETURN 边零消费方(死数据)+ 注释误导

**证据**
- 全库无人 `ListGraphEdgesByType("RETURN")`;
- `filter_nullable_source.go:123` 注释声称 "This wires the RETURN edges + function_summary
  into the flow engine",实际 `computeRetNullable` 走的是 AST(`callResultNullSources` 遍历赋值)。

**修复方案(两个方向,推荐 b)**
- 方案 a(做实):让 `callResultNullSources` 改为消费 RETURN 边
  (retNode→variable_ref 即 "x = f()" 的事实),消除 AST 重扫。改动中等,
  收益是与 #5 修复合并后,跨函数调用事实真正走图;
- 方案 b(诚实化,低风险):暂不接线,但把 `filter_nullable_source.go:119-124` 的注释改准确,
  并在 `graph/interproc.go` 的 RETURN 段注释标注 "consumed by future work;
  current consumers re-derive from AST"。等 #5 完成后再考虑接线。

推荐先 b 后 a:注释是零风险的,接线放到 #5 验证之后。

---

### 问题 7:LockOrderBuilder 按行序而非 CFG 追踪持锁

**证据**
- `lock_order.go:42-70`:`held` 按文档行序累计(FindAll 返回文档序),无视分支互斥;
- branch1 `lock(A); lock(B)`、branch2 `lock(B); lock(A)`(互斥分支)会制造假环
  → LockOrderFilter 找到环 → "confirmed" 假阳性死锁;
- CFG 层(`BuildStmtCFG` + `Reaches`)就在同一个包里,未接入。

**修复方案(方向明确,中等把握——建议先修数据后修检测)**
1. 最小改法(不引入完整数据流):按行序收集 (call, callName, mutexName) 后,
   对每对 A→B 边检查"是否存在一条控制流路径使 A 的 lock 与 B 的 lock 先后可达":
   用 `cfg.NodeAt(lineA).Reaches(nodeA, nodeB)` 过滤——A 的语句节点必须能 CFG 可达 B 的语句节点才发边。
   这能消掉"两个互斥分支先后各出现"的部分假环;
2. 完整改法:对 `held` 集合做 may 前向数据流(union join),在 CFG 节点粒度上传播持锁集合,
   每对 lock(B)@node 时刻对集合中每个 A 发边。复用 null_flow 的引擎模式即可。
先做 1(几行,消掉最常见的"跨互斥分支"假环),2 视假阳性率决定。

**验证**
- 用两个互斥分支的 fixture(分支1 lock(A)→lock(B),分支2 lock(B)→lock(A)),
  断言改后不再产生 deadlock confirmed;
- 真实死锁 fixture(`zz_lock_order_test.go`)不回退。

---

### 问题 8:ALIAS 边忽略 field 属性 → UAF 假阳性路径

**证据**
- `alias.go:103-117`:`q = p->f` 存为 "q 别名 p"(field 存进边 props 但仅作记录);
- `null_flow.go:753-798` `loadAliases` **不读 field 属性**,字段别名当全变量别名:
  `free(p)` 后使用 `q`(q 可能只是 int 字段值的拷贝)被判 dangling;
  must-tier 满足时会升级 "confirmed" → 假阳性 UAF;
- 部分场景下 field 别名是对的方向(`q = p->f` 且 p->f 是指针且被 free),
  所以不能一刀切全删。

**修复方案(高把握)**
在 loadAliases 里解析边 props 的 `field` 字段,仅当 `field == ""`(全变量别名)才进入
freed-state 传播;`field == "[]"`/具名字段的别名保留为将来按需开启(或对指针类型才启用)。

```go
var props struct{ Field string `json:"field"` }
json.Unmarshal([]byte(e.Properties), &props)
if props.Field != "" { continue } // 字段别名不参与全变量 freed 传播
```

**验证**
- fixture:`q = p->f; free(p); return q->x;`(p->f 为 int 场景应不再 confirmed);
- `filter_lifetime_test.go` / `zz_review_verify_test.go` 现有 UAF 用例不回退。

---

### 问题 9:静默退化面广(安全工具的隐性 false negative)

**证据**
- `helpers.go:38-46`(graph)与 `detector.go:52-66`(evidence):文件读取/解析失败
  静默 `continue`,不产边、不告警;
- `null_flow.go` loadDFGCopies/loadAliases/loadFreeSites:任何 DB 错误返回空 map 继续;
- `filter_ownership.go:46`:节点加载失败静默 keep-all。

**修复方案(高把握,纯观测性)**
所有"降级继续"的分支补 `logger.Warn`(logger 已在调用链上,graph builder 与 filter 都持有);
`forEachFile` 统计 skip 计数并入返回值或 scan log("files skipped: N (read=.., parse=..)")。
不改行为,只让退化可见。

**验证**
- 人为 chmod 一个 fixture 文件不可读,断言 scan log 出现 Warn 且 scan 不失败。

---

## 三、性能关键点

### 问题 10:planner 侧 O(rounds×F) 不动点循环(上次只修了 evidence 侧的 O(F²))

**证据**
- `filter_nullable_source.go:202-221` computeRetNullable:
  `for { for 每个未标记函数 { analyzeFlow(重建CFG+effects+worklist) } }`——
  每轮对**所有**未标记函数重跑完整函数内数据流,无增量;
- `filter_taint_source.go:283-302` computeRetTainted 同模式
  (base effects 有预计算,但 analyzeFlow 每轮仍全量重跑);
  computeReturnsParam(368)/computeParamTainted(623) 同族;
- 函数的分析结果只在其 callee 的 retNullable 集合变化时才可能变,而当前不感知这一点。
  调用链深 K 时 = K 轮 × F 次完整分析。

**修复方案(高把握)**
增量跳过:第一轮为每个函数记录它 body 中实际调用的 callee 名集合
(`callResultNullSources` 一遍 AST 就有,或单独轻量收集);后续轮里,
仅当"本轮新加入 retNullable 集合的函数名 ∩ 该函数的 callee 名集合"非空时才重跑该函数的分析,
其余直接复用上一轮的 flow 结果(按 fn.ID 缓存 flowResult)。

```
第一轮:全量分析 + 记录 calleeNames[fid] + 缓存 flow[fid]
后续轮:delta = 本轮新标记的函数名
       仅当 calleeNames[fid] ∩ delta ≠ ∅ 才重新 analyzeFlow
```
正确性不变(retNullable 只增不减;调用集不含 delta 的函数,其分析输入与上轮完全一致)。
taint 三个 fixpoint 同样套用。

**验证**
- 用生成的 perf codebase(`testdata/perf/gen_codebase.go`)对比改前后 plan 阶段耗时
  (scan log 已有 phase timing);
- `definite_null_test.go` / `filter_taint_source_test.go` / `recall_test.go` 全绿。

---

### 问题 11:写入零批量化,全部 autocommit

**证据**
- `GetOrCreateGraphNode`(crud_graph.go:38-55)= INSERT OR IGNORE + SELECT 两次往返/节点;
- 每条边、每个事件、每个 location 各自一个隐式事务;
- scan.go:7 builder 并发 + detector 4 并发 + plan 4 并发共享 `SetMaxOpenConns(4)` 的 SQLite,
  全部串行到单写者;`WithTx` 存在但批量写场景无人用。

**修复方案(高把握,分两步)**
1. **builder 内存去重 + 事务包裹**:每个 builder 在单文件粒度用 `store.WithTx`
   包住整文件的节点+边写入(7 个 builder 已按文件分块,天然事务边界);
   同时在 builder 内存里先 dedup(一个 map[(type,id,props)]int64)避免对同一节点
   反复 GetOrCreate——调用点循环里 caller 节点被重复解析 F×C 次(call_graph.go:45)就是典型;
2. **detector 事件批写**:emitEvent 改为攒批(如每 500 条或每文件 flush),
   location + event 用多值 INSERT(`INSERT INTO ... VALUES (?),(?),...`)。
   注意保持现有失败日志语义(批失败时整批 Warn)。

预期:graph_build 与 detector 阶段 wall-clock 显著下降
(每语句一次 fsync/锁竞争 → 每文件/每批一次)。

**验证**
- scan log 的 `phase timing`(graph_builders_parallel / detectors_total)前后对比;
- `go test ./...` 全绿;`crud_scan_stats_perto` 等统计不回退。

---

### 问题 12:CFG 每扫描重复构建 6+ 次

**证据**
- evidence 侧 6 处 `BuildStmtCFG`(memory_leak.go:103、resource_leak.go:47、
  race_condition.go:413、uninit_variable.go:203、free_summary.go:101/183);
- planner 每个 flow filter 每函数再建一次(同一函数在一次扫描中被建多次);
- CFG 构建是 O(语句数),单次不贵,但乘上 6+ 个调用方与函数数。

**修复方案(方向明确)**
在 graph 包加一个 per-scan 的函数级缓存并贯穿传递:

```go
// internal/graph/cache.go
type CFGCache struct { mu sync.Mutex; m map[string]*StmtCFG } // key: fileID:fnID:startLine
func (c *CFGCache) Get(fileID, fnID, startLine int64, body parser.Node, end int) *StmtCFG
```
- 短平快做法:scan.go 创建一个 `*graph.CFGCache`,通过 detector/filter 构造函数注入
  (与 parser 注入同路数);
- 更轻的替代(如果不想动构造函数签名):包级 `sync.Map` + 每扫描 generation 计数,
  scan 开始时 `graph.ResetCFGCache()`。可先做后者验证收益。

**验证**
- perf codebase 上对比 detectors_total 耗时;
- 现有全部回归测试。

---

### 问题 13:N+1 查询族

**证据**
- `planner.go:235-249` seedCandidatesByType:每事件 GetFunctionByID + GetLocationByID;
- `null_analysis.go:56-61` buildNullModel:每 NULL_VALUE 事件查一次 location;
- `filter_nullable_source.go:174-193` computeRetNullable:每函数 GetFileByID + GetSummaryByFunction;
- `planner.go:214-217` Plan:每候选 GetFileByID。
事件/候选上千时即数千次点查 × 15 个 vuln type。

**修复方案(高把握,纯机械)**
- 加两个批量 API 并在上述热点替换:
  ```go
  // crud_locations.go
  ListLocationsByIDs(ctx, ids []int64) (map[int64]*Location, error)   // WHERE id IN (...),分片≤500
  // crud_functions.go / crud_summary.go
  ListFunctionsByIDs(ctx, ids []int64) (map[int64]*Function, error)
  ListSummariesByFunctionIDs(ctx, ids []int64) (map[int64]*FunctionSummary, error)
  ```
- seed 阶段先一次 `ListFunctions`(本来就有)+ 一次 location 批查建索引,循环内只查 map;
- Plan 的 GetFileByID 换成文件表一次性 map(候选去重后文件数远小于候选数)。

**验证**
- `go test ./...`;输出 JSON 与改前 byte-diff 一致(顺序敏感字段注意保持稳定排序)。

---

### 问题 14:ParseCached 全量常驻 + indexer 双重解析

**证据**
- `parser.go:82-95`:每文件独占 parser + tree + 源码 byte,直到 CloseAll,无淘汰——
  万文件级代码库内存悬崖(tree-sitter tree + 源文本全驻留);
- `indexer.go:34` `NewIndexer` 自建 parser(非缓存 Parse,tree 即用即关),
  scan.go 又有一个共享 parser → 每文件每扫描实际解析 2 次。

**修复方案**
1. (高把握)indexer 复用 scan 级 parser:`NewIndexer(store, logger)` 增加 parser 注入参数
   (scan.go 已有 `p`,直接传入;`index` 命令自己 new 一个并 defer CloseAll)。
   每文件解析成本立刻减半;
2. (中等把握,大库才需要)ParseCached 加 LRU 淘汰:保留热文件
   (容量按字节或文件数可配,默认足够大不改变现有行为)。
   涉及"Node 持有已释放 tree"的 UAF 风险面,动手前先写并发压力测试。

**验证**
1. `indexer_test.go` 全绿;scan log 前后无行为差异;
2. LRU 项用大 codebase 跑 RSS 前后对比。

---

## 四、语义图利用率评估(检视主题的直接回答)

| 边类型/表 | 消费方 | 状态 |
|---|---|---|
| CALL | call_reach(sync.Once 跨类型缓存,设计好) | ✅ 但缺外部函数身份(问题 5)、static 坍缩(问题 3) |
| DATA_FLOW | null_flow 拷贝提示 | ⚠️ 仅 var=var 拷贝;引擎仍靠 AST directAssignments 补全 |
| ALIAS | UAF/双释放 freed 传播 | ⚠️ field 属性被忽略(问题 8) |
| RELEASE | loadFreeSites(仅 release_fn=free) | ⚠️ fclose/close 的 RELEASE 边无人消费 |
| PARAM_BINDING | 仅 taint 过滤器 | ⚠️ 跨文件前向丢失(问题 4) |
| RETURN | **无** | ❌ 死数据(问题 6) |
| LOCK_ORDER | deadlock 过滤器 | ⚠️ 行序构建可造假环(问题 7) |
| GLOBAL_ACCESS | race 过滤器 | ✅ 基本可用 |
| OWNERSHIP_TRANSFER | leak 过滤器(安全网定位) | ✅ 按契约可用 |
| variables 表 | **无** | ❌ 死表(问题 2) |
| StmtCFG | 不持久化 | ⚠️ 每消费方按需重建(问题 12) |

**结构性结论**:
1. 跨过程可空性、taint 的核心推导每次都在 planner 侧从 AST 重推,
   持久化图实际角色是"join 索引 + 拷贝提示",与 CLAUDE.md 的"单一事实源"定位有差距;
2. `evidence/interprocedural.go` 与 `graph/interproc.go` 是**两套系统做同一个
   参数↔调用点 join**,前者不读后者的边(后者还有问题 4 的缺陷);
   长期应收敛为一套(图为准),短期至少修掉问题 4 让两边结果一致;
3. 修复问题 1/2/5 后,图的信噪比会显著提升,再考虑做实 RETURN 边(问题 6 方案 a)
   才有意义。

---

## 五、亮点(避免一边倒)

- `control_flow.go` CFG 构建器对 break/continue 共享栈、for 的 update-before-retest、
  `for(;;)` 不发假出口边、preproc 分支替代语义处理细致,方向保守正确;
- null_flow 引擎的 may/must 双格、field-sensitive killBase、reaching-sources 格设计严谨,
  注释解释了每个反直觉决策(如 `for(;;)`、kill 语义);
- call_reach 的 sync.Once 缓存、detector 的 panic recover、
  `GetOrCreateGraphNode` 原子 upsert、`emitEvent` 失败可见化——都是对的历史修复;
- `walkNode` 的零分配遍历、detector.go/evidence 的 forEachFile 单遍化——
  此前的 O(F²) 修复质量过硬。

---

## 六、修复排期建议(只排序)

| 顺序 | 项 | 理由 |
|------|----|------|
| 1 | 问题 1 + 2(ClearGraph / 删 variables 写) | 一个版本同时止血膨胀与死表;改动小、收益立即 |
| 2 | 问题 3(static 坍缩) | 直接假阴性;改动 ~10 行 |
| 3 | 问题 4(PARAM_BINDING 两阶段) | 几行结构调整,显著提升图质量 |
| 4 | 问题 10(不动点增量缓存) | planner 剩余最大热点 |
| 5 | 问题 11 + 13(批量写 + N+1) | 常规优化,机械替换 |
| 6 | 问题 5 + 6(外部函数身份 / RETURN 诚实化) | 提升图保真度,为后续接线铺路 |
| 7 | 问题 8 + 9(ALIAS field / 观测性) | 精度与可运维性 |
| 8 | 问题 7(lock-order CFG 化) | 先最小改法(Reaches 过滤) |
| 9 | 问题 12 + 14(CFG 缓存 / parser 复用+LRU) | 大库场景收益;14.1(indexer 复用 parser)可提前随手做 |

> 每项修复前建议先在 `sgre/testdata/perf` 生成的大库上记录基线耗时
> (scan log 已有 phase timing),修完对比,避免"感觉变快"。
