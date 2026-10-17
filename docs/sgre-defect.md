# 任务：补强 tree-sitter-c grammar 对 GNU C __attribute__ 与两个扩展的支持

## 仓库
github.com/DannyAn/tree-sitter-c（fork of tree-sitter/tree-sitter-c），当前 v0.24.3 tag。
grammar 文件：grammar.js。已支持 typeof_specifier（四种拼写），本任务补齐另外 6 类缺陷。

## 缺陷清单（均已用 tree-sitter go-tree-sitter v0.25.0 实政，HasError()=true）

### B1: 变量声明后置 __attribute__ 解析失败
当前 grammar 的 attribute/attribute_specifier/attribute_declaration 规则只接在函数、参数、语句、字段、类型 specifier 位置，未接在 init_declarator / pointer_declarator 之后。
失败形态（全部 HasError=true）：
  int g __attribute__((aligned(16))) = 0;
  int g __attribute__((packed)) = 0;
  int g __attribute__((section(".data"))) = 0;
  int g __attribute__((used)) = 0;
  void free_fn(int *p){}  int f(void){ int g __attribute__((cleanup(free_fn))) = 0; return g; }
期望：declaration 规则允许 init_declarator 后跟可选 attribute_specifier，与函数级 attribute 对称。参考已 OK 的 attr_field（struct 字段后置 attribute）和 attr_stmt（语句前置 attribute）的接法。

### B2: typedef 级 __attribute__ 解析失败
失败形态：
  typedef int __attribute__((vector_size(16))) v4si;
  typedef int __attribute__((may_alias)) alias_int;
期望：type_definition 规则允许 type_specifier 与 declarator 之间插入 attribute_specifier。

### B3: enum 级 __attribute__ 解析失败
失败形态：
  enum E __attribute__((packed)) { A, B, C };
期望：enum_specifier 规则允许 enum 体前后可选 attribute_specifier（与 struct_specifier 已支持的 attr_type 对称）。

### B4: 标签级 __attribute__ 解析失败
失败形态：
  int f(void){ goto L; L: __attribute__((cold)); return 0; }
期望：labeled_statement 规则允许冒号后跟可选 attribute_declaration。

### B5: GNU case 范围扩展解析失败
当前 case_statement 只支持 `case <expr>:`，不支持 `case <expr> ... <expr>:`。
失败形态：
  int f(int x){ switch(x){ case 1 ... 5: return 1; default: return 0; } }
期望：case_statement 增加分支 `seq('case', field('value', $.expression), '...', field('value',$.expression), ':', ...)`。注意 `...` 是三个点 token，与 variadic_parameter 的 `...` 复用但位置不同。

### B6: 计算跳转（computed goto）解析失败
两个子形态都失败：
  void *p = &&L;        // 取标签地址（GNU unary &&）
  goto *p;              // 跳转到指针目标
失败整体：
  int f(void){ void *p = &&L; goto *p; L: return 0; }
期望：
  - unary_expression 增加分支 `prec(PREC.UNARY, seq('&&', $._statement_identifier))` 产生标签地址。
  - goto_statement 增加分支 `seq('goto', '*', $.expression, ';')` 支持间接跳转。

## 约束
1. 不破坏现有规则：改完后 `tree-sitter generate` 必须成功，且现有 test/corpus 里所有 *.txt 用例解析结果不变（无新增 ERROR、无节点类型变更）。
2. attribute 的接法要与现有 attribute_specifier/attribute_declaration/attribute 规则复用，不要新造平行的 attribute 规则。
3. `...` 在 case_range 与 variadic_parameter 是同一字面量，无需新 token，只是新产生式。
4. computed goto 的 `&&` 与按位与 `&&`（C 没有按位与 &&，只有逻辑 &&）不冲突；与取地址 `&` 单目不冲突（双 &）。优先级按 PREC.UNARY。
5. 产出后打 tag v0.24.4（或按仓库版本策略），更新 bindings/go（`tree-sitter generate` + `node-gyp build` 或仓库既定流程），确保 Go binding `tree_sitter_c.Language()` 可用。

## 验证
改完 grammar.js 后，用以下 Go 代码逐条验证 HasError()=false（sgre 侧已验证当前全为 true）：
  形态见上表 B1-B6 每条的"失败形态"，改完后应全部 HasError()=false。
另跑 tree-sitter-c 仓库自带的 corpus 测试确保无回归。