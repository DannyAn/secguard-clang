package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type IntegerOverflowDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewIntegerOverflowDetector(store db.Store, p *parser.Parser, logger *log.Logger) *IntegerOverflowDetector {
	return &IntegerOverflowDetector{store: store, parser: p, logger: logger}
}

func (d *IntegerOverflowDetector) Name() string { return "integer_overflow" }

func (d *IntegerOverflowDetector) Domain() string { return "boundary" }

func (d *IntegerOverflowDetector) Capabilities() []string {
	// "truncation" (CWE-197: a wide product narrowed into a small type) is not
	// detected — the declared list must not overstate what the detector emits.
	return []string{"unsigned-wraparound", "size-calculation-overflow"}
}

var sizeFunctions = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true, "memcpy": true,
	"memmove": true, "memset": true, "mmap": true, "alloca": true,
	"strncpy": true, "strncat": true, "snprintf": true,
}

// minMulConstOverflow is the smallest literal multiplier that makes a
// `param * CONST` size product a plausible overflow. `n * 2`/`n * 4` (doubling,
// small magic numbers) need n within one bit of SIZE_MAX/type-max to wrap, which
// is implausible for a count; a block size of >= 256 bytes (`n * 1024`,
// `n * 4096`, `n * sizeof(big_struct)`) can wrap for a realistic caller-supplied
// count. This gates only the literal-constant pattern — `n * sizeof(T)` stays the
// canonical count × element-size CWE-190 and is handled separately.
const minMulConstOverflow = 256

// isSizeFunction reports whether a call name is a size-bearing allocation/copy
// function. Beyond the exact libc set, any name whose lowercased form contains
// "alloc" is treated as an allocator — every allocator-family name (malloc,
// calloc, realloc, alloca, palloc, kmalloc, vmalloc) contains that substring, so
// this one rule covers third-party wrappers like VOS_MALLOC, VOS_MALLOC_F,
// VOS_CALLOC_F, ngx_alloc, apr_palloc, devm_kmalloc, etc. A free/dealloc wrapper
// takes a pointer, not a size, so it carries no overflow-prone arithmetic arg
// and is safely excluded by the arithmetic check even if a name like "dealloc"
// matched.
func isSizeFunction(name string) bool {
	if sizeFunctions[name] {
		return true
	}
	return strings.Contains(strings.ToLower(name), "alloc")
}

// isCallocLike reports whether a call name is calloc or a calloc-family wrapper
// (VOS_CALLOC_F, kcalloc, ngx_calloc, ...), whose first two (or last two, for a
// flags-prefixed wrapper) size arguments carry an implicit multiplication.
func isCallocLike(name string) bool {
	return strings.Contains(strings.ToLower(name), "calloc")
}

func (d *IntegerOverflowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	globalTypedefs := buildGlobalTypedefs(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)
		globals, scopes := buildIntegerOverflowTypeScopes(root, funcs, typedefs)
		binaryExprs := root.FindAll("binary_expression")
		calls := root.FindAll("call_expression")
		assigns := root.FindAll("assignment_expression")
		// Parameter names per function, used to recognize "caller-influenced"
		// operands: arithmetic on a function parameter (vs. a bounded local) is
		// the signal that a variable-bounded size expression may overflow.
		paramsByLine := make(map[int][]string)
		for _, fnNode := range root.FindAll("function_definition") {
			paramsByLine[fnNode.StartLine()] = findParamsInDefinition(fnNode)
		}
		for _, f := range funcs {
			params := make(map[string]bool)
			for _, p := range paramsByLine[f.StartLine] {
				params[p] = true
			}
			assigned := d.collectAssignments(root, f)
			influenced := computeInfluenced(params, assigned)
			// 64-bit (wide) integer variables: a product involving one cannot
			// overflow a 64-bit result on LP64, so they gate the size-calc flag.
			wideVars := make(map[string]bool)
			for _, v := range scopes[f.StartLine].locals {
				if isWideIntegerType(v.typ, typedefs) {
					wideVars[v.name] = true
				}
			}
			for name, typ := range globals {
				if isWideIntegerType(typ, typedefs) {
					wideVars[name] = true
				}
			}

			for _, expr := range binaryExprs {
				if !funcLineRange(f, expr.StartLine()) {
					continue
				}
				if !isArithmeticOp(expr) {
					continue
				}
				if !d.isInBoundsCheck(expr, f) {
					continue
				}
				if !d.feedsIntoSizeCall(calls, expr, f) {
					continue
				}

				if emitEvent(ctx, d.store, d.logger, "INTEGER_OVERFLOW", f.ID, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()}, map[string]string{
					"expression": expr.Text(),
					"category":   "integer_overflow",
				}) {
					result.EventsCreated++
				}
			}

			d.detectSizeCalcOverflow(ctx, calls, f, file, influenced, wideVars, assigned, &result)
			d.detectUnsignedSubUnderflow(ctx, calls, assigns, f, file, scopes[f.StartLine], globals, typedefs, influenced, &result)
		}
	})
	return result, err
}

type integerOverflowTypeScope struct {
	locals []scopedVarDecl
	params map[string]bool
}

// buildIntegerOverflowTypeScopes resolves the variable types needed by the
// unsigned-subtraction check. It includes parameters, locals, and file-scope
// variables, while keeping a separate parameter set because the underflow
// heuristic only trusts subtraction operands influenced by a function caller.
func buildIntegerOverflowTypeScopes(root parser.Node, funcs []*db.Function, typedefs *typedefs) (map[string]string, map[int]integerOverflowTypeScope) {
	globals := make(map[string]string)
	scopes := make(map[int]integerOverflowTypeScope, len(funcs))
	for _, f := range funcs {
		scopes[f.StartLine] = integerOverflowTypeScope{params: make(map[string]bool)}
	}

	for _, decl := range root.FindAll("declaration") {
		line := decl.StartLine()
		base, vars := varDeclParts(decl)
		if base == "" || len(vars) == 0 {
			continue
		}
		owner := functionContainingLine(funcs, line)
		for _, v := range vars {
			typ := base + starSuffix(v.stars)
			if owner == nil {
				globals[v.name] = typ
				continue
			}
			scope := scopes[owner.StartLine]
			scope.locals = append(scope.locals, scopedVarDecl{
				name: v.name,
				typ:  typ,
				line: line,
				end:  declScopeEnd(decl, owner),
			})
			scopes[owner.StartLine] = scope
		}
	}

	for _, param := range root.FindAll("parameter_declaration") {
		owner := functionContainingLine(funcs, param.StartLine())
		if owner == nil {
			continue
		}
		typ := typeSpelling(param)
		name := extractVarFromDeclarator(param)
		if typ == "" || name == "" || parser.IsCTypeKeyword(name) {
			continue
		}
		scope := scopes[owner.StartLine]
		scope.params[name] = true
		scope.locals = append(scope.locals, scopedVarDecl{
			name: name,
			typ:  typ,
			line: param.StartLine(),
			end:  owner.EndLine,
		})
		scopes[owner.StartLine] = scope
	}
	return globals, scopes
}

func functionContainingLine(funcs []*db.Function, line int) *db.Function {
	for _, f := range funcs {
		if f.EndLine >= f.StartLine && line >= f.StartLine && line <= f.EndLine {
			return f
		}
	}
	return nil
}

// collectAssignments builds a one-level variable -> arithmetic-expression map for
// a function, from `int t = n*m;` (init_declarator) and `t = n*m;`
// (assignment_expression). It lets `int t = n*m; malloc(t)` be classified — the
// most common way a size product is split into a named local before allocation.
// Only an unambiguous single assignment is recorded; a second assignment leaves
// the name absent so the value is not guessed.
func (d *IntegerOverflowDetector) collectAssignments(root parser.Node, f *db.Function) map[string]parser.Node {
	assigned := make(map[string]parser.Node)
	for _, init := range root.FindAll("init_declarator") {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		name, expr := declaratorAssignment(init)
		if name != "" && expr != nil {
			assigned[name] = *expr
		}
	}
	for _, assign := range root.FindAll("assignment_expression") {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if children[0].Kind() == "identifier" && (children[1].Kind() == "binary_expression" || children[1].Kind() == "identifier") {
			assigned[children[0].Text()] = children[1]
		}
	}
	return assigned
}

// declaratorAssignment returns the declared variable name and its initializer
// expression for an init_declarator whose value is a single binary_expression.
func declaratorAssignment(init parser.Node) (string, *parser.Node) {
	var name string
	var value *parser.Node
	for _, child := range init.NamedChildren() {
		if child.Kind() == "identifier" && name == "" {
			name = child.Text()
		}
		if child.Kind() == "binary_expression" && value == nil {
			v := child
			value = &v
		}
	}
	return name, value
}

// bareIdentText returns the identifier text of a bare (possibly parenthesized)
// identifier operand, or "" when it is not one.
func bareIdentText(arg parser.Node) string {
	for arg.Kind() == "parenthesized_expression" {
		ch := arg.NamedChildren()
		if len(ch) == 0 {
			return ""
		}
		arg = ch[0]
	}
	if arg.Kind() != "identifier" {
		return ""
	}
	return arg.Text()
}

func isArithmeticOp(expr parser.Node) bool {
	// The operator is read from the anonymous AST token, not the raw text, so a
	// no-whitespace spelling (`n*m`) is recognized exactly like `n * m`.
	return arithOperator(expr) != ""
}

// nodeInfluenced reports whether an assigned expression derives its value from a
// call or an already-influenced variable, so the assigned local is caller/attacker
// influenced (vs. a constant local like `size_t n = 16`).
func nodeInfluenced(n parser.Node, influenced map[string]bool) bool {
	switch n.Kind() {
	case "call_expression":
		return true
	case "identifier":
		return influenced[n.Text()]
	}
	for _, c := range n.NamedChildren() {
		if nodeInfluenced(c, influenced) {
			return true
		}
	}
	return false
}

// computeInfluenced returns the caller/attacker-influenced variable set: a
// function parameter, or a local whose value derives (transitively) from a call
// or another influenced variable. A local assigned a constant (`size_t n = 16`)
// is NOT influenced.
func computeInfluenced(params map[string]bool, assigned map[string]parser.Node) map[string]bool {
	influenced := make(map[string]bool, len(params))
	for p := range params {
		influenced[p] = true
	}
	for changed := true; changed; {
		changed = false
		for name, expr := range assigned {
			if influenced[name] || !nodeInfluenced(expr, influenced) {
				continue
			}
			influenced[name] = true
			changed = true
		}
	}
	return influenced
}

// isInBoundsCheck reports whether expr is an operand of a relational comparison
// (<, <=, >, >=) that itself lives in an if/while condition — i.e. the guard
// computes the same arithmetic that can wrap. This is deliberately narrower
// than "any arithmetic inside any if": equality checks (strcmp(...) == 0,
// rot == len-1), constant-folded allocations (malloc(7 + 3*sizeof(int)) ==
// NULL), and bare pointer arithmetic passed to a call are not overflow guards
// and must not be flagged. The structural Parent() walk replaces the earlier
// line-range heuristic, which matched any arithmetic within a few lines of any
// if-condition and produced ~10 noise candidates on zlib (gun.c's strcmp loops,
// etc.).
func (d *IntegerOverflowDetector) isInBoundsCheck(expr parser.Node, f *db.Function) bool {
	for p := expr.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "binary_expression":
			if isRelationalComparison(*p) {
				return true
			}
		case "if_statement", "while_statement", "for_statement",
			"expression_statement", "return_statement", "compound_statement":
			// Reached a condition/statement boundary without an intervening
			// relational comparison: the arithmetic is not a guard operand.
			return false
		}
	}
	return false
}

// isRelationalComparison reports whether node is a binary_expression whose
// top-level operator is a relational comparison (<, <=, >, >=). It reads the
// operator token from the node's direct children — not the whole text, which
// would be fooled by `->` member access inside an operand (e.g. `x->y == NULL`
// contains `>` and must NOT be treated as relational). Equality, logical, and
// bit-shift operators have their own token kinds and are excluded.
func isRelationalComparison(node parser.Node) bool {
	if node.Kind() != "binary_expression" {
		return false
	}
	for _, child := range node.Children() {
		switch child.Kind() {
		case "<", ">", "<=", ">=":
			return true
		}
	}
	return false
}

func (d *IntegerOverflowDetector) feedsIntoSizeCall(calls []parser.Node, expr parser.Node, f *db.Function) bool {
	exprText := expr.Text()
	operands := extractOperands(expr)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !isSizeFunction(callName) {
			continue
		}
		if call.StartLine() <= expr.StartLine() {
			continue
		}
		callText := call.Text()
		// A whole-identifier token match, not a substring match: a single-char
		// operand (n/m/i/k) must not hit inside an unrelated identifier
		// (`malloc(len)` contains "n" but does not use n).
		for _, op := range operands {
			if containsIdentToken(callText, op) {
				return true
			}
		}
		if strings.Contains(callText, exprText) {
			return true
		}
	}
	return false
}

// containsIdentToken reports whether text contains ident as a whole C identifier
// token (bounded by non-identifier characters), so `n` does not match inside
// `len`.
func containsIdentToken(text, ident string) bool {
	if ident == "" {
		return false
	}
	for i := 0; i+len(ident) <= len(text); i++ {
		if text[i:i+len(ident)] != ident {
			continue
		}
		before := i == 0 || !isIdentByte(text[i-1])
		after := i+len(ident) == len(text) || !isIdentByte(text[i+len(ident)])
		if before && after {
			return true
		}
	}
	return false
}

func isIdentByte(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func extractOperands(expr parser.Node) []string {
	var operands []string
	for _, child := range expr.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_expression" {
			operands = append(operands, child.Text())
		}
		for _, sub := range child.FindAll("identifier") {
			operands = append(operands, sub.Text())
		}
	}
	return operands
}

// sizeCalcCandidate is one overflow-prone size expression and its category.
type sizeCalcCandidate struct {
	expr     parser.Node
	category string
}

// detectSizeCalcOverflow flags an arithmetic expression passed directly as a
// size-function argument whose product/sum/difference can wrap before the
// allocation. It is the "value-analysis lite" half of the integer-overflow
// detector: beyond the canonical `malloc(count * obj_size)` (CWE-190), it now
// recognizes calloc(n, m) and the variable-bounded add/sub/mul-const patterns
// that a full range domain (CodeQL RangeAnalysis, Infer Inferbo) would catch.
//
// Because a *variable* operand cannot be proven large, the variable-bounded
// patterns are gated on the operand being a function parameter (caller/
// attacker-influenced) and are emitted as suspected/possible candidates that
// the AI agent reasons over. This is the AI-fallback tier: static analysis
// recognizes the risky shape, the model proves or refutes it with call-site
// and API-contract reasoning.
func (d *IntegerOverflowDetector) detectSizeCalcOverflow(ctx context.Context, calls []parser.Node, f *db.Function, file *db.File, influenced, wideVars map[string]bool, assigned map[string]parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !isSizeFunction(callName) {
			continue
		}
		args := callNamedArguments(call)

		// calloc(n, m) and its wrappers (VOS_CALLOC_F, kcalloc, ...): the
		// multiplication is implicit across two arguments, so the per-argument
		// sizeCalcExprs scan (which sees only a bare n or m) misses it. Two
		// variable arguments is the classic CWE-190 overflow.
		if isCallocLike(callName) && len(args) >= 2 {
			// A 3-argument wrapper usually prefixes a flags/gfp argument, so
			// the product is the LAST two arguments; a 2-argument call is the
			// standard calloc(n, size).
			a0, a1 := args[0], args[1]
			if len(args) >= 3 {
				a0, a1 = args[len(args)-2], args[len(args)-1]
			}
			product := a0.Text() + " * " + a1.Text()
			if isVariableOperand(a0) && isVariableOperand(a1) {
				d.emitIntegerOverflowText(ctx, file, f, call, product, "size_calc_overflow", result)
				continue
			}
			// calloc(n, sizeof(T)) and calloc(n, CONST) are the SAME implicit
			// product the malloc(n * sizeof(T)) / malloc(n * 2) cases cover, but
			// split across two arguments — the most common allocation idiom in
			// real code and previously a systematic blind spot (CWE-190).
			if c := d.callocOverflowCategory(a0, a1, influenced, wideVars); c != "" {
				d.emitIntegerOverflowText(ctx, file, f, call, product, c, result)
				continue
			}
		}

		for _, arg := range args {
			// Resolve a chain of assignments (`int t = n*m; u = t; malloc(u)`)
			// to the underlying arithmetic before classification, so a size
			// product stored through several named locals is not missed.
			eff := arg
			for depth := 0; depth < 8; depth++ {
				name := bareIdentText(eff)
				if name == "" {
					break
				}
				expr, ok := assigned[name]
				if !ok {
					break
				}
				eff = expr
			}
			for _, c := range d.sizeCalcExprs(eff, influenced, wideVars) {
				d.emitIntegerOverflow(ctx, file, f, c.expr, c.category, result)
			}
		}
	}
}

// callocOverflowCategory classifies the implicit `arg0 * arg1` product of a
// calloc call with the SAME rules sizeCalcExprs applies to `malloc(a * b)`:
//
//   - var * sizeof(T) → size_calc_overflow   (calloc(n, sizeof(int)))
//   - param * CONST   → size_mul_const_overflow (calloc(n, 1024), n caller-influenced)
//
// A constant * constant, a sizeof(char) (==1) operand, or a CONST below
// minMulConstOverflow cannot plausibly overflow and returns "". Both argument
// orders are accepted.
func (d *IntegerOverflowDetector) callocOverflowCategory(a0, a1 parser.Node, influenced, wideVars map[string]bool) string {
	classify := func(arg parser.Node) (isVar, isParam, isSizeof, isNum, sizeofOne, isWide bool, constValue int) {
		for arg.Kind() == "parenthesized_expression" {
			ch := arg.NamedChildren()
			if len(ch) == 0 {
				return
			}
			arg = ch[0]
		}
		switch {
		case isVariableOperand(arg):
			return true, influenced[arg.Text()], false, false, false, wideVars[arg.Text()], 0
		case arg.Kind() == "sizeof_expression":
			return false, false, true, false, sizeofIsOne(arg), true, 0 // sizeof is size_t (64-bit)
		case arg.Kind() == "number_literal":
			return false, false, false, true, false, false, parseConstantIndex(arg.Text())
		}
		return
	}
	v0, p0, s0, n0, o0, w0, c0 := classify(a0)
	v1, p1, s1, n1, o1, w1, c1 := classify(a1)
	// var * sizeof(T): sizeof promotes the product to size_t (64-bit on LP64),
	// so it cannot overflow a 64-bit product — not a CWE-190 on LP64.
	if (v0 && s1 && !o1) || (s0 && !o0 && v1) {
		return ""
	}
	// param * CONST: overflow only when the parameter is a NARROW (<=32-bit)
	// integer type; a 64-bit (size_t/long) parameter makes the product 64-bit.
	if (p0 && n1 && c1 >= minMulConstOverflow) || (n0 && c0 >= minMulConstOverflow && p1) {
		if (p0 && w0) || (p1 && w1) {
			return ""
		}
		return "size_mul_const_overflow"
	}
	return ""
}

func (d *IntegerOverflowDetector) emitIntegerOverflow(ctx context.Context, file *db.File, f *db.Function, expr parser.Node, category string, result *DetectResult) {
	d.emitIntegerOverflowText(ctx, file, f, expr, expr.Text(), category, result)
}

// emitIntegerOverflowText emits an overflow event with an explicit expression
// text. It is used for calloc, whose multiplication is implicit across two
// arguments: recording the call node's text (`calloc(n, m)`) would make the
// planner's operand extraction see the function name as an operand, so the guard
// bound lookup never matches and the candidate can never be suppressed.
func (d *IntegerOverflowDetector) emitIntegerOverflowText(ctx context.Context, file *db.File, f *db.Function, node parser.Node, exprText, category string, result *DetectResult) {
	if emitEvent(ctx, d.store, d.logger, "INTEGER_OVERFLOW", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, map[string]string{
		"expression": exprText,
		"category":   category,
	}) {
		result.EventsCreated++
	}
}

// detectUnsignedSubUnderflow catches unsigned subtraction before a value is
// passed to an ordinary function. The size-calculation paths above only inspect
// allocator/copy arguments and intentionally skip subtraction; this check uses
// type information to handle the common `count - consumed` shape without
// treating every C subtraction as an integer-overflow candidate.
func (d *IntegerOverflowDetector) detectUnsignedSubUnderflow(ctx context.Context, calls, assigns []parser.Node, f *db.Function, file *db.File, scope integerOverflowTypeScope, globals map[string]string, typedefs *typedefs, influenced map[string]bool, result *DetectResult) {
	if scope.locals == nil {
		return
	}
	check := func(expr parser.Node) {
		expr = unwrapExprNode(expr)
		if expr.Kind() != "binary_expression" || arithOperator(expr) != "-" {
			return
		}
		operands := expr.NamedChildren()
		if len(operands) != 2 {
			return
		}
		lhs := operands[0]
		rhs := operands[1]
		lhsUnsigned, lhsInfl := unsignedSubOperand(lhs, expr.StartLine(), globals, scope, typedefs, influenced)
		rhsUnsigned, rhsInfl := unsignedSubOperand(rhs, expr.StartLine(), globals, scope, typedefs, influenced)
		if !lhsUnsigned || !rhsUnsigned || (!lhsInfl && !rhsInfl) {
			return
		}
		if exprTextKey(lhs) == exprTextKey(rhs) || unsignedSubGuarded(expr, lhs, rhs) {
			return
		}
		d.emitIntegerOverflow(ctx, file, f, expr, "unsigned_sub_underflow", result)
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		for _, arg := range callNamedArguments(call) {
			check(arg)
		}
	}
	// A subtraction stored into a local first (`size_t rem = total - consumed;`)
	// is the common underflow shape and must not be missed just because it is not
	// a direct call argument.
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		check(children[1])
	}
}

func unwrapExprNode(node parser.Node) parser.Node {
	for node.Kind() == "parenthesized_expression" {
		children := node.NamedChildren()
		if len(children) == 0 {
			return node
		}
		node = children[0]
	}
	return node
}

func unsignedSubOperand(node parser.Node, line int, globals map[string]string, scope integerOverflowTypeScope, typedefs *typedefs, influenced map[string]bool) (bool, bool) {
	node = unwrapExprNode(node)
	switch node.Kind() {
	case "identifier":
		name := node.Text()
		typ := resolveScopedVar(name, line, globals, scope.locals)
		return isUnsignedScalarType(typ, typedefs), influenced[name]
	case "pointer_expression":
		if !strings.HasPrefix(strings.TrimSpace(node.Text()), "*") {
			return false, false
		}
		children := node.NamedChildren()
		if len(children) == 0 {
			return false, false
		}
		target := unwrapExprNode(children[0])
		if target.Kind() != "identifier" {
			return false, false
		}
		name := target.Text()
		typ := resolveScopedVar(name, line, globals, scope.locals)
		if !isPointerType(typ, typedefs) {
			return false, false
		}
		return isUnsignedScalarType(pointedToResolved(typ, typedefs), typedefs), influenced[name]
	case "subscript_expression":
		children := node.NamedChildren()
		if len(children) == 0 {
			return false, false
		}
		base := unwrapExprNode(children[0])
		if base.Kind() != "identifier" {
			return false, false
		}
		name := base.Text()
		typ := resolveScopedVar(name, line, globals, scope.locals)
		if !isPointerType(typ, typedefs) {
			return false, false
		}
		return isUnsignedScalarType(pointedToResolved(typ, typedefs), typedefs), influenced[name]
	}
	return false, false
}

func isUnsignedScalarType(typ string, typedefs *typedefs) bool {
	resolved := resolveType(strings.TrimSpace(typ), typedefs)
	if resolved == "" || strings.Contains(resolved, "*") {
		return false
	}
	return isUnsignedDecl(resolved) || typedefs.resolvesToUnsigned(resolved)
}

// isWideIntegerType reports whether a type is a 64-bit (or wider) integer type on
// LP64, so a multiplication involving it (`n * sizeof(T)`, `size_t n; n * 1024`)
// cannot overflow a 64-bit product for any realistic operand.
func isWideIntegerType(typ string, typedefs *typedefs) bool {
	resolved := resolveType(strings.TrimSpace(typ), typedefs)
	switch resolved {
	case "size_t", "ssize_t", "long", "unsigned long", "long long", "unsigned long long",
		"int64_t", "uint64_t", "intmax_t", "uintmax_t", "ptrdiff_t", "uintptr_t", "intptr_t":
		return true
	}
	return false
}

func exprTextKey(node parser.Node) string {
	node = unwrapExprNode(node)
	return strings.Join(strings.Fields(node.Text()), "")
}

// unsignedSubGuarded recognizes the two equivalent dominance guards that make a
// subtraction safe: `if (rhs <= lhs) { ... lhs - rhs ... }` and its mirrored
// `if (lhs >= rhs) { ... }`.
func unsignedSubGuarded(expr, lhs, rhs parser.Node) bool {
	for parent := expr.Parent(); parent != nil; parent = parent.Parent() {
		if parent.Kind() != "if_statement" {
			continue
		}
		cons := parent.ChildByFieldName("consequence")
		cond := parent.ChildByFieldName("condition")
		if cons == nil || cond == nil || !nodeContains(*cons, expr) {
			continue
		}
		condition := unwrapExprNode(*cond)
		if condition.Kind() != "binary_expression" {
			continue
		}
		operands := condition.NamedChildren()
		if len(operands) != 2 {
			continue
		}
		left := exprTextKey(operands[0])
		right := exprTextKey(operands[1])
		lhsKey := exprTextKey(lhs)
		rhsKey := exprTextKey(rhs)
		switch relationalOperator(condition) {
		case "<", "<=":
			return right == lhsKey && left == rhsKey
		case ">", ">=":
			return left == lhsKey && right == rhsKey
		}
	}
	return false
}

func nodeContains(parent, child parser.Node) bool {
	return child.StartByte() >= parent.StartByte() && child.EndByte() <= parent.EndByte()
}

func relationalOperator(node parser.Node) string {
	for _, child := range node.Children() {
		switch child.Kind() {
		case "<", "<=", ">", ">=":
			return child.Kind()
		}
	}
	return ""
}

// sizeCalcExprs returns the argument's binary expressions that qualify as a
// size-calculation overflow. Recognized patterns and their categories:
//
//   - var * var         → size_calc_overflow        (n * m)
//   - var * sizeof(T)   → size_calc_overflow        (n * sizeof(int)) — CVE-2021-43267 et al.
//   - param * const     → size_mul_const_overflow   (n * 1024, const >= minMulConstOverflow)
//
// Addition/subtraction (`n + 1`, `n - 1`) is intentionally NOT flagged: it is
// the null-terminator / off-by-one idiom and only overflows for a near-SIZE_MAX
// operand — implausible overflow noise.
//
// The operator is read from the anonymous token child (*, +, -), never from the
// whole text, so `->` member access inside an operand cannot fool the test. A
// parenthesized argument is unwrapped.
func (d *IntegerOverflowDetector) sizeCalcExprs(arg parser.Node, influenced, wideVars map[string]bool) []sizeCalcCandidate {
	nodes := arg.NamedChildren()
	if arg.Kind() == "parenthesized_expression" && len(nodes) > 0 {
		var out []sizeCalcCandidate
		for _, c := range nodes {
			out = append(out, d.sizeCalcExprs(c, influenced, wideVars)...)
		}
		return out
	}
	if arg.Kind() != "binary_expression" {
		return nil
	}
	op := arithOperator(arg)
	if op == "" {
		return nil
	}

	// Recursively flatten chains of the SAME operator so `malloc(a*b*c)` and
	// `malloc(a+b+c)` are classified, not just the top-level two operands. A
	// nested sub-expression of a DIFFERENT operator (`b+c` inside `a*(b+c)`)
	// counts as one opaque operand: it can still overflow but is not a
	// caller-influenced bare identifier.
	var varCount, paramCount, numberCount, sizeofCount, wideCount int
	constValue := 0
	var collect func(n parser.Node)
	collect = func(n parser.Node) {
		for n.Kind() == "parenthesized_expression" {
			ch := n.NamedChildren()
			if len(ch) == 0 {
				return
			}
			n = ch[0]
		}
		switch n.Kind() {
		case "binary_expression":
			if arithOperator(n) == op {
				for _, c := range n.NamedChildren() {
					collect(c)
				}
			} else {
				varCount++
			}
		case "identifier":
			if strings.Contains(n.Text(), "sizeof") {
				return
			}
			if wideVars[n.Text()] {
				wideCount++
			} else {
				varCount++
			}
			if influenced[n.Text()] {
				paramCount++
			}
		case "field_expression":
			varCount++ // a member's width is unknown; conservatively narrow
		case "number_literal":
			numberCount++
			if v := parseConstantIndex(n.Text()); v > constValue {
				constValue = v
			}
		case "sizeof_expression":
			sizeofCount++
			wideCount++ // sizeof yields size_t (64-bit on LP64)
		default:
			// A call_expression (`malloc(get_len() * m)`), subscript,
			// pointer_expression, or any other opaque operand is a possibly-large
			// value: count it as a variable operand so the cross-function size
			// return is not silently ignored.
			varCount++
		}
	}
	collect(arg)

	switch op {
	case "*":
		// A pure-literal product whose value overflows a 32-bit int is a
		// PROVABLE overflow, not a heuristic — emit the definite tier.
		if varCount == 0 && numberCount >= 2 && wideCount == 0 {
			if v, ok := foldLiteralInt(arg); ok && overflowsInt32(v) {
				return []sizeCalcCandidate{{arg, "definite_overflow"}}
			}
			return nil
		}
		// A 64-bit (size_t/long/sizeof) operand promotes the product to 64 bits
		// on LP64, so it cannot overflow a 64-bit result — not a CWE-190.
		if wideCount > 0 {
			return nil
		}
		if numberCount > 0 {
			// var * const — only meaningful when the variable is caller-influenced
			// AND the constant is a large block size (>= minMulConstOverflow), so
			// the product can plausibly overflow. `n * 2`/`n * 4` (doubling, small
			// magic numbers) are dropped as implausible overflow noise.
			if varCount == 1 && paramCount == 1 && constValue >= minMulConstOverflow {
				return []sizeCalcCandidate{{arg, "size_mul_const_overflow"}}
			}
			return nil
		}
		if varCount >= 2 {
			return []sizeCalcCandidate{{arg, "size_calc_overflow"}}
		}
		if varCount == 1 && sizeofCount == 1 {
			// Unreachable via the wideCount guard above (sizeof is wide), kept for
			// clarity: a `var * sizeof` product is 64-bit and never flagged here.
			return nil
		}
		// "+"/"-" (n + 1, n - 1, n + m) are dropped: n + 1 is the null-terminator
		// idiom and n - 1 the off-by-one idiom, and a sum/difference overflows only
		// for two near-SIZE_MAX operands — implausible overflow noise, not CWE-190.
	}
	return nil
}

// foldLiteralInt folds a pure-literal arithmetic expression (number_literal and
// nested *, +, - of literals) to an int64, reporting whether the fold succeeded.
// A macro/identifier/const-symbol operand is NOT foldable here (it is not a bare
// literal), so the result is only used for the definite constant-overflow tier.
func foldLiteralInt(n parser.Node) (int64, bool) {
	for n.Kind() == "parenthesized_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return 0, false
		}
		n = ch[0]
	}
	if n.Kind() == "number_literal" {
		v, err := strconv.ParseInt(strings.TrimSpace(n.Text()), 0, 64)
		if err != nil {
			return 0, false
		}
		return v, true
	}
	if n.Kind() != "binary_expression" {
		return 0, false
	}
	op := arithOperator(n)
	if op != "*" && op != "+" && op != "-" {
		return 0, false
	}
	children := n.NamedChildren()
	if len(children) != 2 {
		return 0, false
	}
	l, lok := foldLiteralInt(children[0])
	r, rok := foldLiteralInt(children[1])
	if !lok || !rok {
		return 0, false
	}
	switch op {
	case "*":
		return l * r, true
	case "+":
		return l + r, true
	case "-":
		return l - r, true
	}
	return 0, false
}

// overflowsInt32 reports whether v falls outside a 32-bit signed int range, so a
// literal product that exceeds it is a provable (definite) integer overflow.
func overflowsInt32(v int64) bool {
	return v < -(1<<31) || v > (1<<31)-1
}

// arithOperator returns the arithmetic operator token of a binary_expression
// (*, +, -), or "" when it is not one of the overflow-prone operators. The
// operator is an ANONYMOUS tree-sitter node, so it is read from Children().
func arithOperator(expr parser.Node) string {
	if expr.Kind() != "binary_expression" {
		return ""
	}
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "*", "+", "-":
			return child.Kind()
		}
	}
	return ""
}

// isVariableOperand reports whether node is a bare variable operand (an
// identifier or field access that is not a sizeof expression).
func isVariableOperand(node parser.Node) bool {
	if node.Kind() != "identifier" && node.Kind() != "field_expression" {
		return false
	}
	return !strings.Contains(node.Text(), "sizeof")
}

// oneByteTypes are C types whose sizeof is 1 on every relevant platform, so a
// `n * sizeof(T)` product cannot overflow when T is one of them (n * 1 == n).
var oneByteTypes = map[string]bool{
	"char": true, "signed char": true, "unsigned char": true,
	"_Bool": true, "bool": true,
	"int8_t": true, "uint8_t": true,
	"int_least8_t": true, "uint_least8_t": true,
	"int_fast8_t": true, "uint_fast8_t": true,
}

// sizeofIsOne reports whether a sizeof_expression evaluates to 1 (its operand is
// a one-byte type), so a `var * sizeof(T)` product cannot overflow.
func sizeofIsOne(node parser.Node) bool {
	ch := node.NamedChildren()
	if len(ch) == 0 {
		return false
	}
	op := ch[0]
	for op.Kind() == "parenthesized_expression" {
		inner := op.NamedChildren()
		if len(inner) == 0 {
			return false
		}
		op = inner[0]
	}
	return oneByteTypes[strings.TrimSpace(op.Text())]
}
