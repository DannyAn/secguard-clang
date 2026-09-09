package evidence

import (
	"context"
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
	return []string{"unsigned-wraparound", "size-calculation-overflow", "truncation"}
}

var sizeFunctions = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true, "memcpy": true,
	"memmove": true, "memset": true, "mmap": true, "alloca": true,
	"strncpy": true, "strncat": true, "snprintf": true,
}

func (d *IntegerOverflowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		binaryExprs := root.FindAll("binary_expression")
		calls := root.FindAll("call_expression")
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

			d.detectSizeCalcOverflow(ctx, calls, f, file, params, &result)
		}
	})
	return result, err
}

func isArithmeticOp(expr parser.Node) bool {
	text := expr.Text()
	for _, op := range []string{" + ", " * ", " - "} {
		if strings.Contains(text, op) {
			return true
		}
	}
	return false
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
		if !sizeFunctions[callName] {
			continue
		}
		if call.StartLine() <= expr.StartLine() {
			continue
		}
		callText := call.Text()
		for _, op := range operands {
			if strings.Contains(callText, op) {
				return true
			}
		}
		if strings.Contains(callText, exprText) {
			return true
		}
	}
	return false
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
func (d *IntegerOverflowDetector) detectSizeCalcOverflow(ctx context.Context, calls []parser.Node, f *db.Function, file *db.File, params map[string]bool, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !sizeFunctions[callName] {
			continue
		}
		args := callNamedArguments(call)

		// calloc(n, m): the multiplication is implicit across two arguments, so
		// the per-argument sizeCalcExprs scan (which sees only a bare n or m)
		// misses it. Two variable arguments is the classic CWE-190 overflow.
		if callName == "calloc" && len(args) >= 2 {
			if isVariableOperand(args[0]) && isVariableOperand(args[1]) {
				d.emitSizeCalc(ctx, file, f, call, "size_calc_overflow", result)
				continue
			}
			// calloc(n, sizeof(T)) and calloc(n, CONST) are the SAME implicit
			// product the malloc(n * sizeof(T)) / malloc(n * 2) cases cover, but
			// split across two arguments — the most common allocation idiom in
			// real code and previously a systematic blind spot (CWE-190).
			if c := d.callocOverflowCategory(args[0], args[1], params); c != "" {
				d.emitSizeCalc(ctx, file, f, call, c, result)
				continue
			}
		}

		for _, arg := range args {
			for _, c := range d.sizeCalcExprs(arg, params) {
				d.emitSizeCalc(ctx, file, f, c.expr, c.category, result)
			}
		}
	}
}

// callocOverflowCategory classifies the implicit `arg0 * arg1` product of a
// calloc call with the SAME rules sizeCalcExprs applies to `malloc(a * b)`:
//
//   - var * sizeof(T) → size_calc_overflow   (calloc(n, sizeof(int)))
//   - param * CONST   → size_mul_const_overflow (calloc(n, 2), n caller-influenced)
//
// A constant * constant, a sizeof(char) (==1) operand, or a CONST <= 1 product
// cannot overflow and returns "". Both argument orders are accepted.
func (d *IntegerOverflowDetector) callocOverflowCategory(a0, a1 parser.Node, params map[string]bool) string {
	classify := func(arg parser.Node) (isVar, isParam, isSizeof, isNum, sizeofOne bool, constValue int) {
		for arg.Kind() == "parenthesized_expression" {
			ch := arg.NamedChildren()
			if len(ch) == 0 {
				return
			}
			arg = ch[0]
		}
		switch {
		case isVariableOperand(arg):
			return true, params[arg.Text()], false, false, false, 0
		case arg.Kind() == "sizeof_expression":
			return false, false, true, false, sizeofIsOne(arg), 0
		case arg.Kind() == "number_literal":
			return false, false, false, true, false, parseConstantIndex(arg.Text())
		}
		return
	}
	v0, p0, s0, n0, o0, c0 := classify(a0)
	v1, p1, s1, n1, o1, c1 := classify(a1)
	if (v0 && s1 && !o1) || (s0 && !o0 && v1) {
		return "size_calc_overflow"
	}
	if (p0 && n1 && c1 > 1) || (n0 && c0 > 1 && p1) {
		return "size_mul_const_overflow"
	}
	return ""
}

func (d *IntegerOverflowDetector) emitSizeCalc(ctx context.Context, file *db.File, f *db.Function, expr parser.Node, category string, result *DetectResult) {
	if emitEvent(ctx, d.store, d.logger, "INTEGER_OVERFLOW", f.ID, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()}, map[string]string{
		"expression": expr.Text(),
		"category":   category,
	}) {
		result.EventsCreated++
	}
}

// sizeCalcExprs returns the argument's binary expressions that qualify as a
// size-calculation overflow. Recognized patterns and their categories:
//
//   - var * var         → size_calc_overflow        (n * m)
//   - var * sizeof(T)   → size_calc_overflow        (n * sizeof(int)) — CVE-2021-43267 et al.
//   - param * const     → size_mul_const_overflow   (n * 2, n caller-influenced)
//   - param + const/var → size_add_overflow         (n + 1, n + m)
//   - param - const     → size_sub_overflow         (n - 1 wraps under 0)
//
// The operator is read from the anonymous token child (*, +, -), never from the
// whole text, so `->` member access inside an operand cannot fool the test. A
// parenthesized argument is unwrapped.
func (d *IntegerOverflowDetector) sizeCalcExprs(arg parser.Node, params map[string]bool) []sizeCalcCandidate {
	nodes := arg.NamedChildren()
	if arg.Kind() == "parenthesized_expression" && len(nodes) > 0 {
		var out []sizeCalcCandidate
		for _, c := range nodes {
			out = append(out, d.sizeCalcExprs(c, params)...)
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
	var varCount, sizeofCount, numberCount, paramCount int
	sizeofOne := false
	constValue := 0
	for _, child := range arg.NamedChildren() {
		switch child.Kind() {
		case "identifier", "field_expression":
			if strings.Contains(child.Text(), "sizeof") {
				return nil
			}
			varCount++
			if params[child.Text()] {
				paramCount++
			}
		case "number_literal":
			numberCount++
			if v := parseConstantIndex(child.Text()); v > constValue {
				constValue = v
			}
		case "sizeof_expression":
			sizeofCount++
			if sizeofIsOne(child) {
				sizeofOne = true
			}
		}
	}

	switch op {
	case "*":
		if numberCount > 0 {
			// var * const — only meaningful when the variable is caller-influenced
			// AND the constant is > 1 (n * 1 cannot overflow).
			if varCount == 1 && paramCount == 1 && constValue > 1 {
				return []sizeCalcCandidate{{arg, "size_mul_const_overflow"}}
			}
			return nil
		}
		if varCount >= 2 {
			return []sizeCalcCandidate{{arg, "size_calc_overflow"}}
		}
		if varCount == 1 && sizeofCount == 1 {
			// n * sizeof(char) == n * 1 cannot overflow.
			if sizeofOne {
				return nil
			}
			return []sizeCalcCandidate{{arg, "size_calc_overflow"}}
		}
	case "+":
		// a + b / a + const — only when at least one operand is caller-influenced.
		if varCount >= 1 && paramCount >= 1 {
			return []sizeCalcCandidate{{arg, "size_add_overflow"}}
		}
	case "-":
		if varCount >= 1 && paramCount >= 1 {
			return []sizeCalcCandidate{{arg, "size_sub_overflow"}}
		}
	}
	return nil
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
