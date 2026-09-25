package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DivideByZeroDetector flags integer/float division or modulo whose divisor is
// not a provably non-zero constant (CWE-369). A literal divisor other than 0
// (e.g. x / 2) and any sizeof expression are treated as safe; everything else
// — a variable, a call result, or a compound expression like (a - b) — is a
// possible zero divisor.
type DivideByZeroDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDivideByZeroDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DivideByZeroDetector {
	return &DivideByZeroDetector{store: store, parser: p, logger: logger}
}

func (d *DivideByZeroDetector) Name() string { return "divide_by_zero" }

func (d *DivideByZeroDetector) Domain() string { return "boundary" }

func (d *DivideByZeroDetector) Capabilities() []string { return []string{"division", "modulo"} }

func (d *DivideByZeroDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	globalTypedefs := buildGlobalTypedefs(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)
		globals, scopes := buildIntegerOverflowTypeScopes(root, funcs, typedefs)
		binaryExprs := root.FindAll("binary_expression")
		allIfs := root.FindAll("if_statement")
		allAssigns := root.FindAll("assignment_expression")
		constants := parser.CollectConstantSymbols(root)
		for _, f := range funcs {
			scope := scopes[f.StartLine]
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine), assignsInFunc(allAssigns, f.StartLine, f.EndLine))
			check := func(expr parser.Node, divisor string) {
				if !possiblyZeroDivisor(divisor) {
					return
				}
				// A divisor spelled as a macro/enum/const symbol whose value is a
				// provably non-zero compile-time constant (`x / BKT_NUM` with
				// `#define BKT_NUM 4096`) is safe at the source, exactly like the
				// literal `x / 4096` — drop it here instead of leaking it to the
				// AI agent as a "possibly-zero variable".
				if constants.NonZero(divisor) {
					return
				}
				// Floating-point division by zero is well-defined by IEEE 754
				// (yields +/-Inf/NaN), not a crash or a memory-safety defect, so it is
				// out of scope for CWE-369. Only integer / and % can trap. A float
				// OPERAND (not just a float literal) makes the whole division float.
				if isFloatDivisionText(expr.Text()) || isFloatDivisionExpr(expr, globals, scope, typedefs) {
					return
				}
				// A guard that implies the divisor is non-zero (a ternary
				// `d ? a/d : x`, or an enclosing `if (d)` / `if (d != 0)`) makes
				// the division safe on every path that reaches it.
				if divisionGuarded(expr, divisor) {
					return
				}
				// RangeFacts covers the early-return guard `if (d == 0) return;
				// a/d;` (d non-zero on the fall-through) and the positive
				// `if (d > 0) { ... a/d ... }`, which divisionGuarded's
				// ancestor walk also handles but only for the immediate
				// enclosing if — AnalyzeBounds adds the fall-through case.
				if bounds.NonZeroAt(divisor, expr.StartLine()) {
					return
				}

				props := map[string]string{
					"expression": expr.Text(),
					// The divisor is the root-cause variable the planner converges
					// on; without it the seed falls back to the full `expression`
					// text, so the dedup key and the report "Variable" column show
					// "x / y" instead of "y".
					"variable": divisor,
					"divisor":  divisor,
					"category": "divide_by_zero",
				}
				if isDefiniteZeroDivisor(divisor, constants) {
					props["definitely_zero"] = "true"
				}
				if emitEvent(ctx, d.store, d.logger, "DIVIDE_BY_ZERO", f.ID, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()}, props) {
					result.EventsCreated++
				}
			}

			for _, expr := range binaryExprs {
				if !funcLineRange(f, expr.StartLine()) {
					continue
				}
				if divisor, ok := divOrModDivisor(expr); ok {
					check(expr, divisor)
				}
			}
			// Compound assignment `a /= b` / `a %= b` is the same division, just
			// written with an assignment operator — not a binary_expression, so it
			// was previously missed entirely.
			for _, assign := range allAssigns {
				if !funcLineRange(f, assign.StartLine()) {
					continue
				}
				if divisor, ok := compoundDivModDivisor(assign); ok {
					check(assign, divisor)
				}
			}
		}
	})
	return result, err
}

// divOrModDivisor returns the right operand of a `/` or `%` binary expression,
// and whether the operator is one of those two.
func divOrModDivisor(expr parser.Node) (string, bool) {
	op := ""
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "/", "%":
			op = child.Kind()
		}
	}
	if op == "" {
		return "", false
	}
	named := expr.NamedChildren()
	if len(named) < 2 {
		return "", false
	}
	return unwrapDivisorNode(named[len(named)-1]).Text(), true
}

// unwrapDivisorNode unwraps a parenthesized/cast divisor (`(size_t)d` → `d`,
// `(d)` → `d`) so the planner's flow analysis and guard matching see the bare
// variable rather than a cast spelling that never matches anything.
func unwrapDivisorNode(n parser.Node) parser.Node {
	for {
		switch n.Kind() {
		case "parenthesized_expression", "cast_expression":
			children := n.NamedChildren()
			if len(children) == 0 {
				return n
			}
			n = children[len(children)-1]
		default:
			return n
		}
	}
}

// compoundDivModDivisor returns the right operand of an `a /= b` / `a %= b`
// compound assignment, and whether the operator is one of those two.
func compoundDivModDivisor(assign parser.Node) (string, bool) {
	if assign.Kind() != "assignment_expression" {
		return "", false
	}
	op := ""
	for _, child := range assign.Children() {
		switch child.Kind() {
		case "/=", "%=":
			op = child.Kind()
		}
	}
	if op == "" {
		return "", false
	}
	named := assign.NamedChildren()
	if len(named) < 2 {
		return "", false
	}
	return unwrapDivisorNode(named[len(named)-1]).Text(), true
}

// possiblyZeroDivisor reports whether a divisor expression can be zero. A
// non-zero integer literal (decimal/hex/octal, with C suffixes), a sizeof
// (compile-time constant), or a named compile-time constant is safe; a zero
// literal remains possible. Reuses nonZeroConstantValue, which parses base-0
// integer literals so `x / 0x20` is recognized as safe where the previous
// strconv.ParseFloat path would have misread it as a possibly-zero variable.
func possiblyZeroDivisor(divisor string) bool {
	t := strings.TrimSpace(divisor)
	if strings.Contains(t, "sizeof") {
		return false
	}
	return !parser.NonZeroConstantValue(t)
}

// isDefiniteZeroDivisor reports whether a divisor is PROVABLY zero: a literal
// `x / 0` (or `0x0`, `00`, `0U`, ...) or a compile-time constant symbol whose
// value is zero (`#define ZERO 0`, `const int ZERO = 0`, `enum { ZERO = 0 }`).
// Such a divisor is a certain divide-by-zero, so the detector marks the event
// "definitely_zero" and the RangeFilter auto-confirms it instead of handing it
// to the AI agent.
func isDefiniteZeroDivisor(divisor string, constants *parser.ConstantEnv) bool {
	d := strings.TrimSpace(divisor)
	if d == "" {
		return false
	}
	if parser.IsZeroConstantValue(d) {
		return true
	}
	if constants != nil && constants.IsZero(d) {
		return true
	}
	return false
}

// divisionGuarded reports whether an enclosing guard implies the divisor is
// non-zero: a ternary `d ? a/d : x` (division in the true branch) or
// `(d == 0) ? x : a/d` (division in the false branch), or an `if (d)` /
// `if (d != 0)` / `while (d)` whose body contains the division. On every path
// that reaches the division, the guard has already established d != 0. The
// condition is parsed as AST (direction + compound + word boundary), not text.
func divisionGuarded(expr parser.Node, divisor string) bool {
	d := strings.TrimSpace(divisor)
	for n, prev := &expr, (*parser.Node)(nil); n != nil; n, prev = n.Parent(), n {
		switch n.Kind() {
		case "conditional_expression":
			cond := n.ChildByFieldName("condition")
			if cond == nil {
				continue
			}
			// The guard only protects the branch the division sits in:
			// - alternative (false) branch: the condition implies d == 0
			//   (`(d == 0) ? x : a/d`), so the false branch is d != 0.
			// - consequence (true) branch: the condition implies d != 0
			//   (`d ? a/d : x`).
			if alt := n.ChildByFieldName("alternative"); prev != nil && alt != nil && nodeWithin(alt, prev) {
				if condEstablishesZero(*cond, d) {
					return true
				}
			} else if condEstablishesNonZero(*cond, d) {
				return true
			}
		case "if_statement", "while_statement":
			// do_statement is deliberately excluded: its condition is evaluated
			// AFTER the body, so the body's division is not guarded by it.
			cond := n.ChildByFieldName("condition")
			if cond != nil && condEstablishesNonZero(*cond, d) {
				return true
			}
		}
	}
	return false
}

// nodeWithin reports whether inner sits within outer's byte range.
func nodeWithin(outer, inner *parser.Node) bool {
	return inner.StartByte() >= outer.StartByte() && inner.EndByte() <= outer.EndByte()
}

// condEstablishesNonZero reports whether a condition, when TRUE, establishes d
// non-zero (truthiness, != 0, > 0, >= 1, < 0, <= -1, or a conjunction thereof).
func condEstablishesNonZero(cond parser.Node, d string) bool {
	for _, v := range nonZeroGuardedVars(cond) {
		if v == d {
			return true
		}
	}
	return false
}

// condEstablishesZero reports whether a condition, when TRUE, establishes d zero
// (== 0, or !d). It is the false-branch counterpart used by a ternary.
func condEstablishesZero(cond parser.Node, d string) bool {
	for _, v := range zeroGuardedVars(cond) {
		if v == d {
			return true
		}
	}
	return false
}

// nonZeroGuardedVars returns the variables a condition establishes as non-zero
// when it evaluates TRUE: `d`, `d != 0`, `d > 0`, `d >= 1`, `d < 0`, `d <= -1`,
// and a `&&` conjunction of those. A `||` disjunction establishes none.
func nonZeroGuardedVars(cond parser.Node) []string {
	for cond.Kind() == "parenthesized_expression" {
		ch := cond.NamedChildren()
		if len(ch) == 0 {
			return nil
		}
		cond = ch[0]
	}
	if cond.Kind() == "identifier" {
		return []string{cond.Text()}
	}
	if cond.Kind() != "binary_expression" {
		return nil
	}
	switch parser.BinaryOperator(cond) {
	case "&&":
		var vars []string
		for _, child := range cond.NamedChildren() {
			vars = append(vars, nonZeroGuardedVars(child)...)
		}
		return vars
	case "||":
		return nil
	case "!=":
		return nonZeroComparisonVar(cond)
	case ">", ">=", "<", "<=":
		return relationalNonZeroVar(cond)
	}
	return nil
}

// nonZeroComparisonVar returns the variable a `d != 0` / `0 != d` comparison
// establishes non-zero.
func nonZeroComparisonVar(cond parser.Node) []string {
	for _, c := range cond.NamedChildren() {
		if isZeroLiteralNode(c) {
			continue
		}
		if name := bareOperandVar(c); name != "" {
			return []string{name}
		}
	}
	return nil
}

// relationalNonZeroVar returns the variable a relational comparison establishes
// non-zero when its constant bound excludes zero (`d > 0`, `d >= 1`, `d < 0`,
// `d <= -1`, `0 < d`, `1 <= d`).
func relationalNonZeroVar(cond parser.Node) []string {
	op := parser.BinaryOperator(cond)
	children := cond.NamedChildren()
	if len(children) != 2 {
		return nil
	}
	l, r := children[0], children[1]
	var name string
	var bound int64
	var reversed bool
	if lv, err := intLiteralValue(l); err == nil {
		if name = bareOperandVar(r); name == "" {
			return nil
		}
		bound, reversed = lv, true
	} else if rv, err := intLiteralValue(r); err == nil {
		if name = bareOperandVar(l); name == "" {
			return nil
		}
		bound, reversed = rv, false
	} else {
		return nil
	}
	// Normalize a reversed comparison (`N > d`) to `d < N`.
	switch op {
	case ">":
		if reversed {
			op = "<"
		}
	case ">=":
		if reversed {
			op = "<="
		}
	case "<":
		if reversed {
			op = ">"
		}
	case "<=":
		if reversed {
			op = ">="
		}
	}
	switch op {
	case ">":
		if bound >= 0 {
			return []string{name}
		}
	case ">=":
		if bound >= 1 {
			return []string{name}
		}
	case "<":
		if bound <= 0 {
			return []string{name}
		}
	case "<=":
		if bound <= -1 {
			return []string{name}
		}
	}
	return nil
}

// zeroGuardedVars returns the variables a condition establishes as zero when it
// evaluates TRUE (`d == 0`, `0 == d`, `!d`).
func zeroGuardedVars(cond parser.Node) []string {
	for cond.Kind() == "parenthesized_expression" {
		ch := cond.NamedChildren()
		if len(ch) == 0 {
			return nil
		}
		cond = ch[0]
	}
	if cond.Kind() == "binary_expression" && parser.BinaryOperator(cond) == "==" {
		for _, c := range cond.NamedChildren() {
			if isZeroLiteralNode(c) {
				continue
			}
			if name := bareOperandVar(c); name != "" {
				return []string{name}
			}
		}
		return nil
	}
	if cond.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(cond.Text()), "!") {
		for _, c := range cond.NamedChildren() {
			if name := bareOperandVar(c); name != "" {
				return []string{name}
			}
		}
	}
	return nil
}

// isZeroLiteralNode reports whether node is the integer literal 0.
func isZeroLiteralNode(n parser.Node) bool {
	v, err := intLiteralValue(n)
	return err == nil && v == 0
}

// intLiteralValue parses a number_literal node to an int64.
func intLiteralValue(n parser.Node) (int64, error) {
	if n.Kind() != "number_literal" {
		return 0, fmt.Errorf("not a number literal")
	}
	return strconv.ParseInt(strings.TrimSpace(n.Text()), 0, 64)
}

// isFloatDivisionExpr reports whether a division/modulo's OPERANDS are
// floating-point typed (float/double), so the division is IEEE 754 float
// division, not an integer trap. A bare-identifier operand is resolved via the
// function type scope; a field/call/compound operand is left to the text
// heuristic (isFloatDivisionText) and is not proven integer here.
func isFloatDivisionExpr(expr parser.Node, globals map[string]string, scope integerOverflowTypeScope, typedefs *typedefs) bool {
	for _, op := range expr.NamedChildren() {
		name := bareOperandVar(op)
		if name == "" {
			continue
		}
		if isFloatType(resolveScopedVar(name, expr.StartLine(), globals, scope.locals), typedefs) {
			return true
		}
	}
	return false
}

// bareOperandVar returns the bare identifier of a division operand, or "" when
// it is not a bare identifier (a call, a compound expression, a field access).
func bareOperandVar(n parser.Node) string {
	for n.Kind() == "parenthesized_expression" {
		ch := n.NamedChildren()
		if len(ch) == 0 {
			return ""
		}
		n = ch[0]
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	return ""
}

// isFloatType reports whether a type is a C floating-point scalar.
func isFloatType(typ string, typedefs *typedefs) bool {
	resolved := resolveType(strings.TrimSpace(typ), typedefs)
	switch resolved {
	case "float", "double", "long double":
		return true
	}
	return false
}

// isFloatDivisionText reports whether a division expression involves a
// floating-point literal (a `.`, an exponent `e`/`E`, or an `f`/`F` suffix on a
// numeric literal). Floating-point division by zero yields ±Inf/NaN per IEEE
// 754 and is not a crash or memory-safety defect, so such expressions are
// excluded from CWE-369 (which is about integer division/modulo trapping).
func isFloatDivisionText(text string) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		// decimal point immediately followed by a digit: 0.5, .5, 0.0f
		if c == '.' && i+1 < len(text) && text[i+1] >= '0' && text[i+1] <= '9' {
			return true
		}
		// exponent: digit followed by e/E followed by digit (1e6, 1e-6)
		if (c == 'e' || c == 'E') && i > 0 && text[i-1] >= '0' && text[i-1] <= '9' {
			return true
		}
	}
	return false
}
