package evidence

import (
	"context"
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

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		binaryExprs := root.FindAll("binary_expression")
		allIfs := root.FindAll("if_statement")
		allAssigns := root.FindAll("assignment_expression")
		for _, f := range funcs {
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine), assignsInFunc(allAssigns, f.StartLine, f.EndLine))
			for _, expr := range binaryExprs {
				if !funcLineRange(f, expr.StartLine()) {
					continue
				}
				divisor, ok := divOrModDivisor(expr)
				if !ok {
					continue
				}
				if !possiblyZeroDivisor(divisor) {
					continue
				}
				// Floating-point division by zero is well-defined by IEEE 754
				// (yields +/-Inf/NaN), not a crash or a memory-safety defect, so it is
				// out of scope for CWE-369. Only integer / and % can trap.
				if isFloatDivisionText(expr.Text()) {
					continue
				}
				// A guard that implies the divisor is non-zero (a ternary
				// `d ? a/d : x`, or an enclosing `if (d)` / `if (d != 0)`) makes
				// the division safe on every path that reaches it.
				if divisionGuarded(expr, divisor) {
					continue
				}
				// RangeFacts covers the early-return guard `if (d == 0) return;
				// a/d;` (d non-zero on the fall-through) and the positive
				// `if (d > 0) { ... a/d ... }`, which divisionGuarded's
				// ancestor walk also handles but only for the immediate
				// enclosing if — AnalyzeBounds adds the fall-through case.
				if bounds.NonZeroAt(divisor, expr.StartLine()) {
					continue
				}

				if emitEvent(ctx, d.store, d.logger, "DIVIDE_BY_ZERO", f.ID, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()}, map[string]string{
					"expression": expr.Text(),
					// The divisor is the root-cause variable the planner converges
					// on; without it the seed falls back to the full `expression`
					// text, so the dedup key and the report "Variable" column show
					// "x / y" instead of "y".
					"variable": divisor,
					"divisor":  divisor,
					"category": "divide_by_zero",
				}) {
					result.EventsCreated++
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
	return named[len(named)-1].Text(), true
}

// possiblyZeroDivisor reports whether a divisor expression can be zero. A
// numeric literal other than 0, or a sizeof (compile-time constant), is safe.
func possiblyZeroDivisor(divisor string) bool {
	t := strings.TrimSpace(divisor)
	if strings.Contains(t, "sizeof") {
		return false
	}
	// A numeric literal (integer or float) is safe unless it is zero. Strip C
	// integer-literal suffixes first (10u, 10U, 10ul, 10ULL, ...) so that
	// "2147483647u" is recognized as a non-zero constant rather than a variable.
	stripped := strings.TrimRight(t, "uUlL")
	if _, err := strconv.ParseFloat(stripped, 64); err == nil {
		return stripped == "0" || stripped == "0.0"
	}
	return true
}

// divisionGuarded reports whether an enclosing guard implies the divisor is
// non-zero: a ternary `d ? a/d : x`, or an `if (d)` / `if (d != 0)` / `while
// (d)` whose body contains the division. On every path that reaches the
// division, the guard has already established d != 0.
func divisionGuarded(expr parser.Node, divisor string) bool {
	d := strings.TrimSpace(divisor)
	for n := &expr; n != nil; n = n.Parent() {
		switch n.Kind() {
		case "conditional_expression":
			named := n.NamedChildren()
			if len(named) == 0 {
				continue
			}
			if guardImpliesNonZero(named[0].Text(), d) {
				return true
			}
		case "if_statement", "while_statement", "do_statement":
			cond := n.ChildByFieldName("condition")
			if cond != nil && guardImpliesNonZero(cond.Text(), d) {
				return true
			}
		}
	}
	return false
}

// guardImpliesNonZero reports whether a guard condition text establishes that
// divisor d is non-zero (truthiness, != 0, or > 0).
func guardImpliesNonZero(condText string, d string) bool {
	ct := strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(strings.TrimSpace(condText), ")"), "("))
	if ct == d {
		return true
	}
	for _, pat := range []string{d + " != 0", d + " > 0", "0 != " + d, "0 < " + d} {
		if strings.Contains(ct, pat) {
			return true
		}
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
