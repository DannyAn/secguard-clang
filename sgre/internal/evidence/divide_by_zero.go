package evidence

import (
	"context"
	"encoding/json"
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

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		binaryExprs := root.FindAll("binary_expression")
		for _, f := range funcs {
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

				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()})
				props, _ := json.Marshal(map[string]string{
					"expression": expr.Text(),
					"divisor":    divisor,
					"category":   "divide_by_zero",
				})
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "DIVIDE_BY_ZERO",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				if err == nil {
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
