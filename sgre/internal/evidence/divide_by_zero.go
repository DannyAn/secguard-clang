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
	// A bare numeric literal (integer or float) is safe unless it is zero.
	if _, err := strconv.ParseFloat(t, 64); err == nil {
		return t == "0" || t == "0.0"
	}
	return true
}
