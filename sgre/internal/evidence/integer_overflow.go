package evidence

import (
	"context"
	"encoding/json"
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

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		binaryExprs := root.FindAll("binary_expression")
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
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

				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()})
				props, _ := json.Marshal(map[string]string{
					"expression": expr.Text(),
					"category":   "integer_overflow",
				})
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "INTEGER_OVERFLOW",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				if err == nil {
					result.EventsCreated++
				}
			}

			d.detectSizeCalcOverflow(ctx, calls, f, file, &result)
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

// detectSizeCalcOverflow flags an arithmetic expression passed directly as a
// size-function argument whose product/sum can wrap before the allocation,
// e.g. malloc(count * obj_size) — the canonical CWE-190 "size calculation
// overflow". The main Detect loop only covers the "wraparound inside a bounds
// check" pattern (the arithmetic lives in an if-condition), so this is a
// separate path: a multiplication of two variables, with no sizeof and no
// constant operand, feeding straight into malloc/calloc/memcpy/etc.
func (d *IntegerOverflowDetector) detectSizeCalcOverflow(ctx context.Context, calls []parser.Node, f *db.Function, file *db.File, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if !sizeFunctions[extractCallName(call)] {
			continue
		}
		for _, argNode := range call.NamedChildren() {
			if argNode.Kind() != "argument_list" {
				continue
			}
			for _, arg := range argNode.NamedChildren() {
				exprs := d.sizeCalcExprs(arg)
				for _, expr := range exprs {
					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: expr.StartLine(), Column: expr.StartColumn()})
					props, _ := json.Marshal(map[string]string{
						"expression": expr.Text(),
						"category":   "size_calc_overflow",
					})
					_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "INTEGER_OVERFLOW",
						EntityID:   f.ID,
						LocationID: locID,
						Properties: string(props),
					})
					if err == nil {
						result.EventsCreated++
					}
				}
			}
		}
	}
}

// sizeCalcExprs returns the argument's binary expressions that qualify as a
// size-calculation overflow. Two patterns are recognized:
//   - var * var  (e.g. n * m) — classic two-variable product
//   - var * sizeof(T)  (e.g. n * sizeof(int)) — the most common CVE pattern
//     (CVE-2021-43267 et al.): a user-controlled count multiplied by a type
//     size can overflow on 32-bit, leading to a small allocation followed by
//     an out-of-bounds write.
// It unwraps a parenthesized argument.
func (d *IntegerOverflowDetector) sizeCalcExprs(arg parser.Node) []parser.Node {
	nodes := arg.NamedChildren()
	if arg.Kind() == "parenthesized_expression" && len(nodes) > 0 {
		var out []parser.Node
		for _, c := range nodes {
			out = append(out, d.sizeCalcExprs(c)...)
		}
		return out
	}
	if arg.Kind() != "binary_expression" {
		return nil
	}
	if !strings.Contains(arg.Text(), " * ") {
		return nil
	}
	var varCount, sizeofCount, numberCount int
	for _, child := range arg.NamedChildren() {
		switch child.Kind() {
		case "identifier", "field_expression":
			if strings.Contains(child.Text(), "sizeof") {
				return nil
			}
			varCount++
		case "number_literal":
			numberCount++
		case "sizeof_expression":
			sizeofCount++
		}
	}
	if numberCount > 0 {
		return nil
	}
	if varCount >= 2 {
		return []parser.Node{arg}
	}
	if varCount == 1 && sizeofCount == 1 {
		return []parser.Node{arg}
	}
	return nil
}
