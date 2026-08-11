package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("integer_overflow: list functions: %w", err)
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.Parse(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		binaryExprs := root.FindAll("binary_expression")
		for _, expr := range binaryExprs {
			if expr.StartLine() < f.StartLine || expr.StartLine() > f.EndLine {
				continue
			}
			if !isArithmeticOp(expr) {
				continue
			}
			if !d.isInBoundsCheck(root, expr, f) {
				continue
			}
			if !d.feedsIntoSizeCall(root, expr, f) {
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

		tree.Close()
	}

	return result, nil
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

func (d *IntegerOverflowDetector) isInBoundsCheck(root parser.Node, expr parser.Node, f *db.Function) bool {
	exprLine := expr.StartLine()
	for _, ifStmt := range root.FindAll("if_statement") {
		if ifStmt.StartLine() < f.StartLine || ifStmt.StartLine() > f.EndLine {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if cond.StartLine() <= exprLine && cond.EndLine() >= exprLine {
			return true
		}
		if cond.StartLine() >= exprLine-5 && cond.StartLine() <= exprLine+5 {
			condText := cond.Text()
			exprText := expr.Text()
			if strings.Contains(condText, exprText) {
				return true
			}
		}
	}
	return false
}

func (d *IntegerOverflowDetector) feedsIntoSizeCall(root parser.Node, expr parser.Node, f *db.Function) bool {
	exprText := expr.Text()
	operands := extractOperands(expr)
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
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
