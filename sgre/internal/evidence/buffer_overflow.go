package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
)

type BufferOverflowDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewBufferOverflowDetector(store db.Store, p *parser.Parser, logger *log.Logger) *BufferOverflowDetector {
	return &BufferOverflowDetector{store: store, parser: p, logger: logger}
}

func (d *BufferOverflowDetector) Name() string { return "buffer_overflow" }

func (d *BufferOverflowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("buffer_overflow: list functions: %w", err)
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

		d.detectUnsafeCalls(ctx, f, file, root, &result)
		d.detectArrayOOB(ctx, f, file, root, &result)

		tree.Close()
	}

	return result, nil
}

func (d *BufferOverflowDetector) detectUnsafeCalls(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName == "" {
			continue
		}
		if isSafeFunction(callName) || isSafeWrapper(callName) {
			continue
		}
		if injectionAPIs[callName] {
			continue
		}
		if !bufferOverflowAPIs[callName] {
			continue
		}
		if hasPrecedingBoundsCheck(root, f, call.StartLine()) {
			continue
		}
		category := "buffer_overflow"

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   category,
			"expression": call.Text(),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "BUFFER_ACCESS",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func hasPrecedingBoundsCheck(root parser.Node, f *db.Function, callLine int) bool {
	ifs := root.FindAll("if_statement")
	for _, ifNode := range ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() >= callLine {
			continue
		}
		condText := ""
		bodyHasReturn := false
		for _, child := range ifNode.NamedChildren() {
			if child.Kind() == "parenthesized_expression" || strings.Contains(child.Text(), ">") || strings.Contains(child.Text(), "<") {
				condText = child.Text()
			}
			if child.Kind() == "compound_statement" {
				bodyText := child.Text()
				if strings.Contains(bodyText, "return") || strings.Contains(bodyText, "break") || strings.Contains(bodyText, "continue") {
					bodyHasReturn = true
				}
				if strings.Contains(bodyText, "=") && !strings.Contains(bodyText, "==") {
					bodyHasReturn = true
				}
			}
			if child.Kind() == "expression_statement" {
				bodyText := child.Text()
				if strings.Contains(bodyText, "return") || strings.Contains(bodyText, "=") {
					bodyHasReturn = true
				}
			}
		}
		if condText == "" || !bodyHasReturn {
			continue
		}
		if !isRelationalCondition(condText) {
			continue
		}
		if hasCapacityExpression(condText) {
			return true
		}
	}
	return false
}

func isRelationalCondition(text string) bool {
	return strings.Contains(text, " > ") || strings.Contains(text, " >= ") ||
		strings.Contains(text, " < ") || strings.Contains(text, " <= ") ||
		strings.Contains(text, ">=") || strings.Contains(text, "<=") ||
		strings.Contains(text, " >") || strings.Contains(text, " <")
}

func hasCapacityExpression(text string) bool {
	keywords := []string{"capacity", "size", "len", "sizeof", "MAX_", "BUF_", "LIMIT", "max_", "buf_"}
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func (d *BufferOverflowDetector) detectArrayOOB(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	subscripts := root.FindAll("subscript_expression")
	for _, sub := range subscripts {
		if sub.StartLine() < f.StartLine || sub.StartLine() > f.EndLine {
			continue
		}
		text := sub.Text()
		if strings.Contains(text, "sizeof") {
			continue
		}
		children := sub.NamedChildren()
		if len(children) < 2 {
			continue
		}
		arrName := children[0].Text()
		indexExpr := children[1].Text()

		arrSize := findArraySize(root, arrName)
		isOOB := false

		if isConstantIndex(indexExpr) {
			idx := parseConstantIndex(indexExpr)
			if arrSize > 0 && idx >= 0 {
				if idx >= arrSize {
					isOOB = true
				}
			} else if arrSize == 0 {
				continue
			}
		} else if arrSize > 0 && isLoopBoundOverflow(root, f, sub, arrSize) {
			isOOB = true
		} else if !isConstantIndex(indexExpr) {
			isOOB = true
		}

		if !isOOB {
			continue
		}

		category := "buffer_overflow"
		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: sub.StartLine()})
		props, _ := json.Marshal(map[string]string{
			"array":      arrName,
			"index":      indexExpr,
			"category":   category,
			"expression": text,
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "BUFFER_ACCESS",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func findArraySize(root parser.Node, arrName string) int {
	for _, decl := range root.FindAll("declaration") {
		for _, ad := range decl.FindAll("array_declarator") {
			if extractDeclaratorName(ad) == arrName {
				for _, child := range ad.NamedChildren() {
					if child.Kind() == "number_literal" || child.Kind() == "identifier" {
						size := parseConstantIndex(child.Text())
						if size > 0 {
							return size
						}
					}
				}
			}
		}
	}
	return 0
}

func isLoopBoundOverflow(root parser.Node, f *db.Function, sub parser.Node, arrSize int) bool {
	for _, forNode := range root.FindAll("for_statement") {
		if forNode.StartLine() < f.StartLine || forNode.EndLine() > f.EndLine {
			continue
		}
		if sub.StartLine() < forNode.StartLine() || sub.StartLine() > forNode.EndLine() {
			continue
		}
		for _, child := range forNode.NamedChildren() {
			condText := child.Text()
			if strings.Contains(condText, "<=") {
				nums := extractNumbers(condText)
				for _, n := range nums {
					if n >= arrSize {
						return true
					}
				}
			}
			if strings.Contains(condText, "<") && !strings.Contains(condText, "<=") {
				nums := extractNumbers(condText)
				for _, n := range nums {
					if n > arrSize {
						return true
					}
				}
			}
		}
	}
	return false
}

func extractNumbers(text string) []int {
	var nums []int
	current := ""
	for _, c := range text {
		if c >= '0' && c <= '9' {
			current += string(c)
		} else {
			if current != "" {
				n := parseConstantIndex(current)
				if n > 0 {
					nums = append(nums, n)
				}
				current = ""
			}
		}
	}
	if current != "" {
		n := parseConstantIndex(current)
		if n > 0 {
			nums = append(nums, n)
		}
	}
	return nums
}

func parseConstantIndex(expr string) int {
	n := 0
	for _, c := range expr {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func isConstantIndex(expr string) bool {
	for _, c := range expr {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(expr) > 0
}
