package planner

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type ReturnCheckFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewReturnCheckFilter(store db.Store, p *parser.Parser, l *log.Logger) *ReturnCheckFilter {
	return &ReturnCheckFilter{store: store, parser: p, logger: l}
}

func (f *ReturnCheckFilter) Name() string { return "return_check" }

func (f *ReturnCheckFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if len(candidates) == 0 {
		return candidates, nil, nil
	}
	if f.parser == nil {
		return nil, nil, fmt.Errorf("filter return_check: parser unavailable, degraded")
	}

	cache := newFileParseCache(f.parser)

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	kept := make([]Candidate, 0, len(candidates))

	for funcID, funcCandidates := range byFunc {
		fn, err := f.store.GetFunctionByID(ctx, funcID)
		if err != nil || fn == nil {
			kept = append(kept, funcCandidates...)
			continue
		}

		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			kept = append(kept, funcCandidates...)
			continue
		}

		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			kept = append(kept, funcCandidates...)
			continue
		}

		ifStmts := body.FindAll("if_statement")
		callExprs := body.FindAll("call_expression")

		for _, c := range funcCandidates {
			result, _ := f.analyzeCandidate(c, callExprs, ifStmts)
			// The detector already suppresses genuinely-checked returns at
			// emission (checkedVars). This filter only upgrades the two shapes
			// whose "unchecked" nature it can prove deterministically — a bare
			// call, or an assignment/declaration with no subsequent sentinel
			// test. It never dismisses: a candidate the detector emitted is
			// real enough that the AI agent, not this filter, should weigh any
			// residual "is it checked?" ambiguity.
			if result == "unchecked" {
				c.SuspicionLevel = "confirmed"
			}
			kept = append(kept, c)
		}
	}

	return kept, nil, nil
}

func (f *ReturnCheckFilter) analyzeCandidate(c Candidate, callExprs, ifStmts []parser.Node) (result, lhsVar string) {
	callNode := findCallAtLine(callExprs, c.Line, c.APIName)
	if callNode == nil {
		return "unknown", ""
	}

	node := callNode.Parent()
	for node != nil {
		switch node.Kind() {
		case "expression_statement":
			return "unchecked", ""

		case "assignment_expression":
			children := node.NamedChildren()
			if len(children) >= 2 {
				lhs := varText(children[0])
				if lhs != "" {
					return checkIfGuarded(lhs, c.Line, ifStmts), lhs
				}
			}
			return "unknown", ""

		case "init_declarator":
			decl := node.Parent()
			if decl != nil && decl.Kind() == "declaration" {
				lhs := declIdentifierName(*decl)
				if lhs != "" {
					return checkIfGuarded(lhs, c.Line, ifStmts), lhs
				}
			}
			return "unknown", ""

		default:
			node = node.Parent()
		}
	}
	return "unknown", ""
}

func findCallAtLine(callExprs []parser.Node, line int, apiName string) *parser.Node {
	for i := range callExprs {
		n := callExprs[i]
		if n.StartLine() == line && callMatchesAPI(n, apiName) {
			return &callExprs[i]
		}
	}
	for i := range callExprs {
		n := callExprs[i]
		if n.StartLine() != line && line >= n.StartLine() && line <= n.EndLine() && callMatchesAPI(n, apiName) {
			return &callExprs[i]
		}
	}
	return nil
}

func callMatchesAPI(call parser.Node, apiName string) bool {
	if apiName == "" {
		return true
	}
	fnChild := call.ChildByFieldName("function")
	return fnChild != nil && fnChild.Text() == apiName
}

func checkIfGuarded(lhsVar string, assignLine int, ifStmts []parser.Node) string {
	if lhsVar == "" {
		return "unknown"
	}
	for _, ifStmt := range ifStmts {
		if ifStmt.StartLine() <= assignLine {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if conditionTestsVar(*cond, lhsVar) {
			return "checked"
		}
	}
	return "unchecked"
}

// conditionTestsVar reports whether cond actually tests varName's value — a
// null/error check like `if (!p)`, `if (p == NULL)`, `if (p < 0)`, or a bare
// truthiness test `if (p)`. A condition that merely *uses* the variable
// (`if (p->len > 0)` or `if (p + 1 < n)`) dereferences it and therefore does
// NOT guard the unchecked-return defect — treating it as a check would dismiss
// a genuine null-deref/error-return bug as a false positive.
func conditionTestsVar(cond parser.Node, varName string) bool {
	node := cond
	for node.Kind() == "parenthesized_expression" {
		children := node.NamedChildren()
		if len(children) == 0 {
			return false
		}
		node = children[0]
	}

	switch node.Kind() {
	case "identifier":
		// `if (p)` — bare truthiness test on the variable itself.
		return node.Text() == varName
	case "field_expression", "subscript_expression":
		// `if (e->buffer)` / `if (arr[i])` — test on a member/element, only a
		// check when the assigned storage location is exactly that expression.
		return node.Text() == varName
	case "unary_expression":
		// `if (!p)` / `if (!e->buffer)` — negation of the variable itself. The
		// operand must be the variable as a whole: `!e->buffer` tests e->buffer,
		// NOT e, so it must not count as a check on e.
		if !strings.HasPrefix(strings.TrimSpace(node.Text()), "!") {
			return false
		}
		for _, n := range node.NamedChildren() {
			switch n.Kind() {
			case "identifier", "field_expression", "subscript_expression":
				return n.Text() == varName
			}
		}
		return false
	case "binary_expression":
		return binaryTestsVar(node, varName)
	}
	return false
}

// binaryTestsVar reports whether a binary condition is a comparison that tests
// varName itself (an identifier/member/element operand against a sentinel), as
// opposed to a comparison over a value derived from it (e.g. `p->len > 0`).
func binaryTestsVar(b parser.Node, varName string) bool {
	if !hasCompareOperator(b) {
		return false
	}
	for _, child := range b.NamedChildren() {
		if child.Kind() != "identifier" && child.Kind() != "field_expression" && child.Kind() != "subscript_expression" {
			continue
		}
		if child.Text() == varName {
			return true
		}
	}
	return false
}

// hasCompareOperator reports whether b is an equality/relational comparison
// (==, !=, <, <=, >, >=) — the operators used to validate a return value.
func hasCompareOperator(b parser.Node) bool {
	for _, child := range b.Children() {
		switch child.Kind() {
		case "==", "!=", "<", "<=", ">", ">=":
			return true
		}
	}
	return false
}

func varText(node parser.Node) string {
	switch node.Kind() {
	case "identifier", "field_expression", "subscript_expression":
		return node.Text()
	}
	// Mirror the detector's assignedVariable fallback: `*p = call()` attributes
	// to the first identifier inside (`p`) so the filter and detector agree on
	// the assigned location instead of leaving the shape unknown.
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

func declIdentifierName(decl parser.Node) string {
	for _, n := range decl.FindAll("identifier") {
		if !parser.IsCTypeKeyword(n.Text()) {
			return n.Text()
		}
	}
	return ""
}
