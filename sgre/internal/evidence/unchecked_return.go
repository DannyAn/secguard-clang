package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UncheckedReturnDetector flags calls to allocation / I/O functions whose
// return value is neither compared directly nor stored into a variable that is
// subsequently checked (CWE-252). This is the C analogue of "missing error
// handling": malloc can return NULL, read/recv can return -1, and ignoring that
// turns a soft failure into a crash or a corruption.
type UncheckedReturnDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUncheckedReturnDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UncheckedReturnDetector {
	return &UncheckedReturnDetector{store: store, parser: p, logger: logger}
}

func (d *UncheckedReturnDetector) Name() string { return "unchecked_return" }

func (d *UncheckedReturnDetector) Domain() string { return "boundary" }

func (d *UncheckedReturnDetector) Capabilities() []string {
	return []string{"null-return", "error-return"}
}

// uncheckedReturnAPIs are calls whose return value must be validated. The
// failure sentinel (NULL or a negative errno value) is irrelevant to the
// detection — only that the value must be checked before use.
var uncheckedReturnAPIs = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true,
	"fopen": true, "fdopen": true, "opendir": true,
	"read": true, "recv": true, "write": true, "send": true,
}

func (d *UncheckedReturnDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		binaries := root.FindAll("binary_expression")
		unarys := root.FindAll("unary_expression")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")

		for _, f := range funcs {
			checked := d.checkedVars(binaries, unarys, ifs, whiles, fors, dos, f)
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				if !uncheckedReturnAPIs[extractCallName(call)] {
					continue
				}
				if callResultChecked(call) {
					continue
				}
				if v := assignedVarOfCall(call); v != "" && checked[v] {
					continue
				}

				if emitEvent(ctx, d.store, d.logger, "UNCHECKED_RETURN", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function":   extractCallName(call),
					"expression": call.Text(),
					"category":   "unchecked_return",
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// checkedVars returns the set of variable names that are validated somewhere in
// f: compared (`p == NULL`, `ret < 0`), negated (`!p`), or used as a bare
// truthiness condition (`if (p)`). A target call's result assigned to one of
// these names counts as checked.
func (d *UncheckedReturnDetector) checkedVars(binaries, unarys, ifs, whiles, fors, dos []parser.Node, f *db.Function) map[string]bool {
	set := make(map[string]bool)
	for _, b := range binaries {
		if !funcLineRange(f, b.StartLine()) {
			continue
		}
		if !hasCompareOp(b) {
			continue
		}
		for _, child := range b.NamedChildren() {
			switch child.Kind() {
			case "identifier", "field_expression", "subscript_expression":
				set[child.Text()] = true
			}
		}
	}
	for _, u := range unarys {
		if !funcLineRange(f, u.StartLine()) {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(u.Text()), "!") {
			continue
		}
		for _, id := range u.FindAll("identifier") {
			set[id.Text()] = true
		}
	}
	for _, cond := range [][]parser.Node{ifs, whiles, fors, dos} {
		for _, node := range cond {
			if !funcLineRange(f, node.StartLine()) {
				continue
			}
			if v := bareConditionVar(node.ChildByFieldName("condition")); v != "" {
				set[v] = true
			}
		}
	}
	return set
}

// bareConditionVar returns the variable name when a condition is a bare
// identifier (`if (p)`), unwrapping parentheses, or "" for any other shape.
func bareConditionVar(cond *parser.Node) string {
	if cond == nil {
		return ""
	}
	n := *cond
	for n.Kind() == "parenthesized_expression" {
		inner := n.NamedChildren()
		if len(inner) == 0 {
			return ""
		}
		n = inner[0]
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	return ""
}

// callResultChecked reports whether the call's value is consumed directly by a
// comparison, a `!` negation, or a branch/loop condition — i.e. validated at
// the call site without going through a named variable.
func callResultChecked(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "binary_expression":
			if hasCompareOp(*p) {
				return true
			}
		case "unary_expression":
			if strings.HasPrefix(strings.TrimSpace(p.Text()), "!") {
				return true
			}
		case "if_statement", "while_statement", "for_statement", "do_statement", "switch_statement":
			return true
		case "return_statement", "expression_statement", "compound_statement",
			"declaration", "argument_list", "assignment_expression", "init_declarator":
			return false
		}
	}
	return false
}

// assignedVarOfCall returns the variable the call's result is assigned into
// (via `v = call(...)` or `T v = call(...)`), or "" when the result is not
// stored in a simple named variable.
func assignedVarOfCall(call parser.Node) string {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			named := p.NamedChildren()
			if len(named) < 2 {
				return ""
			}
			return assignedVariable(named[0])
		case "parenthesized_expression", "cast_expression", "binary_expression",
			"argument_list", "call_expression", "field_expression", "subscript_expression":
			continue
		default:
			return ""
		}
	}
	return ""
}

// hasCompareOp reports whether a binary expression is an equality/relational
// comparison (==, !=, <, <=, >, >=) — the operators used to validate a return
// value (NULL / -1 / 0 / bounds).
func hasCompareOp(expr parser.Node) bool {
	for _, child := range expr.Children() {
		switch child.Kind() {
		case "==", "!=", "<", "<=", ">", ">=":
			return true
		}
	}
	return false
}
