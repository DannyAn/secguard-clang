package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SwitchFlowDetector flags two switch control-flow defects, both heuristic (the
// planner never auto-confirms them):
//
//   - fallthrough (CWE-484): a case body that is non-empty and whose last
//     statement neither terminates (break/continue/return/goto/noreturn call)
//     nor carries an exemption comment (`fall through` etc.), so control falls
//     into the next case.
//   - missing_default (CWE-478): a switch on an enum-typed value that does not
//     cover every enumerator and has no default.
//
// The two are one type because they share the switch AST and are judged by the
// same "is the fall-through / missing case semantically intended" question;
// their CWEs differ, which CategoryCWEs carries.
type SwitchFlowDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSwitchFlowDetector(store db.Store, p *parser.Parser, logger *log.Logger) *SwitchFlowDetector {
	return &SwitchFlowDetector{store: store, parser: p, logger: logger}
}

func (d *SwitchFlowDetector) Name() string { return "switch_flow" }

// fallthroughMarkers is the case-insensitive comment set that exempts an
// intentional fallthrough (the GCC-recognized spellings).
var fallthroughMarkers = []string{
	"fall through", "fallthrough", "falls through", "fallthru", "fall-through",
}

func (d *SwitchFlowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		typedefs := buildGlobalTypedefs(ctx, d.store, d.parser).clone()
		typedefs.addRoot(root)
		enums := collectEnums(root)
		globals, scopes := buildIntegerOverflowTypeScopes(root, funcs, typedefs)

		for _, sw := range root.FindAll("switch_statement") {
			var fn *db.Function
			for _, f := range funcs {
				if sw.StartLine() >= f.StartLine && sw.StartLine() <= f.EndLine {
					fn = f
					break
				}
			}
			if fn == nil {
				continue
			}

			// fallthrough
			body := switchBody(sw)
			if body != nil {
				children := body.NamedChildren()
				for i, child := range children {
					if child.Kind() != "case_statement" {
						continue
					}
					next := nextCaseIndex(children, i)
					if next < 0 {
						break
					}
					stmts := caseBody(child)
					if len(stmts) == 0 {
						continue
					}
					last := stmts[len(stmts)-1]
					if isCaseTerminator(last) {
						continue
					}
					if hasFallthroughComment(children[i+1 : next]) {
						continue
					}
					d.emit(ctx, fn.ID, file, last, "fallthrough", map[string]string{
						"case_end": last.Kind(),
					}, &result)
				}
			}

			// missing_default
			if enumName, ok := switchEnumCondition(sw, globals, scopes, fn, typedefs); ok {
				members := enums[enumName]
				if len(members) == 0 {
					continue
				}
				covered := coveredEnumMembers(body, members)
				if len(covered) == len(members) || hasDefault(body) {
					continue
				}
				cond := switchCondition(sw)
				d.emit(ctx, fn.ID, file, cond, "missing_default", map[string]string{
					"enum_coverage": fmt.Sprintf("%s (covered %d/%d)", enumName, len(covered), len(members)),
				}, &result)
			}
		}
	})
	return result, err
}

func (d *SwitchFlowDetector) emit(ctx context.Context, fnID int64, file *db.File, node parser.Node, category string, extra map[string]string, result *DetectResult) {
	props := map[string]string{
		"category":   category,
		"expression": node.OriginalText(),
	}
	for k, v := range extra {
		props[k] = v
	}
	if emitEvent(ctx, d.store, d.logger, "SWITCH_FLOW", fnID, &db.Location{FileID: file.ID, Line: node.StartLine(), Column: node.StartColumn()}, props) {
		result.EventsCreated++
	}
}

// switchBody returns the switch statement's body compound_statement.
func switchBody(sw parser.Node) *parser.Node {
	return sw.FindFirst("compound_statement")
}

// switchCondition returns the switch condition expression (the operand inside
// the parentheses).
func switchCondition(sw parser.Node) parser.Node {
	cond := sw.ChildByFieldName("condition")
	if cond != nil {
		return *cond
	}
	for _, c := range sw.NamedChildren() {
		if c.Kind() == "parenthesized_expression" {
			return c
		}
	}
	return parser.Node{}
}

// caseBody returns a case/default statement's body statements (everything after
// the `case <value>:` / `default:` label).
func caseBody(cs parser.Node) []parser.Node {
	named := cs.NamedChildren()
	if isDefaultCase(cs) {
		return named
	}
	if len(named) <= 1 {
		return nil
	}
	return named[1:]
}

// isDefaultCase reports whether a case_statement is a `default:` label (its
// leading anonymous child is `default`, not `case`).
func isDefaultCase(cs parser.Node) bool {
	for _, c := range cs.Children() {
		if c.Kind() == "default" {
			return true
		}
		if c.Kind() == "case" {
			return false
		}
	}
	return false
}

func nextCaseIndex(children []parser.Node, i int) int {
	for j := i + 1; j < len(children); j++ {
		if children[j].Kind() == "case_statement" {
			return j
		}
	}
	return -1
}

// hasFallthroughComment reports whether any node between a case and the next
// case is an exemption comment (`fall through` etc.).
func hasFallthroughComment(nodes []parser.Node) bool {
	for _, n := range nodes {
		if n.Kind() != "comment" {
			continue
		}
		if isFallthroughComment(n.Text()) {
			return true
		}
	}
	return false
}

func isFallthroughComment(text string) bool {
	t := strings.TrimSpace(text)
	t = strings.TrimPrefix(t, "/*")
	t = strings.TrimSuffix(t, "*/")
	t = strings.TrimPrefix(t, "//")
	t = strings.ToLower(strings.TrimSpace(t))
	for _, m := range fallthroughMarkers {
		if t == m || strings.HasPrefix(t, m+" ") || strings.HasPrefix(t, m+":") {
			return true
		}
	}
	return false
}

// isCaseTerminator reports whether a case body's last statement provably ends
// the case (break/continue/return/goto, or a noreturn call).
func isCaseTerminator(stmt parser.Node) bool {
	switch stmt.Kind() {
	case "break_statement", "continue_statement", "return_statement", "goto_statement":
		return true
	}
	if stmt.Kind() != "expression_statement" {
		return false
	}
	for _, call := range stmt.FindAll("call_expression") {
		name := extractCallName(call)
		if apikb.IsNoReturnCall(name) || noreturnSwitchCalls[name] {
			return true
		}
	}
	return false
}

var noreturnSwitchCalls = map[string]bool{
	"longjmp":           true,
	"__builtin_trap":    true,
	"__builtin_unreachable": true,
}

// collectEnums maps an enum type name to its enumerator member set.
func collectEnums(root parser.Node) map[string]map[string]bool {
	enums := make(map[string]map[string]bool)
	for _, es := range root.FindAll("enum_specifier") {
		name := ""
		members := map[string]bool{}
		for _, c := range es.NamedChildren() {
			switch c.Kind() {
			case "type_identifier":
				name = c.Text()
			case "enumerator_list":
				for _, en := range c.NamedChildren() {
					if en.Kind() != "enumerator" {
						continue
					}
					for _, id := range en.NamedChildren() {
						if id.Kind() == "identifier" {
							members[id.Text()] = true
						}
					}
				}
			}
		}
		if name != "" && len(members) > 0 {
			enums[name] = members
		}
	}
	return enums
}

// switchEnumCondition resolves the switch condition's enum type name, or false
// when the condition is not a bare identifier of an enum-typed variable.
func switchEnumCondition(sw parser.Node, globals map[string]string, scopes map[int]integerOverflowTypeScope, fn *db.Function, typedefs *typedefs) (string, bool) {
	cond := switchCondition(sw)
	c := stripCastParenNode(cond)
	if c.Kind() != "identifier" {
		return "", false
	}
	scope := scopes[fn.StartLine]
	typ := resolveScopedVar(c.Text(), sw.StartLine(), globals, scope.locals)
	if typ == "" {
		return "", false
	}
	resolved := strings.TrimSpace(resolveType(typ, typedefs))
	if !strings.HasPrefix(resolved, "enum ") {
		return "", false
	}
	name := strings.TrimSpace(strings.TrimPrefix(resolved, "enum "))
	if name == "" {
		return "", false
	}
	return name, true
}

// coveredEnumMembers returns the distinct enum member names a switch covers via
// its identifier case labels.
func coveredEnumMembers(body *parser.Node, members map[string]bool) map[string]bool {
	covered := map[string]bool{}
	if body == nil {
		return covered
	}
	for _, cs := range body.FindAll("case_statement") {
		if isDefaultCase(cs) {
			continue
		}
		named := cs.NamedChildren()
		if len(named) == 0 {
			continue
		}
		label := named[0]
		if label.Kind() == "identifier" && members[label.Text()] {
			covered[label.Text()] = true
		}
	}
	return covered
}

func hasDefault(body *parser.Node) bool {
	if body == nil {
		return false
	}
	for _, cs := range body.FindAll("case_statement") {
		if isDefaultCase(cs) {
			return true
		}
	}
	return false
}
