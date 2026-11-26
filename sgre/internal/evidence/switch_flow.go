package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/config"
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

func (d *SwitchFlowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// The cross-file typedef table is built ONCE outside the per-file loop; the
	// previous code called buildGlobalTypedefs INSIDE forEachFile, re-reading +
	// re-parsing every indexed file once per file (O(F²)) — the dominant
	// detector-phase cost on the benchmark (584ms).
	globalTypedefs := buildGlobalTypedefs(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		typedefs := globalTypedefs.clone()
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
					// A fallthrough that lands on a case whose body STARTS with a
					// terminator (`case ADDR: ...; default: return;`) is
					// behaviorally identical to a `break`: control leaves the
					// switch immediately, so no statement of the next case is
					// shared (issue #269 root cause 5.3). A next case that does
					// work first (`case B: work(); return;`) still shares that
					// work and stays a real fallthrough.
					if nb := caseBody(children[next]); len(nb) > 0 && isCaseTerminator(nb[0]) {
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

			// missing_default (CWE-478)
			enumName, isEnum := switchEnumCondition(sw, globals, scopes, fn, typedefs)
			cond := switchCondition(sw)
			emitted := false

			// Precise enum coverage gap: an enum switch that does not cover every
			// non-sentinel enumerator and has no default at all. This is the one
			// machine-checkable shape (the domain is the enumerator list).
			if isEnum {
				if members := nonSentinelEnumerators(enums[enumName]); len(members) > 0 {
					covered := coveredEnumMembers(body, members)
					if len(covered) < len(members) && !hasDefault(body) {
						d.emit(ctx, fn.ID, file, cond, "missing_default", map[string]string{
							"reason":        "enum_gap",
							"enum_coverage": fmt.Sprintf("%s (covered %d/%d)", enumName, len(covered), len(members)),
							"default":       "none",
						}, &result)
						emitted = true
					}
				}
			}

			// Broader unhandled-value defect: a switch whose default is absent or a
			// no-op, where the unhandled value has downstream state impact (a
			// written state variable read after the switch, or a loop whose
			// continuation depends on a value the switch updates). Heuristic —
			// kept at the suspected tier for the AI to judge reachability.
			if !emitted {
				if reason, stateVars, ok := unhandledStateReason(sw, body, root, fn, scopes, cond, isEnum); ok {
					extra := map[string]string{
						"reason":     reason,
						"state_vars": strings.Join(stateVars, ","),
						"default":    defaultKind(body),
					}
					if ctrl := switchCtrlIdentifier(cond); ctrl != "" {
						extra["variable"] = ctrl
					}
					d.emit(ctx, fn.ID, file, cond, "missing_default", extra, &result)
				}
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
	for _, m := range config.Load().MergedFallthroughMarkers() {
		if t == m || strings.HasPrefix(t, m+" ") || strings.HasPrefix(t, m+":") {
			return true
		}
	}
	return false
}

// isCaseTerminator reports whether a case body's last statement provably ends
// the case (break/continue/return/goto, or a noreturn call).
func isCaseTerminator(stmt parser.Node) bool {
	// A `case X: { ...; break; }` puts the terminator inside a compound
	// statement; drill into it so the inner break/return is recognized. Only
	// the trailing statement matters — a leading block that ends in a
	// non-terminator still falls through.
	for stmt.Kind() == "compound_statement" {
		children := stmt.NamedChildren()
		if len(children) == 0 {
			return false
		}
		stmt = children[len(children)-1]
	}
	switch stmt.Kind() {
	case "break_statement", "continue_statement", "return_statement", "goto_statement":
		return true
	}
	if stmt.Kind() != "expression_statement" {
		return false
	}
	for _, call := range stmt.FindAll("call_expression") {
		name := extractCallName(call)
		if apikb.IsNoReturnCall(name) || config.Load().MergedNoreturnFunctions()[name] {
			return true
		}
	}
	return false
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

// switchCtrlIdentifier returns the switch control expression as a bare
// identifier, or "" when it is not a simple variable (a field read, call, ...).
func switchCtrlIdentifier(cond parser.Node) string {
	c := stripCastParenNode(cond)
	if c.Kind() == "identifier" {
		return c.Text()
	}
	return ""
}

// defaultKind classifies how the switch handles a value that matches no case:
// "none" (no default), "empty" (a default whose body does nothing observable),
// or "effective" (a default that returns/assigns/calls/etc.). An empty default
// leaves downstream state untouched, exactly like having no default.
func defaultKind(body *parser.Node) string {
	if body == nil {
		return "none"
	}
	for _, cs := range body.FindAll("case_statement") {
		if !isDefaultCase(cs) {
			continue
		}
		for _, s := range caseBody(cs) {
			if !isNoOpStmt(s) {
				return "effective"
			}
		}
		return "empty"
	}
	return "none"
}

// isNoOpStmt reports whether a default-body statement has no observable effect
// on program state or control flow (a comment, an empty `;`, or a bare
// break/continue that merely exits the switch without updating state).
func isNoOpStmt(s parser.Node) bool {
	switch s.Kind() {
	case "comment":
		return true
	case "break_statement", "continue_statement":
		return true
	case "expression_statement":
		return len(s.NamedChildren()) == 0
	case "compound_statement":
		for _, c := range s.NamedChildren() {
			if !isNoOpStmt(c) {
				return false
			}
		}
		return true
	}
	return false
}

// switchWrites returns the set of simple variable names written anywhere in the
// switch's case bodies (assignments, ++/--, compound assignments).
func switchWrites(body *parser.Node) map[string]bool {
	writes := map[string]bool{}
	if body == nil {
		return writes
	}
	for _, cs := range body.FindAll("case_statement") {
		for _, stmt := range caseBody(cs) {
			collectWritesIn(stmt, writes)
		}
	}
	return writes
}

func collectWritesIn(node parser.Node, writes map[string]bool) {
	switch node.Kind() {
	case "assignment_expression", "init_declarator":
		if lhs, _, ok := node.AssignParts(); ok {
			if v := assignedVariable(lhs); isSimpleIdentifier(v) {
				writes[v] = true
			}
		}
	case "update_expression":
		for _, c := range node.NamedChildren() {
			if c.Kind() == "identifier" {
				writes[c.Text()] = true
				break
			}
		}
	}
	for _, c := range node.NamedChildren() {
		collectWritesIn(c, writes)
	}
}

// isSimpleIdentifier reports whether name is a plain C identifier (no field /
// subscript / pointer syntax), i.e. a whole-variable state slot.
func isSimpleIdentifier(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		switch {
		case r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// readsAfterSwitch returns the set of identifier names referenced after the
// switch within the same function — the values a missing default would leave
// stale or uninitialized.
func readsAfterSwitch(root parser.Node, fn *db.Function, sw parser.Node) map[string]bool {
	reads := map[string]bool{}
	for _, id := range root.FindAll("identifier") {
		if id.StartLine() > sw.EndLine() && id.StartLine() <= fn.EndLine {
			reads[id.Text()] = true
		}
	}
	return reads
}

func enclosingLoop(sw parser.Node) (parser.Node, bool) {
	for p := sw.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "while_statement", "for_statement", "do_statement":
			return *p, true
		case "function_definition", "translation_unit":
			return parser.Node{}, false
		}
	}
	return parser.Node{}, false
}

// loopConditionVars returns the identifiers a loop's continuation condition
// reads — the variables whose non-progress would stall the loop.
func loopConditionVars(loop parser.Node) map[string]bool {
	vars := map[string]bool{}
	cond := loop.ChildByFieldName("condition")
	if cond == nil {
		return vars
	}
	for _, id := range cond.FindAll("identifier") {
		vars[id.Text()] = true
	}
	return vars
}

// statefulExact / statefulAffixes name the dispatch/status vocabulary that marks
// a switch control variable as a state-machine / message-type / error-code
// selector rather than a local arithmetic counter. Name-based, so it is a
// candidacy heuristic only — the result stays at the suspected tier and the AI
// judges the actual value domain.
var statefulExact = map[string]bool{
	"state": true, "status": true, "mode": true, "type": true, "kind": true,
	"op": true, "opcode": true, "code": true, "cmd": true, "command": true,
	"msg": true, "message": true, "err": true, "errno": true, "error": true,
	"ret": true, "rc": true, "result": true, "phase": true, "step": true,
	"stage": true, "event": true, "action": true, "signal": true, "reason": true,
	"cause": true, "flag": true, "flags": true, "level": true, "priority": true,
	"class": true, "protocol": true, "proto": true, "request": true,
	"response": true, "direction": true, "dir": true, "role": true,
	"family": true,
}

var statefulAffixes = []string{
	"state", "status", "mode", "type", "kind", "code", "cmd", "op", "opcode",
	"msg", "message", "err", "error", "ret", "rc", "result", "phase", "step",
	"stage", "event", "action", "signal", "reason", "cause", "flag", "level",
	"priority", "class", "protocol", "proto", "request", "response", "direction",
	"dir", "role", "family", "packet", "frame", "pkt",
}

func isStatefulVar(name string) bool {
	if name == "" {
		return false
	}
	if statefulExact[name] {
		return true
	}
	lower := strings.ToLower(name)
	for _, a := range statefulAffixes {
		if strings.HasSuffix(lower, "_"+a) || strings.HasPrefix(lower, a+"_") {
			return true
		}
	}
	return false
}

func isParamName(name string, scopes map[int]integerOverflowTypeScope, fn *db.Function) bool {
	if name == "" || fn == nil {
		return false
	}
	return scopes[fn.StartLine].params[name]
}

// unhandledStateReason decides whether a switch that does not effectively handle
// unknown values nonetheless has downstream state impact worth flagging. It
// returns the reason ("loop_progress" or "unhandled_state") and the sorted state
// variables involved.
func unhandledStateReason(sw parser.Node, body *parser.Node, root parser.Node, fn *db.Function, scopes map[int]integerOverflowTypeScope, cond parser.Node, isEnum bool) (string, []string, bool) {
	if defaultKind(body) == "effective" {
		return "", nil, false
	}
	writes := switchWrites(body)
	if len(writes) == 0 {
		return "", nil, false
	}
	ctrl := switchCtrlIdentifier(cond)

	// Loop progress: the switch updates a variable the enclosing loop's
	// continuation condition reads — a missing case leaves it stale and the loop
	// can fail to terminate (CWE-478 root cause of a possible CWE-835 stall).
	if loop, inLoop := enclosingLoop(sw); inLoop {
		condVars := loopConditionVars(loop)
		var touched []string
		for v := range writes {
			if condVars[v] {
				touched = append(touched, v)
			}
		}
		if len(touched) > 0 {
			return "loop_progress", sortStrings(touched), true
		}
	}

	// Dispatch on a state / status / type / error selector (or an external
	// parameter / enum selector) whose unhandled value leaves a written state
	// variable stale downstream.
	if ctrl == "" || !(isStatefulVar(ctrl) || isEnum || isParamName(ctrl, scopes, fn)) {
		return "", nil, false
	}
	stateVars := intersectStrings(writes, readsAfterSwitch(root, fn, sw))
	if len(stateVars) == 0 {
		return "", nil, false
	}
	return "unhandled_state", sortStrings(stateVars), true
}

// sentinelEnumerator reports whether an enumerator name is a boundary/count
// marker (the conventional *_MAX / *_COUNT / *_NUM / *_SIZE / *_END / *_LAST
// enumerators) rather than a dispatchable value, so it is excluded from the
// "must be covered" set.
func sentinelEnumerator(name string) bool {
	upper := strings.ToUpper(name)
	for _, s := range []string{"_MAX", "_COUNT", "_NUM", "_SIZE", "_END", "_LAST"} {
		if strings.HasSuffix(upper, s) {
			return true
		}
	}
	switch upper {
	case "MAX", "COUNT", "NUM", "SIZE", "END", "LAST":
		return true
	}
	return false
}

func nonSentinelEnumerators(members map[string]bool) map[string]bool {
	out := make(map[string]bool, len(members))
	for m := range members {
		if !sentinelEnumerator(m) {
			out[m] = true
		}
	}
	return out
}

func sortStrings(s []string) []string {
	sort.Strings(s)
	return s
}

func intersectStrings(a, b map[string]bool) []string {
	var out []string
	for k := range a {
		if b[k] {
			out = append(out, k)
		}
	}
	return out
}
