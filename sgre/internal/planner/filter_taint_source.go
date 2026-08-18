package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TaintSourceFilter converges the injection / path-traversal / format-string
// candidate streams with the same reaching-sources flow engine as null-deref,
// extended to taint. It seeds gen from user-input sources (getenv, argv, scanf/
// fgets/read/recv buffers, ...), kills from provably-untainted assignments
// (string/number literals, address-of), and copies through plain assignments
// (p = q). A candidate is dropped only when NO taint source can reach its sink
// argument — the conservative direction for a may-taint analysis. Sink arguments
// that are function parameters are kept (a caller may pass tainted data).
//
// This replaces the "default chain = call-reach only" for the three input
// types: a non-literal path/format/command that never touches a taint source is
// provably safe and no longer reaches the AI agent.
type TaintSourceFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewTaintSourceFilter(store db.Store, p *parser.Parser, logger *log.Logger) *TaintSourceFilter {
	return &TaintSourceFilter{store: store, parser: p, logger: logger}
}

func (f *TaintSourceFilter) Name() string { return "taint_source" }

// taintSourceFuncs return user-controlled data as their return value.
var taintSourceFuncs = map[string]bool{
	"getenv": true, "gets": true, "getchar": true, "fgetc": true,
	"getcwd": true, "readlink": true,
}

// taintBufferFuncs write user-controlled data into a pointer argument.
var taintBufferFuncs = map[string]bool{
	"scanf": true, "sscanf": true, "fscanf": true, "vscanf": true,
	"fgets": true, "gets": true,
	"read": true, "recv": true, "recvfrom": true, "recvmsg": true,
}

func (f *TaintSourceFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	// Inter-procedural summaries: which functions can return a tainted value
	// (RETURN / CALL edges) and which (function, parameter) pairs receive tainted
	// data from a caller (PARAM_BINDING edges).
	retTainted := f.computeRetTainted(ctx)
	paramTainted := f.computeParamTainted(ctx, retTainted)

	flows, paramsByFunc := f.buildFlows(ctx, byFunc, retTainted)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		sink := f.sinkVariable(ctx, c)
		// Unresolvable sink (complex expression, non-bare argument) → keep.
		if sink == "" {
			kept = append(kept, c)
			continue
		}
		// A parameter can be tainted by the caller. It is kept; if a PARAM_BINDING
		// edge proves a tainted argument flows into it, the sink is confirmed.
		if idx, isParam := paramsByFunc[c.FunctionID][sink]; isParam {
			if paramTainted[c.FunctionID][idx] {
				c.HasTaintSource = true
				if c.SuspicionLevel == "suspected" {
					c.SuspicionLevel = "confirmed"
				}
			}
			kept = append(kept, c)
			continue
		}
		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		if flow.reaching(sink, c.Line) {
			c.HasTaintSource = true
			if c.SuspicionLevel == "suspected" {
				c.SuspicionLevel = "confirmed"
			}
			kept = append(kept, c)
			continue
		}
		dropped = dismiss(dropped, c, f.Name(),
			fmt.Sprintf("no tainted source reaches %s at line %d", sink, c.Line))
	}
	return kept, dropped, nil
}

// sinkVariable returns the bare identifier of the sink argument, or "" when the
// argument is a complex expression the flow engine does not track (kept
// conservatively). It reads the sink field each detector stores.
func (f *TaintSourceFilter) sinkVariable(ctx context.Context, c Candidate) string {
	switch c.Category {
	case "path_traversal", "format_string":
		event, err := f.store.GetEventByID(ctx, c.DerefEventID)
		if err != nil || event == nil {
			return ""
		}
		p := parseEventProps(event.Properties)
		if p.Path != "" {
			return bareIdentVar(p.Path)
		}
		if p.FormatArg != "" {
			return bareIdentVar(p.FormatArg)
		}
		return ""
	default:
		// command_injection stores the bare sink arg in props.variable.
		return bareIdentVar(c.VariableName)
	}
}

func (f *TaintSourceFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate, retTainted map[string]bool) (map[int64]*flowResult, map[int64]map[string]int) {
	flows := make(map[int64]*flowResult, len(byFunc))
	paramsByFunc := make(map[int64]map[string]int, len(byFunc))
	cache := newFileParseCache(f.parser)
	for fid := range byFunc {
		fn, err := f.store.GetFunctionByID(ctx, fid)
		if err != nil || fn == nil {
			continue
		}
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}

		genByLine, killByLine := taintEffectsWithCallees(body, retTainted)
		analyzer := newFlowAnalyzer(f.store, f.parser)
		flows[fid] = analyzer.analyzeFlow(ctx, fn, body, root, genByLine, killByLine, false, false)
		paramsByFunc[fid] = paramsOf(fn, root)
	}
	return flows, paramsByFunc
}

// computeRetTainted returns the set of function NAMES that can return a tainted
// value, as a monotone boolean fixpoint over the call graph. It is the
// inter-procedural half of the taint analysis: a function returns taint if one
// of its `return <expr>` statements returns a taint source directly, a tainted
// variable, or the result of a call whose callee itself returns taint. The
// fixpoint re-runs the intra-procedural flow with the current callee summary
// until no new function is marked (the RETURN / CALL edges carry the fact
// across function boundaries).
func (f *TaintSourceFilter) computeRetTainted(ctx context.Context) map[string]bool {
	retTainted := make(map[string]bool)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return retTainted
	}

	type funcInfo struct {
		fn   *db.Function
		body parser.Node
		root parser.Node
	}
	infos := make([]funcInfo, 0, len(funcs))
	cache := newFileParseCache(f.parser)
	for _, fn := range funcs {
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		infos = append(infos, funcInfo{fn: fn, body: body, root: root})
	}

	// Base taint effects (independent of the callee summary) are computed once.
	type baseEffects struct {
		gen  map[int][]string
		kill map[int][]string
	}
	base := make(map[int64]baseEffects, len(infos))
	for _, info := range infos {
		gen, kill := taintEffects(info.body)
		base[info.fn.ID] = baseEffects{gen: gen, kill: kill}
	}

	for {
		changed := false
		for _, info := range infos {
			if retTainted[info.fn.Name] {
				continue // monotone: already proven to return taint
			}
			b := base[info.fn.ID]
			gen := addCalleeTaintGen(info.body, b.gen, retTainted)
			analyzer := newFlowAnalyzer(f.store, f.parser)
			flow := analyzer.analyzeFlow(ctx, info.fn, info.body, info.root, gen, b.kill, false, false)
			if returnsTaint(info.body, flow) {
				retTainted[info.fn.Name] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return retTainted
}

// computeParamTainted returns, per function, the set of parameter indices that
// receive tainted data from some caller — the forward half of the inter-
// procedural taint, consuming the PARAM_BINDING edges (caller argument →
// callee parameter). For each such edge whose caller-side argument has a taint
// source reaching the call site, the callee's parameter is marked tainted. The
// caller flows are built with the return-taint summary so `x = g()` where g
// returns taint also propagates. This is a single forward pass (not a full
// fixpoint): transitive param→param chains are rare and stay conservative.
func (f *TaintSourceFilter) computeParamTainted(ctx context.Context, retTainted map[string]bool) map[int64]map[int]bool {
	result := make(map[int64]map[int]bool)
	edges, err := f.store.ListGraphEdgesByType(ctx, "PARAM_BINDING")
	if err != nil || len(edges) == 0 {
		return result
	}

	// Resolve variable_ref nodes (edge source = caller argument) and parameter
	// nodes (edge destination = callee parameter).
	argName := make(map[int64]string)
	argLine := make(map[int64]int)
	argFunc := make(map[int64]int64)
	if refs, err := f.store.ListGraphNodesByEntityType(ctx, "variable_ref"); err == nil {
		for _, n := range refs {
			var props struct {
				Name string `json:"name"`
				Line int    `json:"line"`
			}
			if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
				continue
			}
			argName[n.ID] = props.Name
			argLine[n.ID] = props.Line
			argFunc[n.ID] = n.EntityID
		}
	}
	paramFunc := make(map[int64]int64)
	paramIndex := make(map[int64]int)
	if params, err := f.store.ListGraphNodesByEntityType(ctx, "parameter"); err == nil {
		for _, n := range params {
			var props struct {
				Index int `json:"index"`
			}
			if json.Unmarshal([]byte(n.Properties), &props) != nil {
				continue
			}
			paramFunc[n.ID] = n.EntityID
			paramIndex[n.ID] = props.Index
		}
	}

	// Build the caller flow once per caller that appears in a PARAM_BINDING edge.
	callerIDs := make(map[int64]bool)
	for _, e := range edges {
		if fid := argFunc[e.SrcID]; fid != 0 {
			callerIDs[fid] = true
		}
	}
	callerFlows := make(map[int64]*flowResult)
	cache := newFileParseCache(f.parser)
	for fid := range callerIDs {
		fn, err := f.store.GetFunctionByID(ctx, fid)
		if err != nil || fn == nil {
			continue
		}
		file, err := f.store.GetFileByID(ctx, fn.FileID)
		if err != nil || file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}
		genByLine, killByLine := taintEffectsWithCallees(body, retTainted)
		analyzer := newFlowAnalyzer(f.store, f.parser)
		callerFlows[fid] = analyzer.analyzeFlow(ctx, fn, body, root, genByLine, killByLine, false, false)
	}

	for _, e := range edges {
		callerID := argFunc[e.SrcID]
		calleeID := paramFunc[e.DstID]
		idx := paramIndex[e.DstID]
		name := argName[e.SrcID]
		line := argLine[e.SrcID]
		flow := callerFlows[callerID]
		if flow == nil || name == "" {
			continue
		}
		if flow.reaching(name, line) {
			if result[calleeID] == nil {
				result[calleeID] = make(map[int]bool)
			}
			result[calleeID][idx] = true
		}
	}
	return result
}

// returnsTaint reports whether the function body returns a tainted value on some
// path, given its intra-procedural flow (which already incorporates the taint of
// any called functions).
func returnsTaint(body parser.Node, flow *flowResult) bool {
	if flow == nil {
		return false
	}
	for _, ret := range body.FindAll("return_statement") {
		for _, child := range ret.NamedChildren() {
			if isTaintSourceExpr(child) {
				return true
			}
			if child.Kind() == "identifier" && flow.reaching(child.Text(), ret.StartLine()) {
				return true
			}
		}
	}
	return false
}

// taintEffectsWithCallees is taintEffects plus a gen for every `x = g(...)`
// whose callee is known to return taint (the RETURN-edge summary).
func taintEffectsWithCallees(body parser.Node, retTainted map[string]bool) (map[int][]string, map[int][]string) {
	gen, kill := taintEffects(body)
	gen = addCalleeTaintGen(body, gen, retTainted)
	return gen, kill
}

// addCalleeTaintGen adds, to gen, every `x = g(...)` assignment whose callee g is
// in retTainted. It returns a new map (the input is not mutated), so the caller's
// base gen stays reusable across fixpoint iterations.
func addCalleeTaintGen(body parser.Node, gen map[int][]string, retTainted map[string]bool) map[int][]string {
	if len(retTainted) == 0 {
		return gen
	}
	out := make(map[int][]string, len(gen))
	for line, vars := range gen {
		out[line] = append([]string(nil), vars...)
	}
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		if callee := rhsCallName(rhs); callee != "" && retTainted[callee] {
			out[rhs.StartLine()] = append(out[rhs.StartLine()], name)
		}
	})
	return out
}

// taintEffects extracts the per-line taint gen (a variable becomes tainted) and
// kill (a variable is provably overwritten with an untainted value) effects.
func taintEffects(body parser.Node) (genByLine, killByLine map[int][]string) {
	gen := make(map[int][]string)
	kill := make(map[int][]string)

	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		switch {
		case isTaintSourceExpr(rhs):
			gen[rhs.StartLine()] = append(gen[rhs.StartLine()], name)
		case isDefinitelyUnTainted(rhs):
			kill[rhs.StartLine()] = append(kill[rhs.StartLine()], name)
		}
	})

	// Input calls that write into a buffer argument (fgets(buf,...), read(fd,buf,...),
	// scanf("...", &buf), recv(fd, buf, ...)).
	for _, call := range body.FindAll("call_expression") {
		for _, v := range taintBufferArgVars(call) {
			gen[call.StartLine()] = append(gen[call.StartLine()], v)
		}
	}

	return gen, kill
}

// isTaintSourceExpr reports whether expr is a user-controlled value: a call to a
// taint-returning function, argv, or a subscript/deref of argv.
func isTaintSourceExpr(expr parser.Node) bool {
	switch expr.Kind() {
	case "call_expression":
		return taintSourceFuncs[callName(expr)]
	case "identifier":
		return expr.Text() == "argv"
	case "subscript_expression":
		children := expr.NamedChildren()
		return len(children) >= 1 && children[0].Kind() == "identifier" && children[0].Text() == "argv"
	case "pointer_expression":
		return strings.Contains(expr.Text(), "argv")
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if isTaintSourceExpr(c) {
				return true
			}
		}
	}
	return false
}

// isDefinitelyUnTainted reports whether expr is provably not user-controlled:
// a string/number/char literal, a compound literal, or an address-of (&x).
// An array/pointer identifier is deliberately NOT here: it may be a buffer that
// received tainted input, so the AST copy step must propagate its taint.
func isDefinitelyUnTainted(expr parser.Node) bool {
	switch expr.Kind() {
	case "string_literal", "number_literal", "char_literal", "compound_literal_expression":
		return true
	case "pointer_expression":
		return strings.HasPrefix(expr.Text(), "&")
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if !isDefinitelyUnTainted(c) {
				return false
			}
		}
		return true
	}
	return false
}

// taintBufferArgVars returns the buffer variables an input call writes into.
func taintBufferArgVars(call parser.Node) []string {
	name := callName(call)
	if !taintBufferFuncs[name] {
		return nil
	}
	var args []parser.Node
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			args = child.NamedChildren()
			break
		}
	}
	switch name {
	case "fgets", "gets":
		if len(args) >= 1 {
			return pointerArgVars(args[0])
		}
	case "read", "recv", "recvfrom", "recvmsg":
		if len(args) >= 2 {
			return pointerArgVars(args[1])
		}
	case "scanf", "sscanf", "fscanf", "vscanf":
		var vars []string
		for _, a := range args[1:] {
			vars = append(vars, pointerArgVars(a)...)
		}
		return vars
	}
	return nil
}

// pointerArgVars returns the variable an input call writes through: a bare
// identifier, or &x (address-of a bare identifier).
func pointerArgVars(arg parser.Node) []string {
	switch arg.Kind() {
	case "identifier":
		return []string{arg.Text()}
	case "pointer_expression":
		if v := strings.TrimPrefix(arg.Text(), "&"); bareIdentVar(v) != "" {
			return []string{v}
		}
	}
	return nil
}

// bareIdentVar returns s when it is a C identifier, else "".
func bareIdentVar(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return ""
	}
	return s
}

// callName extracts the called function name from a call_expression.
func callName(call parser.Node) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_expression" {
			return child.Text()
		}
	}
	return ""
}

// rhsCallName returns the called function name when expr is a call_expression
// (possibly wrapped in a cast or parentheses), else "".
func rhsCallName(expr parser.Node) string {
	switch expr.Kind() {
	case "call_expression":
		return callName(expr)
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if name := rhsCallName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// paramsOf returns the positional parameter index of each parameter name of the
// function whose definition starts at fn.StartLine.
func paramsOf(fn *db.Function, root parser.Node) map[string]int {
	out := make(map[string]int)
	for _, def := range root.FindAll("function_definition") {
		if def.StartLine() != fn.StartLine {
			continue
		}
		for i, p := range paramNamesOfDef(def) {
			if p != "" {
				out[p] = i
			}
		}
		break
	}
	return out
}

func paramNamesOfDef(def parser.Node) []string {
	for _, child := range def.NamedChildren() {
		if child.Kind() == "function_declarator" {
			return paramNamesOfDeclarator(child)
		}
		if child.Kind() == "pointer_declarator" {
			for _, gc := range child.NamedChildren() {
				if gc.Kind() == "function_declarator" {
					return paramNamesOfDeclarator(gc)
				}
			}
		}
	}
	return nil
}

func paramNamesOfDeclarator(decl parser.Node) []string {
	var out []string
	for _, child := range decl.NamedChildren() {
		if child.Kind() != "parameter_list" {
			continue
		}
		for _, param := range child.NamedChildren() {
			if param.Kind() != "parameter_declaration" {
				continue
			}
			if name := declaratorName(param); name != "" {
				out = append(out, name)
			}
		}
	}
	return out
}
