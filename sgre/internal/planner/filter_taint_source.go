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
	// data from a caller (PARAM_BINDING edges). returnsParam is the
	// context-sensitive half: a function that returns a parameter verbatim is
	// tainted IFF that parameter is tainted — a call-site property the 0-CFA
	// retTainted summary cannot express.
	returnsParam, err := f.computeReturnsParam(ctx)
	if err != nil {
		// Fail-closed: the summaries drive candidate DROPPING. If the graph
		// reads fail (e.g. under parallel-planner DB contention), keep every
		// candidate rather than silently dropping findings on empty summaries.
		return candidates, nil, nil
	}
	retTainted, err := f.computeRetTainted(ctx, returnsParam)
	if err != nil {
		return candidates, nil, nil
	}
	paramTainted, err := f.computeParamTainted(ctx, retTainted, returnsParam)
	if err != nil {
		return candidates, nil, nil
	}

	flows, paramsByFunc := f.buildFlows(ctx, byFunc, retTainted, returnsParam, paramTainted)

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

func (f *TaintSourceFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate, retTainted map[string]bool, returnsParam map[string]map[int]bool, paramTainted map[int64]map[int]bool) (map[int64]*flowResult, map[int64]map[string]int) {
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

		genByLine, killByLine := taintEffectsWithCallees(body, retTainted, returnsParam)
		analyzer := newFlowAnalyzer(f.store, f.parser)
		analyzer.dfgCopies = map[int64]map[int][]copyPair{fid: taintCopiesFor(body, returnsParam)}
		// Seed the caller-influenced parameters as entry taint, so a sink on a
		// LOCAL derived from a tainted parameter is not missed (the inter-
		// procedural context flows into the callee body).
		analyzer.entrySeeds = taintedParamsFor(fn, root, paramTainted[fid])
		flows[fid] = analyzer.analyzeFlow(ctx, fn, body, root, genByLine, killByLine, false, false)
		paramsByFunc[fid] = paramsOf(fn, root)
	}
	return flows, paramsByFunc
}

// taintedParamsFor returns the parameter NAMES of fn that are tainted, or nil
// when none. A parameter is tainted when some caller passes taint into it, OR
// when the function is externally callable (non-static): an external caller can
// supply attacker-controlled input, so its parameters are conservatively tainted
// even when the local index has no caller.
func taintedParamsFor(fn *db.Function, root parser.Node, taintedIdx map[int]bool) map[string]bool {
	params := paramsOf(fn, root)
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]bool)
	for name, idx := range params {
		if taintedIdx[idx] || !fn.IsStatic {
			out[name] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// computeRetTainted returns the set of function NAMES that can return a tainted
// value, as a monotone boolean fixpoint over the call graph. It is the
// inter-procedural half of the taint analysis: a function returns taint if one
// of its `return <expr>` statements returns a taint source directly, a tainted
// variable, or the result of a call whose callee itself returns taint. The
// fixpoint re-runs the intra-procedural flow with the current callee summary
// until no new function is marked (the RETURN / CALL edges carry the fact
// across function boundaries).
//
// returnsParam carries the context-sensitive half: `x = g(v)` where g returns
// its parameter verbatim is tainted iff v is tainted, so the fixpoint also
// injects those as dataflow copies and taint-source gens.
func (f *TaintSourceFilter) computeRetTainted(ctx context.Context, returnsParam map[string]map[int]bool) (map[string]bool, error) {
	retTainted := make(map[string]bool)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("taint ret summary: list functions: %w", err)
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
			gen := addCalleeTaintGen(info.body, b.gen, retTainted, returnsParam)
			analyzer := newFlowAnalyzer(f.store, f.parser)
			analyzer.dfgCopies = map[int64]map[int][]copyPair{info.fn.ID: taintCopiesFor(info.body, returnsParam)}
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
	return retTainted, nil
}

// computeReturnsParam returns, per function NAME, the set of parameter indices
// the function returns verbatim (`return <param>`). Such a function is a
// taint-passthrough: its return value is tainted iff that parameter is tainted,
// which is a call-site (context-sensitive) property the flat retTainted summary
// cannot express. This is the concrete 1-CFA-style step: it lets `x = id(v)`
// propagate v's taint to x instead of being treated as an opaque call.
func (f *TaintSourceFilter) computeReturnsParam(ctx context.Context) (map[string]map[int]bool, error) {
	result := make(map[string]map[int]bool)
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("taint returnsParam summary: list functions: %w", err)
	}

	type funcInfo struct {
		name   string
		body   parser.Node
		params map[string]int
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
		infos = append(infos, funcInfo{name: fn.Name, body: body, params: paramsOf(fn, root)})
	}

	mark := func(name string, idx int) bool {
		if result[name] == nil {
			result[name] = make(map[int]bool)
		}
		if result[name][idx] {
			return false
		}
		result[name][idx] = true
		return true
	}

	// Base case: `return <param>` verbatim.
	for _, info := range infos {
		for _, ret := range info.body.FindAll("return_statement") {
			for _, child := range ret.NamedChildren() {
				if child.Kind() != "identifier" {
					continue
				}
				if idx, ok := info.params[child.Text()]; ok {
					mark(info.name, idx)
				}
			}
		}
	}

	// Transitive fixpoint: `return g(args)` where g returns its param j verbatim
	// and args[j] is one of f's parameters — so f returns taint iff that
	// parameter is tainted (wrap2(s) { return id(s); }). Sets only grow, so the
	// fixpoint terminates; it handles the multi-level passthrough the flat
	// retTainted summary cannot.
	for {
		changed := false
		for _, info := range infos {
			for _, ret := range info.body.FindAll("return_statement") {
				for _, child := range ret.NamedChildren() {
					if child.Kind() != "call_expression" {
						continue
					}
					callee := callName(child)
					if callee == "" {
						continue
					}
					args := callArgs(child)
					for j := range result[callee] {
						if j >= len(args) || args[j].Kind() != "identifier" {
							continue
						}
						if idx, ok := info.params[args[j].Text()]; ok && mark(info.name, idx) {
							changed = true
						}
					}
				}
			}
		}
		if !changed {
			break
		}
	}
	return result, nil
}

// passthroughCopiesFor returns the copy pairs introduced by taint-passthrough
// calls: `x = g(a0, a1, ...)` where g returns parameter i verbatim and a_i is a
// bare identifier v becomes `x = v` (x inherits v's taint). The copy pairs are
// fed into the flow engine's dfgCopies channel, so the shared reaching-sources
// engine treats the passthrough call exactly like a plain assignment.
func taintCopiesFor(body parser.Node, returnsParam map[string]map[int]bool) map[int][]copyPair {
	out := passthroughCopiesFor(body, returnsParam)
	for line, pairs := range formatCopies(body) {
		if out == nil {
			out = make(map[int][]copyPair)
		}
		out[line] = append(out[line], pairs...)
	}
	return out
}

// formatCopies returns the copy pairs introduced by formatting calls:
// `sprintf(dst, fmt, arg)` / `snprintf(dst, size, fmt, arg)` make dst inherit the
// taint of each bare-identifier variadic argument (`snprintf(cmd, "admin_tool %s",
// user_cmd)` taints cmd iff user_cmd is tainted).
func formatCopies(body parser.Node) map[int][]copyPair {
	out := make(map[int][]copyPair)
	for _, call := range body.FindAll("call_expression") {
		name := callName(call)
		if name != "sprintf" && name != "snprintf" && name != "vsprintf" && name != "vsnprintf" {
			continue
		}
		args := callArgs(call)
		fmtIdx := 1
		if name == "snprintf" || name == "vsnprintf" {
			fmtIdx = 2
		}
		if len(args) <= fmtIdx+1 {
			continue
		}
		dstName := bareIdentVar(args[0].Text())
		if dstName == "" {
			continue
		}
		for _, arg := range args[fmtIdx+1:] {
			if arg.Kind() == "identifier" {
				out[call.StartLine()] = append(out[call.StartLine()], copyPair{lhs: dstName, rhs: arg.Text()})
			}
		}
	}
	return out
}

func passthroughCopiesFor(body parser.Node, returnsParam map[string]map[int]bool) map[int][]copyPair {
	if len(returnsParam) == 0 {
		return nil
	}
	out := make(map[int][]copyPair)
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" || rhs.Kind() != "call_expression" {
			return
		}
		callee := callName(rhs)
		if callee == "" {
			return
		}
		for i, arg := range callArgs(rhs) {
			if !returnsParam[callee][i] {
				continue
			}
			if arg.Kind() == "identifier" {
				out[rhs.StartLine()] = append(out[rhs.StartLine()], copyPair{lhs: name, rhs: arg.Text()})
			}
		}
	})
	return out
}

// callArgs returns the positional argument nodes of a call_expression.
func callArgs(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

// computeParamTainted returns, per function, the set of parameter indices that
// receive tainted data from some caller — the forward half of the inter-
// procedural taint, consuming the PARAM_BINDING edges (caller argument →
// callee parameter). It is a monotone fixpoint over the call graph: each
// iteration rebuilds every caller's flow with its already-proven tainted
// parameters seeded at entry, so a transitive param→param chain (main → A → B)
// propagates taint across any number of hops instead of stopping after one.
func (f *TaintSourceFilter) computeParamTainted(ctx context.Context, retTainted map[string]bool, returnsParam map[string]map[int]bool) (map[int64]map[int]bool, error) {
	result := make(map[int64]map[int]bool)
	edges, err := f.store.ListGraphEdgesByType(ctx, "PARAM_BINDING")
	if err != nil {
		return nil, fmt.Errorf("taint param summary: list PARAM_BINDING edges: %w", err)
	}
	if len(edges) == 0 {
		return result, nil
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

	// Callers that appear in a PARAM_BINDING edge, resolved once.
	callerIDs := make(map[int64]bool)
	for _, e := range edges {
		if fid := argFunc[e.SrcID]; fid != 0 {
			callerIDs[fid] = true
		}
	}

	for {
		changed := false
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
			genByLine, killByLine := taintEffectsWithCallees(body, retTainted, returnsParam)
			analyzer := newFlowAnalyzer(f.store, f.parser)
			analyzer.dfgCopies = map[int64]map[int][]copyPair{fid: taintCopiesFor(body, returnsParam)}
			// Seed this caller's already-proven tainted parameters so its own
			// parameter arguments (which may be its params) carry taint forward.
			analyzer.entrySeeds = taintedParamsFor(fn, root, result[fid])
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
				if !result[calleeID][idx] {
					result[calleeID][idx] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	return result, nil
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
// whose callee is known to return taint (the RETURN-edge summary) or whose
// callee returns a taint-source argument verbatim (the param-sensitive summary).
func taintEffectsWithCallees(body parser.Node, retTainted map[string]bool, returnsParam map[string]map[int]bool) (map[int][]string, map[int][]string) {
	gen, kill := taintEffects(body)
	gen = addCalleeTaintGen(body, gen, retTainted, returnsParam)
	return gen, kill
}

// addCalleeTaintGen adds, to gen, every `x = g(...)` assignment whose callee g is
// in retTainted (returns taint unconditionally), or whose callee returns a
// parameter verbatim and that argument is a taint source (returns taint iff the
// arg is tainted — the context-sensitive case). It returns a new map (the input
// is not mutated), so the caller's base gen stays reusable across fixpoint
// iterations.
func addCalleeTaintGen(body parser.Node, gen map[int][]string, retTainted map[string]bool, returnsParam map[string]map[int]bool) map[int][]string {
	if len(retTainted) == 0 && len(returnsParam) == 0 {
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
		callee := rhsCallName(rhs)
		if callee == "" {
			return
		}
		if retTainted[callee] {
			out[rhs.StartLine()] = append(out[rhs.StartLine()], name)
			return
		}
		for i, arg := range callArgs(rhs) {
			if returnsParam[callee][i] && isTaintSourceExpr(arg) {
				out[rhs.StartLine()] = append(out[rhs.StartLine()], name)
			}
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
