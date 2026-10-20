package evidence

import (
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// CallerNullDetector closes the inter-procedural null gap for function
// parameters: a callee that dereferences its parameter without a guard has an
// implicit non-null precondition, and that precondition is violated when a
// caller can pass NULL (or a value it has not proven non-null) for that
// parameter. It emits a NULL_VALUE with origin "caller_null" for each such
// (callee, parameter) pair, which the null-deref flow then seeds at the
// callee's entry — so `process(NULL)` reaches `ctx->field` in process.
//
// Argument classification is conservative and low-false-positive:
//   - literal NULL (`NULL`, `0`, `(T *)NULL`) → a definite null source;
//   - `&x` / string literal / guarded variable → provably non-null, skipped;
//   - anything else (an unguarded variable) → an UNKNOWN null source, so the
//     dereference stays suspected and the AI confirms the caller contract.
//
// A caller whose early-return null check (`if (ctx == NULL) return;`) dominates
// the call proves non-null and is skipped, so an all-guarded function does not
// surface. Same-name static overloads across files are skipped (never guessed).
type CallerNullDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewCallerNullDetector(store db.Store, p *parser.Parser, logger *log.Logger) *CallerNullDetector {
	return &CallerNullDetector{store: store, parser: p, logger: logger}
}

func (d *CallerNullDetector) Name() string { return "caller_null" }

func (d *CallerNullDetector) Domain() string { return "memory" }

func (d *CallerNullDetector) Capabilities() []string {
	return []string{"caller-null", "interprocedural-param-null"}
}

type calleeParamInfo struct {
	fn    *db.Function
	names []string
	types []string
}

func (d *CallerNullDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	callees := d.buildCalleeIndex(ctx)

	type agg struct {
		definite bool
		caller   string
		line     int
		argText  string
	}
	sites := map[string]agg{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")

		// A call argument that names an array (global or caller-local) can never
		// be NULL, so it must not seed a caller_null source. Precompute per caller
		// to avoid re-walking the tree for every call site.
		nonNullArrays := make(map[int64]map[string]bool, len(funcs))
		for _, fn := range funcs {
			nonNullArrays[fn.ID] = collectNonNullableArrays(root, fn)
		}

		for _, call := range calls {
			callee := calleeName(call)
			info, ok := callees[callee]
			if !ok {
				continue
			}
			var caller *db.Function
			for _, fn := range funcs {
				if funcLineRange(fn, call.StartLine()) {
					caller = fn
					break
				}
			}
			if caller == nil {
				continue
			}
			args := getCallArgs(call)
			for i, arg := range args {
				if i >= len(info.names) || info.names[i] == "..." {
					continue
				}
				if !strings.HasSuffix(strings.TrimSpace(info.types[i]), "*") {
					continue
				}
				kind, definite := d.classifyArg(arg, caller, ifs, assigns, calls, nonNullArrays[caller.ID], call)
				if kind == "safe" {
					continue
				}
				key := callee + "\x00" + strconv.Itoa(i)
				cur := sites[key]
				if definite && !cur.definite {
					cur.definite = true
					cur.caller = caller.Name
					cur.line = call.StartLine()
					cur.argText = arg.Text()
				} else if cur.caller == "" {
					cur.caller = caller.Name
					cur.line = call.StartLine()
					cur.argText = arg.Text()
				}
				sites[key] = cur
			}
		}
	})
	if err != nil {
		return result, err
	}

	for key, s := range sites {
		parts := strings.SplitN(key, "\x00", 2)
		info := callees[parts[0]]
		idx, _ := strconv.Atoi(parts[1])
		if info.fn == nil || idx >= len(info.names) {
			continue
		}
		definite := "false"
		if s.definite {
			definite = "true"
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", info.fn.ID, &db.Location{FileID: info.fn.FileID, Line: info.fn.StartLine}, map[string]string{
			"variable":   info.names[idx],
			"origin":     "caller_null",
			"definite":   definite,
			"function":   s.caller,
			"expression": s.argText,
		}) {
			result.EventsCreated++
		}
	}
	return result, nil
}

// buildCalleeIndex maps each uniquely-defined function name to its parameter
// names/types and its function row. Same-name static overloads across files are
// dropped (ambiguous, never guessed).
func (d *CallerNullDetector) buildCalleeIndex(ctx context.Context) map[string]calleeParamInfo {
	out := map[string]calleeParamInfo{}
	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return out
	}
	byName := map[string]*db.Function{}
	dup := map[string]bool{}
	for _, fn := range funcs {
		if _, seen := byName[fn.Name]; seen {
			dup[fn.Name] = true
			continue
		}
		byName[fn.Name] = fn
	}
	files, err := d.store.ListFiles(ctx)
	if err != nil {
		return out
	}
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		for _, fnDef := range tree.RootNode().FindAll("function_definition") {
			name, names, types := functionParamNames(fnDef)
			if name == "" || dup[name] {
				continue
			}
			fn := byName[name]
			if fn == nil {
				continue
			}
			out[name] = calleeParamInfo{fn: fn, names: names, types: types}
		}
	}
	return out
}

func functionParamNames(fnDef parser.Node) (string, []string, []string) {
	var name string
	var names, types []string
	for _, child := range fnDef.NamedChildren() {
		if child.Kind() != "function_declarator" {
			continue
		}
		for _, c := range child.NamedChildren() {
			switch c.Kind() {
			case "identifier":
				name = c.Text()
			case "parameter_list":
				for _, param := range c.NamedChildren() {
					switch param.Kind() {
					case "parameter_declaration":
						names = append(names, paramName(param))
						types = append(types, normalizeSpelling(typeSpelling(param)))
					case "variadic_parameter", "variadic_type_identifier":
						names = append(names, "...")
						types = append(types, "...")
					}
				}
			}
		}
	}
	return name, names, types
}

// classifyArg classifies a call argument's nullability at the call site.
func (d *CallerNullDetector) classifyArg(arg parser.Node, caller *db.Function, ifs, assigns, calls []parser.Node, nonNullArrays map[string]bool, call parser.Node) (string, bool) {
	switch arg.Kind() {
	case "null":
		// tree-sitter-c parses `NULL` as a `null` literal node (not an
		// identifier), so a literal NULL argument is a DEFINITE null source.
		return "null", true
	case "identifier":
		if arg.Text() == "NULL" {
			return "null", true
		}
		if nonNullArrays[arg.Text()] {
			return "safe", false
		}
		if callerGuardsVar(caller, ifs, assigns, calls, arg.Text(), call) {
			return "safe", false
		}
		return "null", false
	case "number_literal":
		if strings.TrimSpace(arg.Text()) == "0" {
			return "null", true
		}
		return "safe", false
	case "cast_expression":
		op := castOperand(arg)
		if op.Kind() == "null" || (op.Kind() == "identifier" && op.Text() == "NULL") {
			return "null", true
		}
		if op.Kind() == "number_literal" && strings.TrimSpace(op.Text()) == "0" {
			return "null", true
		}
		if isNonNullExpr(arg) {
			return "safe", false
		}
		return "null", false
	}
	if isNonNullExpr(arg) {
		return "safe", false
	}
	return "null", false
}

// callerGuardsVar reports whether the caller proves varName non-null at the
// call. Four idioms count: a dominating early-return null check
// (`if (v == NULL) return;`), a positive branch (`if (v != NULL) { f(v); }`),
// a short-circuit conjunction (`v != NULL && f(v)`), and an assert
// precondition (`assert(v != NULL); f(v);`).
func callerGuardsVar(f *db.Function, ifs, assigns, calls []parser.Node, varName string, call parser.Node) bool {
	if callerEarlyReturnGuards(f, ifs, assigns, varName, call) {
		return true
	}
	if callerPositiveBranchGuards(f, ifs, assigns, varName, call) {
		return true
	}
	if callerShortCircuitGuards(varName, call) {
		return true
	}
	return callerAssertGuards(f, assigns, calls, varName, call)
}

// callerEarlyReturnGuards covers a dominating early-return null check
// (`if (v == NULL) return;`). The guard must lexically precede the call (byte
// offset, so a same-line `if (v == NULL) return; f(v);` still counts) and its
// non-null scope must cover the call line.
func callerEarlyReturnGuards(f *db.Function, ifs, assigns []parser.Node, varName string, call parser.Node) bool {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		if ifNode.EndByte() > call.StartByte() {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		if condition == nil {
			continue
		}
		consequence := ifNode.ChildByFieldName("consequence")
		if consequence == nil || !isExitBlock(*consequence) {
			continue
		}
		guarded := false
		for _, gv := range earlyReturnGuardedVars(*condition) {
			if gv == varName {
				guarded = true
				break
			}
		}
		if !guarded {
			continue
		}
		scopeEnd := guardExitBound(*consequence, ifNode, f)
		if end := guardScopeEnd(assigns, f, varName, ifNode.EndLine()); end < scopeEnd {
			scopeEnd = end
		}
		if call.StartLine() <= scopeEnd {
			return true
		}
	}
	return false
}

// callerPositiveBranchGuards covers `if (v != NULL) { ...; f(v); ... }`: a
// call inside the consequence runs only when the condition is TRUE — exactly
// the direction that establishes v non-null. The else branch proves nothing
// (a call there sees v NULL), and a reassignment of v inside the branch
// truncates the fact.
func callerPositiveBranchGuards(f *db.Function, ifs, assigns []parser.Node, varName string, call parser.Node) bool {
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		condition := ifNode.ChildByFieldName("condition")
		consequence := ifNode.ChildByFieldName("consequence")
		if condition == nil || consequence == nil {
			continue
		}
		if call.StartByte() < consequence.StartByte() || call.EndByte() > consequence.EndByte() {
			continue
		}
		guarded := false
		for _, gv := range parser.GuardedNonnullVars(*condition) {
			if gv == varName {
				guarded = true
				break
			}
		}
		if !guarded {
			continue
		}
		if call.StartLine() <= guardScopeEnd(assigns, f, varName, consequence.StartLine()-1) {
			return true
		}
	}
	return false
}

// callerShortCircuitGuards covers `v != NULL && f(v)` and nested conjunctions:
// the right operand of && evaluates only when the left is TRUE, so a call
// inside the right operand of an ancestor && whose left establishes varName
// non-null is guarded. An || ancestor proves nothing about its right side
// (that side runs when the left is FALSE) and is skipped; the call must be
// byte-contained in the right operand so `a && b || f(v)` (where f runs with
// a possibly-false left) does not match the && layer.
func callerShortCircuitGuards(varName string, call parser.Node) bool {
	for node := call.Parent(); node != nil; node = node.Parent() {
		if node.Kind() != "binary_expression" || parser.BinaryOperator(*node) != "&&" {
			continue
		}
		kids := node.NamedChildren()
		if len(kids) < 2 {
			continue
		}
		if call.StartByte() < kids[1].StartByte() || call.EndByte() > kids[1].EndByte() {
			continue
		}
		for _, gv := range parser.GuardedNonnullVars(kids[0]) {
			if gv == varName {
				return true
			}
		}
	}
	return false
}

// callerAssertGuards covers `assert(v != NULL); f(v);`: the assert aborts on
// the false branch, so the variables it establishes non-null hold on the
// fall-through up to a reassignment.
func callerAssertGuards(f *db.Function, assigns, calls []parser.Node, varName string, call parser.Node) bool {
	for _, ac := range calls {
		if !funcLineRange(f, ac.StartLine()) {
			continue
		}
		if ac.EndByte() > call.StartByte() {
			continue
		}
		if calleeName(ac) != "assert" {
			continue
		}
		if p := ac.Parent(); p == nil || p.Kind() != "expression_statement" {
			continue
		}
		args := getCallArgs(ac)
		if len(args) == 0 {
			continue
		}
		for _, gv := range assertGuardedVars(args[0]) {
			if gv == varName && call.StartLine() <= guardScopeEnd(assigns, f, varName, ac.StartLine()) {
				return true
			}
		}
	}
	return false
}
