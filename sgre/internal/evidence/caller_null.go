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

		for _, call := range root.FindAll("call_expression") {
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
				kind, definite := d.classifyArg(arg, caller, ifs, assigns, call)
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
func (d *CallerNullDetector) classifyArg(arg parser.Node, caller *db.Function, ifs, assigns []parser.Node, call parser.Node) (string, bool) {
	switch arg.Kind() {
	case "identifier":
		if arg.Text() == "NULL" {
			return "null", true
		}
		if callerGuardsVar(caller, ifs, assigns, arg.Text(), call) {
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
		if op.Kind() == "identifier" && op.Text() == "NULL" {
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

// callerGuardsVar reports whether the caller proves varName non-null at the call
// via a dominating early-return null check (`if (v == NULL) return;`). The guard
// must lexically precede the call (byte offset, so a same-line
// `if (v == NULL) return; f(v);` still counts) and its non-null scope must cover
// the call line.
func callerGuardsVar(f *db.Function, ifs, assigns []parser.Node, varName string, call parser.Node) bool {
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
