package planner

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// argShapeCounts is the per-(callee, parameter) census of in-tree call-site
// argument shapes. literal counts provably-constant arguments (string/number
// literals, address-of, compound literals — isDefinitelyUnTainted), tainted
// counts direct taint-source expressions (getenv(...), argv[1], ...), and
// variable counts everything else (bare identifiers, complex expressions)
// whose provenance the census does not resolve.
type argShapeCounts struct {
	literal  int
	tainted  int
	variable int
}

func (a *argShapeCounts) sites() int {
	if a == nil {
		return 0
	}
	return a.literal + a.tainted + a.variable
}

// allLiteral reports whether the census PROVES the parameter cannot receive
// non-constant data in-tree: at least one call site binds it, and every one
// binds a compile-time constant.
func (a *argShapeCounts) allLiteral() bool {
	return a != nil && a.literal > 0 && a.tainted == 0 && a.variable == 0
}

// fact renders the compact census for the callsites@ hint token value:
// "3:all-literal" or "5:3-literal,2-var" (only non-zero classes listed, in
// literal/tainted/var order). Empty when no call site binds the parameter.
func (a *argShapeCounts) fact() string {
	if a == nil || a.sites() == 0 {
		return ""
	}
	if a.allLiteral() {
		return fmt.Sprintf("%d:all-literal", a.literal)
	}
	var classes []string
	if a.literal > 0 {
		classes = append(classes, fmt.Sprintf("%d-literal", a.literal))
	}
	if a.tainted > 0 {
		classes = append(classes, fmt.Sprintf("%d-tainted", a.tainted))
	}
	if a.variable > 0 {
		classes = append(classes, fmt.Sprintf("%d-var", a.variable))
	}
	return fmt.Sprintf("%d:%s", a.sites(), strings.Join(classes, ","))
}

// callsiteCensus aggregates the in-tree call sites of every function: per
// (callee, parameter index) the shape of the bound argument, plus the set of
// function names whose address is taken anywhere in the scan (a function
// referenced through a pointer has callers the direct-call census cannot see).
//
// It exists because a non-static function's parameters are conservatively
// treated as attacker-reachable (an external caller may pass anything), which
// kept every "wrapper called only with literals" candidate alive as suspected
// and the AI then confirmed them from the parameter shape alone. The census
// gives both the filter (a provably all-literal parameter can be dropped) and
// the classifier (the callsites@ token names the non-constant callers worth
// inspecting) the caller-side evidence the PARAM_BINDING graph cannot express:
// literal arguments bind no variable_ref edge, so the existing fixpoint is
// silent about them.
type callsiteCensus struct {
	params    map[int64]map[int]*argShapeCounts
	addrTaken map[string]bool
}

// shapes returns the census of one (function, parameter), nil when no in-tree
// call site binds it.
func (cs *callsiteCensus) shapes(funcID int64, paramIdx int) *argShapeCounts {
	if cs == nil {
		return nil
	}
	return cs.params[funcID][paramIdx]
}

// gateDrop reports whether the census proves a non-static function's
// parameter cannot receive attacker-controlled data in-tree: the function is
// never address-taken (every caller is a direct, visible call) and every
// in-tree call site binds a compile-time constant to this parameter. Zero
// call sites does NOT gate — an external TU may still call it — matching the
// scan-tree boundary assumption every reachability filter already makes.
func (cs *callsiteCensus) gateDrop(funcID int64, funcName string, paramIdx int) (*argShapeCounts, bool) {
	if cs == nil || cs.addrTaken[funcName] {
		return nil, false
	}
	shapes := cs.shapes(funcID, paramIdx)
	if !shapes.allLiteral() {
		return nil, false
	}
	return shapes, true
}

// factFor renders the callsites@ token value for one (function, parameter).
func (cs *callsiteCensus) factFor(funcID int64, paramIdx int) string {
	return cs.shapes(funcID, paramIdx).fact()
}

// computeCallsiteSummary walks every function body's call expressions and
// every file's address-of expressions, producing the call-site census. It is
// a single AST pass (no fixpoint): shapes are syntactic, so callee summaries
// cannot change them.
func (f *TaintSourceFilter) computeCallsiteSummary(ctx context.Context) (*callsiteCensus, error) {
	census := &callsiteCensus{
		params:    make(map[int64]map[int]*argShapeCounts),
		addrTaken: make(map[string]bool),
	}
	// Object-like macros that expand to a string literal are compile-time
	// constants: a caller spelled `log_msg(MSG_FMT)` must count as LITERAL, not
	// as a variable. Counting it as `2-var` kept a wrapper whose every caller
	// passes a constant format in front of the classifier, which then confirmed
	// a format-string defect that does not exist. A name defined BOTH ways
	// somewhere in the tree stays non-literal (conservative).
	stringMacro := map[string]bool{}
	nonStringMacro := map[string]bool{}
	isStringMacro := func(name string) bool {
		return stringMacro[name] && !nonStringMacro[name]
	}
	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("callsite census: list functions: %w", err)
	}
	funcByName := make(map[string][]int64, len(funcs))
	for _, fn := range funcs {
		funcByName[fn.Name] = append(funcByName[fn.Name], fn.ID)
	}
	if len(funcByName) == 0 {
		return census, nil
	}

	cache := newFileParseCache(f.parser)
	fileByID := listFilesByID(ctx, f.store)
	// A macro constant is usually defined in a header that holds no function, so
	// the string-macro table must be built from EVERY indexed file, not only the
	// callers' files.
	for _, file := range fileByID {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		fileMacros := parser.CollectStringMacros(root)
		for name := range fileMacros {
			stringMacro[name] = true
		}
		for _, def := range root.FindAll("preproc_def") {
			name := ""
			for _, child := range def.NamedChildren() {
				if child.Kind() == "identifier" && name == "" {
					name = child.Text()
				}
			}
			if name != "" && !fileMacros[name] {
				nonStringMacro[name] = true
			}
		}
	}
	scannedRoot := make(map[int64]bool)
	for _, fn := range funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}

		calls := body.FindAll("call_expression")
		// Local/field string constants: an argument spelled with a variable whose
		// EVERY write in this function is a compile-time string (a literal or a
		// string macro) is a constant too — the census previously classified by
		// argument SYNTAX only, so `const char *fmt = "x"; log_msg(fmt)` counted
		// as a VARIABLE, the all-literal gate never fired, and a wrapper whose
		// callers all pass constants still reached the classifier (production:
		// format-string false positives whose callers pass a local template).
		locals := collectLocalStringConsts(body, isStringMacro)
		for _, call := range calls {
			name := callName(call)
			if name == "" {
				continue
			}
			calleeIDs := funcByName[name]
			if len(calleeIDs) == 0 {
				continue
			}
			for i, arg := range callArgs(call) {
				var kind int // 0 literal, 1 tainted, 2 variable
				switch {
				case isDefinitelyUnTainted(arg):
					kind = 0
				case arg.Kind() == "identifier" && isStringMacro(arg.Text()):
					kind = 0
				case (arg.Kind() == "identifier" || arg.Kind() == "field_expression") &&
					localConstAt(locals, compactIdentText(arg.Text()), call.StartLine(), calls):
					kind = 0
				case isTaintSourceExpr(arg):
					kind = 1
				default:
					kind = 2
				}
				for _, calleeID := range calleeIDs {
					if census.params[calleeID] == nil {
						census.params[calleeID] = make(map[int]*argShapeCounts)
					}
					shapes := census.params[calleeID][i]
					if shapes == nil {
						shapes = &argShapeCounts{}
						census.params[calleeID][i] = shapes
					}
					switch kind {
					case 0:
						shapes.literal++
					case 1:
						shapes.tainted++
					default:
						shapes.variable++
					}
				}
			}
		}

		// Address-taken / decay scan runs once per FILE over the whole tree:
		// any identifier that names a function but is NOT the definition's own
		// declarator and NOT a direct-call callee is a function-pointer
		// reference (`&fn`, `fp = fn`, `register(fn)`, `(cast)fn`) — the
		// function then has callers the direct-call census cannot see, so the
		// all-literal gate must not fire for it. Over-marking (a same-named
		// local/field/parameter) only keeps candidates, never drops them.
		if !scannedRoot[fn.FileID] {
			scannedRoot[fn.FileID] = true
			for _, id := range root.FindAll("identifier") {
				if len(funcByName[id.Text()]) == 0 || isDirectCallee(id) {
					continue
				}
				census.addrTaken[id.Text()] = true
			}
		}
	}
	return census, nil
}

// isDirectCallee reports whether the identifier is the callee of a direct
// call (`fn(args)`) or the function's own definition/declaration declarator
// — the two identifier positions that are NOT function-pointer references.
func isDirectCallee(id parser.Node) bool {
	parent := id.Parent()
	if parent == nil {
		return false
	}
	switch parent.Kind() {
	case "function_declarator":
		return true
	case "call_expression":
		kids := parent.NamedChildren()
		return len(kids) > 0 && kids[0].Kind() == "identifier" &&
			kids[0].StartLine() == id.StartLine() && kids[0].StartColumn() == id.StartColumn()
	}
	return false
}

// sanitizeKills returns the per-line path-taint kills introduced by
// path-sanitizer calls: `base = basename(p)` / `seg = strrchr(p, '/')` assign
// a value that cannot contain a directory component, so the assignment
// target's PATH taint is killed. The kill is deliberately path-traversal-
// only: a sanitized filename still carries format specifiers, so applying it
// to the format-string flow would turn real CWE-134 findings into drops.
func sanitizeKills(body parser.Node) map[int][]string {
	out := make(map[int][]string)
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" || !isPathSanitizeCall(rhs) {
			return
		}
		out[rhs.StartLine()] = append(out[rhs.StartLine()], name)
	})
	return out
}

// isPathSanitizeCall reports whether expr is a call whose result is provably
// directory-free: basename-family (including project-declared
// [sanitize_functions] entries), or strrchr/rindex with a '/' separator (any
// other needle leaves the directory structure intact).
func isPathSanitizeCall(expr parser.Node) bool {
	if expr.Kind() != "call_expression" {
		return false
	}
	name := callName(expr)
	if name == "strrchr" || name == "rindex" {
		args := callArgs(expr)
		return len(args) >= 2 && strings.TrimSpace(args[1].Text()) == "'/'"
	}
	return apikb.IsPathSanitizer(name)
}

// mergeKills returns kill merged with extra without mutating either input.
func mergeKills(kill, extra map[int][]string) map[int][]string {
	if len(extra) == 0 {
		return kill
	}
	out := make(map[int][]string, len(kill)+len(extra))
	for line, vars := range kill {
		out[line] = append([]string(nil), vars...)
	}
	for line, vars := range extra {
		out[line] = append(out[line], vars...)
	}
	return out
}

// expandCallsiteFact renders the compact census fact for evidence text:
// "5:3-literal,2-var" → "5 call sites (3 literal, 2 var)".
func expandCallsiteFact(fact string) string {
	parts := strings.SplitN(fact, ":", 2)
	if len(parts) != 2 {
		return fact
	}
	if parts[1] == "all-literal" {
		return fmt.Sprintf("%s call sites (all literal)", parts[0])
	}
	return fmt.Sprintf("%s call sites (%s)", parts[0], parts[1])
}

// localConst describes a variable (or field chain) in ONE function whose writes
// are all compile-time strings: `literalOnly` is false as soon as any write
// assigns a non-literal, and `lastLiteralLine` is the last write's line.
type localConst struct {
	literalOnly     bool
	lastLiteralLine int
}

// collectLocalStringConsts builds the per-function constant table the call-site
// census consults. isStringMacro reports object-like macros that expand to a
// string literal.
func collectLocalStringConsts(body parser.Node, isStringMacro func(string) bool) map[string]localConst {
	out := make(map[string]localConst)
	record := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		key := compactIdentText(lhs.Text())
		// `const char *fmt = "x"` wraps the target in a pointer_declarator, so the
		// lhs text is `*fmt`; the census argument is spelled `fmt`.
		if lhs.Kind() != "identifier" && lhs.Kind() != "field_expression" {
			if name := declaratorName(lhs); name != "" {
				key = name
			}
		}
		if key == "" {
			return
		}
		cur, seen := out[key]
		if !seen {
			cur = localConst{literalOnly: true}
		}
		if isStringConstText(rhs.Text(), isStringMacro) {
			cur.lastLiteralLine = node.StartLine()
		} else {
			cur.literalOnly = false
		}
		out[key] = cur
	}
	for _, assign := range body.FindAll("assignment_expression") {
		record(assign)
	}
	for _, init := range body.FindAll("init_declarator") {
		record(init)
	}
	return out
}

// localConstAt reports whether the lvalue is a constant at this call site: every
// write in the function assigned a compile-time string, the last one sits before
// the call, and no CALL happens in between (an intervening call could mutate the
// value through an escaped pointer, which this syntactic analysis cannot see).
func localConstAt(locals map[string]localConst, key string, callLine int, calls []parser.Node) bool {
	lc, ok := locals[key]
	if !ok || !lc.literalOnly || lc.lastLiteralLine <= 0 || lc.lastLiteralLine >= callLine {
		return false
	}
	for _, call := range calls {
		line := call.StartLine()
		if line > lc.lastLiteralLine && line < callLine {
			return false
		}
	}
	return true
}

// isStringConstText reports whether an initializer expression is a compile-time
// string: a C string literal (adjacent literals included) or an object-like
// macro that expands to one.
func isStringConstText(text string, isStringMacro func(string) bool) bool {
	t := strings.TrimSpace(text)
	if parser.IsCStringLiteralText(t) {
		return true
	}
	return isStringMacro(compactIdentText(t))
}

// compactIdentText strips whitespace from an lvalue/argument spelling so two
// spellings of one expression compare equal.
func compactIdentText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}
