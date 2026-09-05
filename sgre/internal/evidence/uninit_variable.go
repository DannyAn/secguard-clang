package evidence

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type UninitVariableDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUninitVariableDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UninitVariableDetector {
	return &UninitVariableDetector{store: store, parser: p, logger: logger}
}

func (d *UninitVariableDetector) Name() string { return "uninit_variable" }

func (d *UninitVariableDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	summaries := buildFuncSummaries(ctx, d.store, d.parser, d.logger)
	// Macro write-summaries are collected across the whole scan tree: a macro
	// defined in a .h header (POOL_FOR, LIST_FOR_EACH, ...) and called in a .c
	// source is invisible to the per-file WriteSummaries of the source file, so
	// a macro-initialized iterator would be misreported as uninitialized. The
	// parser cache makes the second pass cheap.
	macroWrites := d.collectMacroWrites(ctx)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		// The three sub-detectors plus BuildCFG used to issue ~21 whole-tree
		// FindAll walks per function when handed the file root (and one
		// full-file walk per function just to locate the function subtree);
		// hoisting every scan here collapses that to a single walk per kind
		// per file. The per-function loops below filter by line range.
		decls := root.FindAll("declaration")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")
		inits := root.FindAll("init_declarator")
		returns := root.FindAll("return_statement")
		unarys := root.FindAll("unary_expression")
		ptrs := root.FindAll("pointer_expression")
		fields := root.FindAll("field_expression")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)

		for _, f := range funcs {
			d.detectStackUninit(ctx, f, file, decls, assigns, calls, returns, inits, ifs, whiles, fors, bodies, summaries, macroWrites, &result)
			d.detectHeapUninit(ctx, f, file, inits, assigns, unarys, ptrs, fields, &result)
			d.detectStructPartialUninit(ctx, f, file, decls, assigns, calls, fields, summaries, macroWrites, &result)
		}
	})
	return result, err
}

// collectMacroWrites merges the per-file macro write-summaries across the whole
// scan tree so a macro defined in one file (a .h header) is visible at call
// sites in every other file.
func (d *UninitVariableDetector) collectMacroWrites(ctx context.Context) map[string]macros.WriteSummary {
	var perFile []map[string]macros.WriteSummary
	if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node) {
		perFile = append(perFile, macros.WriteSummaries(root))
	}); err != nil {
		// A top-level traversal failure leaves the whole whitelist empty, which
		// would misreport every macro-initialized iterator as uninitialized.
		// Degrade (empty whitelist) but record it so the false-positive flood is
		// attributable in the scan log.
		if d.logger != nil {
			d.logger.Warn("collect_macro_writes: top-level traversal failed; macro-based initialization whitelist is incomplete", "error", err)
		}
	}
	return macros.MergeWriteSummaries(perFile...)
}

// varDecl describes one declaration of a local variable for scope-aware uninit
// tracking. C allows the same name in two nested blocks (`int v;` in two
// different `if` bodies); tracking every fact by bare name would let one
// occurrence's output-parameter init line suppress (or, worse, hide) the other's
// genuinely-uninitialized use. varKey scopes each fact to its declaration line.
type varDecl struct {
	name     string
	declLine int
	scopeEnd int
}

// varKey returns a scope-aware key for a variable occurrence: name plus the line
// of the declaration that introduced it. Two `int v` in different blocks get
// different keys, so their init/assign facts no longer collide.
func varKey(name string, declLine int) string {
	return fmt.Sprintf("%s@%d", name, declLine)
}

// enclosingScopeEnd returns the end line of the innermost scope that contains
// node: the enclosing compound_statement, or — for a single-statement
// if/loop/switch body without braces — the enclosing control-flow statement.
// It bounds a declaration's shadowing range for varKey resolution.
func enclosingScopeEnd(node parser.Node) int {
	for n := node.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "compound_statement":
			return n.EndLine()
		case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
			return n.EndLine()
		}
	}
	return node.EndLine()
}

// resolveVarKey maps a bare identifier use at useLine to the varKey of the
// declaration that is in scope there: the latest declaration (innermost shadow)
// whose declLine is before the use and whose scopeEnd covers it. It returns ""
// when no such declaration exists (e.g. a global or a macro-typed identifier).
func resolveVarKey(declsByName map[string][]varDecl, name string, useLine int) string {
	var best int = -1
	for _, d := range declsByName[name] {
		if d.declLine < useLine && d.scopeEnd >= useLine && d.declLine > best {
			best = d.declLine
		}
	}
	if best < 0 {
		return ""
	}
	return varKey(name, best)
}

func (d *UninitVariableDetector) detectStackUninit(ctx context.Context, f *db.Function, file *db.File, decls, assigns, calls, returns, inits, ifs, whiles, fors []parser.Node, bodies map[int]parser.Node, summaries summaryMap, macroWrites map[string]macros.WriteSummary, result *DetectResult) {
	uninitVars := make(map[string]bool)
	assignSites := make(map[string][]int)
	declsByName := make(map[string][]varDecl)
	// outputParamInitLines maps a variable to the line after which it is
	// definitely written via an output parameter (`&x` passed to a writer). A
	// use before that line (e.g. inside a failure branch, TC16) stays reported;
	// a use after it is initialized. This is kept separate from assignSites
	// because hasUnassignedPath only matches assignment/declaration statements,
	// so an output-param call line would otherwise never count as an assign.
	outputParamInitLines := make(map[string]int)

	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		isStatic := false
		hasInit := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "storage_class_specifier" && child.Text() == "static" {
				isStatic = true
			}
			if child.Kind() == "init_declarator" {
				hasInit = true
				// Only the declarator (children[0]) is the assigned variable; the
				// value (children[1]) is a read, e.g. `int b = a;` assigns b and
				// reads a. The previous loop added every identifier (b AND a),
				// which wrongly recorded a as "assigned" and hid a copy-uninit.
				dc := child.NamedChildren()
				if len(dc) >= 1 {
					if name := extractVarName(dc[0]); name != "" {
						assignSites[varKey(name, decl.StartLine())] = append(assignSites[varKey(name, decl.StartLine())], decl.StartLine())
					}
				}
			}
		}
		if hasInit || isStatic {
			continue
		}
		scopeEnd := enclosingScopeEnd(decl)
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" && !parser.IsCTypeKeyword(child.Text()) {
				uninitVars[varKey(child.Text(), decl.StartLine())] = true
				declsByName[child.Text()] = append(declsByName[child.Text()], varDecl{name: child.Text(), declLine: decl.StartLine(), scopeEnd: scopeEnd})
			}
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		// assignmentLHSName recovers the real write target even when a macro
		// call site glues a call_expression as the first named child and buries
		// the LHS in an ERROR node (`LIST_FOR_EACH(x, h)\n q = 1`).
		if name := assignmentLHSName(assign); name != "" {
			if key := resolveVarKey(declsByName, name, assign.StartLine()); key != "" {
				assignSites[key] = append(assignSites[key], assign.StartLine())
			}
		}
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// A function-like macro that writes one of its parameters initializes the
		// argument passed at that position (`#define OUT(x) (x) = ...` → `OUT(v)`).
		// Record the written argument as an output-param init line so a LATER use
		// of that argument is not reported.
		if written := macros.WrittenArgs(call, macroWrites); len(written) > 0 {
			for name := range written {
				if key := resolveVarKey(declsByName, name, call.StartLine()); key != "" {
					if call.StartLine() > outputParamInitLines[key] {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// va_start/va_copy initialize the va_list (an array type that decays to
		// a pointer, so it is passed as an identifier, not `&ap`).
		if callName == "va_start" || callName == "va_copy" {
			if args := getCallArgs(call); len(args) > 0 {
				if name := extractVarName(args[0]); name != "" {
					if key := resolveVarKey(declsByName, name, call.StartLine()); key != "" {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// A copy/init call's first argument is the DESTINATION buffer (written,
		// not read): `strncpy_s(buf, ...)`, `memcpy(dst, ...)`, `sprintf(buf,
		// ...)`. A whole array decays to a pointer, so it is passed as an
		// identifier, not `&buf`; mark it initialized so a LATER read is not
		// reported. (A field destination is handled by detectStructPartialUninit.)
		if isDestWriter(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				if key := resolveVarKey(declsByName, args[0].Text(), call.StartLine()); key != "" {
					outputParamInitLines[key] = call.StartLine()
				}
			}
		}
		// `&whole_var` passed to an output-param writer initializes the variable
		// after the call. Known initializers and local functions that write the
		// parameter on every path initialize unconditionally; a local function
		// that writes only on its success path requires the caller to guard the
		// error return (TC16); unknown/external functions are assumed to write
		// (they have no body to prove otherwise).
		summary, hasSummary := summaries[callName]
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for argIdx, arg := range child.NamedChildren() {
				if arg.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
					continue
				}
				inner := arg.NamedChildren()
				if len(inner) == 0 || inner[0].Kind() != "identifier" {
					continue // only whole-variable &x, not &x.field
				}
				name := inner[0].Text()
				key := resolveVarKey(declsByName, name, call.StartLine())
				if key == "" {
					continue
				}
				initLine := call.StartLine()
				if hasSummary && !isOutputParamInitializer(callName) {
					if summary.ParamWrites[argIdx] {
						initLine = call.StartLine() // writes on every path
					} else if summary.ParamConditionalWrites[argIdx] {
						// Writes only on success. Initialize only past the
						// caller's error guard, if any; otherwise keep it as a
						// potential uninit (conservative, TC16).
						g := outputParamGuardLine(ifs, f, call, callName)
						if g == 0 {
							continue
						}
						initLine = g
					} else {
						// No direct write found: a wrapper that forwards the
						// pointer to another writer (lpGet -> lpGetWithBuf), or a
						// never-writer. Assume the wrapper writes it.
						initLine = call.StartLine()
					}
				}
				if initLine > outputParamInitLines[key] {
					outputParamInitLines[key] = initLine
				}
			}
		}
		// A field passed by address to any function (`getShort(&s.f)`) is an
		// output-param: the callee writes s.f, so the base struct s is being
		// initialized field-by-field. Without this, structs filled through
		// getter/read calls were reported as wholly uninitialized. A whole
		// variable is deliberately NOT treated this way: an output-param may
		// write only on its success path (cf. TC16 init_via_ptr), so `&x` alone
		// does not prove x is initialized on every path.
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				if arg.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
					continue
				}
				inner := arg.NamedChildren()
				if len(inner) == 0 {
					continue
				}
				target := inner[0]
				if target.Kind() == "field_expression" || target.Kind() == "subscript_expression" {
					if base := extractVarName(target); base != "" {
						if key := resolveVarKey(declsByName, base, call.StartLine()); key != "" {
							assignSites[key] = append(assignSites[key], call.StartLine())
						}
					}
				}
			}
		}
	}

	body := bodies[f.StartLine]
	cfg := graph.BuildStmtCFG(body, f.EndLine)
	cfgValid := body.Kind() == "compound_statement"
	if !cfgValid && d.logger != nil {
		d.logger.Debug("uninit: CFG construction degenerate, using conservative fallback",
			"function", f.Name,
		)
	}

	// Loop-carried lazy init: `while (...) { if (g == NULL) { v = ...; g = ...; }
	// ... use(v) ... }`. The guard is true on the first pass (g is null/zero
	// before the loop), so v is written before every in-loop use. Record it so a
	// use after the guard block, still inside the loop, is treated as
	// initialized.
	loopInit := make(map[string]loopCarriedInit)
	for _, loop := range append(append([]parser.Node{}, whiles...), fors...) {
		if !funcLineRange(f, loop.StartLine()) {
			continue
		}
		body := loop.ChildByFieldName("body")
		if body == nil {
			continue
		}
		guardIf := firstIfInLoopBody(*body)
		if guardIf == nil || guardIf.ChildByFieldName("alternative") != nil {
			continue
		}
		g := nullZeroGuardVar(guardIf.ChildByFieldName("condition"))
		if g == "" || !nullZeroInitializedBefore(g, loop.StartLine(), decls, assigns) {
			continue
		}
		cons := guardIf.ChildByFieldName("consequence")
		if cons == nil {
			continue
		}
		for name := range straightLinePrefixAssignedVars(*cons) {
			key := resolveVarKey(declsByName, name, cons.StartLine())
			if key == "" || !uninitVars[key] {
				continue
			}
			loopInit[key] = loopCarriedInit{blockEnd: cons.EndLine(), loopEnd: loop.EndLine()}
		}
	}

	checkUse := func(useLine int, name string) {
		if parser.IsCTypeKeyword(name) {
			return
		}
		key := resolveVarKey(declsByName, name, useLine)
		if key == "" || !uninitVars[key] {
			return
		}
		declLine := declLineFromKey(key)
		// Output-param initialization: a use after the (possibly guard-delayed)
		// write-through point is initialized. A use before it — e.g. inside the
		// failure branch of a conditional writer (TC16) — stays reported.
		if initLine, ok := outputParamInitLines[key]; ok && useLine > initLine {
			return
		}
		// Loop-carried lazy init: a use after the guard block, within the same
		// loop, reads a value written on the first iteration.
		if li, ok := loopInit[key]; ok && useLine > li.blockEnd && useLine <= li.loopEnd {
			return
		}
		sites := assignSites[key]
		if len(sites) == 0 {
			d.insertValueUseEvent(ctx, f, file, useLine, declLine, name, "stack_uninit", result)
			return
		}
		if cfgValid && hasUnassignedPath(cfg, name, useLine, sites) {
			d.insertValueUseEvent(ctx, f, file, useLine, declLine, name, "stack_uninit", result)
			return
		}
		if !cfgValid {
			allInIf := true
			for _, s := range sites {
				if !isInIfRange(ifs, f, s) {
					allInIf = false
					break
				}
			}
			if allInIf {
				d.insertValueUseEvent(ctx, f, file, useLine, declLine, name, "stack_uninit", result)
			}
		}
	}

	// scanUses reports uses of uninitialized variables among the identifiers
	// within node at the given line. Identifiers that are the operand of an
	// address-of (`&x`) are write targets, not reads, so they are skipped;
	// skipName (e.g. the callee of a call) is also excluded. A struct VALUE's
	// base (`s` in `s.f`) is a field access handled by struct-partial-uninit,
	// not a scalar read, so it is skipped too.
	scanUses := func(node parser.Node, line int, skipName string, extraSkip map[string]bool) {
		addressed := addressedArgs(node)
		// An assignment embedded in a condition (`while ((c = *str++))`) WRITES its
		// LHS before the condition is evaluated, so the LHS identifier is not a
		// read of an uninitialized value. Skip every assignment write target
		// (chained assignments included), matching the assignment-RHS scan.
		writes := nestedAssignTargets(node)
		for _, id := range node.FindAll("identifier") {
			name := id.Text()
			if name == skipName || addressed[name] || writes[name] || extraSkip[name] || isValueFieldBase(id) || isInsideTypeExpr(id) {
				continue
			}
			checkUse(line, name)
		}
	}

	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		scanUses(ret, ret.StartLine(), "", nil)
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		extra := macros.WrittenArgs(call, macroWrites)
		// va_start/va_copy's first argument is the va_list they INITIALIZE, not a
		// read of its current value. Without skipping it, the va_start line
		// reports the (just-declared, still-uninitialized) va_list as a
		// use-before-init false positive — the write target is misread as a use.
		if callName == "va_start" || callName == "va_copy" {
			if args := getCallArgs(call); len(args) > 0 {
				if name := extractVarName(args[0]); name != "" {
					if extra == nil {
						extra = map[string]bool{}
					}
					extra[name] = true
				}
			}
		}
		// A copy/init call's destination is written, not read: skip it so the
		// call line does not report the just-declared buffer as use-before-init.
		if isDestWriter(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				if extra == nil {
					extra = map[string]bool{}
				}
				extra[args[0].Text()] = true
			}
		}
		// A field-setter macro's argument is the base of a MEMBER write
		// (`SET_FIELD(x, 0)` → (x).field = 0), not a whole-value read; the member
		// itself is handled by the struct-partial path. Skip the base so the call
		// line does not report x as a scalar use-before-init.
		for name := range macros.WrittenFieldArgs(call, macroWrites) {
			if extra == nil {
				extra = map[string]bool{}
			}
			extra[name] = true
		}
		scanUses(call, call.StartLine(), callName, extra)
	}

	// A read in an assignment/initializer RHS also uses the variable
	// (`int b = a;` reads uninitialized a). The LHS is a write target, so only
	// the RHS is scanned. This closes the copy-uninit gap (a used to initialize
	// b was previously never reported).
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		// assignmentRHSStart accounts for the macro call-site mangling that
		// shifts the RHS from children[1] to children[2] (`total += q` →
		// assignment_expression[call_expression, ERROR(total), identifier(q)]).
		rhsStart := assignmentRHSStart(assign)
		if len(children) <= rhsStart {
			continue
		}
		// A chained assignment `a = b = c = v` puts b and c in the RHS as WRITE
		// targets, not reads; only v (the value) is read. Skip nested LHS so
		// `code = first = index = 0` does not report first/index as read.
		writes := nestedAssignTargets(children[rhsStart])
		addressed := addressedArgs(children[rhsStart])
		for _, id := range children[rhsStart].FindAll("identifier") {
			name := id.Text()
			if addressed[name] || writes[name] || isValueFieldBase(id) || isInsideTypeExpr(id) {
				continue
			}
			checkUse(assign.StartLine(), name)
		}
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		children := init.NamedChildren()
		if len(children) < 2 {
			continue
		}
		scanUses(children[1], init.StartLine(), "", nil)
	}

	// Scan only the *condition* of a branch/loop, not the whole subtree. The
	// previous version scanned the entire if/while/for node, which pulled every
	// identifier in the body (including the variables being assigned there) up
	// to the statement's start line — so a variable assigned at the top of a
	// loop body looked "used before init" at the loop's opening line.
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		if cond := ifNode.ChildByFieldName("condition"); cond != nil {
			scanUses(*cond, cond.StartLine(), "", nil)
		}
	}

	for _, whileNode := range whiles {
		if !funcLineRange(f, whileNode.StartLine()) {
			continue
		}
		if cond := whileNode.ChildByFieldName("condition"); cond != nil {
			scanUses(*cond, cond.StartLine(), "", nil)
		}
	}

	for _, forNode := range fors {
		if !funcLineRange(f, forNode.StartLine()) {
			continue
		}
		cond := forNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		// The for-initializer runs exactly once before the condition, so a
		// variable assigned there (`for (i=0; i<n; i++)`) is definitely
		// initialized before the condition reads it — even though both the
		// initializer and condition sit on the same source line. Without this,
		// `i` was reported as use-before-init at the for-loop's opening line.
		initWrites := forInitWrites(forNode)
		addressed := addressedArgs(*cond)
		// An assignment inside the condition (`for (; (x = next()); )`) writes its
		// LHS, so the LHS identifier is not a read of an uninitialized value.
		condWrites := nestedAssignTargets(*cond)
		for _, id := range cond.FindAll("identifier") {
			if initWrites[id.Text()] || addressed[id.Text()] || condWrites[id.Text()] || isInsideTypeExpr(id) {
				continue
			}
			checkUse(cond.StartLine(), id.Text())
		}
	}
}

// forInitWrites returns the set of variable names assigned in a for-loop's
// initializer clause (`for (i=0; ...)`, `for (i=0,j=0; ...)`,
// `for (int i=0; ...)`). These are write targets that precede the condition.
func forInitWrites(forNode parser.Node) map[string]bool {
	writes := make(map[string]bool)
	init := forNode.ChildByFieldName("initializer")
	if init == nil {
		return writes
	}
	for _, assign := range init.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			writes[children[0].Text()] = true
		}
	}
	for _, decl := range init.FindAll("init_declarator") {
		children := decl.NamedChildren()
		if len(children) >= 1 {
			if name := extractVarName(children[0]); name != "" {
				writes[name] = true
			}
		}
	}
	return writes
}

// assignmentLHSName returns the write-target identifier of an assignment_expression,
// recovering the real LHS from an ERROR child when a macro call site glues a
// call_expression as the first named child. For a clean `a = b` it is "a"; for
// `LIST_FOR_EACH(x, h)\n q = 1` (parsed as
// assignment_expression[call_expression, ERROR(q), number_literal]) it recovers
// "q" from the ERROR child.
func assignmentLHSName(assign parser.Node) string {
	children := assign.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	if children[0].Kind() == "identifier" {
		return children[0].Text()
	}
	if len(children) >= 2 && children[0].Kind() == "call_expression" && children[1].Kind() == "ERROR" {
		return firstIdentifier(children[1])
	}
	return ""
}

// assignmentRHSStart returns the index into an assignment_expression's
// NamedChildren() where the RHS (the value) begins: 1 for a clean `a = b`, 2 for
// the macro call-site mangling `total += q` →
// assignment_expression[call_expression, ERROR(total), identifier(q)].
func assignmentRHSStart(assign parser.Node) int {
	children := assign.NamedChildren()
	if len(children) >= 3 && children[0].Kind() == "call_expression" && children[1].Kind() == "ERROR" {
		return 2
	}
	return 1
}

// hasUnassignedPath reports whether there is a control-flow path from the
// function entry to the use that avoids every assignment to varName before the
// use — i.e. the variable may be read uninitialized. It uses the statement-level
// CFG (BuildStmtCFG), replacing the old scope-tree approximation (BuildCFGFromLists).
//
// The avoid set is built from the CFG nodes whose statement ACTUALLY assigns
// varName (not cfg.NodeAt(line), which resolves to the enclosing control-flow
// header when several statements share a line, e.g. `while (c) { x = n; n--; }`).
func hasUnassignedPath(cfg *graph.StmtCFG, varName string, useLine int, assignLines []int) bool {
	if cfg == nil {
		return false
	}
	useNode := cfg.NodeAt(useLine)
	if useNode == nil {
		return false // cannot locate the use; conservative (no report here)
	}
	avoid := make(map[int]bool)
	for _, a := range assignLines {
		if a >= useLine {
			continue
		}
		for _, n := range cfg.Nodes {
			if n.Kind != "stmt" || n.StartLine != a {
				continue
			}
			if assignsVar(n.Stmt, varName) {
				avoid[n.ID] = true
			}
		}
	}
	return cfg.ReachesAvoiding(cfg.Entry, avoid, useNode.ID)
}

// assignsVar reports whether stmt directly assigns varName, covering every
// target of a chained assignment (`code = first = index = 0`), a plain
// assignment_expression (a for-init `i=0`), and a declaration initializer
// (`int x = ...`). A control-flow header that merely contains the line is not a
// match.
func assignsVar(stmt parser.Node, varName string) bool {
	var assigns []parser.Node
	switch stmt.Kind() {
	case "assignment_expression":
		assigns = []parser.Node{stmt}
	case "expression_statement":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() == "assignment_expression" {
				assigns = append(assigns, child)
			}
		}
	case "declaration":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			c := child.NamedChildren()
			if len(c) >= 1 && extractVarName(c[0]) == varName {
				return true
			}
		}
		return false
	case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
		// `if ((x = f()) == -1)` / `while ((x = next()) != NULL)` assigns x every
		// time the condition is evaluated, so the control-flow header counts as an
		// assign site for x on all paths reaching it.
		if cond := stmt.ChildByFieldName("condition"); cond != nil {
			for _, a := range cond.FindAll("assignment_expression") {
				for _, name := range chainedWriteTargets(a) {
					if name == varName {
						return true
					}
				}
			}
		}
		if init := stmt.ChildByFieldName("initializer"); init != nil {
			for _, a := range init.FindAll("assignment_expression") {
				for _, name := range chainedWriteTargets(a) {
					if name == varName {
						return true
					}
				}
			}
		}
		return false
	default:
		return false
	}
	for _, a := range assigns {
		for _, name := range chainedWriteTargets(a) {
			if name == varName {
				return true
			}
		}
	}
	return false
}

// loopCarriedInit records a variable that is initialized on the first loop
// iteration and retains that value on every later iteration: the classic
// `while (...) { if (g == NULL) { v = ...; g = ...; } ... use(v) ... }`
// lazy-init idiom. The guard `g == NULL` is guaranteed TRUE on the first pass
// (g is null/zero-initialized immediately before the loop), so v is written
// before any use inside the loop. A naive CFG reachability sees the guard's
// false edge — only reachable via the back edge, i.e. after v was already
// written — and wrongly reports v as possibly uninitialized.
type loopCarriedInit struct {
	blockEnd int // end line of the guard if-block (v is written before this)
	loopEnd  int // end line of the enclosing loop (scopes the suppression)
}

// firstIfInLoopBody returns the first statement of a loop body when it is an
// `if` guard (the lazy-init guard shape), or nil. A leading declaration or other
// statement disqualifies the pattern conservatively.
func firstIfInLoopBody(body parser.Node) *parser.Node {
	if body.Kind() == "if_statement" {
		return &body
	}
	if body.Kind() != "compound_statement" {
		return nil
	}
	for _, child := range body.NamedChildren() {
		if child.Kind() == "if_statement" {
			return &child
		}
		return nil
	}
	return nil
}

// nullZeroGuardVar returns the variable name g when cond is a positive
// "g is null/zero/false" test (`g == NULL`, `NULL == g`, `!g`, `g == 0`), the
// guard shape that is TRUE on the first pass when g is null/zero before the
// loop. It returns "" for any other condition (a bare `if (g)` truthiness guard
// is deliberately NOT matched: it does not prove g is the pre-loop sentinel).
func nullZeroGuardVar(cond *parser.Node) string {
	if cond == nil {
		return ""
	}
	t := strings.TrimSpace(cond.Text())
	t = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(t), "("), ")"))
	var g string
	switch {
	case strings.HasSuffix(t, "== NULL"):
		g = strings.TrimSpace(strings.TrimSuffix(t, "== NULL"))
	case strings.HasPrefix(t, "NULL =="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "NULL =="))
	case strings.HasSuffix(t, "== 0"):
		g = strings.TrimSpace(strings.TrimSuffix(t, "== 0"))
	case strings.HasPrefix(t, "0 =="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "0 =="))
	case strings.HasPrefix(t, "!") && !strings.HasPrefix(t, "!="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "!"))
	default:
		return ""
	}
	if g == "" || strings.ContainsAny(g, " ()[]+-*/%&|^!<>=?.,;:\"'\t\n") {
		return ""
	}
	return g
}

// isNullZeroExpr reports whether node is a literal null/zero sentinel.
func isNullZeroExpr(node parser.Node) bool {
	t := strings.TrimSpace(strings.Trim(node.Text(), "() \t"))
	return t == "NULL" || t == "0" || t == "0x0" || t == "false" || t == "FALSE"
}

// nullZeroInitializedBefore reports whether g's last write before loopStart is
// a null/zero sentinel, so the lazy-init guard `g == NULL` / `!g` is TRUE when
// the loop is first entered.
func nullZeroInitializedBefore(g string, loopStart int, decls, assigns []parser.Node) bool {
	lastNull := -1
	lastWrite := -1
	for _, decl := range decls {
		if decl.StartLine() >= loopStart {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			c := child.NamedChildren()
			if len(c) < 2 || extractVarName(c[0]) != g {
				continue
			}
			if isNullZeroExpr(c[1]) {
				if decl.StartLine() > lastNull {
					lastNull = decl.StartLine()
				}
			} else if decl.StartLine() > lastWrite {
				lastWrite = decl.StartLine()
			}
		}
	}
	for _, assign := range assigns {
		if assign.StartLine() >= loopStart {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" || children[0].Text() != g {
			continue
		}
		if isNullZeroExpr(children[1]) {
			if assign.StartLine() > lastNull {
				lastNull = assign.StartLine()
			}
		} else if assign.StartLine() > lastWrite {
			lastWrite = assign.StartLine()
		}
	}
	return lastNull >= 0 && lastNull > lastWrite
}

// straightLinePrefixAssignedVars returns the variable names assigned by the
// straight-line prefix of block: every statement up to (but not including) the
// first nested conditional. Those writes are unconditional whenever the block
// is entered, which is the safe subset for loop-carried initialization.
func straightLinePrefixAssignedVars(block parser.Node) map[string]bool {
	vars := make(map[string]bool)
	collect := func(node parser.Node) {
		for _, assign := range node.FindAll("assignment_expression") {
			if name := assignmentLHSName(assign); name != "" {
				vars[name] = true
			}
		}
		for _, decl := range node.FindAll("init_declarator") {
			c := decl.NamedChildren()
			if len(c) >= 1 {
				if name := extractVarName(c[0]); name != "" {
					vars[name] = true
				}
			}
		}
	}
	if block.Kind() != "compound_statement" {
		collect(block)
		return vars
	}
	for _, child := range block.NamedChildren() {
		switch child.Kind() {
		case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
			return vars
		}
		collect(child)
	}
	return vars
}

func isInIfRange(ifs []parser.Node, f *db.Function, line int) bool {
	for _, ifNode := range ifs {
		if ifNode.StartLine() >= f.StartLine && ifNode.StartLine() <= f.EndLine {
			if line >= ifNode.StartLine() && line <= ifNode.EndLine() {
				return true
			}
		}
	}
	return false
}

func (d *UninitVariableDetector) detectHeapUninit(ctx context.Context, f *db.Function, file *db.File, inits, assigns, unarys, ptrs, fields []parser.Node, result *DetectResult) {
	mallocVars := make(map[string]int) // varName -> line of the malloc assignment

	checkInit := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs := children[0]
		rhs := children[1]
		varName := extractVarName(lhs)
		if varName == "" {
			return
		}
		callExpr := rhs
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					callExpr = child
					break
				}
			}
		}
		if callExpr.Kind() == "call_expression" {
			callName := extractCallName(callExpr)
			if callName == "malloc" || callName == "realloc" {
				mallocVars[varName] = node.StartLine()
			}
		}
	}

	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkInit(init)
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkInit(assign)
	}

	// A whole-var reassignment after the malloc (p = &x, p = other) redirects p
	// away from the allocated memory, so p is no longer an "uninitialized heap
	// block". A re-malloc (p = malloc(...) again) keeps it allocated.
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		if lhs.Kind() != "identifier" {
			continue
		}
		name := lhs.Text()
		mallocLine, isMalloc := mallocVars[name]
		if !isMalloc || assign.StartLine() <= mallocLine {
			continue
		}
		rhs := children[1]
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					rhs = child
					break
				}
			}
		}
		if rhs.Kind() == "call_expression" {
			if n := extractCallName(rhs); n == "malloc" || n == "calloc" || n == "realloc" {
				mallocVars[name] = assign.StartLine()
				continue
			}
		}
		delete(mallocVars, name)
	}

	writtenThroughPtr := make(map[string]bool)
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		text := assign.Text()
		for varName := range mallocVars {
			if strings.Contains(text, varName+"->") || strings.Contains(text, "*"+varName) {
				writtenThroughPtr[varName] = true
			}
		}
	}

	for _, unary := range unarys {
		if !funcLineRange(f, unary.StartLine()) {
			continue
		}
		if isInsideTypeExpr(unary) {
			continue
		}
		text := unary.Text()
		if !strings.HasPrefix(text, "*") {
			continue
		}
		varName := strings.TrimSpace(text[1:])
		if isHeapVar(mallocVars, varName) && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, unary.StartLine(), mallocVars[varName], varName, "heap_uninit", result)
		}
	}

	for _, ptr := range ptrs {
		if !funcLineRange(f, ptr.StartLine()) {
			continue
		}
		if isInsideTypeExpr(ptr) {
			continue
		}
		children := ptr.NamedChildren()
		if len(children) == 0 {
			continue
		}
		varName := children[0].Text()
		if isHeapVar(mallocVars, varName) && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, ptr.StartLine(), mallocVars[varName], varName, "heap_uninit", result)
		}
	}

	for _, field := range fields {
		if !funcLineRange(f, field.StartLine()) {
			continue
		}
		if isInsideTypeExpr(field) {
			continue
		}
		children := field.NamedChildren()
		if len(children) == 0 {
			continue
		}
		varName := children[0].Text()
		if isHeapVar(mallocVars, varName) && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), mallocVars[varName], varName, "heap_uninit", result)
		}
	}
}

func (d *UninitVariableDetector) detectStructPartialUninit(ctx context.Context, f *db.Function, file *db.File, decls, assigns, calls, fields []parser.Node, summaries summaryMap, macroWrites map[string]macros.WriteSummary, result *DetectResult) {
	structVars := make(map[string]int)
	initializedFields := make(map[string]bool)
	// A struct passed by address to a KNOWN initializer (memset(&s, 0, ...),
	// or an output-param filler) — or to a local function that writes the
	// pointer parameter on every path — has its fields written by the callee,
	// so it is not a definite partial-init defect. An arbitrary `&s` to an
	// unknown/conditional function is conservatively kept (cf. TC16).
	initializedVars := outputParamInitializedVars(calls, f, summaries)

	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		hasInit := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "init_declarator" {
				hasInit = true
			}
		}
		if hasInit {
			continue
		}
		for _, child := range decl.NamedChildren() {

			if child.Kind() == "identifier" && !parser.IsCTypeKeyword(child.Text()) {
				structVars[child.Text()] = decl.StartLine()
			}
		}
	}

	// A struct assigned as a whole (`s = other`) is fully initialized, so none
	// of its fields can be a partial-init defect.
	wholeAssigned := make(map[string]bool)
	// writePaths are field/subscript paths that are a write target or the base
	// of one. Reading such a path is part of the write, not a use of an
	// uninitialized member: in `s.a.b = s.a.c = 0`, the base `s.a` is addressed
	// to write b/c, not read.
	writePaths := make(map[string]bool)

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 1 {
			continue
		}
		lhs := children[0]
		if lhs.Kind() == "identifier" {
			if _, isStruct := structVars[lhs.Text()]; isStruct {
				wholeAssigned[lhs.Text()] = true
			}
			continue
		}
		// A field/subscript write (`s.f = ...`, `s.f[i] = ...`) initializes that
		// member. Normalize the member path so `s.f[i]` and `s.f` map to the
		// same key — the previous version keyed by the full assignment text,
		// which never matched the field-read text.
		if lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression" {
			initializedFields[fieldPath(lhs)] = true
			for _, p := range fieldWritePaths(lhs) {
				writePaths[p] = true
			}
		}
	}

	// A field passed by address to a function (`getShort(&s.f)`) is written by
	// the callee (output-param), so it counts as initialized. This is the common
	// "fill a struct field-by-field through getter/read calls" idiom.
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				if arg.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
					continue
				}
				inner := arg.NamedChildren()
				if len(inner) == 0 {
					continue
				}
				target := inner[0]
				if target.Kind() == "field_expression" || target.Kind() == "subscript_expression" {
					initializedFields[fieldPath(target)] = true
				}
			}
		}
	}

	// A field/subscript passed as the raw destination of a copy/init call
	// (`strncpy_s(msg.pool_name, ...)`) is written by the callee. The array
	// decays to a pointer with no `&`, so the `&s.f` output-param loop above
	// misses it; mark the field path initialized so a struct filled through
	// strncpy_s/memcpy/sprintf is not reported as partial-init.
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if !isDestWriter(extractCallName(call)) {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		if args[0].Kind() == "field_expression" || args[0].Kind() == "subscript_expression" {
			initializedFields[fieldPath(args[0])] = true
		}
	}

	// A function-like macro that writes a whole argument (`ZERO(x)` → memset(&x))
	// or a member of it (`SET_FIELD(x, 0)` → (x).field = 0) initializes the
	// corresponding struct / field. Macro writes were only applied to the scalar
	// path before; mirror them here so a struct filled through an initializer or
	// field-setter macro is not reported partial-init.
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		for name := range macros.WrittenArgs(call, macroWrites) {
			initializedVars[name] = true
		}
		for name, suffix := range macros.WrittenFieldArgs(call, macroWrites) {
			initializedFields[name+suffix] = true
		}
	}

	for _, field := range fields {
		if !funcLineRange(f, field.StartLine()) {
			continue
		}
		children := field.NamedChildren()
		if len(children) == 0 {
			continue
		}
		varName := children[0].Text()
		if _, isStruct := structVars[varName]; !isStruct {
			continue
		}
		if initializedVars[varName] {
			continue
		}
		if wholeAssigned[varName] {
			continue
		}
		// A path that is a write target (or its base) is not a read.
		if writePaths[fieldPath(field)] {
			continue
		}
		if !initializedFields[fieldPath(field)] {
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), structVars[varName], varName, "struct_partial_uninit", result)
		}
	}
}

// isHeapVar reports whether name is currently tracked as a malloc'd variable.
func isHeapVar(m map[string]int, name string) bool {
	_, ok := m[name]
	return ok
}

// fieldPath returns the canonical member path of a field or subscript access:
// `s.f` and `s.f[i]` both normalize to `s.f`. This makes field-read and
// subscript-write detection agree when an array member is written element-wise
// (`s.arr[i] = ...`) but read as a whole (`use(s.arr)`).
func fieldPath(node parser.Node) string {
	switch node.Kind() {
	case "subscript_expression":
		children := node.NamedChildren()
		if len(children) > 0 {
			return fieldPath(children[0])
		}
	case "field_expression":
		return node.Text()
	}
	return node.Text()
}

// fieldWritePaths returns the field/subscript paths that a write to lhs
// touches: the target itself plus every field base it is nested under. Writing
// `s.a.b` addresses (and thus "uses", but only as a write target) both `s.a.b`
// and its base `s.a`, so neither is a read of an uninitialized member.
func fieldWritePaths(lhs parser.Node) []string {
	var paths []string
	cur := lhs
	for {
		switch cur.Kind() {
		case "field_expression", "subscript_expression":
			paths = append(paths, fieldPath(cur))
			children := cur.NamedChildren()
			if len(children) == 0 {
				return paths
			}
			cur = children[0]
		default:
			return paths
		}
	}
}

func (d *UninitVariableDetector) insertValueUseEvent(ctx context.Context, f *db.Function, file *db.File, line, declLine int, varName, origin string, result *DetectResult) {
	props := map[string]any{
		"variable": varName,
		"origin":   origin,
	}
	if declLine > 0 {
		props["decl_line"] = declLine
	}
	if emitEvent(ctx, d.store, d.logger, "VALUE_USE", f.ID, &db.Location{FileID: file.ID, Line: line}, props) {
		result.EventsCreated++
	}
}

// declLineFromKey recovers the declaration line embedded in a scope-aware varKey
// ("name@declLine"), so the classifier's evidence can carry the declaration
// anchor for uninit candidates whose Code Context window cannot reach it.
func declLineFromKey(key string) int {
	if i := strings.LastIndex(key, "@"); i >= 0 && i+1 < len(key) {
		if n, err := strconv.Atoi(key[i+1:]); err == nil {
			return n
		}
	}
	return 0
}

var outputParamInitializers = map[string]bool{
	"pthread_create":        true,
	"DES_set_key_unchecked": true,
	"DES_set_key_checked":   true,
	"pthread_mutex_init":    true,
	"pthread_cond_init":     true,
	"pthread_rwlock_init":   true,
	"sem_init":              true,
	"regcomp":               true,
	"regexec":               true,
	"OpenProcessToken":      true,
	"GetTokenInformation":   true,
	"RegCreateKeyExA":       true,
	"RegCreateKeyExW":       true,
	"RegOpenKeyExA":         true,
	"RegOpenKeyExW":         true,
	"GetTempPathA":          true,
	"GetTempPathW":          true,
	"GetTempFileNameA":      true,
	"GetTempFileNameW":      true,
	"stat":                  true,
	"fstat":                 true,
	"lstat":                 true,
	"gettimeofday":          true,
	"clock_gettime":         true,
	"strtol":                true,
	"strtoul":               true,
	"wcstombs":              true,
	"memset":                true,
	"memset_s":              true,
	"bzero":                 true,
	"CreateProcessA":        true,
	"CreateProcessW":        true,
	"CreateProcessAsA":      true,
	"CreateProcessAsW":      true,
}

func isOutputParamInitializer(name string) bool {
	return outputParamInitializers[name]
}

// destWriters lists string/memory copy and init functions whose FIRST argument
// is the destination buffer — written by the callee, never read. A destination
// array/field decays to a raw pointer (`strncpy_s(msg.name, ...)`, `memcpy(dst,
// ...)`), so it is passed WITHOUT `&` and the `&x` output-param path never sees
// it. Marking arg 0 as a write (not a read) stops a struct/array filled through
// these calls from being reported as uninitialized.
var destWriters = map[string]bool{
	"memset":      true,
	"memset_s":    true,
	"bzero":       true,
	"strcpy":      true,
	"strcpy_s":    true,
	"strncpy":     true,
	"strncpy_s":   true,
	"memcpy":      true,
	"memcpy_s":    true,
	"memmove":     true,
	"memmove_s":   true,
	"sprintf":     true,
	"sprintf_s":   true,
	"snprintf":    true,
	"snprintf_s":  true,
	"vsprintf":    true,
	"vsprintf_s":  true,
	"vsnprintf":   true,
	"vsnprintf_s": true,
}

func isDestWriter(name string) bool {
	return destWriters[name]
}

// outputParamGuardLine reports the line after which a conditional output
// parameter is definitely written, given the caller guards the call's error
// return with an exit (`if (fn(&x) != OK) return;` / `rc = fn(&x); if (rc) return;`).
// It returns 0 when no such guard is found, so the caller keeps the variable as
// a potential uninit (conservative, TC16).
func outputParamGuardLine(ifs []parser.Node, f *db.Function, call parser.Node, callName string) int {
	callLine := call.StartLine()
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		// The guard is the error check on this call and may sit any number of
		// statements AFTER the call (`rc = fn(&x); ...; if (rc != 0) return;`).
		// There is deliberately NO fixed line window: a guard 3+ lines below the
		// call was previously missed and the output was misreported as uninit.
		if ifNode.StartLine() < callLine {
			continue
		}
		cons := ifNode.ChildByFieldName("consequence")
		cond := ifNode.ChildByFieldName("condition")
		// Form A: the call IS the guard's condition (`if (fn(...) != 0)`) — the
		// call and the if share a line. Form B: `rc = fn(...); if (rc != 0)` —
		// the call result is captured in an assignment whose left-hand variable
		// is then tested by a LATER guard's condition. The condition must
		// reference that exact variable (matched as an identifier, not a
		// substring, so `rc` does not match `rc2`); an unrelated guard
		// (`if (other) return`) does not establish the output.
		formA := cond != nil && ifNode.StartLine() == callLine && strings.Contains(cond.Text(), callName)
		formB := false
		if ifNode.StartLine() > callLine {
			if parent := call.Parent(); parent != nil && cond != nil &&
				(parent.Kind() == "assignment_expression" || parent.Kind() == "init_declarator") {
				if lhs := parent.NamedChildren(); len(lhs) > 0 {
					if v := strings.TrimSpace(lhs[0].Text()); v != "" {
						for _, id := range cond.FindAll("identifier") {
							if id.Text() == v {
								formB = true
								break
							}
						}
					}
				}
			}
		}
		if !formA && !formB {
			continue
		}
		// Error-exit guard (`if (FAIL) return;`): the output is written on the
		// fall-through, so init starts after the if.
		if cons != nil && isExitStmt(*cons) {
			return ifNode.EndLine()
		}
		// Success-block guard (`if (OK) { use }`): the output is written inside
		// the block, so init starts at the if's opening line.
		return ifNode.StartLine() - 1
	}
	return 0
}

// isExitStmt reports whether a statement (or a compound block) terminates its
// path via return/break/continue/goto — the shape of an error guard whose
// fall-through is the success continuation.
func isExitStmt(node parser.Node) bool {
	switch node.Kind() {
	case "return_statement", "break_statement", "continue_statement", "goto_statement":
		return true
	case "compound_statement":
		for _, c := range node.NamedChildren() {
			if isExitStmt(c) {
				return true
			}
		}
	}
	return false
}

// addressedArgs returns the set of variable names whose address is taken
// (`&x`) within node. Address-of parses as a pointer_expression (the same node
// as a `*p` dereference); only `&`-prefixed nodes count. A `&x` argument is a
// write target for the callee, not a read of x's current value, so it must
// never be treated as a use-before-init.
func addressedArgs(node parser.Node) map[string]bool {
	addressed := make(map[string]bool)
	for _, ptr := range node.FindAll("pointer_expression") {
		if !strings.HasPrefix(strings.TrimSpace(ptr.Text()), "&") {
			continue
		}
		if name := extractVarName(ptr); name != "" {
			addressed[name] = true
		}
	}
	return addressed
}

// nestedAssignTargets returns the identifier names that are assignment LHS
// within node (including node itself when it is an assignment). These are write
// targets, not reads: in `a = b = c = v` the RHS `b = c = v` writes b and c, so
// scanning the RHS must not report b/c as use-before-init.
func nestedAssignTargets(node parser.Node) map[string]bool {
	targets := make(map[string]bool)
	for _, assign := range node.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			targets[children[0].Text()] = true
		}
	}
	return targets
}

// isValueFieldBase reports whether id is the base of a DOT field access on a
// struct VALUE (`s` in `s.f`), as opposed to a pointer dereference (`p` in
// `p->f`). Reading `s.f` addresses s to reach a member, which is a partial-init
// concern (handled separately), not a scalar use-before-init of s itself — while
// `p->f` dereferences the pointer p, so an uninitialized p IS a real use.
func isValueFieldBase(id parser.Node) bool {
	p := id.Parent()
	if p == nil || p.Kind() != "field_expression" {
		return false
	}
	children := p.NamedChildren()
	if len(children) == 0 || children[0].Kind() != "identifier" || children[0].Text() != id.Text() {
		return false
	}
	// Arrow access (`p->f`) keeps the base as a pointer read; dot access
	// (`s.f`) treats the base as a struct value.
	return !strings.Contains(p.Text(), "->")
}

// outputParamInitializedVars returns the set of variable names within f whose
// address is passed (`&x`) to an output-parameter writer: either a KNOWN
// initializer (memset, bzero, stat, ...) or a local function whose parameter at
// that position is written on every path (see FuncSummary.ParamWrites). An
// arbitrary `&x` to an unknown/conditional function is conservatively kept
// (cf. TestSecurity_TC16_UninitInterprocedural).
func outputParamInitializedVars(calls []parser.Node, f *db.Function, summaries summaryMap) map[string]bool {
	// `&s` to a writer initializes the whole struct on three tiers, mirroring
	// the scalar path's model:
	//   - known initializer (memset, stat, ...) → writes unconditionally;
	//   - local function whose ParamWrites marks the position → every path;
	//   - local function whose ParamConditionalWrites marks the position → the
	//     caller tests the return (`while (dequeue(&s) == OK)` / `if (get(&s))`),
	//     so the guarded path is where the callee wrote its output.
	// An UNKNOWN/external `&s` is conservatively kept — a generic void* filler
	// may write only some fields (cf. tc84 FlowGetKey).
	initialized := make(map[string]bool)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		knownInit := isOutputParamInitializer(callName)
		summary, hasSummary := summaries[callName]
		if !knownInit && !hasSummary {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for argIdx, arg := range child.NamedChildren() {
				if arg.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
					continue
				}
				inner := arg.NamedChildren()
				if len(inner) == 0 || inner[0].Kind() != "identifier" {
					continue
				}
				name := inner[0].Text()
				switch {
				case knownInit:
					initialized[name] = true
				case summary.ParamWrites[argIdx]:
					initialized[name] = true
				case summary.ParamConditionalWrites[argIdx] && callInBranchCondition(call):
					initialized[name] = true
				}
			}
		}
	}
	return initialized
}

// callInBranchCondition reports whether call sits inside the condition of an
// enclosing if/while/do/for — i.e. the caller tests the call's return value.
// It is the caller-side guard for a conditional output-param writer: the
// consequent body / fall-through runs on the checked path, which is where the
// callee wrote its output (`while (dequeue(&s) == OK) { use(s) }`).
func callInBranchCondition(call parser.Node) bool {
	for n := call.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "if_statement", "while_statement", "do_statement", "for_statement":
			cond := n.ChildByFieldName("condition")
			return cond != nil && nodeWithin(cond, &call)
		case "parenthesized_expression", "binary_expression", "unary_expression", "conditional_expression", "call_expression", "argument_list":
			// transparent wrappers around the call; keep climbing
		default:
			return false
		}
	}
	return false
}
