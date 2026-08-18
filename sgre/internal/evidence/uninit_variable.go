package evidence

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
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

	summaries := buildFuncSummaries(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
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

		for _, f := range funcs {
			d.detectStackUninit(ctx, f, file, decls, assigns, calls, returns, inits, ifs, whiles, fors, funcDefs, summaries, &result)
			d.detectHeapUninit(ctx, f, file, inits, assigns, unarys, ptrs, fields, &result)
			d.detectStructPartialUninit(ctx, f, file, decls, assigns, calls, fields, summaries, &result)
		}
	})
	return result, err
}

func (d *UninitVariableDetector) detectStackUninit(ctx context.Context, f *db.Function, file *db.File, decls, assigns, calls, returns, inits, ifs, whiles, fors, funcDefs []parser.Node, summaries summaryMap, result *DetectResult) {
	uninitVars := make(map[string]int)
	assignSites := make(map[string][]int)

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
						assignSites[name] = append(assignSites[name], decl.StartLine())
					}
				}
			}
		}
		if hasInit || isStatic {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" && !parser.IsCTypeKeyword(child.Text()) {
				uninitVars[child.Text()] = decl.StartLine()
			}
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			assignSites[children[0].Text()] = append(assignSites[children[0].Text()], assign.StartLine())
		}
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// `&whole_var` passed to an output-param writer (a known initializer, or
		// a local function whose parameter at this position is written on every
		// path) initializes the variable.
		if isOutputParamInitializer(callName) || summaries[callName] != nil {
			summary := summaries[callName]
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
					if isOutputParamInitializer(callName) || summary.ParamWrites[argIdx] {
						assignSites[name] = append(assignSites[name], call.StartLine())
					}
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
						assignSites[base] = append(assignSites[base], call.StartLine())
					}
				}
			}
		}
	}

	body := extractFunctionBodyFrom(funcDefs, f.StartLine)
	cfg := graph.BuildStmtCFG(body, f.EndLine)
	cfgValid := body.Kind() == "compound_statement"
	if !cfgValid && d.logger != nil {
		d.logger.Debug("uninit: CFG construction degenerate, using conservative fallback",
			"function", f.Name,
		)
	}

	checkUse := func(useLine int, name string) {
		if parser.IsCTypeKeyword(name) {
			return
		}
		if _, uninit := uninitVars[name]; !uninit {
			return
		}
		sites := assignSites[name]
		if len(sites) == 0 {
			d.insertValueUseEvent(ctx, f, file, useLine, name, "stack_uninit", result)
			return
		}
		if cfgValid && hasUnassignedPath(cfg, name, useLine, sites) {
			d.insertValueUseEvent(ctx, f, file, useLine, name, "stack_uninit", result)
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
				d.insertValueUseEvent(ctx, f, file, useLine, name, "stack_uninit", result)
			}
		}
	}

	// scanUses reports uses of uninitialized variables among the identifiers
	// within node at the given line. Identifiers that are the operand of an
	// address-of (`&x`) are write targets, not reads, so they are skipped;
	// skipName (e.g. the callee of a call) is also excluded. A struct VALUE's
	// base (`s` in `s.f`) is a field access handled by struct-partial-uninit,
	// not a scalar read, so it is skipped too.
	scanUses := func(node parser.Node, line int, skipName string) {
		addressed := addressedArgs(node)
		for _, id := range node.FindAll("identifier") {
			name := id.Text()
			if name == skipName || addressed[name] || isValueFieldBase(id) {
				continue
			}
			checkUse(line, name)
		}
	}

	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		scanUses(ret, ret.StartLine(), "")
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		scanUses(call, call.StartLine(), extractCallName(call))
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
		if len(children) < 2 {
			continue
		}
		// A chained assignment `a = b = c = v` puts b and c in the RHS as WRITE
		// targets, not reads; only v (the value) is read. Skip nested LHS so
		// `code = first = index = 0` does not report first/index as read.
		writes := nestedAssignTargets(children[1])
		addressed := addressedArgs(children[1])
		for _, id := range children[1].FindAll("identifier") {
			name := id.Text()
			if addressed[name] || writes[name] || isValueFieldBase(id) {
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
		scanUses(children[1], init.StartLine(), "")
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
			scanUses(*cond, cond.StartLine(), "")
		}
	}

	for _, whileNode := range whiles {
		if !funcLineRange(f, whileNode.StartLine()) {
			continue
		}
		if cond := whileNode.ChildByFieldName("condition"); cond != nil {
			scanUses(*cond, cond.StartLine(), "")
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
		for _, id := range cond.FindAll("identifier") {
			if initWrites[id.Text()] || addressed[id.Text()] {
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
			d.insertValueUseEvent(ctx, f, file, unary.StartLine(), varName, "heap_uninit", result)
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
			d.insertValueUseEvent(ctx, f, file, ptr.StartLine(), varName, "heap_uninit", result)
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
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), varName, "heap_uninit", result)
		}
	}
}

func (d *UninitVariableDetector) detectStructPartialUninit(ctx context.Context, f *db.Function, file *db.File, decls, assigns, calls, fields []parser.Node, summaries summaryMap, result *DetectResult) {
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
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), varName, "struct_partial_uninit", result)
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

func (d *UninitVariableDetector) insertValueUseEvent(ctx context.Context, f *db.Function, file *db.File, line int, varName, origin string, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: line})
	props, _ := json.Marshal(map[string]string{
		"variable": varName,
		"origin":   origin,
	})
	_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  "VALUE_USE",
		EntityID:   f.ID,
		LocationID: locID,
		Properties: string(props),
	})
	if err == nil {
		result.EventsCreated++
	}
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
	"bzero":                 true,
	"CreateProcessA":        true,
	"CreateProcessW":        true,
	"CreateProcessAsA":      true,
	"CreateProcessAsW":      true,
}

func isOutputParamInitializer(name string) bool {
	return outputParamInitializers[name]
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
				argText := arg.Text()
				if !strings.HasPrefix(argText, "&") {
					continue
				}
				name := strings.TrimPrefix(argText, "&")
				if knownInit {
					initialized[name] = true
					continue
				}
				if summary.ParamWrites[argIdx] {
					initialized[name] = true
				}
			}
		}
	}
	return initialized
}
