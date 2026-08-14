package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("uninit: list functions: %w", err)
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}

		// Bind every FindAll walk to this function's own subtree rather than the
		// whole file. The three sub-detectors plus BuildCFG issue ~21 full-file
		// walks per function when handed the file root; scoping to the function
		// body collapses that to a single full-file walk (locating the function)
		// and leaves the rest bounded by the function's size. This is the dominant
		// cost of the uninit detector on large codebases.
		root, ok := functionRoot(tree.RootNode(), f.StartLine)
		if !ok {
			continue
		}

		d.detectStackUninit(ctx, f, file, root, &result)
		d.detectHeapUninit(ctx, f, file, root, &result)
		d.detectStructPartialUninit(ctx, f, file, root, &result)

		tree.Close()
	}

	return result, nil
}

// functionRoot returns the function_definition subtree whose declaration starts
// at startLine. The indexer records a function's StartLine/EndLine from the
// function_definition node itself, so StartLine is an exact key.
func functionRoot(root parser.Node, startLine int) (parser.Node, bool) {
	for _, fn := range root.FindAll("function_definition") {
		if fn.StartLine() == startLine {
			return fn, true
		}
	}
	return parser.Node{}, false
}

func (d *UninitVariableDetector) detectStackUninit(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	uninitVars := make(map[string]int)
	assignSites := make(map[string][]int)

	for _, decl := range root.FindAll("declaration") {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
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
				for _, dc := range child.NamedChildren() {
					if dc.Kind() == "identifier" {
						assignSites[dc.Text()] = append(assignSites[dc.Text()], decl.StartLine())
					}
				}
			}
		}
		if hasInit || isStatic {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" {
				uninitVars[child.Text()] = decl.StartLine()
			}
		}
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			assignSites[children[0].Text()] = append(assignSites[children[0].Text()], assign.StartLine())
		}
	}

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if isOutputParamInitializer(callName) {
			for _, child := range call.NamedChildren() {
				if child.Kind() == "argument_list" {
					for _, arg := range child.NamedChildren() {
						argText := arg.Text()
						if strings.HasPrefix(argText, "&") {
							assignSites[strings.TrimPrefix(argText, "&")] = append(assignSites[strings.TrimPrefix(argText, "&")], call.StartLine())
						}
					}
				}
			}
		}
	}

	cfg := graph.BuildCFG(root, f.StartLine, f.EndLine)
	cfgValid := cfg != nil && cfg.Root != nil && len(cfg.Root.Children) > 0
	if !cfgValid && d.logger != nil {
		d.logger.Debug("uninit: CFG construction degenerate, using conservative fallback",
			"function", f.Name,
		)
	}

	checkUse := func(useLine int, name string) {
		if _, uninit := uninitVars[name]; !uninit {
			return
		}
		sites := assignSites[name]
		if len(sites) == 0 {
			d.insertValueUseEvent(ctx, f, file, useLine, name, "stack_uninit", result)
			return
		}
		if cfgValid && hasUnassignedPath(cfg, f.StartLine, useLine, sites) {
			d.insertValueUseEvent(ctx, f, file, useLine, name, "stack_uninit", result)
			return
		}
		if !cfgValid {
			allInIf := true
			for _, s := range sites {
				if !isInIfRange(root, f, s) {
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
	// skipName (e.g. the callee of a call) is also excluded.
	scanUses := func(node parser.Node, line int, skipName string) {
		addressed := addressedArgs(node)
		for _, id := range node.FindAll("identifier") {
			name := id.Text()
			if name == skipName || addressed[name] {
				continue
			}
			checkUse(line, name)
		}
	}

	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() < f.StartLine || ret.StartLine() > f.EndLine {
			continue
		}
		scanUses(ret, ret.StartLine(), "")
	}

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		scanUses(call, call.StartLine(), extractCallName(call))
	}

	for _, ifNode := range root.FindAll("if_statement") {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() > f.EndLine {
			continue
		}
		scanUses(ifNode, ifNode.StartLine(), "")
	}

	for _, whileNode := range root.FindAll("while_statement") {
		if whileNode.StartLine() < f.StartLine || whileNode.StartLine() > f.EndLine {
			continue
		}
		scanUses(whileNode, whileNode.StartLine(), "")
	}

	for _, forNode := range root.FindAll("for_statement") {
		if forNode.StartLine() < f.StartLine || forNode.StartLine() > f.EndLine {
			continue
		}
		scanUses(forNode, forNode.StartLine(), "")
	}
}

func hasUnassignedPath(cfg *graph.CFG, funcEntry int, useLine int, assignLines []int) bool {
	if cfg == nil || cfg.Root == nil {
		return false
	}
	for _, a := range assignLines {
		if a >= useLine {
			continue
		}
		scope := cfg.FindInnermostScope(a)
		if scope == cfg.Root {
			return false
		}
	}
	useScope := cfg.FindInnermostScope(useLine)
	for _, a := range assignLines {
		if a >= useLine {
			continue
		}
		assignScope := cfg.FindInnermostScope(a)
		if assignScope == useScope {
			return false
		}
	}
	return true
}

func isInIfRange(root parser.Node, f *db.Function, line int) bool {
	for _, ifNode := range root.FindAll("if_statement") {
		if ifNode.StartLine() >= f.StartLine && ifNode.StartLine() <= f.EndLine {
			if line >= ifNode.StartLine() && line <= ifNode.EndLine() {
				return true
			}
		}
	}
	return false
}

func (d *UninitVariableDetector) detectHeapUninit(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	mallocVars := make(map[string]bool)

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
				mallocVars[varName] = true
			}
		}
	}

	for _, init := range root.FindAll("init_declarator") {
		if init.StartLine() < f.StartLine || init.StartLine() > f.EndLine {
			continue
		}
		checkInit(init)
	}
	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		checkInit(assign)
	}

	writtenThroughPtr := make(map[string]bool)
	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		text := assign.Text()
		for varName := range mallocVars {
			if strings.Contains(text, varName+"->") || strings.Contains(text, "*"+varName) {
				writtenThroughPtr[varName] = true
			}
		}
	}

	for _, unary := range root.FindAll("unary_expression") {
		if unary.StartLine() < f.StartLine || unary.StartLine() > f.EndLine {
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
		if mallocVars[varName] && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, unary.StartLine(), varName, "heap_uninit", result)
		}
	}

	for _, ptr := range root.FindAll("pointer_expression") {
		if ptr.StartLine() < f.StartLine || ptr.StartLine() > f.EndLine {
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
		if mallocVars[varName] && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, ptr.StartLine(), varName, "heap_uninit", result)
		}
	}

	for _, field := range root.FindAll("field_expression") {
		if field.StartLine() < f.StartLine || field.StartLine() > f.EndLine {
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
		if mallocVars[varName] && !writtenThroughPtr[varName] {
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), varName, "heap_uninit", result)
		}
	}
}

func (d *UninitVariableDetector) detectStructPartialUninit(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	structVars := make(map[string]int)
	initializedFields := make(map[string]bool)
	// A struct passed by address to a KNOWN initializer (memset(&s, 0, ...),
	// or an output-param filler) has its fields written by the callee, so it
	// is not a definite partial-init defect. An arbitrary `&s` to an unknown
	// function is conservatively kept (cf. TC16 interprocedural uninit).
	initializedVars := outputParamInitializedVars(root, f)

	for _, decl := range root.FindAll("declaration") {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
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

			if child.Kind() == "identifier" {
				structVars[child.Text()] = decl.StartLine()
			}
		}
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		text := assign.Text()
		for varName := range structVars {
			if strings.Contains(text, varName+".") || strings.Contains(text, varName+"->") {
				initializedFields[text] = true
			}
		}
	}

	for _, field := range root.FindAll("field_expression") {
		if field.StartLine() < f.StartLine || field.StartLine() > f.EndLine {
			continue
		}
		text := field.Text()
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
		if !initializedFields[text] {
			d.insertValueUseEvent(ctx, f, file, field.StartLine(), varName, "struct_partial_uninit", result)
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

// outputParamInitializedVars returns the set of variable names within f whose
// address is passed (`&x`) to a KNOWN output-parameter initializer (memset,
// bzero, OpenProcessToken, CreateProcessA, ...). These callees are known to
// write through the pointer, so the variable is considered initialized —
// unlike an arbitrary `&x` to an unknown function, which may or may not write
// (conservatively treated as uninitialized, cf.
// TestSecurity_TC16_UninitInterprocedural).
func outputParamInitializedVars(root parser.Node, f *db.Function) map[string]bool {
	initialized := make(map[string]bool)
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		if !isOutputParamInitializer(extractCallName(call)) {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				argText := arg.Text()
				if strings.HasPrefix(argText, "&") {
					initialized[strings.TrimPrefix(argText, "&")] = true
				}
			}
		}
	}
	return initialized
}
