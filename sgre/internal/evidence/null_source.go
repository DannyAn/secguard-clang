package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type NullSourceDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewNullSourceDetector(store db.Store, p *parser.Parser, logger *log.Logger) *NullSourceDetector {
	return &NullSourceDetector{store: store, parser: p, logger: logger}
}

func (d *NullSourceDetector) Name() string { return "null_source" }

func (d *NullSourceDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Pass 1: return-null and malloc sources. detectReturnNull populates the
	// function_summary return-nullability that detectExternalCall consults, so it
	// must complete for every function before the external-call pass builds its
	// nullable-function map.
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		macros := macroFreeSummaries(root)
		for _, f := range funcs {
			d.detectReturnNull(ctx, f, file, returns, &result)
			d.detectMallocResult(ctx, f, file, assigns, inits, &result)
			d.detectExplicitNull(ctx, f, file, assigns, inits, &result)
			d.detectMacroNull(ctx, f, file, calls, macros, &result)
		}
	})
	if err != nil {
		return result, fmt.Errorf("null source: %w", err)
	}

	knownFuncs, retTypes := d.getKnownFunctionNames(ctx)
	nullableFuncs := d.getNullableReturnFunctions(ctx)

	// Pass 2: external-call sources, now that nullableFuncs is complete.
	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		for _, f := range funcs {
			d.detectExternalCall(ctx, f, file, assigns, inits, &result, knownFuncs, retTypes, nullableFuncs)
		}
	})
	return result, err
}

func (d *NullSourceDetector) detectReturnNull(ctx context.Context, f *db.Function, file *db.File, returns []parser.Node, result *DetectResult) {
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		// Inspect the return VALUE, not the raw text: `return foo(x, 0)` must
		// not be read as `return 0` (the previous substring match on " 0"
		// treated every `return call(..., 0)` as nullable).
		children := ret.NamedChildren()
		if len(children) == 0 {
			continue
		}
		expr := strings.TrimSpace(children[0].Text())
		if !isNullLiteral(expr) && expr != "0" {
			continue
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: ret.StartLine(), Column: ret.StartColumn()}, map[string]string{"variable": "<return>", "origin": "return"}) {
			result.EventsCreated++
			if err := d.store.UpdateReturnNullable(ctx, f.ID, true); err != nil && d.logger != nil {
				d.logger.Warn("update return nullable failed", "function_id", f.ID, "error", err)
			}
		}
	}
}

func (d *NullSourceDetector) detectMallocResult(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult) {
	allocators := []string{"malloc", "calloc", "realloc"}

	checkNode := func(node parser.Node) {
		text := node.Text()
		for _, a := range allocators {
			if strings.Contains(text, a) {
				children := node.NamedChildren()
				if len(children) < 2 {
					return
				}
				lhs := children[0]
				varName := assignedVariable(lhs)
				if varName != "" {
					if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine()}, map[string]string{"variable": varName, "origin": a}) {
						result.EventsCreated++
					}
				}
				return
			}
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

// detectExplicitNull records a DEFINITE null source: `p = NULL` / `p = nullptr`
// / `p = (void*)0`. Unlike malloc/fopen (which may or may not return NULL),
// an explicit null assignment means the pointer IS null, so a later dereference
// is a definite null-deref (the must-analysis tier the AI does not need to
// re-derive). It deliberately skips bare `0` (ambiguous with a zero int).
func (d *NullSourceDetector) detectExplicitNull(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult) {
	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		varName := assignedVariable(children[0])
		if varName == "" {
			return
		}
		if !isNullLiteral(children[1].Text()) {
			return
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine()}, map[string]string{"variable": varName, "origin": "explicit_null", "definite": "true"}) {
			result.EventsCreated++
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

// detectMacroNull records a DEFINITE null source for a call to a function-like
// macro that frees and then nulls its first argument (`SAFE_FREE(p)`). The
// free/p=NULL inside the macro is invisible to tree-sitter, so this is how the
// null-source model learns that p is null after the call.
func (d *NullSourceDetector) detectMacroNull(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, macros map[string]macroFreeSummary, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		s, ok := macros[extractCallName(call)]
		if !ok || !s.freesArg || !s.nullsArg {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		varName := assignedVariable(args[0])
		if varName == "" {
			continue
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine()}, map[string]string{"variable": varName, "origin": "explicit_null", "definite": "true"}) {
			result.EventsCreated++
		}
	}
}

// isNullLiteral reports whether an expression is an explicit null pointer
// constant (NULL, nullptr, or a (void*)0 cast). Bare 0 is excluded because it
// is ambiguous with a zero integer value.
func isNullLiteral(text string) bool {
	t := strings.TrimSpace(text)
	switch t {
	case "NULL", "nullptr", "(void*)0", "(void *)0", "((void*)0)", "((void *)0)":
		return true
	}
	return false
}

func (d *NullSourceDetector) detectExternalCall(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult, knownFuncs map[string]bool, retTypes map[string]string, nullableFuncs map[string]bool) {
	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs := children[0]
		rhs := children[1]
		varName := assignedVariable(lhs)
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
		if callExpr.Kind() != "call_expression" {
			return
		}
		callName := extractCallName(callExpr)
		if callName == "" || isAllocator(callName) {
			return
		}
		// A function returning a non-pointer primitive (int/size_t/...)
		// can never be null — skip it. This is the dominant false-null-source
		// (redis: sdslen/atoi/snprintf/strlen were treated as nullable).
		if neverNullFunctions[callName] {
			return
		}
		if rt, ok := retTypes[callName]; ok && neverNullReturnTypes[rt] {
			return
		}
		if knownFuncs[callName] && !nullableFuncs[callName] {
			return
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: node.StartLine()}, map[string]string{"variable": varName, "origin": "external_call", "function": callName}) {
			result.EventsCreated++
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

func (d *NullSourceDetector) getKnownFunctionNames(ctx context.Context) (map[string]bool, map[string]string) {
	funcs, _ := d.store.ListFunctions(ctx)
	known := make(map[string]bool, len(funcs))
	retTypes := make(map[string]string, len(funcs))
	for _, f := range funcs {
		known[f.Name] = true
		retTypes[f.Name] = f.ReturnType
	}
	return known, retTypes
}

// neverNullReturnTypes are C primitive types that can never hold a pointer.
// A function returning one of these cannot return NULL. Deliberately excludes
// "char"/"unsigned char"/struct names/typedefs: those may be `T *` in disguise
// (the indexer stores the base type name without the `*`).
var neverNullReturnTypes = map[string]bool{
	"size_t": true, "ssize_t": true, "int": true, "long": true, "short": true,
	"double": true, "float": true, "unsigned": true, "unsigned int": true,
	"unsigned long": true, "unsigned short": true, "unsigned long long": true,
	"long long": true, "int64_t": true, "uint64_t": true, "int32_t": true,
	"uint32_t": true, "int16_t": true, "uint16_t": true, "int8_t": true,
	"uint8_t": true, "bool": true, "_Bool": true,
}

// neverNullFunctions are libc/posix functions whose return is never a null
// pointer (non-pointer return). Pointer-returning "can be null" functions
// (strchr, strstr, strtok, memchr, fopen, ...) are deliberately NOT listed.
var neverNullFunctions = map[string]bool{
	"atoi": true, "atol": true, "atoll": true, "strtol": true, "strtoul": true,
	"strtoll": true, "strtoull": true, "strtod": true, "strtof": true,
	"strlen": true, "strcmp": true, "strncmp": true, "snprintf": true,
	"sprintf": true, "vsnprintf": true, "abs": true, "labs": true, "llabs": true,
}

func (d *NullSourceDetector) getNullableReturnFunctions(ctx context.Context) map[string]bool {
	funcs, _ := d.store.ListFunctions(ctx)
	m := make(map[string]bool)
	for _, f := range funcs {
		sum, err := d.store.GetSummaryByFunction(ctx, f.ID)
		if err != nil || sum == nil {
			continue
		}
		if sum.ReturnNullable {
			m[f.Name] = true
		}
	}
	return m
}

func isAllocator(name string) bool {
	switch name {
	case "malloc", "calloc", "realloc", "free":
		return true
	}
	return false
}

func extractCallName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// assignedVariable returns the storage location a value is assigned into,
// matching the dereference detector's attribution so that a NULL_VALUE source
// and a later DEREFERENCE resolve to the same variable. A field access is
// attributed by its full path text ("p->data"), not its first identifier
// ("p"), so that `p->data = malloc()` marks `p->data` (and only `p->data`) as
// nullable rather than suppressing every deref of `p`.
func assignedVariable(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "field_expression", "subscript_expression":
		return lhs.Text()
	case "pointer_expression":
		// `*p = value` writes THROUGH p (to the object p points at); it does NOT
		// assign p itself. `void **out; *out = f()` is an output-parameter write,
		// not "out = f()". The previous fallthrough attributed `*out = f()` to
		// "out", marking the output parameter as a nullable source so the very
		// next `if (*out == NULL)` read as a null-deref (the dominant false
		// positive). Match assignTargetName's semantics: return "".
		return ""
	}
	// Other shapes: attribute to the first identifier inside.
	for _, child := range lhs.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}
