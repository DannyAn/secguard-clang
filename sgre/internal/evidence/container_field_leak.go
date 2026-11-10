package evidence

// Global-container shallow-free analysis (issue #255).
//
// The allocation-centric memory-leak analysis tracks an allocation until it is
// freed, escapes, or is transferred — all from the allocator's function. That
// model misses the defect where a heap object's FIELD owns a separate block and
// the deletion path frees only the outer object:
//
//	cfg_t *cfg = malloc(sizeof(*cfg));      // policy_create
//	policy_t *policy = policy_new(cfg);     // policy_new stores cfg into policy->cfg
//	g_policy_table[idx] = policy;           // the object is owned by a global slot
//
//	policy_t *policy = g_policy_table[idx]; // policy_delete
//	policy_free(policy);                    // frees the OUTER object only
//	g_policy_table[idx] = NULL;             // the slot is cleared -> cfg is unreachable
//
// cfg is reachable only through  g_policy_table[idx] -> policy -> policy->cfg,
// so no function-local leak analysis can see it: the allocation is in create,
// the shallow release is in delete, and the loss materializes when the global
// slot is cleared. This pass models exactly that chain:
//
//	global container  ->  element object  ->  the element object's heap-owning field
//
// and reports a MEMORY_ALLOC candidate at the slot-clear line when the release
// path does not release that field. The candidate carries the full reference
// chain plus the field's allocation/store witnesses so the classifier does not
// need to trace the three functions by hand.
//
// Precision posture (why the facts are gated):
//   - The container must be a file-scope pointer-to-pointer (`T **g`), an array
//     of pointers (`T *g[N]`), or a single pointer global (`T *g`) whose slot is
//     cleared/overwritten after the object is released.
//   - The field must be DECLARED as a pointer of the element type (repofacts
//     pointer-member census) and must have a proven heap witness: a malloc/
//     allocator result stored into it, or a wrapper that stores a heap argument
//     into the object it returns (or fills a caller-owned object) and is called
//     with a heap value. A borrowed pointer field (weak ref, string literal,
//     parent-owned child) has no such witness and is never reported.
//   - The outer release must be proven: a deallocator call, a freeing macro, or
//     an in-tree helper whose parameter-free summary proves `free(p)`.
//   - A field release ANYWHERE in the deleting function suppresses the report.
//     A conditional release is therefore a false negative here rather than a
//     speculative report; the conditional shape stays a future refinement.
//
// The pass runs only when at least one global container exists, and it reports
// `suspected` candidates only — never auto-confirmed, because the closed-world
// release analysis cannot see an out-of-scan destructor (the same soundness
// limit that disabled LeakProofFilter for the allocation-centric candidates).

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

type containerFact struct {
	name       string
	objectType string
	// indexed marks a slot addressed by subscript (`T **g` / `T *g[N]`):
	// `g[i] = obj` / `obj = g[i]`. A plain pointer global (`T *g`) is not
	// indexed and uses the bare identifier as its slot.
	indexed bool
}

type heapFieldWitness struct {
	allocFunc string
	allocLine int
	allocAPI  string
	storeFunc string
	storeLine int
}

type wrapperKind int

const (
	// wrapperReturnsObject: the wrapper allocates/owns the object and returns
	// it; the call result is the object.
	wrapperReturnsObject wrapperKind = iota
	// wrapperFillsParam: the wrapper fills a caller-owned object passed as an
	// argument; that argument is the object.
	wrapperFillsParam
)

// wrapperFieldStore records `base->field = param` in a wrapper function: the
// caller's heap argument is stored into an object field by the callee, which is
// the interprocedural link the allocation-centric analysis cannot see.
type wrapperFieldStore struct {
	funcName       string
	paramIdx       int
	field          string
	baseType       string
	line           int
	kind           wrapperKind
	objectParamIdx int
}

type containerLeakFacts struct {
	containers map[string]containerFact
	ambiguous  map[string]bool
	heapFields map[string]map[string]heapFieldWitness
	wrappers   map[string][]wrapperFieldStore
}

func newContainerLeakFacts() *containerLeakFacts {
	return &containerLeakFacts{
		containers: map[string]containerFact{},
		ambiguous:  map[string]bool{},
		heapFields: map[string]map[string]heapFieldWitness{},
		wrappers:   map[string][]wrapperFieldStore{},
	}
}

func (f *containerLeakFacts) addContainer(c containerFact) {
	if f.ambiguous[c.name] {
		return
	}
	if prev, ok := f.containers[c.name]; ok {
		// A same-named container declared with a different element type in
		// another translation unit is ambiguous; a guessed element type is
		// worse than an unknown one.
		if prev.objectType != c.objectType || prev.indexed != c.indexed {
			f.ambiguous[c.name] = true
			delete(f.containers, c.name)
		}
		return
	}
	f.containers[c.name] = c
}

func (f *containerLeakFacts) addHeapField(typ, field string, w heapFieldWitness) {
	if typ == "" || field == "" {
		return
	}
	if f.heapFields[typ] == nil {
		f.heapFields[typ] = map[string]heapFieldWitness{}
	}
	if _, exists := f.heapFields[typ][field]; !exists {
		f.heapFields[typ][field] = w
	}
}

// containerSlotLoad is `obj = <global container slot>` in one function.
type containerSlotLoad struct {
	container string
	slot      string
	obj       string
	line      int
	// rewriteLine is the first line after the load that assigns the loaded
	// variable again (0 = never). A release after that line releases the NEW
	// value, not the container object, so it must not be paired with this load.
	rewriteLine int
}

// containerSlotClear is a write to a global container slot (NULL/0, or any
// overwrite) that drops the last reference to the loaded object.
type containerSlotClear struct {
	container string
	slot      string
	line      int
}

// containerObjRelease is a proven release of a loaded object (directly, via an
// alias, or via an in-tree helper whose parameter-free summary proves it), or
// of a container slot itself.
type containerObjRelease struct {
	container string
	slot      string
	obj       string
	line      int
	api       string
}

// containerReleaseSite holds one function's global-container facts.
type containerReleaseSite struct {
	funcID        int64
	fileID        int64
	funcName      string
	loads         []containerSlotLoad
	clears        []containerSlotClear
	releases      []containerObjRelease
	fieldReleases map[string]map[string]bool
}

// containerTransfer is a heap allocation handed into a wrapper-owned object
// that escapes the caller; it is an ownership transfer, not a function-local
// loss, so the allocation-site candidate must be released instead of reported.
type containerTransfer struct {
	funcID    int64
	fileID    int64
	line      int
	variable  string
	allocLine int
	wrapper   string
}

type typeScope struct {
	globals    map[string]string
	locals     map[int][]scopedVarDecl
	params     map[int]map[string]string
	paramNames map[int][]string
	td         *typedefs
}

// newTypeScope builds a per-file variable-type scope: file-scope declarations,
// per-function locals (with their closing line), and per-function parameter
// types/order. It mirrors the scope model ArgumentTypeDetector uses so a type
// resolves the same way in every consumer.
func newTypeScope(root parser.Node, funcs []*db.Function, funcDefs []parser.Node, td *typedefs) *typeScope {
	s := &typeScope{
		globals:    map[string]string{},
		locals:     map[int][]scopedVarDecl{},
		params:     map[int]map[string]string{},
		paramNames: map[int][]string{},
		td:         td,
	}
	for _, decl := range root.FindAll("declaration") {
		base, decls := varDeclParts(decl)
		if base == "" {
			continue
		}
		line := decl.StartLine()
		owner := -1
		var ownerFn *db.Function
		for _, fn := range funcs {
			if funcLineRange(fn, line) {
				owner = fn.StartLine
				ownerFn = fn
				break
			}
		}
		end := 0
		if ownerFn != nil {
			end = declScopeEnd(decl, ownerFn)
		}
		for _, v := range decls {
			typ := strings.TrimSpace(base + starSuffix(v.stars))
			if owner == -1 {
				if _, exists := s.globals[v.name]; !exists {
					s.globals[v.name] = typ
				}
			} else {
				s.locals[owner] = append(s.locals[owner], scopedVarDecl{name: v.name, typ: typ, line: line, end: end})
			}
		}
	}
	for _, fd := range funcDefs {
		start := fd.StartLine()
		names := extractFunctionParamsFrom(funcDefs, start)
		_, types := functionParamsFrom(fd)
		m := make(map[string]string, len(names))
		for i, name := range names {
			if i < len(types) && types[i] != "..." && types[i] != "void" {
				m[name] = types[i]
			}
		}
		if len(m) > 0 {
			s.params[start] = m
		}
		if len(names) > 0 {
			s.paramNames[start] = names
		}
	}
	return s
}

func (s *typeScope) varTypeAt(name string, line, funcStart int) string {
	if locals := s.locals[funcStart]; len(locals) > 0 {
		if t := resolveScopedVar(name, line, nil, locals); t != "" {
			return t
		}
	}
	if t := s.params[funcStart][name]; t != "" {
		return t
	}
	return s.globals[name]
}

func (s *typeScope) objectTypeAt(name string, line, funcStart int) string {
	return objectTypeFromSpelling(s.varTypeAt(name, line, funcStart), s.td)
}

// objectTypeFromSpelling resolves a declared type to the object type name the
// layout / pointer-member census is keyed by: `policy_t *` → `policy_t`,
// `struct policy_s *` → `policy_s`, a pointer typedef → its pointee type.
//
// Only POINTER typedefs and tagged aggregates are resolved. An anonymous
// `typedef struct {...} policy_t;` must keep the alias as the key: the census
// registers the alias, and the typedef's underlying spelling is the whole
// struct body.
func objectTypeFromSpelling(typ string, td *typedefs) string {
	base, _ := splitPointerAndStars(typ)
	seen := map[string]bool{}
	for i := 0; i < 8 && base != "" && !seen[base]; i++ {
		seen[base] = true
		if td == nil {
			break
		}
		underlying, ok := td.underlying[base]
		if !ok {
			break
		}
		next, stars := splitPointerAndStars(underlying)
		next = stripAggregatePrefix(next)
		if next == "" {
			break
		}
		if stars == 0 {
			// A non-pointer typedef of an ANONYMOUS aggregate must not be
			// replaced by its body spelling.
			if strings.ContainsAny(next, "{}") {
				break
			}
			// A tagged aggregate (`struct policy_s`) is the canonical key.
			if !strings.Contains(next, " ") || strings.HasPrefix(strings.TrimSpace(underlying), "struct ") ||
				strings.HasPrefix(strings.TrimSpace(underlying), "union ") {
				base = next
				continue
			}
			break
		}
		base = next
	}
	base = stripAggregatePrefix(strings.TrimSpace(base))
	if base == "" || base == unknownType || isBuiltinTypeName(base) {
		return ""
	}
	return base
}

func stripAggregatePrefix(name string) string {
	t := strings.TrimSpace(name)
	for _, prefix := range []string{"struct ", "union ", "enum ", "const ", "volatile "} {
		t = strings.TrimPrefix(t, prefix)
	}
	return strings.TrimSpace(t)
}

// splitPointerAndStars splits a type spelling into its base and trailing
// pointer depth: `policy_t **` → ("policy_t", 2).
func splitPointerAndStars(typ string) (string, int) {
	t := strings.TrimSpace(typ)
	stars := 0
	for strings.HasSuffix(t, "*") {
		stars++
		t = strings.TrimSpace(strings.TrimSuffix(t, "*"))
	}
	for _, prefix := range []string{"const ", "volatile "} {
		t = strings.TrimPrefix(t, prefix)
	}
	return strings.TrimSpace(t), stars
}

// isBuiltinTypeName reports whether the (typedef-resolved) base names a C
// builtin scalar, which has no struct members to walk.
func isBuiltinTypeName(name string) bool {
	if name == "" {
		return true
	}
	words := strings.Fields(name)
	if len(words) == 0 {
		return true
	}
	for _, w := range words {
		switch w {
		case "char", "short", "int", "long", "float", "double", "signed", "unsigned",
			"void", "bool", "_Bool", "size_t", "ssize_t", "int8_t", "uint8_t",
			"int16_t", "uint16_t", "int32_t", "uint32_t", "int64_t", "uint64_t",
			"intptr_t", "uintptr_t", "wchar_t":
		default:
			return false
		}
	}
	return true
}

// slotDeclInfo is one declarator's slot shape: `T **g` → stars 2 (indexed
// container), `T *g[N]` → stars 1 + array (indexed container), `T *g` → stars 1
// (single-slot container).
type slotDeclInfo struct {
	name    string
	stars   int
	isArray bool
	ok      bool
}

func analyzeSlotDeclarator(n parser.Node) slotDeclInfo {
	var kinds []string
	cur := n
	for i := 0; i < 8; i++ {
		switch cur.Kind() {
		case "init_declarator":
			d := cur.ChildByFieldName("declarator")
			if d == nil {
				return slotDeclInfo{}
			}
			cur = *d
			continue
		case "pointer_declarator":
			kinds = append(kinds, "p")
		case "array_declarator":
			kinds = append(kinds, "a")
		case "parenthesized_declarator":
		case "identifier":
			stars := 0
			isArray := false
			for i, k := range kinds {
				if k != "a" {
					stars++
					continue
				}
				// An array that is not the LAST declarator layer is a
				// pointer-to-array (`T (*g)[N]`), not a container of pointers.
				if i != len(kinds)-1 {
					return slotDeclInfo{}
				}
				isArray = true
			}
			return slotDeclInfo{name: cur.Text(), stars: stars, isArray: isArray, ok: true}
		default:
			return slotDeclInfo{}
		}
		kids := cur.NamedChildren()
		if len(kids) == 0 {
			return slotDeclInfo{}
		}
		cur = kids[0]
	}
	return slotDeclInfo{}
}

// containerFactsFromDeclaration extracts every global container declared by one
// file-scope declaration. Only `T **name`, `T *name[N]` and `T *name` are
// containers whose slot holds an object pointer; `T name[N]` stores objects by
// value and is not modelled here.
func containerFactsFromDeclaration(decl parser.Node, td *typedefs) []containerFact {
	var spec []string
	var declarators []parser.Node
	for _, c := range decl.NamedChildren() {
		switch c.Kind() {
		case "primitive_type", "sized_type_specifier", "type_identifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			spec = append(spec, strings.TrimSpace(c.Text()))
		case "init_declarator", "pointer_declarator", "array_declarator", "identifier":
			declarators = append(declarators, c)
		}
	}
	if len(spec) == 0 {
		return nil
	}
	objectType := objectTypeFromSpelling(strings.Join(spec, " "), td)
	if objectType == "" {
		return nil
	}
	var out []containerFact
	for _, d := range declarators {
		info := analyzeSlotDeclarator(d)
		if !info.ok || info.name == "" {
			continue
		}
		switch {
		case info.isArray:
			// Array of pointers (`T *g[N]`) only; an array of T** stores another
			// indirection level and is not a direct object slot.
			if info.stars != 1 {
				continue
			}
			out = append(out, containerFact{name: info.name, objectType: objectType, indexed: true})
		case info.stars == 1:
			out = append(out, containerFact{name: info.name, objectType: objectType, indexed: false})
		case info.stars == 2:
			// `T **g`: each element is a `T *` slot.
			out = append(out, containerFact{name: info.name, objectType: objectType, indexed: true})
		}
	}
	return out
}

// functionOwner returns the function a declaration/statement belongs to, or nil
// for a file-scope declaration.
func functionOwner(n parser.Node, funcs []*db.Function) *db.Function {
	line := n.StartLine()
	for _, f := range funcs {
		if funcLineRange(f, line) {
			return f
		}
	}
	return nil
}

// detectGlobalContainerFieldLeaks is the pass entry point.
func (d *MemoryLeakDetector) detectGlobalContainerFieldLeaks(ctx context.Context, globalTypedefs *typedefs, allocReturns map[string]bool, result *DetectResult) error {
	facts := newContainerLeakFacts()

	// Pass 1: declarations (containers, direct field heap witnesses, wrapper
	// parameter→field stores). It needs no summaries, so a container-less scan
	// pays only this one pass.
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)
		funcDefs := root.FindAll("function_definition")
		scope := newTypeScope(root, funcs, funcDefs, typedefs)
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		returns := root.FindAll("return_statement")

		for _, decl := range root.FindAll("declaration") {
			if functionOwner(decl, funcs) != nil {
				continue
			}
			for _, c := range containerFactsFromDeclaration(decl, typedefs) {
				facts.addContainer(c)
			}
		}
		for _, f := range funcs {
			collectHeapFieldStores(facts, f, scope, assigns, inits, returns, allocReturns)
		}
	})
	if err != nil {
		return err
	}
	if len(facts.containers) == 0 {
		return nil
	}

	summaries := buildFuncSummaries(ctx, d.store, d.parser, d.logger)

	// Pass 2: resolve wrapper heap witnesses and collect every function's
	// container deletion-path facts. Resolution/emission happens afterwards so
	// the container element type can be matched against the complete
	// heap-field set regardless of file order.
	var sites []containerReleaseSite
	var transfers []containerTransfer
	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		typedefs := globalTypedefs.clone()
		typedefs.addRoot(root)
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		decls := root.FindAll("declaration")
		macros := macroFreeSummaries(root)

		for _, f := range funcs {
			localVars := findLocalVarsFrom(decls, f)
			allocVars := allocVarsFrom(f, inits, assigns, calls, allocReturns)
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				stores := facts.wrappers[extractCallName(call)]
				if len(stores) == 0 {
					continue
				}
				args := getCallArgs(call)
				transferred := map[string]bool{}
				for _, st := range stores {
					if st.paramIdx >= len(args) {
						continue
					}
					argName := identifierOfExpr(args[st.paramIdx])
					if argName == "" {
						continue
					}
					alloc, isHeap := allocVars[argName]
					if !isHeap {
						continue
					}
					facts.addHeapField(st.baseType, st.field, heapFieldWitness{
						allocFunc: f.Name, allocLine: alloc.line, allocAPI: alloc.api,
						storeFunc: st.funcName, storeLine: st.line,
					})
					if transferred[argName] {
						continue
					}
					// Suppress the create-site candidate only when the wrapper
					// object demonstrably enters a global container slot: the
					// deletion-path pass then owns the field's fate. A mere
					// `return`/local escape is NOT enough — a shallow free of a
					// locally owned object would then lose its only report.
					escapes := false
					switch st.kind {
					case wrapperReturnsObject:
						escapes = callResultStoredInContainer(call, facts, f, inits, assigns, localVars)
					case wrapperFillsParam:
						if st.objectParamIdx < len(args) {
							if objName := identifierOfExpr(args[st.objectParamIdx]); objName != "" {
								escapes = variableStoredInContainer(objName, facts, f, inits, assigns, localVars)
							}
						}
					}
					if escapes {
						transferred[argName] = true
						transfers = append(transfers, containerTransfer{
							funcID: f.ID, fileID: file.ID, line: call.StartLine(),
							variable: argName, allocLine: alloc.line,
							wrapper: extractCallName(call),
						})
					}
				}
			}

			loads, clears, objReleases, fieldReleases := collectContainerSlots(facts, f, inits, assigns, calls, macros, summaries, localVars)
			if len(loads) == 0 && len(objReleases) == 0 {
				continue
			}
			sites = append(sites, containerReleaseSite{
				funcID: f.ID, fileID: file.ID, funcName: f.Name,
				loads: loads, clears: clears, releases: objReleases,
				fieldReleases: fieldReleases,
			})
		}
	})
	if err != nil {
		return err
	}

	return d.emitContainerFieldLeaks(ctx, facts, sites, transfers, result)
}

// collectHeapFieldStores collects, for one function, both the direct
// `obj->field = malloc(...)` heap-field facts and the wrapper facts linking a
// parameter to an object field (`obj->field = param` where obj is returned or
// is a parameter).
func collectHeapFieldStores(facts *containerLeakFacts, f *db.Function, scope *typeScope, assigns, inits, returns []parser.Node, allocReturns map[string]bool) {
	paramIdx := map[string]int{}
	for i, name := range scope.paramNames[f.StartLine] {
		paramIdx[name] = i
	}
	returned := returnedVarsOf(returns, f)
	aliases := findAliases(f, inits, assigns)

	check := func(node parser.Node) {
		if !funcLineRange(f, node.StartLine()) {
			return
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok || lhs.Kind() != "field_expression" {
			return
		}
		if node.Kind() == "assignment_expression" {
			if op := node.ChildByFieldName("operator"); op != nil && op.Text() != "=" {
				return
			}
		}
		base, field := extractFieldAccess(lhs)
		if base == "" || field == "" {
			return
		}
		baseType := scope.objectTypeAt(base, node.StartLine(), f.StartLine)
		if baseType == "" {
			return
		}
		if isHeapValueExpr(rhs, allocReturns) {
			facts.addHeapField(baseType, field, heapFieldWitness{
				allocFunc: f.Name, allocLine: node.StartLine(), allocAPI: calleeNameOf(rhs),
				storeFunc: f.Name, storeLine: node.StartLine(),
			})
			return
		}
		srcName := identifierOfExpr(rhs)
		if srcName == "" {
			return
		}
		// One-hop alias of a parameter (`obj->f = q; q = cfg;`).
		if a, ok := aliases[srcName]; ok && a.field == "" {
			srcName = a.baseVar
		}
		idx, isParam := paramIdx[srcName]
		if !isParam {
			return
		}
		st := wrapperFieldStore{funcName: f.Name, paramIdx: idx, field: field, baseType: baseType, line: node.StartLine()}
		if returned[base] {
			st.kind = wrapperReturnsObject
		} else if objIdx, ok := paramIdx[base]; ok {
			st.kind = wrapperFillsParam
			st.objectParamIdx = objIdx
		} else {
			return
		}
		facts.wrappers[f.Name] = append(facts.wrappers[f.Name], st)
	}
	for _, node := range inits {
		check(node)
	}
	for _, node := range assigns {
		check(node)
	}
}

func returnedVarsOf(returns []parser.Node, f *db.Function) map[string]bool {
	out := map[string]bool{}
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		for _, child := range ret.NamedChildren() {
			if id := identifierOfExpr(child); id != "" {
				out[id] = true
			}
		}
	}
	return out
}

type localAlloc struct {
	line int
	api  string
}

// allocVarsFrom returns the local variables that hold a fresh allocation in f,
// with the allocation line and API. It is the "is this argument a heap value"
// oracle for the wrapper call sites.
func allocVarsFrom(f *db.Function, inits, assigns, calls []parser.Node, allocReturns map[string]bool) map[string]localAlloc {
	out := map[string]localAlloc{}
	check := func(node parser.Node) {
		if !funcLineRange(f, node.StartLine()) {
			return
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		if node.Kind() == "assignment_expression" {
			if op := node.ChildByFieldName("operator"); op != nil && op.Text() != "=" {
				return
			}
			if lhs.Kind() != "identifier" {
				return
			}
		}
		name := extractVarFromDeclarator(lhs)
		if name == "" || !isHeapValueExpr(rhs, allocReturns) {
			return
		}
		out[name] = localAlloc{line: node.StartLine(), api: calleeNameOf(rhs)}
	}
	for _, node := range inits {
		check(node)
	}
	for _, node := range assigns {
		check(node)
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if name := outputParamAllocVar(call); name != "" {
			if _, exists := out[name]; !exists {
				out[name] = localAlloc{line: call.StartLine(), api: extractCallName(call)}
			}
		}
	}
	return out
}

// identifierOfExpr returns the bare identifier of an expression after unwrapping
// casts and parentheses, else "".
func identifierOfExpr(node parser.Node) string {
	node = unwrapCastParen(node)
	if node.Kind() == "identifier" {
		return strings.TrimSpace(node.Text())
	}
	return ""
}

// isHeapValueExpr reports whether an expression itself is a heap allocation
// (an allocator call, possibly cast/parenthesized).
func isHeapValueExpr(node parser.Node, allocReturns map[string]bool) bool {
	return isMallocExpr(unwrapCastParen(node), allocReturns)
}

func calleeNameOf(node parser.Node) string {
	node = unwrapCastParen(node)
	if node.Kind() != "call_expression" {
		return ""
	}
	return extractCallName(node)
}

// callResultStoredInContainer reports whether the wrapper call's returned
// object — directly or through the local it is assigned to — is stored into a
// global container slot. Only then does the container deletion-path pass own
// the field's fate and the allocation-site candidate get re-homed.
func callResultStoredInContainer(call parser.Node, facts *containerLeakFacts, f *db.Function, inits, assigns []parser.Node, localVars map[string]bool) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "return_statement":
			return false
		case "assignment_expression", "init_declarator":
			lhs, rhs, ok := p.AssignParts()
			if !ok || !nodeWithin(&rhs, &call) {
				return false
			}
			if _, _, ok := containerSlotOf(lhs, facts, localVars); ok {
				return true
			}
			name := extractVarFromDeclarator(lhs)
			if name == "" {
				return false
			}
			return variableStoredInContainer(name, facts, f, inits, assigns, localVars)
		case "expression_statement", "compound_statement", "function_definition", "if_statement",
			"while_statement", "for_statement", "do_statement", "switch_statement":
			return false
		}
	}
	return false
}

// variableStoredInContainer reports whether variable name is stored into a
// global container slot somewhere in f.
func variableStoredInContainer(name string, facts *containerLeakFacts, f *db.Function, inits, assigns []parser.Node, localVars map[string]bool) bool {
	for _, node := range append(append([]parser.Node{}, inits...), assigns...) {
		if !funcLineRange(f, node.StartLine()) {
			continue
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			continue
		}
		if _, _, ok := containerSlotOf(lhs, facts, localVars); ok && identifierOfExpr(rhs) == name {
			return true
		}
	}
	return false
}

// containerSlotOf resolves an expression to a global container slot. The
// container's shape decides the form: an indexed container's slot is a
// subscript (`g[i]`), a single-pointer container's slot is the bare name.
func containerSlotOf(node parser.Node, facts *containerLeakFacts, localVars map[string]bool) (containerFact, string, bool) {
	node = unwrapCastParen(node)
	switch node.Kind() {
	case "subscript_expression":
		base, _, ok := subscriptBaseIndex(node)
		if !ok || localVars[base] {
			return containerFact{}, "", false
		}
		c, ok := facts.containers[base]
		if !ok || !c.indexed {
			return containerFact{}, "", false
		}
		return c, node.Text(), true
	case "identifier":
		name := strings.TrimSpace(node.Text())
		if localVars[name] {
			return containerFact{}, "", false
		}
		c, ok := facts.containers[name]
		if !ok || c.indexed {
			return containerFact{}, "", false
		}
		return c, name, true
	}
	return containerFact{}, "", false
}

// collectContainerSlots collects one function's loads from a global container,
// slot clears, proven releases of a loaded element, and proven field releases.
func collectContainerSlots(facts *containerLeakFacts, f *db.Function, inits, assigns, calls []parser.Node, macros map[string]macroFreeSummary, summaries summaryMap, localVars map[string]bool) ([]containerSlotLoad, []containerSlotClear, []containerObjRelease, map[string]map[string]bool) {
	var loads []containerSlotLoad
	var clears []containerSlotClear
	var releases []containerObjRelease
	fieldReleases := map[string]map[string]bool{}
	aliases := findAliases(f, inits, assigns)

	markField := func(label, field string) {
		if label == "" || field == "" {
			return
		}
		if fieldReleases[label] == nil {
			fieldReleases[label] = map[string]bool{}
		}
		fieldReleases[label][field] = true
	}
	aliasTarget := func(id string) string {
		if a, ok := aliases[id]; ok && a.field == "" {
			return a.baseVar
		}
		return id
	}

	checkSlot := func(node parser.Node, asLoad bool) {
		if !funcLineRange(f, node.StartLine()) {
			return
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		if node.Kind() == "assignment_expression" {
			if op := node.ChildByFieldName("operator"); op != nil && op.Text() != "=" {
				return
			}
		}
		if asLoad {
			if node.Kind() == "init_declarator" || lhs.Kind() == "identifier" {
				if name := extractVarFromDeclarator(lhs); name != "" {
					if c, slot, ok := containerSlotOf(rhs, facts, localVars); ok {
						rewrite := 0
						for _, l := range writeLinesFor(assigns, inits, f, name) {
							if l > node.StartLine() {
								rewrite = l
								break
							}
						}
						loads = append(loads, containerSlotLoad{container: c.name, slot: slot, obj: name, line: node.StartLine(), rewriteLine: rewrite})
					}
				}
			}
		}
		if c, slot, ok := containerSlotOf(lhs, facts, localVars); ok {
			clears = append(clears, containerSlotClear{container: c.name, slot: slot, line: node.StartLine()})
		}
	}
	for _, node := range inits {
		checkSlot(node, true)
	}
	for _, node := range assigns {
		checkSlot(node, true)
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		args := getCallArgs(call)
		macroFree := macros[name].freesArg
		dealloc := apikb.IsDeallocator(name)
		s := summaries[name]
		for ai, arg := range args {
			// A deallocator / freeing macro releases its FIRST argument only; a
			// summary's per-parameter facts decide the rest.
			directFreeArg := (ai == 0 && (dealloc || macroFree)) || (s != nil && s.ParamDirectFrees[ai])
			// A direct release of the slot itself: `free(g[i])`.
			if c, slot, ok := containerSlotOf(arg, facts, localVars); ok && directFreeArg {
				releases = append(releases, containerObjRelease{container: c.name, slot: slot, line: call.StartLine(), api: name})
			}
			// A release of a loaded object (possibly through a whole-variable alias).
			if id := argIdentifier(arg); id != "" && directFreeArg {
				releases = append(releases, containerObjRelease{obj: aliasTarget(id), line: call.StartLine(), api: name})
			}
			// `free(obj->f)` / `helper(obj->f)`: a direct field release.
			if fe := fieldExprOf(arg); fe != nil {
				label, field := fieldAccessLabel(*fe)
				if label != "" && field != "" && directFreeArg {
					markField(label, field)
				}
			}
			// `q = obj->f; free(q)` / `q = obj; helper(q)`.
			if id := argIdentifier(arg); id != "" && directFreeArg {
				if fe, ok := aliases[id]; ok && fe.field != "" {
					markField(fe.baseVar, fe.field)
				}
			}
			// A helper that frees fields through the whole object argument
			// (`deep_free(p)` → `free(p->f)`).
			if s != nil && len(s.ParamFieldFrees[ai]) > 0 {
				if id := argIdentifier(arg); id != "" {
					label := aliasTarget(id)
					for _, field := range s.ParamFieldFrees[ai] {
						markField(label, field)
					}
				}
			}
		}
	}
	return loads, clears, releases, fieldReleases
}

// fieldExprOf unwraps casts/parens and returns a field_expression node, else nil.
func fieldExprOf(node parser.Node) *parser.Node {
	node = unwrapCastParen(node)
	if node.Kind() == "field_expression" {
		return &node
	}
	return nil
}

// fieldAccessLabel returns (label, field) for a field_expression whose base is
// an identifier, subscript, or nested field expression. The label is what a
// load's object variable and a direct slot release share.
func fieldAccessLabel(node parser.Node) (string, string) {
	children := node.NamedChildren()
	if len(children) < 2 {
		return "", ""
	}
	field := ""
	for _, child := range children {
		if child.Kind() == "field_identifier" {
			field = child.Text()
		}
	}
	if field == "" {
		return "", ""
	}
	base := children[0]
	switch base.Kind() {
	case "identifier", "subscript_expression", "field_expression":
		return strings.TrimSpace(base.Text()), field
	}
	return "", ""
}

// emitContainerFieldLeaks resolves the collected per-function facts into
// candidates and emits the ownership-transfer releases.
func (d *MemoryLeakDetector) emitContainerFieldLeaks(ctx context.Context, facts *containerLeakFacts, sites []containerReleaseSite, transfers []containerTransfer, result *DetectResult) error {
	repoFacts := repofacts.FactsFromCtx(ctx)
	if repoFacts == nil {
		built, err := repofacts.Build(ctx, d.store, d.parser, d.logger)
		if err == nil {
			repoFacts = built
		}
	}

	seen := map[string]bool{}
	for _, t := range transfers {
		key := fmt.Sprintf("transfer:%d:%s:%d", t.funcID, t.variable, t.allocLine)
		if seen[key] {
			continue
		}
		seen[key] = true
		if emitEvent(ctx, d.store, d.logger, "MEMORY_RELEASE", t.funcID, &db.Location{FileID: t.fileID, Line: t.line}, map[string]any{
			"variable":   t.variable,
			"origin":     "container_transfer",
			"alloc_line": t.allocLine,
			"free_api":   t.wrapper,
		}) {
			result.EventsCreated++
		}
	}

	for _, site := range sites {
		for _, load := range site.loads {
			rel, ok := pickRelease(site.releases, load)
			if !ok {
				continue
			}
			clear, ok := pickClear(site.clears, load.slot, rel.line)
			if !ok {
				continue
			}
			c := facts.containers[load.container]
			d.emitContainerField(ctx, facts, repoFacts, site, c, load, rel, clear, seen, result)
		}
		// A slot freed in place (`free(g[i]); g[i] = NULL;`) has no load
		// variable; the container name alone identifies the element type.
		for _, rel := range site.releases {
			if rel.obj != "" || rel.slot == "" {
				continue
			}
			clear, ok := pickClear(site.clears, rel.slot, rel.line)
			if !ok {
				continue
			}
			c, ok := facts.containers[rel.container]
			if !ok {
				continue
			}
			load := containerSlotLoad{container: rel.container, slot: rel.slot, obj: rel.slot, line: rel.line}
			d.emitContainerField(ctx, facts, repoFacts, site, c, load, rel, clear, seen, result)
		}
	}
	return nil
}

func (d *MemoryLeakDetector) emitContainerField(ctx context.Context, facts *containerLeakFacts, repoFacts *repofacts.Facts, site containerReleaseSite, c containerFact, load containerSlotLoad, rel containerObjRelease, clear containerSlotClear, seen map[string]bool, result *DetectResult) {
	witnesses := facts.heapFields[c.objectType]
	if len(witnesses) == 0 {
		return
	}
	var fields []string
	if repoFacts != nil {
		list, ok := repoFacts.PointerFields(c.objectType)
		if !ok {
			return
		}
		fields = list
	} else {
		for field := range witnesses {
			fields = append(fields, field)
		}
		sort.Strings(fields)
	}
	released := site.fieldReleases[load.obj]
	if released == nil {
		released = site.fieldReleases[load.slot]
	}
	for _, field := range fields {
		w, ok := witnesses[field]
		if !ok || released[field] {
			continue
		}
		key := fmt.Sprintf("leak:%d:%s:%s:%d", site.funcID, load.slot, field, clear.line)
		if seen[key] {
			continue
		}
		seen[key] = true
		objLabel := load.obj
		if objLabel == "" {
			objLabel = load.slot
		}
		chain := fmt.Sprintf("%s -> %s -> %s->%s", load.slot, objLabel, objLabel, field)
		props := map[string]string{
			"variable":     field,
			"origin":       "container_field",
			"api":          w.allocAPI,
			"container":    c.name,
			"slot":         load.slot,
			"object":       objLabel,
			"field":        field,
			"ref_chain":    chain,
			"shallow_free": fmt.Sprintf("%s:%d", rel.api, rel.line),
			"field_alloc":  fmt.Sprintf("%s:%d", w.allocFunc, w.allocLine),
			"field_store":  fmt.Sprintf("%s:%d", w.storeFunc, w.storeLine),
		}
		if emitEvent(ctx, d.store, d.logger, "MEMORY_ALLOC", site.funcID, &db.Location{FileID: site.fileID, Line: clear.line}, props) {
			result.EventsCreated++
		}
	}
}

// pickRelease returns the first proven release of the loaded object (or of the
// exact slot) at or after the load.
func pickRelease(releases []containerObjRelease, load containerSlotLoad) (containerObjRelease, bool) {
	best := containerObjRelease{}
	found := false
	for _, r := range releases {
		if r.line < load.line {
			continue
		}
		if load.rewriteLine > 0 && r.line >= load.rewriteLine {
			continue
		}
		if !((r.obj != "" && r.obj == load.obj) || (r.obj == "" && r.slot != "" && r.slot == load.slot)) {
			continue
		}
		if !found || r.line < best.line {
			best, found = r, true
		}
	}
	return best, found
}

// pickClear returns the first slot clear at or after the release line.
func pickClear(clears []containerSlotClear, slot string, after int) (containerSlotClear, bool) {
	best := containerSlotClear{}
	found := false
	for _, c := range clears {
		if c.slot != slot || c.line < after {
			continue
		}
		if !found || c.line < best.line {
			best, found = c, true
		}
	}
	return best, found
}
