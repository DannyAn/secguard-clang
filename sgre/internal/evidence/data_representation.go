package evidence

import (
	"context"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DataRepresentationDetector flags a callback / generic-pointer API call whose
// comparator (or callback) interprets the type-erased `void *` element with a
// different object representation than the caller actually passed (CWE-843
// type confusion). The canonical shape is a qsort comparator:
//
//	int cmp(const void *a, const void *b) { const char *s = *(const char **)a; }
//	char buf[100];
//	qsort(buf, 100, sizeof(char), cmp);   // elements are char, not char *
//
// The comparator casts `a` to `const char **` (pointer depth 2) and dereferences
// it, so it assumes each element is itself a pointer — but the base holds `char`
// scalars (depth 0). Reading the first bytes of a string as a pointer is type
// confusion. The CORRECT form `(const char *)a` has depth 1 and matches.
//
// This is fundamentally a PAIR property — the same comparator cast can be right
// for one call site (`char *arr[]`, element depth 1) and wrong for another
// (`char buf[]`, depth 0) — so the detector compares, per call site, the base
// element pointer depth against the comparator's interpretation depth. It only
// supports direct `qsort`/`bsearch` calls with a named comparator that casts a
// `void *` parameter directly; indirect callbacks and multi-level deref chains
// are out of phase-1 scope (never guessed).
type DataRepresentationDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDataRepresentationDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DataRepresentationDetector {
	return &DataRepresentationDetector{store: store, parser: p, logger: logger}
}

func (d *DataRepresentationDetector) Name() string { return "data_representation" }

func (d *DataRepresentationDetector) Domain() string { return "contract" }

func (d *DataRepresentationDetector) Capabilities() []string {
	return []string{"data-representation", "callback-pointer-depth-mismatch"}
}

// comparatorAPIs maps an API name to its (base-argument-index,
// comparator-argument-index) positions.
var comparatorAPIs = map[string][2]int{
	"qsort":   {0, 3},
	"bsearch": {1, 4},
}

// comparatorInterpret records how a comparator casts its void* element pointers.
type comparatorInterpret struct {
	depth    int
	castType string
}

func (d *DataRepresentationDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	typedefs := buildGlobalTypedefs(ctx, d.store, d.parser)
	interpret := buildComparatorInterpretation(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		globals := map[string]string{}
		locals := map[int][]scopedVarDecl{}
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
				typ := base + starSuffix(v.stars)
				if owner == -1 {
					globals[v.name] = typ
				} else {
					locals[owner] = append(locals[owner], scopedVarDecl{name: v.name, typ: typ, line: line, end: end})
				}
			}
		}

		for _, call := range root.FindAll("call_expression") {
			api := calleeName(call)
			idxs, ok := comparatorAPIs[api]
			if !ok {
				continue
			}
			var f *db.Function
			for _, fn := range funcs {
				if funcLineRange(fn, call.StartLine()) {
					f = fn
					break
				}
			}
			if f == nil {
				continue
			}
			args := getCallArgs(call)
			if len(args) <= idxs[1] {
				continue
			}
			baseArg, comparArg := args[idxs[0]], args[idxs[1]]
			if comparArg.Kind() != "identifier" {
				continue
			}
			compar := comparArg.Text()
			ci, ok := interpret[compar]
			if !ok {
				continue
			}
			baseDepth := baseElementDepth(baseArg, call.StartLine(), globals, locals[f.StartLine])
			if baseDepth < 0 || baseDepth == ci.depth {
				continue
			}

			if emitEvent(ctx, d.store, d.logger, "DATA_REPRESENTATION_MISMATCH", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
				"function":   compar,
				"variable":   baseVarName(baseArg),
				"expression": call.Text(),
				"category":   "data_representation_mismatch",
				"expected":   baseElementType(baseArg, call.StartLine(), globals, locals[f.StartLine], typedefs),
				"actual":     ci.castType,
			}) {
				result.EventsCreated++
			}
		}
	})
	return result, err
}

// buildComparatorInterpretation maps each function name to how it casts its
// `void *` parameters: `(const char **)a` → element depth 1 (element is a
// pointer) with cast type "char **"; `(const char *)a` → depth 0 (element is a
// scalar). A conflicting or unresolvable interpretation is omitted.
func buildComparatorInterpretation(ctx context.Context, store db.Store, p *parser.Parser) map[string]comparatorInterpret {
	m := make(map[string]comparatorInterpret)
	files, err := store.ListFiles(ctx)
	if err != nil {
		return m
	}
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		for _, fn := range tree.RootNode().FindAll("function_definition") {
			name, _ := functionParamsFrom(fn)
			if name == "" {
				continue
			}
			voidParams := voidParamNames(fn)
			if len(voidParams) == 0 {
				continue
			}
			if ci, ok := interpretInfo(fn, voidParams); ok {
				m[name] = ci
			}
		}
	}
	return m
}

// voidParamNames returns the names of a function's `void *` parameters (the
// type-erased element pointers a comparator receives).
func voidParamNames(fnDef parser.Node) map[string]bool {
	names := map[string]bool{}
	for _, child := range fnDef.NamedChildren() {
		if child.Kind() != "function_declarator" {
			continue
		}
		for _, pc := range child.NamedChildren() {
			if pc.Kind() != "parameter_list" {
				continue
			}
			for _, param := range pc.NamedChildren() {
				if param.Kind() != "parameter_declaration" || normalizeSpelling(typeSpelling(param)) != "void *" {
					continue
				}
				if nm := paramName(param); nm != "" {
					names[nm] = true
				}
			}
		}
	}
	return names
}

func paramName(param parser.Node) string {
	for _, child := range param.NamedChildren() {
		switch child.Kind() {
		case "pointer_declarator", "identifier", "init_declarator":
			if n, _ := argDeclaratorVar(child); n != "" {
				return n
			}
		}
	}
	return ""
}

// interpretInfo returns the comparator's element interpretation from its direct
// casts of a void* param. `(char **)a` → {depth:1, castType:"char **"};
// `(char *)a` → {depth:0, castType:"char *"}. Conflicting casts (different
// depths) make it unresolvable.
func interpretInfo(fnDef parser.Node, voidParams map[string]bool) (comparatorInterpret, bool) {
	var ci comparatorInterpret
	found := false
	for _, cast := range fnDef.FindAll("cast_expression") {
		target := normalizeSpelling(castTargetType(cast))
		if !strings.HasSuffix(strings.TrimSpace(target), "*") {
			continue
		}
		operand := castOperand(cast)
		for operand.Kind() == "parenthesized_expression" {
			inner := operand.NamedChildren()
			if len(inner) == 0 {
				break
			}
			operand = inner[0]
		}
		if operand.Kind() != "identifier" || !voidParams[operand.Text()] {
			continue
		}
		depth := countStars(target) - 1
		if !found {
			ci = comparatorInterpret{depth: depth, castType: target}
			found = true
		} else if ci.depth != depth {
			return comparatorInterpret{}, false
		}
	}
	return ci, found
}

// baseElementDepth returns the pointer depth of the base argument's ELEMENT:
// `char buf[100]` → 0 (char scalar), `char *arr[]` → 1 (char * pointer),
// `char **p` → 1. Returns -1 when the base cannot be resolved.
func baseElementDepth(base parser.Node, line int, globals map[string]string, locals []scopedVarDecl) int {
	switch base.Kind() {
	case "identifier":
		return countStars(resolveScopedVar(base.Text(), line, globals, locals)) - 1
	case "pointer_expression":
		tgt, ok := base.AddressTakenTarget()
		if !ok || tgt.Kind() != "identifier" {
			return -1
		}
		return countStars(resolveScopedVar(tgt.Text(), line, globals, locals))
	}
	return -1
}

func baseVarName(base parser.Node) string {
	switch base.Kind() {
	case "identifier":
		return base.Text()
	case "pointer_expression":
		if tgt, ok := base.AddressTakenTarget(); ok {
			return tgt.Text()
		}
	}
	return ""
}

// baseElementType returns the base's ELEMENT type spelling: "char *" (char
// buf[100]) → "char", "char **" (char *arr[]) → "char *", "char" (&scalar) →
// "char". It strips exactly one pointer/array level.
func baseElementType(base parser.Node, line int, globals map[string]string, locals []scopedVarDecl, typedefs *typedefs) string {
	name := baseVarName(base)
	if name == "" {
		return ""
	}
	t := resolveType(resolveScopedVar(name, line, globals, locals), typedefs)
	return stripOneStar(t)
}

func stripOneStar(t string) string {
	t = strings.TrimSpace(t)
	if strings.HasSuffix(t, "*") {
		return strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(t), "*"))
	}
	return t
}

func countStars(t string) int {
	t = strings.TrimSpace(t)
	n := 0
	for strings.HasSuffix(t, "*") {
		n++
		t = strings.TrimSpace(strings.TrimSuffix(t, "*"))
	}
	return n
}
