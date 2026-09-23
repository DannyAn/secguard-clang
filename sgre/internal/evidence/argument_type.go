package evidence

import (
	"context"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// ArgumentTypeDetector flags an explicit pointer cast passed to a function whose
// pointed-to object type is incompatible with the source object's type
// (CWE-686 / CERT EXP37-C): `void f(uint *p); bool b; f((uint *)&b);`. The cast
// makes the callee access the bool object with uint semantics — a size and
// representation mismatch, not a legal conversion.
//
// Phase 1 is deliberately narrow and low-false-positive: it inspects only
// DIRECT calls whose argument is an EXPLICIT cast to a pointer type, and it
// flags only numeric-object reinterpretations that provably read more bytes
// than the source object holds (bool→uint, uint32→uint64) or change the
// object's representation kind (int↔float). void*, char*/byte casts, identical
// types, and same-size integer reinterpretation are filtered as legal C
// boundaries. Function pointers, indirect calls, aggregate (struct/union)
// reinterpretation, and cast-less (implicit) mismatches are out of scope.
type ArgumentTypeDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewArgumentTypeDetector(store db.Store, p *parser.Parser, logger *log.Logger) *ArgumentTypeDetector {
	return &ArgumentTypeDetector{store: store, parser: p, logger: logger}
}

func (d *ArgumentTypeDetector) Name() string { return "argument_type" }

func (d *ArgumentTypeDetector) Domain() string { return "contract" }

func (d *ArgumentTypeDetector) Capabilities() []string {
	return []string{"argument-type-mismatch", "incompatible-pointer-cast"}
}

func (d *ArgumentTypeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	typedefs := buildGlobalTypedefs(ctx, d.store, d.parser)
	globalParams := buildGlobalFunctionParams(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		// File-scope declarations (globals) are visible in every function;
		// locals are bucketed per function (by start line) and carry their line
		// so same-named variables in disjoint scopes resolve to the nearest
		// declaration, not a later out-of-scope shadow.
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
			callee := calleeName(call)
			if callee == "" {
				continue
			}
			params, ok := globalParams[callee]
			if !ok {
				continue
			}
			args := getCallArgs(call)
			for i, arg := range args {
				if i >= len(params) {
					break
				}
				if params[i] == "..." {
					continue
				}
				if d.checkArgument(ctx, file, f, callee, params[i], arg, call.StartLine(), globals, locals[f.StartLine], typedefs) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

func (d *ArgumentTypeDetector) checkArgument(ctx context.Context, file *db.File, f *db.Function, callee, expected string, arg parser.Node, line int, globals map[string]string, locals []scopedVarDecl, typedefs *typedefs) bool {
	// void* parameter boundary: the callee accepts any pointer, never a violation.
	if pointedToResolved(expected, typedefs) == "void" {
		return false
	}
	if arg.Kind() != "cast_expression" {
		return false
	}
	target := castTargetType(arg)
	if !isPointerType(target, typedefs) {
		return false
	}
	targetPointed := pointedToResolved(target, typedefs)

	operand := castOperand(arg)
	varName, source, actual := sourceObjectInfo(operand, line, globals, locals, typedefs)
	if source == "" {
		return false
	}
	if compatibleObjectTypes(targetPointed, source, typedefs) {
		return false
	}

	return emitEvent(ctx, d.store, d.logger, "ARGUMENT_TYPE_MISMATCH", f.ID, &db.Location{FileID: file.ID, Line: arg.StartLine(), Column: arg.StartColumn()}, map[string]string{
		"function":   callee,
		"variable":   varName,
		"expression": arg.Text(),
		"category":   "argument_type_mismatch",
		"expected":   expected,
		"actual":     actual,
		"cast":       target,
	})
}

// calleeName returns the identifier of a direct call's callee, or "" for any
// indirect form (function pointer, field access, parenthesized callee).
func calleeName(call parser.Node) string {
	kids := call.NamedChildren()
	if len(kids) == 0 {
		return ""
	}
	if kids[0].Kind() == "identifier" {
		return kids[0].Text()
	}
	return ""
}

// castTargetType returns the type spelling of an explicit cast's target, e.g.
// "uint *" for `(uint *)&x`. The type_descriptor child holds the full type
// including any abstract pointer declarator.
func castTargetType(cast parser.Node) string {
	for _, child := range cast.NamedChildren() {
		if child.Kind() == "type_descriptor" {
			return typeSpelling(child)
		}
	}
	return ""
}

// castOperand returns the cast's operand (its last named child): `(T)x` → x.
func castOperand(cast parser.Node) parser.Node {
	kids := cast.NamedChildren()
	if len(kids) == 0 {
		return parser.Node{}
	}
	return kids[len(kids)-1]
}

// sourceObjectInfo resolves a cast operand to (variable name, object type,
// actual expression type). `&flag` (flag declared bool) → ("flag", "bool",
// "bool *"); a pointer variable `p` declared `bool *p` → ("p", "bool", "bool *").
func sourceObjectInfo(operand parser.Node, line int, globals map[string]string, locals []scopedVarDecl, typedefs *typedefs) (string, string, string) {
	switch operand.Kind() {
	case "pointer_expression":
		tgt, ok := operand.AddressTakenTarget()
		if !ok || tgt.Kind() != "identifier" {
			return "", "", ""
		}
		name := tgt.Text()
		rt := resolveType(resolveScopedVar(name, line, globals, locals), typedefs)
		return name, rt, rt + " *"
	case "identifier":
		name := operand.Text()
		rt := resolveType(resolveScopedVar(name, line, globals, locals), typedefs)
		return name, pointedToResolved(rt, typedefs), rt
	case "parenthesized_expression":
		inner := operand.NamedChildren()
		if len(inner) == 0 {
			return "", "", ""
		}
		return sourceObjectInfo(inner[0], line, globals, locals, typedefs)
	}
	return "", "", ""
}

type scopedVarDecl struct {
	name string
	typ  string
	line int
	// end is the line the declaration's scope closes on. A shadowing declaration
	// in a nested block must stop shadowing after that block ends; without it,
	// resolveScopedVar keeps resolving to the (now out-of-scope) inner
	// declaration on every later line of the enclosing block.
	end int
}

// declScopeEnd returns the line the declaration's scope closes on. The parent of
// a declaration is its enclosing scope: a compound_statement for a block, or the
// for/while/if/switch statement whose header declares it (the name is in scope
// for the whole statement). Anything else falls back to the function end.
func declScopeEnd(decl parser.Node, fn *db.Function) int {
	if p := decl.Parent(); p != nil {
		switch p.Kind() {
		case "compound_statement", "for_statement", "while_statement", "if_statement", "do_statement", "switch_statement":
			return p.EndLine()
		}
	}
	return fn.EndLine
}

// resolveScopedVar returns the type of name at line: the nearest same-name
// declaration whose scope still contains line (declared on or before line, and
// whose enclosing block has not yet closed), then a file-scope global.
func resolveScopedVar(name string, line int, globals map[string]string, locals []scopedVarDecl) string {
	best := ""
	bestLine := -1
	for _, d := range locals {
		if d.name != name || d.line > line {
			continue
		}
		if d.end > 0 && line > d.end {
			continue
		}
		if d.line > bestLine {
			best = d.typ
			bestLine = d.line
		}
	}
	if best != "" {
		return best
	}
	return globals[name]
}

func isPointerType(t string, typedefs *typedefs) bool {
	return strings.HasSuffix(strings.TrimSpace(resolveType(t, typedefs)), "*")
}

// pointedToResolved returns the object type a (possibly typedef) pointer type
// points to: "uint *" → "uint", a typedef `cstr_t` = `char *` → "char".
func pointedToResolved(t string, typedefs *typedefs) string {
	t = resolveType(strings.TrimSpace(t), typedefs)
	if strings.HasSuffix(t, "*") {
		return strings.TrimSpace(strings.TrimSuffix(t, "*"))
	}
	return t
}

func resolveType(t string, typedefs *typedefs) string {
	t = strings.TrimSpace(t)
	if typedefs == nil {
		return t
	}
	seen := map[string]bool{}
	for {
		base, ok := typedefs.underlying[t]
		if !ok || base == t || seen[t] {
			return t
		}
		seen[t] = true
		t = base
	}
}

// compatibleObjectTypes reports whether reinterpret-casting an object of source
// type to a pointer-to-target type is a legal C boundary (filtered) or a
// candidate incompatibility (reported). See the detector doc comment for the
// phase-1 scope.
func compatibleObjectTypes(target, source string, typedefs *typedefs) bool {
	t := normalizeSpelling(resolveType(target, typedefs))
	s := normalizeSpelling(resolveType(source, typedefs))
	if t == "" || s == "" {
		return true
	}
	if t == s {
		return true
	}
	if t == "void" || s == "void" {
		return true
	}
	// Casting TO a byte type (char family) is idiomatic byte access.
	if isByteSpelling(t) {
		return true
	}

	tk, tsz, tnum := numericInfo(t)
	sk, ssz, snum := numericInfo(s)
	if tnum && snum {
		if tk != sk {
			return false
		}
		// Same representation kind: incompatible only when the target provably
		// reads more bytes than the object holds (bool→uint, uint32→uint64).
		if tsz > 0 && ssz > 0 && tsz > ssz {
			return false
		}
		return true
	}
	// Pointer-to-pointer, aggregate, or opaque reinterpretation: out of scope.
	return true
}

func normalizeSpelling(t string) string {
	t = strings.TrimSpace(t)
	fields := strings.Fields(t)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case "const", "volatile", "restrict":
			continue
		}
		out = append(out, f)
	}
	return strings.Join(out, " ")
}

type numericKind int

const (
	numNone numericKind = iota
	numInt
	numFloat
)

func numericInfo(t string) (numericKind, int, bool) {
	switch {
	case t == "bool" || t == "_Bool":
		return numInt, 1, true
	case isByteSpelling(t):
		return numInt, 1, true
	case isFloatSpelling(t):
		return numFloat, floatSize(t), true
	case isIntSpelling(t):
		return numInt, intSize(t), true
	case strings.HasPrefix(t, "enum"):
		return numInt, 4, true
	}
	return numNone, 0, false
}

func isByteSpelling(t string) bool {
	switch t {
	case "char", "signed char", "unsigned char":
		return true
	}
	return false
}

func isFloatSpelling(t string) bool {
	switch t {
	case "float", "double", "long double":
		return true
	}
	return false
}

func floatSize(t string) int {
	switch t {
	case "float":
		return 4
	case "double":
		return 8
	case "long double":
		return 16
	}
	return 0
}

func isIntSpelling(t string) bool {
	tt := " " + t + " "
	if intSize(t) != 0 {
		return true
	}
	// "long"/"unsigned long" are platform-ambiguous in size but still integers.
	return strings.Contains(tt, "long") && !strings.Contains(tt, "double")
}

func intSize(t string) int {
	tt := " " + t + " "
	switch {
	case strings.Contains(tt, "long long"):
		return 8
	case strings.Contains(tt, "long"):
		return 0
	case strings.Contains(tt, "short"):
		return 2
	case strings.Contains(tt, "int8_t"), strings.Contains(tt, "uint8_t"):
		return 1
	case strings.Contains(tt, "int16_t"), strings.Contains(tt, "uint16_t"):
		return 2
	case strings.Contains(tt, "int32_t"), strings.Contains(tt, "uint32_t"):
		return 4
	case strings.Contains(tt, "int64_t"), strings.Contains(tt, "uint64_t"):
		return 8
	case strings.Contains(tt, "size_t"), strings.Contains(tt, "ssize_t"), strings.Contains(tt, "ptrdiff_t"), strings.Contains(tt, "intptr_t"), strings.Contains(tt, "uintptr_t"):
		return 8
	case strings.Contains(tt, "int"), strings.Contains(tt, "signed"), strings.Contains(tt, "unsigned"):
		return 4
	}
	return 0
}

// buildGlobalFunctionParams maps every indexed function/prototype name to its
// ordered parameter type spellings (e.g. "process" → ["uint *"]), read across
// all indexed files so a callee declared in another file still resolves.
func buildGlobalFunctionParams(ctx context.Context, store db.Store, p *parser.Parser) map[string][]string {
	m := make(map[string][]string)
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
		for name, params := range collectFunctionParams(tree.RootNode()) {
			m[name] = params
		}
	}
	return m
}

func collectFunctionParams(root parser.Node) map[string][]string {
	m := make(map[string][]string)
	for _, node := range root.FindAll("function_definition") {
		if name, params := functionParamsFrom(node); name != "" {
			m[name] = params
		}
	}
	for _, node := range root.FindAll("declaration") {
		for _, child := range node.NamedChildren() {
			if child.Kind() != "function_declarator" {
				continue
			}
			if name, params := functionNameAndParams(child); name != "" {
				m[name] = params
			}
		}
	}
	return m
}

func functionParamsFrom(node parser.Node) (string, []string) {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "function_declarator" {
			return functionNameAndParams(child)
		}
		if child.Kind() == "pointer_declarator" {
			for _, gc := range child.NamedChildren() {
				if gc.Kind() == "function_declarator" {
					return functionNameAndParams(gc)
				}
			}
		}
	}
	return "", nil
}

func functionNameAndParams(fd parser.Node) (string, []string) {
	name := ""
	var params []string
	for _, child := range fd.NamedChildren() {
		switch child.Kind() {
		case "identifier":
			name = child.Text()
		case "parameter_list":
			params = paramTypes(child)
		}
	}
	return name, params
}

func paramTypes(pl parser.Node) []string {
	var types []string
	for _, param := range pl.NamedChildren() {
		switch param.Kind() {
		case "parameter_declaration":
			if t := typeSpelling(param); t != "" && t != "void" {
				types = append(types, t)
			}
		case "variadic_parameter", "variadic_type_identifier":
			types = append(types, "...")
		}
	}
	return types
}

// typeSpelling extracts a declaration/descriptor's type spelling: the leading
// type specifiers plus ` *` per pointer/array declarator level, without the
// declared name. `uint *buf` → "uint *", `unsigned int x` → "unsigned int".
func typeSpelling(node parser.Node) string {
	var spec []string
	stars := 0
	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "sized_type_specifier", "type_identifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			spec = append(spec, child.Text())
		case "pointer_declarator", "abstract_pointer_declarator", "array_declarator":
			stars += declaratorStars(child)
		}
	}
	if len(spec) == 0 {
		return ""
	}
	return strings.TrimSpace(strings.Join(spec, " ")) + starSuffix(stars)
}

func starSuffix(stars int) string {
	if stars == 0 {
		return ""
	}
	return " " + strings.Repeat("*", stars)
}

func declaratorStars(node parser.Node) int {
	switch node.Kind() {
	case "pointer_declarator", "abstract_pointer_declarator", "array_declarator":
	default:
		return 0
	}
	depth := 1
	for _, child := range node.NamedChildren() {
		switch child.Kind() {
		case "pointer_declarator", "abstract_pointer_declarator", "array_declarator":
			depth = 1 + declaratorStars(child)
			return depth
		}
	}
	return depth
}

type argVarDecl struct {
	name  string
	stars int
}

func varDeclParts(decl parser.Node) (string, []argVarDecl) {
	var spec []string
	var decls []argVarDecl
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "sized_type_specifier", "type_identifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			spec = append(spec, child.Text())
		case "init_declarator", "pointer_declarator", "identifier":
			if name, stars := argDeclaratorVar(child); name != "" {
				decls = append(decls, argVarDecl{name: name, stars: stars})
			}
		}
	}
	if len(spec) == 0 {
		return "", nil
	}
	return strings.TrimSpace(strings.Join(spec, " ")), decls
}

func argDeclaratorVar(node parser.Node) (string, int) {
	switch node.Kind() {
	case "init_declarator":
		for _, child := range node.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				return child.Text(), 0
			case "pointer_declarator", "array_declarator":
				return argDeclaratorVar(child)
			}
		}
	case "pointer_declarator", "array_declarator":
		for _, child := range node.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				return child.Text(), 1
			case "pointer_declarator", "array_declarator":
				name, stars := argDeclaratorVar(child)
				return name, stars + 1
			}
		}
	case "identifier":
		return node.Text(), 0
	}
	return "", 0
}
