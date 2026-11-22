package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// structPartialFacts bundles the "collect" declarations and the "compute"
// write-path state the struct-partial-uninit reads are judged against.
type structPartialFacts struct {
	structVars        map[string]int
	structDeclsByName map[string][]varDecl
	initializedFields map[string]bool
	unionVars         map[string]bool
	unionInitialized  map[string]bool
	wholeAssigned     map[string]bool
	writePaths        map[string]bool
	initializedVars   map[string]bool
	initializedFrom   map[string]int
}

func (s *structPartialFacts) resolve(name string, line int) string {
	return resolveVarKey(s.structDeclsByName, name, line)
}

func (s *structPartialFacts) scopedPath(key, bareBase, full string) string {
	if !strings.HasPrefix(full, bareBase) {
		return full
	}
	return key + full[len(bareBase):]
}

func (d *UninitVariableDetector) detectStructPartialUninit(ctx context.Context, in *uninitScanInputs) {
	facts := d.collectStructPartialFacts(in)
	d.computeStructPartialWrites(in, facts)
	d.emitStructPartialUses(ctx, in, facts)
}

func (d *UninitVariableDetector) collectStructPartialFacts(in *uninitScanInputs) *structPartialFacts {
	f, decls := in.f, in.decls
	calls, ifs := in.calls, in.ifs
	summaries, unionTypedefs := in.summaries, in.unionTypedefs
	bound := in.bound
	// Scope-aware tracking (UN-04): structVars and every per-variable fact are
	// keyed by varKey(name@declLine) so two `s` in nested blocks no longer collide.
	structVars := make(map[string]int) // varKey -> decl line
	structDeclsByName := make(map[string][]varDecl)
	initializedFields := make(map[string]bool)
	// unionVars marks declarations whose type is a union_specifier. A union's
	// members SHARE storage, so writing any one member initializes that storage:
	// a later read of a DIFFERENT member is implementation-defined, not a
	// use-of-uninitialized-memory defect (issue #253 P2-1: `u.vlan = x` followed
	// by a read of `u.id` was auto-confirmed CWE-457). This must NOT be applied
	// to structs, where `s.a = 1; return s.b` is a genuine partial-init defect.
	unionVars := make(map[string]bool)
	unionInitialized := make(map[string]bool)
	// isValue is the same `(A) & x` disambiguation the scalar path uses (see
	// detectStackUninit): without it a genuine bit-and argument would be read as
	// an address-of and mark a field as callee-initialized.
	isValue := func(name string) bool { return bound[name] }
	// A struct passed by address to a KNOWN initializer (memset(&s, 0, ...),
	// or an output-param filler) — or to a local function that writes the
	// pointer parameter on every path — has its fields written by the callee,
	// so it is not a definite partial-init defect. An arbitrary `&s` to an
	// unknown/conditional function is conservatively kept (cf. TC16).
	initializedVars, initializedFrom := outputParamInitializedVars(calls, ifs, f, summaries, isValue)

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
		isUnion := false
		for _, child := range decl.NamedChildren() {
			switch child.Kind() {
			case "union_specifier":
				isUnion = true
			case "type_identifier":
				if unionTypedefs[child.Text()] {
					isUnion = true
				}
			}
		}
		for _, child := range decl.NamedChildren() {

			if child.Kind() == "identifier" && !parser.IsCTypeKeyword(child.Text()) {
				key := varKey(child.Text(), decl.StartLine())
				structVars[key] = decl.StartLine()
				structDeclsByName[child.Text()] = append(structDeclsByName[child.Text()], varDecl{name: child.Text(), declLine: decl.StartLine(), scopeEnd: enclosingScopeEnd(decl)})
				if isUnion {
					unionVars[key] = true
				}
			}
		}
	}

	return &structPartialFacts{
		structVars:        structVars,
		structDeclsByName: structDeclsByName,
		initializedFields: initializedFields,
		unionVars:         unionVars,
		unionInitialized:  unionInitialized,
		initializedVars:   initializedVars,
		initializedFrom:   initializedFrom,
	}
}

func (d *UninitVariableDetector) computeStructPartialWrites(in *uninitScanInputs, facts *structPartialFacts) {
	f := in.f
	assigns, calls := in.assigns, in.calls
	macroWrites := in.macroWrites
	bound := in.bound
	structVars := facts.structVars
	initializedFields := facts.initializedFields
	unionVars := facts.unionVars
	unionInitialized := facts.unionInitialized
	initializedVars := facts.initializedVars
	isValue := func(name string) bool { return bound[name] }
	// A write inside a runtime branch initializes a field on only some paths, so
	// it must not suppress a later read here; the planner drops the read only when
	// the write covers every path (UN-06).
	uncond := func(n parser.Node) bool { return !isConditionalNode(n) }
	resolve := facts.resolve
	scopedPath := facts.scopedPath
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
		if !uncond(assign) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 1 {
			continue
		}
		lhs := children[0]
		if lhs.Kind() == "identifier" {
			if key := resolve(lhs.Text(), assign.StartLine()); key != "" {
				if _, isStruct := structVars[key]; isStruct {
					wholeAssigned[key] = true
				}
			}
			continue
		}
		// A field/subscript write (`s.f = ...`, `s.f[i] = ...`) initializes that
		// member. Normalize the member path so `s.f[i]` and `s.f` map to the
		// same key — the previous version keyed by the full assignment text,
		// which never matched the field-read text.
		if lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression" {
			base := fieldBaseName(lhs)
			key := resolve(base, assign.StartLine())
			if key == "" {
				continue
			}
			if _, isStruct := structVars[key]; !isStruct {
				continue
			}
			initializedFields[scopedPath(key, base, fieldPath(lhs))] = true
			if unionVars[key] {
				unionInitialized[key] = true
			}
			for _, p := range fieldWritePaths(lhs) {
				writePaths[scopedPath(key, base, p)] = true
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
		if !uncond(call) {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				target, ok := addressOfTargetScoped(arg, isValue)
				if !ok {
					continue
				}
				if target.Kind() == "field_expression" || target.Kind() == "subscript_expression" {
					if base := fieldBaseName(target); base != "" {
						if key := resolve(base, call.StartLine()); key != "" {
							initializedFields[scopedPath(key, base, fieldPath(target))] = true
						}
					}
				}
			}
		}
	}

	// A field/subscript passed as the raw destination of a copy/init call
	// (`strncpy_s(msg.pool_name, ...)`, `memcpy_s(&s.field, ...)`) is written
	// by the callee. The array decays to a pointer with no `&`, so the `&s.f`
	// output-param loop above misses it; mark the field path initialized so a
	// struct filled through strncpy_s/memcpy_s/sprintf is not reported as
	// partial-init. destWriteTarget unifies the bare and &-prefixed shapes
	// (UN-15).
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		if !isDestWriter(name) && destWriterArgs[name] == nil {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		if !uncond(call) {
			continue
		}
		target, ok := destWriterTargetArg(name, args)
		if !ok {
			continue
		}
		base, path, whole := destWriteTarget(target)
		if base == "" || whole {
			continue
		}
		if key := resolve(base, call.StartLine()); key != "" {
			initializedFields[scopedPath(key, base, path)] = true
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
		if !uncond(call) {
			continue
		}
		for name := range macros.WrittenArgs(call, macroWrites) {
			initializedVars[name] = true
		}
		for name := range macros.WrittenFree(call, macroWrites) {
			initializedVars[name] = true
		}
		for name, suffix := range macros.WrittenFieldArgs(call, macroWrites) {
			initializedFields[name+suffix] = true
		}
		// A parse/deserialize macro (`CAP_MSG_HEAD_PARSE(msg, head)`) whose body
		// is in an invisible third-party header writes its by-value struct
		// argument wholesale; mark it initialized so its field reads are not
		// reported partial-init.
		if structOutputMacroName(extractCallName(call)) {
			for _, arg := range getCallArgs(call) {
				if arg.Kind() == "identifier" {
					initializedVars[arg.Text()] = true
				}
			}
		}
	}

	facts.wholeAssigned = wholeAssigned
	facts.writePaths = writePaths
}

func (d *UninitVariableDetector) emitStructPartialUses(ctx context.Context, in *uninitScanInputs, facts *structPartialFacts) {
	f, file := in.f, in.file
	fields := in.fields
	result := in.result
	structVars, initializedFields := facts.structVars, facts.initializedFields
	unionInitialized, wholeAssigned := facts.unionInitialized, facts.wholeAssigned
	writePaths := facts.writePaths
	initializedVars, initializedFrom := facts.initializedVars, facts.initializedFrom
	resolve := facts.resolve
	scopedPath := facts.scopedPath
	for _, field := range fields {
		if !funcLineRange(f, field.StartLine()) {
			continue
		}
		if isFieldWriteTarget(field) || isAddressOnlyUse(field) {
			continue
		}
		children := field.NamedChildren()
		if len(children) == 0 {
			continue
		}
		base := fieldBaseName(field)
		key := resolve(base, field.StartLine())
		if key == "" {
			continue
		}
		if _, isStruct := structVars[key]; !isStruct {
			continue
		}
		if initializedVars[base] {
			continue
		}
		if wholeAssigned[key] {
			continue
		}
		// A union member write initializes the shared storage, so a read of any
		// other member is not a partial-init defect (only structs are per-field).
		if unionInitialized[key] {
			continue
		}
		// A path that is a write target (or its base) is not a read.
		if writePaths[scopedPath(key, base, fieldPath(field))] {
			continue
		}
		// A write established only past a caller-side guard initializes the
		// fields read on the success continuation; a read on or before the
		// guard (the error branch) stays reported, matching the scalar path.
		if from, ok := initializedFrom[base]; ok && field.StartLine() > from {
			continue
		}
		if !initializedFields[scopedPath(key, base, fieldPath(field))] {
			d.insertValueUseEventAt(ctx, f, file, field.StartLine(), field.StartColumn(), structVars[key], base, fieldPath(field), "", "struct_partial_uninit", "", 0, "", result)
		}
	}
}
