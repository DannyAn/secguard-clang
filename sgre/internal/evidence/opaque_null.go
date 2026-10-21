package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// OpaqueNullDetector seeds null sources for code whose type contracts are not
// visible in the scan tree. Tree-sitter recovers the full syntax of a
// function whose parameter uses a third-party typedef (the AST, the deref
// sinks, everything), but the null-deref pipeline only reports a dereference
// a NULL_VALUE source can reach — and a field value of an externally-defined
// struct (`tree = (T *)(resp->group_data)`) has no seeding path: the field's
// VALUE nullability contract is invisible.
//
// The gap is filled with a FAIL-OPEN source (origin "opaque_field_read",
// never definite): the candidate stays suspected and the AI judges the
// contract, mirroring the external_call / assumed-return tiers. The domain is
// deliberately narrow: the base parameter's type must not be defined anywhere
// in the scan tree (unknown typedef / struct); a locally-defined struct keeps
// its current behavior (field value flow is a separate analysis). Recorded
// for a pointer assigned the field read (`p = base->f`, cast allowed) at the
// assignment line, and for a chained dereference's intermediate value
// (`base->f1->f2` reads the `base->f1` field value) at function entry.
//
// Parameter-level opacity is NOT this detector's job: whether a pointer
// PARAMETER can be NULL is decided by CallerNullDetector's open-chain
// fixpoint (zero-call-site entries are open there), which also owns the
// candidate-volume contract for forwarding chains.
type OpaqueNullDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewOpaqueNullDetector(store db.Store, p *parser.Parser, logger *log.Logger) *OpaqueNullDetector {
	return &OpaqueNullDetector{store: store, parser: p, logger: logger}
}

func (d *OpaqueNullDetector) Name() string { return "opaque_null" }

func (d *OpaqueNullDetector) Domain() string { return "memory" }

func (d *OpaqueNullDetector) Capabilities() []string {
	return []string{"opaque-type-null-source", "external-contract-fail-open"}
}

func (d *OpaqueNullDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	definedTypes, err := d.collectGlobalFacts(ctx)
	if err != nil {
		return result, err
	}

	hasEntryPoint := scanHasEntryPoint(ctx, d.store)
	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		fnDefs := root.FindAll("function_definition")
		for _, f := range funcs {
			fnDef := findFnDefByName(fnDefs, f.Name)
			if fnDef.Kind() == "" {
				continue
			}
			d.seedOpaqueFieldRead(ctx, f, file, fnDef, definedTypes, hasEntryPoint, &result)
		}
	})
	if err != nil {
		return result, fmt.Errorf("opaque null: %w", err)
	}
	return result, nil
}

// collectGlobalFacts walks every INDEXED file and gathers the tree-wide fact
// the field-read channel needs: which type names are DEFINED in the scan tree.
//
// It must use forEachIndexedFile, not forEachFile: the latter only visits files
// that contain at least one indexed function, and in a real C tree essentially
// every struct/typedef lives in a header that defines no function. A
// function-only census therefore sees almost no types at all, marks every
// in-tree header type opaque, and seeds fail-open field-read sources for
// contracts the tree can fully see (a false-positive class the opaque
// channel must never introduce).
func (d *OpaqueNullDetector) collectGlobalFacts(ctx context.Context) (map[string]bool, error) {
	definedTypes := map[string]bool{}
	err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node) {
		collectDefinedTypes(root, definedTypes)
	})
	return definedTypes, err
}

// collectDefinedTypes adds every type name whose LAYOUT is visible in this
// file's tree to definedTypes:
//
//   - a struct/union/enum specifier WITH a body defines its tag;
//   - a typedef defines its name when the underlying type is a body-having
//     specifier, a primitive/sizeof-composable spelling, or a type_identifier
//     that is itself defined in-tree;
//   - a FORWARD-DECLARATION typedef (`typedef struct x_struct x_t;`, the
//     incomplete-type issue's exact form) defines nothing — the layout stays
//     invisible, so x_t remains opaque.
func collectDefinedTypes(root parser.Node, definedTypes map[string]bool) {
	bodied := map[string]bool{}
	for _, kind := range []string{"struct_specifier", "union_specifier", "enum_specifier"} {
		for _, ss := range root.FindAll(kind) {
			hasBody := false
			for _, c := range ss.NamedChildren() {
				if c.Kind() == "field_declaration_list" || c.Kind() == "enumerator_list" {
					hasBody = true
					break
				}
			}
			if !hasBody {
				continue
			}
			for _, c := range ss.NamedChildren() {
				if c.Kind() == "type_identifier" {
					name := strings.TrimSpace(c.Text())
					bodied[name] = true
					definedTypes[name] = true
					break
				}
			}
		}
	}
	for _, td := range root.FindAll("type_definition") {
		kids := td.NamedChildren()
		if len(kids) == 0 {
			continue
		}
		// The typedef NAME is the trailing type_identifier: `typedef <underlying> x_t`.
		name := ""
		if kids[len(kids)-1].Kind() == "type_identifier" {
			name = strings.TrimSpace(kids[len(kids)-1].Text())
		}
		if name == "" {
			continue
		}
		underlying := kids[0]
		switch underlying.Kind() {
		case "struct_specifier", "union_specifier", "enum_specifier":
			// `typedef struct x {...} x_t;` (body) or `typedef struct x x_t;`
			// (forward declaration). Opaque unless the specifier has a body.
			for _, c := range underlying.NamedChildren() {
				if c.Kind() == "field_declaration_list" || c.Kind() == "enumerator_list" {
					definedTypes[name] = true
					break
				}
			}
		case "primitive_type", "sized_type_specifier":
			definedTypes[name] = true
		case "type_identifier":
			// `typedef known_s alias_t;`: visible only when the referenced
			// name is itself defined in-tree.
			if definedTypes[strings.TrimSpace(underlying.Text())] {
				definedTypes[name] = true
			}
		}
	}
}

// seedOpaqueFieldRead emits fail-open null sources for reads of fields whose
// base parameter type is not defined in the scan tree: an assigned pointer
// (`tree = (T *)(resp->group_data)`) gets a source at the assignment line, and
// a chained dereference's intermediate value (`para->orig->base_dn` reads the
// `para->orig` field value) gets one at function entry. In a COMPLETE-PROGRAM
// scan a struct defined in-tree keeps its current behavior (the visible layout
// is assumed to carry the project's field invariants); in a BOUNDARY scan (no
// entry point) that assumption is dropped and every base pointer parameter is
// fail-open, because the field VALUE comes from an out-of-tree caller.
func (d *OpaqueNullDetector) seedOpaqueFieldRead(ctx context.Context, f *db.Function, file *db.File, fnDef parser.Node, definedTypes map[string]bool, hasEntryPoint bool, result *DetectResult) {
	_, names, types := functionParamNames(fnDef)
	opaqueParams := map[string]bool{}
	for i, pname := range names {
		if pname == "..." {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(types[i]), "*") {
			continue
		}
		// In a BOUNDARY scan (no `main`) the base parameter's field VALUE comes
		// from an out-of-tree caller even when its layout is fully visible, so
		// every pointer parameter is fail-open. In a COMPLETE-PROGRAM scan a
		// visible layout is assumed to carry the project's own field invariants
		// (precision policy, not a proof).
		if !hasEntryPoint || typeSpellingOpaque(types[i], definedTypes) {
			opaqueParams[pname] = true
		}
	}
	if len(opaqueParams) == 0 {
		return
	}

	emitted := map[string]bool{}
	emit := func(variable string, line int) {
		if variable == "" || emitted[variable] {
			return
		}
		emitted[variable] = true
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: line, Column: 1}, map[string]string{
			"variable": variable,
			"origin":   "opaque_field_read",
			"definite": "false",
		}) {
			result.EventsCreated++
		}
	}

	checkAssign := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		varName := assignedVariable(lhs)
		if varName == "" {
			return
		}
		inner := stripCasts(rhs)
		switch inner.Kind() {
		case "field_expression", "subscript_expression":
		default:
			return
		}
		if base := leftmostIdentifier(inner); base != "" && opaqueParams[base] {
			emit(varName, node.StartLine())
		}
	}
	for _, assign := range fnDef.FindAll("assignment_expression") {
		checkAssign(assign)
	}
	for _, init := range fnDef.FindAll("init_declarator") {
		checkAssign(init)
	}

	// A chained field dereference `base->f1->f2` dereferences the VALUE of
	// `base->f1`; when base's type is opaque that value's nullability is
	// unknown. The intermediate variable is attributed exactly like the
	// dereference detector attributes it (the outer field's base text), so
	// the planner's reaching analysis matches source to sink.
	for _, fe := range fnDef.FindAll("field_expression") {
		base := stripCasts(derefBaseChild(fe))
		if base.Kind() != "field_expression" {
			continue
		}
		if root := leftmostIdentifier(base); root != "" && opaqueParams[root] {
			emit(base.Text(), f.StartLine)
		}
	}
}

// typeSpellingOpaque reports whether a parameter type spelling names a type
// that is not defined anywhere in the scan tree. Primitive and stdint names
// are never opaque; `struct x *` / `x_t *` are opaque unless x / x_t is
// defined in-tree.
func typeSpellingOpaque(spelling string, definedTypes map[string]bool) bool {
	name := strings.TrimSpace(spelling)
	name = strings.TrimSuffix(name, "*")
	for _, kw := range []string{"struct ", "union ", "enum "} {
		name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), kw))
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	if primitiveTypeNames[name] {
		return false
	}
	return !definedTypes[name]
}

var primitiveTypeNames = map[string]bool{
	"void": true, "char": true, "short": true, "int": true, "long": true,
	"float": true, "double": true, "signed": true, "unsigned": true,
	"bool": true, "_Bool": true, "_Complex": true,
	"size_t": true, "ssize_t": true, "ptrdiff_t": true, "intptr_t": true,
	"uintptr_t": true, "intmax_t": true, "uintmax_t": true,
	"off_t": true, "time_t": true, "clock_t": true, "pid_t": true, "uid_t": true,
	"gid_t": true, "mode_t": true, "dev_t": true, "ino_t": true,
	"int8_t": true, "int16_t": true, "int32_t": true, "int64_t": true,
	"uint8_t": true, "uint16_t": true, "uint32_t": true, "uint64_t": true,
	"FILE": true, "va_list": true,
}

// stripCasts unwraps cast and parenthesized expressions down to the operand.
func stripCasts(n parser.Node) parser.Node {
	for n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
		next := parser.Node{}
		for _, c := range n.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			next = c
			break
		}
		if next.Kind() == "" {
			return n
		}
		n = next
	}
	return n
}

// derefBaseChild returns the base operand of a field/subscript/pointer
// expression (the dereferenced pointer), or a zero Node.
func derefBaseChild(n parser.Node) parser.Node {
	kids := n.NamedChildren()
	if n.Kind() == "pointer_expression" {
		if len(kids) == 0 {
			return parser.Node{}
		}
		return kids[0]
	}
	if n.Kind() == "field_expression" || n.Kind() == "subscript_expression" {
		if len(kids) == 0 {
			return parser.Node{}
		}
		return kids[0]
	}
	return parser.Node{}
}

// derefBaseTexts collects the base texts of every dereference in a function
// body (field access, subscript, explicit `*p`), keyed by the text the
// dereference detector would attribute.
func derefBaseTexts(fnDef parser.Node) map[string]bool {
	out := map[string]bool{}
	for _, kind := range []string{"field_expression", "subscript_expression", "pointer_expression"} {
		for _, n := range fnDef.FindAll(kind) {
			base := stripCasts(derefBaseChild(n))
			if base.Kind() == "" {
				continue
			}
			out[strings.TrimSpace(base.Text())] = true
		}
	}
	return out
}

// leftmostIdentifier walks a field/subscript chain to its leftmost identifier
// (`resp->hdr->data` → resp, `tree[0].name` → tree).
func leftmostIdentifier(n parser.Node) string {
	for n.Kind() == "field_expression" || n.Kind() == "subscript_expression" ||
		n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
		if n.Kind() == "cast_expression" || n.Kind() == "parenthesized_expression" {
			n = stripCasts(n)
			continue
		}
		base := derefBaseChild(n)
		if base.Kind() == "" {
			return ""
		}
		if base.Kind() == "identifier" {
			return base.Text()
		}
		n = base
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	return ""
}

func findFnDefByName(fnDefs []parser.Node, name string) parser.Node {
	none := parser.Node{}
	for _, fd := range fnDefs {
		if n, _, _ := functionParamNames(fd); n == name {
			return fd
		}
	}
	return none
}
