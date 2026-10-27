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
		// Per-file field-reference census: the count field of a count-gated
		// array buffer is usually referenced in the SAME file as the pointer
		// field (the candidate function and its guarded sibling both read
		// `resp->group_num`), so a file-local census is precise enough and
		// avoids cross-file base-name collisions.
		fieldRefs := collectFieldRefs(root)
		fnDefs := root.FindAll("function_definition")
		for _, f := range funcs {
			fnDef := findFnDefByName(fnDefs, f.Name)
			if fnDef.Kind() == "" {
				continue
			}
			d.seedOpaqueFieldRead(ctx, f, file, fnDef, definedTypes, fieldRefs, hasEntryPoint, &result)
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
			// (forward declaration). Opaque unless the specifier has a body —
			// OR the tag it names is defined elsewhere in the tree: the split
			// form `typedef struct Foo Foo_t;` + `struct Foo { ... };` defines
			// the alias through the tag's body, not the typedef's own node.
			hasBody := false
			tagName := ""
			for _, c := range underlying.NamedChildren() {
				switch c.Kind() {
				case "field_declaration_list", "enumerator_list":
					hasBody = true
				case "type_identifier":
					tagName = strings.TrimSpace(c.Text())
				}
			}
			if hasBody || (tagName != "" && definedTypes[tagName]) {
				definedTypes[name] = true
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
func (d *OpaqueNullDetector) seedOpaqueFieldRead(ctx context.Context, f *db.Function, file *db.File, fnDef parser.Node, definedTypes map[string]bool, fieldRefs map[string]map[string]bool, hasEntryPoint bool, result *DetectResult) {
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
	emit := func(variable string, line int, countField string) {
		if variable == "" || emitted[variable] {
			return
		}
		emitted[variable] = true
		props := map[string]string{
			"variable": variable,
			"origin":   "opaque_field_read",
			"definite": "false",
		}
		if countField != "" {
			props["count_field"] = countField
		}
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: line, Column: 1}, props) {
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
			// A count-gated array buffer: `tree = (T *)(resp->group_data)`
			// where `resp->group_num` (or a same-stem count field) is referenced
			// in this file. Record the pairing so the null-deref filter can
			// label the source array-buffer@<count-field> instead of the flat
			// opaque-origin tier.
			countField := countFieldFor(fieldRefs, base, fieldNameOf(inner))
			emit(varName, node.StartLine(), countField)
		}
	}
	for _, assign := range fnDef.FindAll("assignment_expression") {
		checkAssign(assign)
	}
	for _, init := range fnDef.FindAll("init_declarator") {
		checkAssign(init)
	}

	// A chained field dereference `base->f1->f2` (or through a subscript,
	// `base->f1[i]->f2`) dereferences the VALUE of `base->f1`; when base's
	// type is opaque that value's nullability is unknown. The intermediate
	// variable is attributed exactly like the dereference detector attributes
	// it (the outer field's base text), so the planner's reaching analysis
	// matches source to sink.
	for _, fe := range fnDef.FindAll("field_expression") {
		base := stripCasts(derefBaseChild(fe))
		if base.Kind() != "field_expression" && base.Kind() != "subscript_expression" {
			continue
		}
		if root := leftmostIdentifier(base); root != "" && opaqueParams[root] {
			emit(base.Text(), f.StartLine, "")
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

// collectFieldRefs builds a base-identifier → field-name set from every
// field access in a file (`resp->group_num`, `msg.hdr->data`). The census is
// file-local by design: the count field of a count-gated array buffer is
// usually referenced in the SAME file as the pointer field, and a file-local
// key keeps the base name from colliding across files with unrelated types.
func collectFieldRefs(root parser.Node) map[string]map[string]bool {
	refs := map[string]map[string]bool{}
	for _, fe := range root.FindAll("field_expression") {
		base := leftmostIdentifier(fe)
		field := fieldNameOf(fe)
		if base == "" || field == "" {
			continue
		}
		if refs[base] == nil {
			refs[base] = map[string]bool{}
		}
		refs[base][field] = true
	}
	return refs
}

// fieldNameOf returns the terminal field name of a field/subscript expression
// (`resp->group_data` → "group_data", `resp->group_data[0]` → "group_data"),
// or "" for anything else.
func fieldNameOf(n parser.Node) string {
	if n.Kind() != "field_expression" {
		return ""
	}
	kids := n.NamedChildren()
	if len(kids) == 0 {
		return ""
	}
	last := kids[len(kids)-1]
	if last.Kind() == "field_identifier" {
		return strings.TrimSpace(last.Text())
	}
	return ""
}

// dataFieldSuffixes are the pointer/array-buffer field suffixes the count/data
// pairing strips to find the shared stem (`group_data` → stem `group`).
var dataFieldSuffixes = []string{
	"_data", "_list", "_array", "_buffer", "_buf", "_items", "_entries",
	"_table", "_nodes", "_objs", "_objects", "_elements", "_records",
	"_ptr", "_mem", "_pool", "_info", "_msg", "_pkt", "_head", "_node",
	"_slots", "_cache", "_set", "_vlan", "_rule", "_entry",
}

// countFieldSuffixes are the count/length suffixes that pair with a data
// field's stem (`group_num`, `group_count`, `group_size`, ...).
var countFieldSuffixes = []string{
	"_num", "_count", "_size", "_len", "_cnt", "_total", "_number", "_n",
}

// countFieldFor returns the paired count field spelling (`resp->group_num`)
// when the file references a count field whose stem matches the data field's
// stem, or "". It is the count-gated-array-buffer signal behind the
// array-buffer@<count-field> null-deref tier. The pairing is a NAME heuristic,
// deliberately a label-only refinement (the source stays suspected) — the AI
// verifies the count field actually gates the buffer.
func countFieldFor(fieldRefs map[string]map[string]bool, base, dataField string) string {
	fields := fieldRefs[base]
	if len(fields) == 0 {
		return ""
	}
	stem := ""
	for _, suf := range dataFieldSuffixes {
		if strings.HasSuffix(dataField, suf) {
			if s := strings.TrimSuffix(dataField, suf); s != "" {
				stem = s
				break
			}
		}
	}
	if stem == "" {
		return ""
	}
	for _, suf := range countFieldSuffixes {
		if fields[stem+suf] {
			return base + "->" + stem + suf
		}
	}
	return ""
}
