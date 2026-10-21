package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// OpaqueNullDetector closes the null-source gap for code whose type contracts
// are not visible in the scan tree. Tree-sitter recovers the full syntax of a
// function whose parameter uses a third-party typedef (the AST, the deref
// sinks, everything), but the null-deref pipeline only reports a dereference
// a NULL_VALUE source can reach — and the two existing seeding directions both
// need information this code cannot supply:
//
//   - parameters: caller_null synthesizes a source only from an IN-TREE call
//     site. A function called from outside the scan tree (an exported API, a
//     registered callback) has no visible caller, so its parameters have no
//     nullability model at all.
//   - field reads: `tree = (T *)(resp->group_data)` stores a field value of an
//     externally-defined struct. The field's value nullability is unknown, and
//     no seeding path records it.
//
// Both gaps are filled with FAIL-OPEN sources (origin "opaque_param" /
// "opaque_field_read", never definite): the candidate stays suspected and the
// AI judges the contract, mirroring the external_call / assumed-return tiers.
// The domains are deliberately narrow to keep the fail-open surface bounded:
//
//   - opaque_param: a function with ZERO in-tree call sites (an exported API,
//     a registered callback) seeds every dereferenced pointer parameter; a
//     function WITH in-tree callers seeds only an OPAQUE-typed parameter that
//     some call site passes unproven non-null (blocking the planner's
//     onlyUnprovenCallerNullSources dismissal — the volume guard keeps
//     tree-defined types dismissible). Entry guards are not checked here —
//     the planner's path-sensitive guard model kills the source behind
//     `if (p == NULL) return;`, so a guarded body never surfaces.
//   - opaque_field_read: the base parameter's type is not defined anywhere in
//     the scan tree (unknown typedef / struct), so the field VALUE contract is
//     invisible. A locally-defined struct keeps its current behavior (field
//     value flow is a separate analysis). Recorded for a pointer assigned the
//     field read (`p = base->f`, cast allowed) at the assignment line, and for
//     a chained dereference's intermediate value (`base->f1->f2` reads the
//     `base->f1` field value) at function entry.
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

	definedTypes, calleeNames, addrTaken, err := d.collectGlobalFacts(ctx)
	if err != nil {
		return result, err
	}

	// The caller_null seeds (origin "caller_null", variable = the CALLEE's
	// parameter name, entity = the callee's function ID) mark the parameters
	// that at least one in-tree call site passes UNPROVEN non-null. This
	// detector runs in the deferred serial phase after caller_null (see
	// RunAllDetectors), so the events are already in the store.
	callerNullParams, err := d.collectCallerNullParams(ctx)
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		fnDefs := root.FindAll("function_definition")
		for _, f := range funcs {
			fnDef := findFnDefByName(fnDefs, f.Name)
			if fnDef.Kind() == "" {
				continue
			}
			d.seedOpaqueParam(ctx, f, file, fnDef, calleeNames, addrTaken, callerNullParams, definedTypes, &result)
			d.seedOpaqueFieldRead(ctx, f, file, fnDef, definedTypes, &result)
		}
	})
	if err != nil {
		return result, fmt.Errorf("opaque null: %w", err)
	}
	return result, nil
}

// collectCallerNullParams maps a callee function ID to the set of its
// parameter names for which the caller_null detector seeded an unproven
// argument (classifyArg != safe). A literal-NULL caller also lands here, which
// is fine: a definite caller_null source never triggers the dismissal this
// feed exists to block.
func (d *OpaqueNullDetector) collectCallerNullParams(ctx context.Context) (map[int64]map[string]bool, error) {
	events, err := d.store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		return nil, fmt.Errorf("opaque null: list null value events: %w", err)
	}
	out := map[int64]map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if props.Origin != "caller_null" || props.Variable == "" || e.EntityID == 0 {
			continue
		}
		if out[e.EntityID] == nil {
			out[e.EntityID] = map[string]bool{}
		}
		out[e.EntityID][props.Variable] = true
	}
	return out, nil
}

// collectGlobalFacts walks every file once and gathers the tree-wide facts the
// two seeding channels need: which type names are DEFINED in the scan tree
// (typedefs and struct/union/enum definitions), which function names are
// called somewhere in the tree, and which function names are address-taken.
func (d *OpaqueNullDetector) collectGlobalFacts(ctx context.Context) (map[string]bool, map[string]bool, map[string]bool, error) {
	definedTypes := map[string]bool{}
	calleeNames := map[string]bool{}
	addrTaken := map[string]bool{}
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		for _, td := range root.FindAll("type_definition") {
			// The typedef NAME is the trailing type_identifier (after the
			// underlying type): `typedef struct x_struct x_t;` names x_t.
			kids := td.NamedChildren()
			for i := len(kids) - 1; i >= 0; i-- {
				if kids[i].Kind() == "type_identifier" {
					definedTypes[strings.TrimSpace(kids[i].Text())] = true
					break
				}
			}
		}
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
						definedTypes[strings.TrimSpace(c.Text())] = true
						break
					}
				}
			}
		}
		for _, call := range root.FindAll("call_expression") {
			if name := calleeName(call); name != "" {
				calleeNames[name] = true
			}
		}
		for _, unary := range root.FindAll("unary_expression") {
			if !strings.HasPrefix(strings.TrimSpace(unary.Text()), "&") {
				continue
			}
			for _, c := range unary.NamedChildren() {
				if c.Kind() == "identifier" {
					addrTaken[c.Text()] = true
				}
			}
		}
	})
	return definedTypes, calleeNames, addrTaken, err
}

// seedOpaqueParam emits a fail-open null source for pointer parameters whose
// external contract the scan tree cannot see. Two shapes:
//
//   - ZERO in-tree callers (the original channel): a non-static function no
//     in-tree call site names (an exported API, a registered callback, or a
//     static function whose only address-taken use is external). The external
//     contract covers EVERY dereferenced pointer parameter regardless of
//     type visibility — no caller is visible to argue otherwise.
//   - IN-TREE callers, opaque type only: when a call site passes a parameter
//     UNPROVEN non-null (a caller_null seed exists for it) AND the
//     parameter's type is not defined in the scan tree, the fail-open seed
//     must keep the candidate out of the planner's
//     onlyUnprovenCallerNullSources dismissal — otherwise an opaque-type
//     contract would be dropped as an "analyzer limitation" and the report
//     form's parameter positions (resp->group_data) would go dark exactly
//     when the function HAS callers (the production shape). A tree-defined
//     type stays dismissible: that is the candidate-volume guard, so the
//     ordinary in-tree call chain does not explode.
//
// Entry guards are never checked here — the planner's path-sensitive guard
// model kills the source behind `if (p == NULL) return;`.
func (d *OpaqueNullDetector) seedOpaqueParam(ctx context.Context, f *db.Function, file *db.File, fnDef parser.Node, calleeNames, addrTaken map[string]bool, callerNullParams map[int64]map[string]bool, definedTypes map[string]bool, result *DetectResult) {
	if f.Name == "main" {
		return
	}
	hasCallers := calleeNames[f.Name]
	unsafeParams := callerNullParams[f.ID]
	if f.IsStatic && !addrTaken[f.Name] && !hasCallers {
		// Dead code: no caller anywhere, and the name was never taken.
		return
	}
	name, names, types := functionParamNames(fnDef)
	if name == "" {
		return
	}
	derefBases := derefBaseTexts(fnDef)

	seed := func(pname string) {
		if emitEvent(ctx, d.store, d.logger, "NULL_VALUE", f.ID, &db.Location{FileID: file.ID, Line: f.StartLine, Column: 1}, map[string]string{
			"variable": pname,
			"origin":   "opaque_param",
			"definite": "false",
		}) {
			result.EventsCreated++
		}
	}

	if !hasCallers && len(unsafeParams) == 0 {
		for i, pname := range names {
			if pname == "..." {
				continue
			}
			if !strings.HasSuffix(strings.TrimSpace(types[i]), "*") {
				continue
			}
			if !derefBases[pname] {
				continue
			}
			seed(pname)
		}
		return
	}
	for i, pname := range names {
		if pname == "..." {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(types[i]), "*") {
			continue
		}
		if !derefBases[pname] {
			continue
		}
		if unsafeParams[pname] && typeSpellingOpaque(types[i], definedTypes) {
			seed(pname)
		}
	}
}

// seedOpaqueFieldRead emits fail-open null sources for reads of fields whose
// base parameter type is not defined in the scan tree: an assigned pointer
// (`tree = (T *)(resp->group_data)`) gets a source at the assignment line, and
// a chained dereference's intermediate value (`para->orig->base_dn` reads the
// `para->orig` field value) gets one at function entry. Structs defined
// in-tree keep their current behavior.
func (d *OpaqueNullDetector) seedOpaqueFieldRead(ctx context.Context, f *db.Function, file *db.File, fnDef parser.Node, definedTypes map[string]bool, result *DetectResult) {
	_, names, types := functionParamNames(fnDef)
	opaqueParams := map[string]bool{}
	for i, pname := range names {
		if pname == "..." {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(types[i]), "*") {
			continue
		}
		if typeSpellingOpaque(types[i], definedTypes) {
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
