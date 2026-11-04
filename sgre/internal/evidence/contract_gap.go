package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// ContractGapDetector closes the OPEN-WORLD half of the "function entry
// validation" gap: a struct-pointer parameter's field is dereferenced without a
// null guard, yet the field's nullness is caller/framework-supplied (the field
// is never written inside the function, so the intra-procedural null-deref
// pipeline has no source to prove) AND the code itself treats the field as
// nullable somewhere. This is the "implicit contract" candidate the guide
// describes; it is deliberately NOT a provable null-deref — those stay in
// null-deref (CWE-476).
//
// Evidence (at least one required, else no candidate):
//   - E-b self: the function null-checks the field on another path;
//   - E-a sibling: another function with the SAME parameter struct type
//     null-checks the same field (type-anchored cross-function contract);
//   - E-c caller: a caller null-checks the field before the call (planner filter
//     re-verifies and suppresses when ALL callers validate).
//
// Deterministic cuts live here and in the planner filter so the AI only ever
// sees the small open-world residual:
//   - a field WRITTEN inside the function is function-controlled, so null-deref
//     owns it (skipped here — no double report);
//   - reachability and guard dominance are re-verified in ContractGapFilter.
type ContractGapDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewContractGapDetector(store db.Store, p *parser.Parser, logger *log.Logger) *ContractGapDetector {
	return &ContractGapDetector{store: store, parser: p, logger: logger}
}

func (d *ContractGapDetector) Name() string { return "contract_gap" }

func (d *ContractGapDetector) Domain() string { return "contract" }

func (d *ContractGapDetector) Capabilities() []string {
	return []string{"entry-validation", "implicit-contract", "pointer-field-null"}
}

// candidateField is one intra-procedural candidate collected in pass 1.
type candidateField struct {
	fn        *db.Function
	file      *db.File
	obj       string
	objType   string
	field     string
	sites     []derefSite
	selfGuard bool
	// guardLine is the line of the same-function NULL check that guards the
	// field (0 = no self-guard). The deref site sits OUTSIDE this guard's scope,
	// which is the contract gap; surfacing the line lets the classifier see the
	// guard structure without a source read.
	guardLine int
}

type fieldAccess struct {
	base  string
	field string
}

type derefSite struct {
	line  int
	text  string
	count string
}

func (d *ContractGapDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Pass 1: intra-procedural candidate collection (deref + E-b + not-written).
	var cands []candidateField
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		fieldExprs := root.FindAll("field_expression")
		subs := root.FindAll("subscript_expression")
		ptrExprs := root.FindAll("pointer_expression")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		loops := root.FindAll("for_statement")
		loops = append(loops, root.FindAll("while_statement")...)
		comparisons := root.FindAll("binary_expression")

		for _, f := range funcs {
			cands = append(cands, d.collectFunctionCandidates(f, file, funcDefs, fieldExprs, subs, ptrExprs, assigns, inits, loops, comparisons)...)
		}
	})
	if err != nil {
		return result, err
	}

	// Cross-function contract evidence.
	sibling := d.collectSiblingContracts(ctx)

	// Pass 2: emit when E-b (self) or E-a (sibling) evidence is present. The
	// evidence is tiered by strength because the planner pre-dismisses the weak
	// tiers (issue #200):
	//   - "sibling": another function in the SAME FILE with the same parameter
	//     struct type null-checks the field — the same-TU comparison that proves
	//     the missing guard is an omission, not the project's design;
	//   - "self": only this function checks the field somewhere (its own guard
	//     does not dominate the deref) — a scope-gap hypothesis, not a sibling
	//     reference, and the production-scan weak tier;
	//   - "sibling-weak": a type-anchored guard in ANOTHER FILE only — the
	//     unrelated-TU evidence that dominated the production candidate count
	//     with ~2% precision.
	// All three are emitted so the planner's dismissal is ledgered instead of a
	// silent seed-time drop.
	for _, cand := range cands {
		evidence := ""
		var sib siblingGuard
		if g := firstForeignGuard(sibling.sameFile[cand.file.ID][cand.objType][cand.field], cand.fn.Name); g.fnName != "" {
			evidence, sib = "sibling", g
		} else if cand.selfGuard {
			evidence = "self"
		} else if g := firstForeignGuard(sibling.crossFile[cand.objType][cand.field], cand.fn.Name); g.fnName != "" {
			evidence, sib = "sibling-weak", g
		}
		if evidence == "" {
			continue
		}
		for _, site := range cand.sites {
			props := map[string]interface{}{
				"category":   "ptr_guard",
				"variable":   cand.obj + "->" + cand.field,
				"subject":    cand.obj,
				"count":      site.count,
				"use_line":   site.line,
				"missing":    "ptr-null",
				"evidence":   evidence,
				"expression": site.text,
			}
			// The self-guard's line: the field IS null-checked there, but this
			// deref site sits outside that guard's scope — the contract gap.
			if cand.selfGuard && cand.guardLine > 0 {
				props["guard_line"] = cand.guardLine
			}
			if sib.fnName != "" {
				props["sibling_function"] = sib.fnName
				props["sibling_guard_line"] = sib.line
			}
			if emitEvent(ctx, d.store, d.logger, "CONTRACT_GAP", cand.fn.ID, &db.Location{FileID: cand.file.ID, Line: site.line, Column: 1}, props) {
				result.EventsCreated++
			}
		}
	}
	return result, nil
}

// collectFunctionCandidates returns the candidate fields of one function.
func (d *ContractGapDetector) collectFunctionCandidates(f *db.Function, file *db.File, funcDefs, fieldExprs, subs, ptrExprs, assigns, inits, loops, comparisons []parser.Node) []candidateField {
	names, types := functionParamNamesFor(funcDefs, f.StartLine)
	if len(names) == 0 {
		return nil
	}
	typeByName := make(map[string]string, len(names))
	paramSet := make(map[string]bool, len(names))
	for i, n := range names {
		if n == "" || n == "..." {
			continue
		}
		paramSet[n] = true
		if i < len(types) {
			typeByName[n] = types[i]
		}
	}

	accesses := collectFieldAccesses(f, fieldExprs)
	written := writtenFields(f, assigns, inits)

	byBase := map[string][]fieldAccess{}
	for _, a := range accesses {
		if !paramSet[a.base] {
			continue
		}
		byBase[a.base] = append(byBase[a.base], a)
	}

	var out []candidateField
	for obj, accs := range byBase {
		for _, a := range accs {
			field := a.field
			if written[obj+"->"+field] {
				continue
			}
			derived := derivedLocals(f, obj, field, assigns, inits)
			sites := fieldDerefSites(f, obj, field, derived, fieldExprs, subs, ptrExprs)
			if len(sites) == 0 {
				continue
			}
			for i := range sites {
				countField, _ := countFieldGates(f, obj, field, sites[i].line, accesses, loops, subs)
				sites[i].count = countField
			}
			selfGuard, guardLine := fieldNullChecked(f, obj, field, derived, comparisons)
			out = append(out, candidateField{
				fn:        f,
				file:      file,
				obj:       obj,
				objType:   typeByName[obj],
				field:     field,
				sites:     sites,
				selfGuard: selfGuard,
				guardLine: guardLine,
			})
		}
	}
	return out
}

// siblingGuard names the function whose null check proves the field is treated
// as nullable, and the guard line.
type siblingGuard struct {
	fnName string
	line   int
}

// siblingContracts is the tiered E-a cross-function evidence index: the guard
// in the SAME translation unit (strong: the same file's functions share the
// project/struct convention, so an unguarded sibling is an omission) and the
// guard found only in another file (weak type-anchored evidence). Production
// triage showed the same-file split is the real discriminator: the four real
// implicit-contract findings all live beside a same-file guarded sibling.
type siblingContracts struct {
	sameFile  map[int64]map[string]map[string][]siblingGuard
	crossFile map[string]map[string][]siblingGuard
}

// firstForeignGuard returns the first guard whose function is not fnName: the
// candidate's own check is the "self" tier, not sibling evidence.
func firstForeignGuard(guards []siblingGuard, fnName string) siblingGuard {
	for _, g := range guards {
		if g.fnName != "" && g.fnName != fnName {
			return g
		}
	}
	return siblingGuard{}
}

// collectSiblingContracts builds the E-a cross-function contract index:
// parameter struct type (normalized type spelling, e.g. "Nac_LdapSearchAckMsg_t *")
// -> field name -> a function with that parameter type null-checks the field.
// It is type-anchored, never name-guessed across unrelated structs, and keeps
// the same-file and cross-file tiers separate.
func (d *ContractGapDetector) collectSiblingContracts(ctx context.Context) siblingContracts {
	out := siblingContracts{
		sameFile:  map[int64]map[string]map[string][]siblingGuard{},
		crossFile: map[string]map[string][]siblingGuard{},
	}
	_ = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		comparisons := root.FindAll("binary_expression")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		for _, f := range funcs {
			names, types := functionParamNamesFor(funcDefs, f.StartLine)
			typeByName := make(map[string]string, len(names))
			paramSet := make(map[string]bool, len(names))
			for i, n := range names {
				if n == "" || n == "..." {
					continue
				}
				paramSet[n] = true
				if i < len(types) {
					typeByName[n] = types[i]
				}
			}
			// A guard on a LOCAL derived from the field (`tree = resp->group_data;
			// if (tree == NULL)`) is a guard of the same field's nullability. Follow
			// those aliases so the sibling proof is not limited to direct
			// `obj->field == NULL` checks — the same resolution the self-guard
			// evidence already uses.
			localOrigins := functionLocalFieldOrigins(f, paramSet, assigns, inits)
			for _, be := range comparisons {
				if !funcLineRange(f, be.StartLine()) {
					continue
				}
				op := parser.BinaryOperator(be)
				if op != "==" && op != "!=" {
					continue
				}
				hasNull := false
				for _, opNode := range be.NamedChildren() {
					if parser.IsNullOperand(opNode) {
						hasNull = true
						break
					}
				}
				if !hasNull {
					continue
				}
				for _, opNode := range be.NamedChildren() {
					if parser.IsNullOperand(opNode) {
						continue
					}
					base, field := "", ""
					switch opNode.Kind() {
					case "field_expression":
						base, field = directFieldAccess(opNode)
						if base == "" || !paramSet[base] {
							base = ""
						}
					case "identifier":
						if o, ok := localOrigins[opNode.Text()]; ok {
							base, field = o.base, o.field
						}
					}
					if base == "" || field == "" {
						continue
					}
					t := typeByName[base]
					if t == "" {
						continue
					}
					guard := siblingGuard{fnName: f.Name, line: be.StartLine()}
					if out.sameFile[file.ID] == nil {
						out.sameFile[file.ID] = map[string]map[string][]siblingGuard{}
					}
					if out.sameFile[file.ID][t] == nil {
						out.sameFile[file.ID][t] = map[string][]siblingGuard{}
					}
					out.sameFile[file.ID][t][field] = append(out.sameFile[file.ID][t][field], guard)
					if out.crossFile[t] == nil {
						out.crossFile[t] = map[string][]siblingGuard{}
					}
					out.crossFile[t][field] = append(out.crossFile[t][field], guard)
				}
			}
		}
	})
	return out
}

// fieldOrigin is the (parameter, field) a local was derived from.
type fieldOrigin struct {
	base  string
	field string
}

// functionLocalFieldOrigins maps each local identifier in f assigned a
// parameter field's value (`tree = resp->group_data`, `tree = (T
// *)(resp->group_data)`) to that origin, so a NULL check on the local counts as
// a check of the field.
func functionLocalFieldOrigins(f *db.Function, paramSet map[string]bool, assigns, inits []parser.Node) map[string]fieldOrigin {
	out := map[string]fieldOrigin{}
	record := func(lhs, rhs parser.Node) {
		// The declarator may be a pointer declarator (`p17_node_t *tree = ...`),
		// so extractVarName (not lhs.Kind()=="identifier") resolves the local.
		name := extractVarName(lhs)
		if name == "" {
			return
		}
		base, field := derivedFieldOrigin(rhs)
		if base == "" || field == "" || !paramSet[base] {
			return
		}
		if _, seen := out[name]; !seen {
			out[name] = fieldOrigin{base: base, field: field}
		}
	}
	for _, a := range assigns {
		if !funcLineRange(f, a.StartLine()) {
			continue
		}
		if lhs, rhs, ok := a.AssignParts(); ok {
			record(lhs, rhs)
		}
	}
	for _, d := range inits {
		if !funcLineRange(f, d.StartLine()) {
			continue
		}
		if lhs, rhs, ok := d.AssignParts(); ok {
			record(lhs, rhs)
		}
	}
	return out
}

// derivedFieldOrigin extracts (base, field) from an expression that is a field
// read, optionally wrapped in parentheses or a cast (`(T *)(base->field)`).
func derivedFieldOrigin(n parser.Node) (string, string) {
	switch n.Kind() {
	case "field_expression":
		return directFieldAccess(n)
	case "parenthesized_expression", "cast_expression":
		for _, c := range n.NamedChildren() {
			if c.Kind() == "type_descriptor" {
				continue
			}
			if base, field := derivedFieldOrigin(c); base != "" {
				return base, field
			}
		}
	}
	return "", ""
}

// functionParamNamesFor returns the (names, types) of the function whose
// definition starts at startLine, reusing functionParamNames from caller_null.go.
func functionParamNamesFor(funcDefs []parser.Node, startLine int) ([]string, []string) {
	for _, def := range funcDefs {
		if def.StartLine() != startLine {
			continue
		}
		_, names, types := functionParamNames(def)
		return names, types
	}
	return nil, nil
}

// collectFieldAccesses returns every `base->field` access inside f whose base is
// a bare identifier (a struct/union pointer member read).
func collectFieldAccesses(f *db.Function, fieldExprs []parser.Node) []fieldAccess {
	seen := map[string]bool{}
	var out []fieldAccess
	for _, fe := range fieldExprs {
		if !funcLineRange(f, fe.StartLine()) {
			continue
		}
		base, field := directFieldAccess(fe)
		if base == "" || field == "" {
			continue
		}
		key := base + "->" + field
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fieldAccess{base: base, field: field})
	}
	return out
}

// directFieldAccess returns (base, field) when fe is `base->field` with a bare
// identifier base (`obj->group_data` → obj, group_data). A nested access
// (`obj->a->b`) has a field_expression base and is rejected so only the innermost
// direct member read is matched.
func directFieldAccess(fe parser.Node) (string, string) {
	if fe.Kind() != "field_expression" {
		return "", ""
	}
	kids := fe.NamedChildren()
	if len(kids) < 2 || kids[0].Kind() != "identifier" {
		return "", ""
	}
	base := kids[0].Text()
	for _, c := range kids[1:] {
		if c.Kind() == "field_identifier" {
			return base, c.Text()
		}
	}
	return "", ""
}

// writtenFields returns the set of `base->field` locations ASSIGNED inside f.
func writtenFields(f *db.Function, assigns, inits []parser.Node) map[string]bool {
	out := make(map[string]bool)
	add := func(n parser.Node) {
		lhs, _, ok := n.AssignParts()
		if !ok {
			return
		}
		base, field := directFieldAccess(lhs)
		if base != "" && field != "" {
			out[base+"->"+field] = true
		}
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			add(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			add(i)
		}
	}
	return out
}

// derivedLocals returns the set of local variable names assigned `obj->field`
// (or a cast/paren wrapper) — `p = obj->P` or `p = (T*)obj->P`.
func derivedLocals(f *db.Function, obj, field string, assigns, inits []parser.Node) map[string]bool {
	out := make(map[string]bool)
	add := func(n parser.Node) {
		lhs, rhs, ok := n.AssignParts()
		if !ok {
			return
		}
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		if rhsDerivesFromField(rhs, obj, field) {
			out[name] = true
		}
	}
	for _, a := range assigns {
		if funcLineRange(f, a.StartLine()) {
			add(a)
		}
	}
	for _, i := range inits {
		if funcLineRange(f, i.StartLine()) {
			add(i)
		}
	}
	return out
}

// rhsDerivesFromField reports whether rhs is `obj->field` possibly wrapped in
// parentheses/casts.
func rhsDerivesFromField(rhs parser.Node, obj, field string) bool {
	switch rhs.Kind() {
	case "field_expression":
		b, fl := directFieldAccess(rhs)
		return b == obj && fl == field
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if rhsDerivesFromField(c, obj, field) {
				return true
			}
		}
	}
	return false
}

// fieldDerefSites returns every line where `obj->field` (or a derived local) is
// dereferenced: `obj->P->x`, `obj->P[i]`, `*obj->P`, or `p->x` / `p[i]` / `*p`.
func fieldDerefSites(f *db.Function, obj, field string, derived map[string]bool, fieldExprs, subs, ptrExprs []parser.Node) []derefSite {
	var out []derefSite
	add := func(line int, text string) {
		if line == 0 {
			return
		}
		for _, s := range out {
			if s.line == line {
				return
			}
		}
		out = append(out, derefSite{line: line, text: text})
	}
	for _, fe := range fieldExprs {
		if !funcLineRange(f, fe.StartLine()) {
			continue
		}
		kids := fe.NamedChildren()
		if len(kids) == 0 {
			continue
		}
		// `obj->field->x`, `(T*)obj->field->x`, `((T*)obj->field)->x`.
		if rhsDerivesFromField(kids[0], obj, field) {
			add(fe.StartLine(), fe.Text())
		}
		if kids[0].Kind() == "identifier" && derived[kids[0].Text()] {
			add(fe.StartLine(), fe.Text())
		}
	}
	for _, s := range subs {
		if !funcLineRange(f, s.StartLine()) {
			continue
		}
		kids := s.NamedChildren()
		if len(kids) == 0 {
			continue
		}
		if rhsDerivesFromField(kids[0], obj, field) {
			add(s.StartLine(), s.Text())
		}
		if kids[0].Kind() == "identifier" && derived[kids[0].Text()] {
			add(s.StartLine(), s.Text())
		}
	}
	for _, pe := range ptrExprs {
		if !funcLineRange(f, pe.StartLine()) {
			continue
		}
		for _, c := range pe.NamedChildren() {
			if rhsDerivesFromField(c, obj, field) {
				add(pe.StartLine(), pe.Text())
			}
			if c.Kind() == "identifier" && derived[c.Text()] {
				add(pe.StartLine(), pe.Text())
			}
		}
	}
	return out
}

// fieldNullChecked reports whether `obj->field` (or a derived local) is compared
// against NULL anywhere in f — the E-b self-guard evidence — and the line of the
// first such check (0 when none).
func fieldNullChecked(f *db.Function, obj, field string, derived map[string]bool, comparisons []parser.Node) (bool, int) {
	for _, be := range comparisons {
		if !funcLineRange(f, be.StartLine()) {
			continue
		}
		op := parser.BinaryOperator(be)
		if op != "==" && op != "!=" {
			continue
		}
		hasNull := false
		hasField := false
		for _, opNode := range be.NamedChildren() {
			if parser.IsNullOperand(opNode) {
				hasNull = true
				continue
			}
			if opNode.Kind() == "field_expression" {
				if b, fl := directFieldAccess(opNode); b == obj && fl == field {
					hasField = true
				}
			}
			if opNode.Kind() == "identifier" && derived[opNode.Text()] {
				hasField = true
			}
		}
		if hasNull && hasField {
			return true, be.StartLine()
		}
	}
	return false, 0
}

// countFieldGates reports whether a count/length field `obj->N` (N != field)
// gates the dereference at derefLine (loop bound / subscript index). It is
// OPTIONAL evidence, never a detection gate.
func countFieldGates(f *db.Function, obj, field string, derefLine int, accesses []fieldAccess, loops, subs []parser.Node) (string, bool) {
	counts := map[string]bool{}
	for _, a := range accesses {
		if a.base == obj && a.field != field {
			counts[a.field] = true
		}
	}
	for n := range counts {
		for _, lp := range loops {
			if !funcLineRange(f, lp.StartLine()) {
				continue
			}
			cond := lp.ChildByFieldName("condition")
			if cond == nil || !condRefersField(*cond, obj, n) {
				continue
			}
			body := lp.ChildByFieldName("body")
			if body != nil && derefLine >= body.StartLine() && derefLine <= body.EndLine() {
				return obj + "->" + n, true
			}
		}
		for _, s := range subs {
			if !funcLineRange(f, s.StartLine()) {
				continue
			}
			if strings.Contains(s.Text(), obj+"->"+n) {
				return obj + "->" + n, true
			}
		}
	}
	return "", false
}

// condRefersField reports whether cond (a loop condition) references `obj->N`.
func condRefersField(cond parser.Node, obj, field string) bool {
	if strings.Contains(cond.Text(), obj+"->"+field) {
		return true
	}
	for _, fe := range cond.FindAll("field_expression") {
		if b, fl := directFieldAccess(fe); b == obj && fl == field {
			return true
		}
	}
	return false
}
