package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Unchecked external index into a fixed-capacity array.
//
// The constant/loop-bound proof in checkArrayOOB only reports an out-of-bounds
// access it can PROVE. The production shape that matters most — a fixed-size
// array indexed by a struct field that arrives from configuration or input
// (`p->svr[p->actived_index]`) — is neither provable nor safe: the field's
// range is unknown at the access site, so the access is indistinguishable from
// an OOB read until someone validates it. That shape is seeded here at the
// heuristic tier (suspected, handed to the AI agent) with the chain evidence
// the classifier needs:
//
//   - `index_source`: the struct field the index comes from (directly or via a
//     local copy), plus the fact that no bounds check on that value dominates
//     the access;
//   - `elem_field`: the pointer member read from the element itself
//     (`svr[idx].domain`), i.e. an indeterminate pointer taken out of possibly
//     out-of-range memory;
//   - `escape`/`escape_deref`: the element (or its address) is passed to a
//     callee which reads a pointer member from it, the null-deref sink the OOB
//     element feeds.
//
// Volume guards keep this channel from flooding: only struct-field-derived
// indices seed (a plain parameter/local index does not — that is the ordinary
// loop shape), the capacity must be a resolved fixed size, a bounds check at
// least as tight as the capacity in the same function suppresses the access, and
// duplicates of the same (array, index field) pair inside one function collapse
// into one candidate.

// uncheckedIndexAccess is one subscript access awaiting emission.
type uncheckedIndexAccess struct {
	sub      parser.Node
	array    string
	index    string
	source   string
	kind     string
	size     int
	sizeName string
}

func (d *BufferOverflowDetector) detectUncheckedIndex(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, fnDefs []parser.Node, result *DetectResult) {
	byKey := make(map[string][]uncheckedIndexAccess)
	var order []string

	for _, sub := range bc.subs {
		if !funcLineRange(f, sub.StartLine()) {
			continue
		}
		if strings.Contains(sub.Text(), "sizeof") {
			continue
		}
		array, field, ok := memberSubscriptBase(sub)
		if !ok {
			continue
		}
		index := sub.NamedChildren()[1].Text()
		source, ok := externalIndexSource(bc, f, index, sub.StartLine())
		if !ok {
			continue
		}
		size, sizeName := 0, ""
		if fnDef := findFnDefByName(fnDefs, f.Name); fnDef.Kind() != "" {
			if n, sym, ok := structFieldCapacity(bc, f, fnDef, array, field); ok {
				size, sizeName = n, sym
			}
		}
		if size <= 0 {
			size, sizeName = fieldArrayCapacity(bc, field)
		}
		if size <= 0 {
			continue
		}
		if hasIndexBoundsGuard(bc, f, index, source, size, sub.StartLine()) {
			continue
		}
		kind := subscriptAccessKind(bc, f, sub)
		key := array + "|" + source + "|" + kind
		if _, seen := byKey[key]; !seen {
			order = append(order, key)
		}
		byKey[key] = append(byKey[key], uncheckedIndexAccess{
			sub: sub, array: array, index: index, source: source,
			kind: kind, size: size, sizeName: sizeName,
		})
	}

	for _, key := range order {
		group := byKey[key]
		first := group[0]
		for _, g := range group[1:] {
			if g.sub.StartLine() < first.sub.StartLine() {
				first = g
			}
		}
		props := map[string]string{
			"array":        first.array,
			"index":        first.index,
			"category":     uncheckedIndexCategory(first.kind),
			"expression":   first.sub.Text(),
			"size":         strconv.Itoa(first.size),
			"index_source": first.source,
		}
		if first.sizeName != "" {
			props["capacity_symbol"] = first.sizeName
		}
		if elem, ok := elementPointerField(bc, first.sub); ok {
			props["elem_field"] = elem
		}
		escape, deref := escapedElementDeref(bc, fnDefs, group)
		if escape != "" {
			props["escape"] = escape
		}
		if deref != "" {
			props["escape_deref"] = deref
		}
		if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: first.sub.StartLine()}, props) {
			result.EventsCreated++
		}
	}
}

func uncheckedIndexCategory(kind string) string {
	if kind == "write" {
		return "array_oob_write_unchecked"
	}
	return "array_oob_read_unchecked"
}

// memberSubscriptBase returns the base text and array field of a STRUCT MEMBER
// array subscript (`p->svr[i]` → "p->svr", "svr"), ok=false for a bare-array
// subscript (that path is served by checkArrayOOB).
func memberSubscriptBase(sub parser.Node) (string, string, bool) {
	children := sub.NamedChildren()
	if len(children) < 2 || children[0].Kind() != "field_expression" {
		return "", "", false
	}
	fe := children[0]
	kids := fe.NamedChildren()
	if len(kids) < 2 || kids[0].Kind() != "identifier" {
		return "", "", false
	}
	for _, c := range kids[1:] {
		if c.Kind() == "field_identifier" {
			return strings.TrimSpace(fe.Text()), c.Text(), true
		}
	}
	return "", "", false
}

// fieldArrayCapacity resolves the element count of a struct member array FIELD
// (numeric literal or object-like macro). The field name alone does not identify
// the struct, so the size is returned only when every declaration of that field
// agrees; sizeName reports the macro spelling when the declarator used one (it
// is the symbol a bounds check compares against). A struct declared in an
// included header — the normal C layout — is resolved through the tree-wide
// census, so `p->svr[p->idx]` is analyzed even when the struct is not in this
// translation unit''s file.
func fieldArrayCapacity(bc *bufCtx, field string) (int, string) {
	if size, symbol := fieldArrayCapacityLocal(bc, field); size > 0 {
		return size, symbol
	}
	if ff, ok := bc.facts.FieldByName(field); ok && ff.Array && ff.Count > 0 {
		return ff.Count, ff.Symbol
	}
	return 0, ""
}

// fieldArrayCapacityLocal resolves the capacity from the CURRENT file's field
// declarations (the fast path). A struct declared in a header is served by the
// tree-wide fallback in fieldArrayCapacity.
func fieldArrayCapacityLocal(bc *bufCtx, field string) (int, string) {
	sizes := map[int]bool{}
	symbol := ""
	for _, fd := range bc.fields {
		for _, ad := range fd.FindAll("array_declarator") {
			if arrayDeclaratorName(ad) != field {
				continue
			}
			for _, child := range ad.NamedChildren() {
				switch child.Kind() {
				case "number_literal":
					if n := parseConstantIndex(child.Text()); n > 0 {
						sizes[n] = true
					}
				case "identifier":
					if n, ok := bc.macros[child.Text()]; ok && n > 0 {
						sizes[n] = true
						symbol = child.Text()
					}
				}
			}
		}
	}
	if len(sizes) != 1 {
		return 0, ""
	}
	for n := range sizes {
		return n, symbol
	}
	return 0, ""
}

// externalIndexSource reports the struct FIELD an index value comes from, or
// ok=false when the index is not field-derived. It accepts a direct field read
// (`p->idx`, `p.idx`, optionally cast) and one level of local copy
// (`unsigned int i = p->idx; arr[i]`), which is the production spelling.
func externalIndexSource(bc *bufCtx, f *db.Function, indexExpr string, line int) (string, bool) {
	if field, ok := fieldAccessField(strings.TrimSpace(stripCast(indexExpr))); ok {
		return field, true
	}
	if !isBareIdent(strings.TrimSpace(indexExpr)) {
		return "", false
	}
	indexVar := strings.TrimSpace(indexExpr)
	bestLine := -1
	bestField := ""
	consider := func(node parser.Node) {
		if node.StartLine() >= line || !funcLineRange(f, node.StartLine()) {
			return
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok || assignedVariable(lhs) != indexVar {
			return
		}
		field, ok := fieldAccessField(stripCast(strings.TrimSpace(rhs.Text())))
		if !ok {
			return
		}
		if node.StartLine() > bestLine {
			bestLine = node.StartLine()
			bestField = field
		}
	}
	for _, init := range bc.inits {
		consider(init)
	}
	for _, assign := range bc.assigns {
		consider(assign)
	}
	if bestField == "" {
		return "", false
	}
	return bestField, true
}

// stripCast removes a leading C cast `(type)` from an expression so the
// underlying field read is still recognized (`(unsigned int)p->idx`).
func stripCast(text string) string {
	text = strings.TrimSpace(text)
	for strings.HasPrefix(text, "(") {
		depth := 0
		end := -1
		for i, r := range text {
			if r == '(' {
				depth++
			} else if r == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return text
		}
		inner := strings.TrimSpace(text[1:end])
		if inner == "" || strings.ContainsAny(inner, "&|!<>=+-*/") {
			return text
		}
		text = strings.TrimSpace(text[end+1:])
	}
	return text
}

// fieldAccessField returns the member name of `x->f` / `x.f`, ok=false otherwise.
func fieldAccessField(text string) (string, bool) {
	if idx := strings.LastIndex(text, "->"); idx > 0 {
		f := strings.TrimSpace(text[idx+2:])
		if isBareIdent(f) {
			return f, true
		}
		return "", false
	}
	if idx := strings.LastIndex(text, "."); idx > 0 {
		f := strings.TrimSpace(text[idx+1:])
		if isBareIdent(f) {
			return f, true
		}
	}
	return "", false
}

// hasIndexBoundsGuard reports whether a bounds check covering the capacity
// dominates this access. Only the two idiomatic shapes count, with the real
// capacity as the bound:
//
//   - exit-on-violation: `if (idx >= CAP) return;` (also `idx > CAP-1`), where
//     the failing branch exits and the surviving values are < CAP;
//   - positive guard: `if (idx < CAP) { use }` (also `idx <= CAP-1`), or the
//     same condition with an exiting `else`, where the access sits on the
//     guarded side.
//
// A guard against a bound LARGER than the capacity (`idx >= 8` for a 4-element
// array) still admits out-of-range values, so it is not a guard; an unrelated
// `if (x < 8)` does not reference the index at all.
func hasIndexBoundsGuard(bc *bufCtx, f *db.Function, indexExpr, sourceField string, size, line int) bool {
	tokens := []string{strings.TrimSpace(indexExpr), sourceField}
	for _, ifn := range bc.ifs {
		if ifn.StartLine() < f.StartLine || ifn.StartLine() >= line {
			continue
		}
		cond := ifn.ChildByFieldName("condition")
		if cond == nil || !isRelationalCondition(cond.Text()) {
			continue
		}
		op, bound, ok := guardTerm(cond.Text(), tokens, bc.macros)
		if !ok {
			continue
		}
		cons := ifn.ChildByFieldName("consequence")
		alt := ifn.ChildByFieldName("alternative")
		inConsequence := cons != nil && line >= cons.StartLine() && line <= cons.EndLine()
		switch op {
		case ">=":
			// Surviving values are < bound, so the check only protects the
			// array when the bound is not larger than its capacity.
			if bound <= size && cons != nil && bodyExits(*cons) && !inConsequence {
				return true
			}
		case ">":
			if bound < size && cons != nil && bodyExits(*cons) && !inConsequence {
				return true
			}
		case "<":
			if bound <= size && (inConsequence || (alt != nil && bodyExits(*alt))) {
				return true
			}
		case "<=":
			if bound < size && (inConsequence || (alt != nil && bodyExits(*alt))) {
				return true
			}
		}
	}
	return false
}

// guardTerm parses one relational comparison between an index token and a
// constant/macro bound from a condition (`idx >= COUNT`, `(COUNT > idx)`).
func guardTerm(condText string, tokens []string, macros map[string]int) (string, int, bool) {
	cond := strings.Join(strings.Fields(condText), "")
	for _, tok := range tokens {
		t := strings.Join(strings.Fields(tok), "")
		if t == "" {
			continue
		}
		for _, op := range []string{">=", "<=", ">", "<"} {
			if i := strings.Index(cond, t+op); i >= 0 {
				if v, ok := leadingBound(cond[i+len(t)+len(op):], macros); ok {
					return op, v, true
				}
			}
			if i := strings.Index(cond, op+t); i >= 0 {
				if v, ok := trailingBound(cond[:i], macros); ok {
					return reverseOp(op), v, true
				}
			}
		}
	}
	return "", 0, false
}

func reverseOp(op string) string {
	switch op {
	case ">=":
		return "<="
	case "<=":
		return ">="
	case ">":
		return "<"
	case "<":
		return ">"
	}
	return op
}

// leadingBound resolves the constant/macro at the start of text.
func leadingBound(text string, macros map[string]int) (int, bool) {
	name := ""
	for _, r := range text {
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			name += string(r)
			continue
		}
		break
	}
	return resolveBound(name, macros)
}

// trailingBound resolves the constant/macro at the end of text.
func trailingBound(text string, macros map[string]int) (int, bool) {
	name := ""
	for i := len(text) - 1; i >= 0; i-- {
		r := rune(text[i])
		if r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			name = string(r) + name
			continue
		}
		break
	}
	return resolveBound(name, macros)
}

func resolveBound(name string, macros map[string]int) (int, bool) {
	if name == "" {
		return 0, false
	}
	if v, ok := macros[name]; ok {
		return v, true
	}
	if v := parseConstantIndex(name); v >= 0 {
		return v, true
	}
	return 0, false
}

// elementPointerField returns the member read from the indexed element when the
// subscript is the base of a field access (`svr[idx].domain` / `svr[idx]->domain`).
func elementPointerField(bc *bufCtx, sub parser.Node) (string, bool) {
	p := sub.Parent()
	if p == nil || p.Kind() != "field_expression" {
		return "", false
	}
	kids := p.NamedChildren()
	if len(kids) < 2 || !sameNode(kids[0], sub) {
		return "", false
	}
	for _, c := range kids[1:] {
		if c.Kind() != "field_identifier" {
			continue
		}
		if isPointerTypedField(bc, c.Text()) {
			return c.Text(), true
		}
	}
	return "", false
}

// isPointerTypedField reports whether a struct field is declared through a
// pointer declarator (`const char *domain`, `void *ctx`). The declarator is
// nested, so findFieldTypeName (which matches direct field_identifier children)
// cannot see it. Unknown fields are treated as non-pointer so the chain hint
// stays honest.
func isPointerTypedField(bc *bufCtx, field string) bool {
	for _, fd := range bc.fields {
		for _, pd := range fd.FindAll("pointer_declarator") {
			if arrayDeclaratorName(pd) == field {
				return true
			}
		}
	}
	if ff, ok := bc.facts.FieldByName(field); ok {
		return ff.Pointer
	}
	return false
}

// escapedElementDeref reports the callee that receives the out-of-bounds
// element (by value or address) and the pointer member that callee reads from
// it — the null-deref sink the OOB element feeds. Only callees DEFINED in the
// same file can be followed; an external callee still yields its name so the
// classifier knows the element escapes.
func escapedElementDeref(bc *bufCtx, fnDefs []parser.Node, group []uncheckedIndexAccess) (string, string) {
	// An element passed BY ADDRESS (`&p->svr[idx]`) escapes as a pointer: the
	// callee can dereference any member of a possibly out-of-range element, so
	// that is the strongest chain link. Prefer it over a by-value argument
	// (`p->svr[idx].domain`) and keep the source order within each class.
	ordered := make([]uncheckedIndexAccess, 0, len(group))
	for _, g := range group {
		if subscriptAddressed(g.sub) {
			ordered = append(ordered, g)
		}
	}
	for _, g := range group {
		if !subscriptAddressed(g.sub) {
			ordered = append(ordered, g)
		}
	}
	for _, g := range ordered {
		call, argIdx, ok := enclosingCallArgument(g.sub)
		if !ok {
			continue
		}
		callee := calleeName(call)
		if callee == "" {
			continue
		}
		fnDef := findFnDefByName(fnDefs, callee)
		if fnDef.Kind() == "" {
			return callee, ""
		}
		_, names, _ := functionParamNames(fnDef)
		if argIdx >= len(names) {
			return callee, ""
		}
		param := names[argIdx]
		member, line, ok := paramPointerMemberRead(bc, fnDef, param)
		if !ok {
			return callee, ""
		}
		return callee, member + "@" + strconv.Itoa(line)
	}
	return "", ""
}

// paramPointerMemberRead returns the first pointer-typed member read
// (`param->field`) inside a callee body.
func paramPointerMemberRead(bc *bufCtx, fnDef parser.Node, param string) (string, int, bool) {
	for _, fe := range fnDef.FindAll("field_expression") {
		base, field := directFieldAccess(fe)
		if base != param || field == "" {
			continue
		}
		if isPointerTypedField(bc, field) {
			return field, fe.StartLine(), true
		}
	}
	return "", 0, false
}

// enclosingCallArgument walks up from a node to the call argument that contains
// it, returning the call node and the argument index.
func enclosingCallArgument(node parser.Node) (parser.Node, int, bool) {
	for p := node.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "argument_list" {
			call := p.Parent()
			if call == nil || call.Kind() != "call_expression" {
				return parser.Node{}, 0, false
			}
			for i, arg := range p.NamedChildren() {
				if containsNode(arg, node) {
					return *call, i, true
				}
			}
			return *call, 0, false
		}
		switch p.Kind() {
		case "function_definition", "declaration", "expression_statement", "compound_statement":
			return parser.Node{}, 0, false
		}
	}
	return parser.Node{}, 0, false
}

func containsNode(outer, inner parser.Node) bool {
	if outer.StartByte() <= inner.StartByte() && outer.EndByte() >= inner.EndByte() {
		return true
	}
	return false
}

// subscriptAddressed reports whether a subscript is passed by address
// (`&arr[idx]`, optionally cast/parenthesized) rather than by value.
func subscriptAddressed(sub parser.Node) bool {
	for p := sub.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "cast_expression", "parenthesized_expression":
			continue
		case "pointer_expression":
			return strings.HasPrefix(strings.TrimSpace(p.Text()), "&")
		default:
			return false
		}
	}
	return false
}
