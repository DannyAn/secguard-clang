package evidence

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

// sizeofTypeName returns the plain type name inside `sizeof(T)` when T is a
// bare type identifier (`sizeof(PacketHeader)` → "PacketHeader"), or "" for any
// other operand (`sizeof(dst)`, `sizeof(*p)`, `sizeof(n)`, `sizeof(int)`'s
// primitive). It feeds the struct-field exact-fit proof: `memcpy(&x->field,
// src, sizeof(T))` where x->field is declared as type T.
func sizeofTypeName(sizeText string) string {
	t := strings.TrimSpace(sizeText)
	if !strings.HasPrefix(t, "sizeof") {
		return ""
	}
	rest := strings.TrimSpace(t[len("sizeof"):])
	rest = strings.Trim(rest, "()")
	rest = strings.TrimSpace(rest)
	// Only a bare identifier could be a typedef/struct type name; a keyword
	// (int/char/struct) or an expression is not a field type we can match.
	if !isBareIdent(rest) || parser.IsCTypeKeyword(rest) {
		return ""
	}
	return rest
}

// fieldAccessName returns the field name of a member access (`x->f`, `x.f` →
// "f"), or "" for a bare identifier.
func fieldAccessName(dst string) string {
	if idx := strings.LastIndex(dst, "->"); idx >= 0 {
		return strings.TrimSpace(dst[idx+2:])
	}
	if idx := strings.LastIndex(dst, "."); idx >= 0 {
		return strings.TrimSpace(dst[idx+1:])
	}
	return ""
}

// findFieldTypeName resolves the declared TYPE of a struct field by scanning the
// file's field_declarations (`struct S { T field; }`). It returns the type
// spelling only when every declaration of that field name agrees on one type
// (mirroring findFieldArraySize's ambiguity guard); otherwise "".
// fieldDeclarationName returns the declared name of a struct field, descending
// pointer/array declarators so `char *b` and `int a[4]` are not invisible.
func fieldDeclarationName(fd parser.Node) string {
	for _, child := range fd.NamedChildren() {
		switch child.Kind() {
		case "field_identifier":
			return child.Text()
		case "pointer_declarator", "array_declarator":
			if name := arrayDeclaratorName(child); name != "" {
				return name
			}
		}
	}
	return ""
}

func findFieldTypeName(bc *bufCtx, field string) string {
	seen := make(map[string]bool)
	var found string
	for _, fd := range bc.fields {
		if fieldDeclarationName(fd) != field {
			continue
		}
		t := typeSpelling(fd)
		if t == "" {
			continue
		}
		seen[t] = true
		found = t
	}
	if len(seen) == 1 {
		return found
	}
	if ff, ok := bc.facts.FieldByName(field); ok {
		return ff.Type
	}
	return ""
}

// arrayDeclaratorName returns the declared name of an array declarator,
// handling both plain identifiers and struct field identifiers
// (field_identifier), which extractDeclaratorName does not cover.
func arrayDeclaratorName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_identifier" {
			return child.Text()
		}
		if child.Kind() == "pointer_declarator" {
			return arrayDeclaratorName(child)
		}
	}
	return ""
}

// subscriptAccessKind reports whether a subscript expression is an assignment
// target (write) or appears on the read side (read).
func subscriptAccessKind(bc *bufCtx, f *db.Function, sub parser.Node) string {
	// Decide read vs write by the AST parent relationship, not a same-line text
	// match. The previous `strings.Contains(children[0].Text(), subText)` matched
	// both subscripts of `a[i] = a[i] + 1` on one line and mis-categorized the
	// read side as a write, routing it to the wrong vuln type (BO-14).
	// `prev` tracks the outermost expression seen so far, so a write through an
	// element member (`p->arr[i].field = x`) is still recognized: the assignment
	// target is the enclosing field_expression, not the subscript itself.
	prev := sub
	for p := sub.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			children := p.NamedChildren()
			if len(children) >= 1 && sameNode(children[0], prev) {
				return "write"
			}
			return "read"
		case "update_expression":
			return "write"
		case "argument_list":
			// A subscript under `&` passed as the DESTINATION of a writer call
			// (`memset(&g_table->slot[i], 0, sizeof(item_t))`) is a WRITE to that
			// element: the callee writes through the address, it does not read the
			// element (issue #261 item 3). Without this, the address-of made the
			// walk fall through to "read" and routed the sibling write to the
			// out-of-bounds READ channel instead of the WRITE channel.
			if argListParentWritesThrough(prev, *p) {
				return "write"
			}
			prev = *p
			continue
		case "binary_expression", "parenthesized_expression", "cast_expression",
			"subscript_expression", "call_expression",
			"field_expression", "pointer_expression", "unary_expression":
			prev = *p
			continue // nested inside a larger expression; keep walking up
		default:
			return "read"
		}
	}
	return "read"
}

// argListParentWritesThrough reports whether the argument node `prev` is the
// FIRST argument of `argList` and the enclosing call is a dest-writer
// (memset/memcpy/strcpy/...): those write through arg 0, so a subscript (or an
// `&subscript`) in that position is a write, not a read.
func argListParentWritesThrough(prev, argList parser.Node) bool {
	parent := argList.Parent()
	if parent == nil || parent.Kind() != "call_expression" {
		return false
	}
	if !isDestWriter(extractCallName(*parent)) {
		return false
	}
	children := argList.NamedChildren()
	return len(children) >= 1 && sameNode(children[0], prev)
}

// heapAllocationSize returns the size expression of a variable's
// malloc/calloc/realloc allocation within the function (e.g. "user_len"),
// or false when no allocation is visible.
func heapAllocationSize(bc *bufCtx, f *db.Function, varName string) (string, bool) {
	checkRHS := func(lhsText string, rhs parser.Node) (string, bool) {
		if lhsText != varName {
			return "", false
		}
		call := unwrapAllocationCall(rhs)
		if call == nil {
			return "", false
		}
		name := extractCallName(*call)
		if !apikb.IsAllocator(name) {
			return "", false
		}
		args := callNamedArguments(*call)
		if len(args) == 0 {
			return "", false
		}
		// realloc(p, n): the size is the SECOND argument (the first is the old
		// pointer p) — taking args[0] returned the pointer and made the capacity
		// completely wrong (BO-08). calloc(n, m): args[0] is the ELEMENT COUNT,
		// which is the natural unit for a later p[idx] comparison, so it is kept.
		// malloc(n): args[0] is the byte size.
		if name == "realloc" && len(args) >= 2 {
			return strings.TrimSpace(args[1].Text()), true
		}
		return strings.TrimSpace(args[0].Text()), true
	}

	for _, decl := range bc.inits {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		lhs, rhs, ok := decl.AssignParts()
		if !ok {
			continue
		}
		if expr, ok := checkRHS(extractVarFromDeclarator(lhs), rhs); ok {
			return expr, true
		}
	}
	for _, assign := range bc.assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if expr, ok := checkRHS(children[0].Text(), children[1]); ok {
			return expr, true
		}
	}
	return "", false
}

func unwrapAllocationCall(node parser.Node) *parser.Node {
	if node.Kind() == "call_expression" {
		return &node
	}
	for _, child := range node.NamedChildren() {
		if call := unwrapAllocationCall(child); call != nil {
			return call
		}
	}
	return nil
}

// isLoopBoundOverflowForHeap flags a heap-pointer subscript when the enclosing
// loop bound provably exceeds the allocation size, e.g. `malloc(user_len)`
// with `for (i = 0; i < user_len + 10; i++) buf[i]`.
func isLoopBoundOverflowForHeap(bc *bufCtx, f *db.Function, indexExpr string, line int, allocExpr string) bool {
	for _, forNode := range bc.fors {
		if forNode.StartLine() < f.StartLine || forNode.EndLine() > f.EndLine {
			continue
		}
		if line < forNode.StartLine() || line > forNode.EndLine() {
			continue
		}
		cond := forNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		condText := cond.Text()
		if strings.Contains(condText, "&&") || strings.Contains(condText, "||") {
			continue
		}
		// The subscript index must reference the loop variable (possibly offset).
		// The previous child-scan also matched the loop BODY (`buf[i] = ...`) as an
		// "init", extracting a bogus index and silently skipping the check.
		loopVar := forLoopIndex(forNode)
		if loopVar == "" {
			continue
		}
		if _, ok := indexOffset(indexExpr, loopVar); !ok {
			continue
		}
		bound := extractLoopBound(condText)
		if bound == "" {
			continue
		}
		if allocExpr != "" && strings.Contains(bound, allocExpr) && positiveOffset(bound, allocExpr) > 0 {
			return true
		}
		if constAlloc := parseConstantIndex(allocExpr); constAlloc > 0 {
			if boundConst := parseConstantIndex(bound); boundConst > constAlloc {
				return true
			}
		}
	}
	return false
}

func extractLoopBound(cond string) string {
	for _, op := range []string{"<=", ">=", "<", ">"} {
		if !strings.Contains(cond, op) {
			continue
		}
		parts := strings.SplitN(cond, op, 2)
		if len(parts) != 2 {
			continue
		}
		bound := strings.TrimSpace(parts[1])
		if idx := strings.Index(bound, ";"); idx >= 0 {
			bound = bound[:idx]
		}
		return strings.TrimSpace(bound)
	}
	return ""
}

func extractLoopIndex(init string) string {
	init = strings.SplitN(init, "=", 2)[0]
	fields := strings.Fields(init)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimPrefix(fields[len(fields)-1], "*")
}

func positiveOffset(bound, allocExpr string) int {
	i := strings.Index(bound, allocExpr)
	if i < 0 {
		return 0
	}
	rest := strings.TrimSpace(bound[i+len(allocExpr):])
	if strings.Contains(rest, " - ") {
		return 0
	}
	nums := extractNumbers(rest)
	if len(nums) == 0 {
		return 0
	}
	return nums[0]
}

// suppressExactFitCopy reports whether a sized copy (memcpy/memmove/strncpy/
// strncat) copies exactly as many bytes as the destination was allocated for
// (or fewer: alloc size = copy size + a positive offset). `p = malloc(n);
// memcpy(p, src, n)` is an exact-fit copy and safe, as is `p = malloc(n+1);
// memcpy(p, src, n)`. The check is deliberately conservative: it only fires
// when the destination's allocation size expression is textually equal to, or
// a positive-constant superset of, the copy size expression.
func suppressExactFitCopy(bc *bufCtx, f *db.Function, call parser.Node) bool {
	name := extractCallName(call)
	var sizeIdx int
	switch name {
	case "memcpy", "memmove", "strncpy", "strncat":
		sizeIdx = 2
	default:
		return false // strcpy/strcat carry no size; handled by other rules
	}
	args := callNamedArguments(call)
	if len(args) <= sizeIdx {
		return false
	}
	dstName := strings.TrimSpace(args[0].Text())
	copySize := strings.TrimSpace(args[sizeIdx].Text())
	allocExpr, ok := heapAllocationSize(bc, f, dstName)
	if !ok {
		return false
	}
	allocExpr = strings.TrimSpace(allocExpr)
	if copySize == "" || allocExpr == "" {
		return false
	}
	// Exact fit: malloc(n) then memcpy(..., n).
	if copySize == allocExpr {
		return true
	}
	// Alloc is the copy size plus a positive offset: malloc(n + 1) then
	// memcpy(..., n) fits. Only a leading "+" is trusted as positive here.
	if rest := strings.TrimPrefix(allocExpr, copySize); strings.HasPrefix(strings.TrimSpace(rest), "+") {
		return true
	}
	// Alloc is the copy size scaled by an element size: malloc(n * sizeof(int))
	// then memcpy(..., n) copies n BYTES into n*sizeof(int) BYTES — safe (BO-13).
	// The previous textual compare saw `n` != `n * sizeof(int)` and reported it.
	if rest := strings.TrimSpace(strings.TrimPrefix(allocExpr, copySize)); strings.HasPrefix(rest, "*") {
		return true
	}
	if rest := strings.TrimSpace(strings.TrimSuffix(allocExpr, copySize)); strings.HasSuffix(rest, "*") {
		return true
	}
	return false
}

// suppressReadFamily reports whether a read/recv/fread call is provably bounded
// by the destination's capacity (BO-12):
//
//   - read(fd, buf, sizeof(buf)) / recv(s, buf, sizeof(buf), 0): the sizeof size
//     always fits the buffer;
//   - read(fd, buf, n) with a constant n <= capacity;
//   - fread(buf, size, nmemb, stream) with constant size*nmemb <= capacity.
func (d *BufferOverflowDetector) suppressReadFamily(bc *bufCtx, f *db.Function, call parser.Node, callName string) bool {
	args := callNamedArguments(call)
	var dstArg parser.Node
	var byteSize int // assigned in every non-returning branch; -2 = sizeof(dst)
	switch callName {
	case "read", "recv":
		if len(args) < 3 {
			return false
		}
		dstArg = args[1]
		if strings.HasPrefix(strings.TrimSpace(args[2].Text()), "sizeof") {
			byteSize = -2
		} else if n := parseConstantSize(args[2]); n > 0 {
			byteSize = n
		} else {
			return false
		}
	case "fread":
		if len(args) < 3 {
			return false
		}
		dstArg = args[0]
		n := parseConstantSize(args[1])
		m := parseConstantSize(args[2])
		if n > 0 && m > 0 {
			byteSize = n * m
		} else {
			return false
		}
	default:
		return false
	}
	dstName := extractArgName(dstArg)
	if dstName == "" {
		return false
	}
	if byteSize == -2 {
		return true
	}
	capacity := findArraySize(bc, f, dstName, call.StartLine())
	if capacity <= 0 {
		capacity = constantAllocationSize(bc, f, dstName)
	}
	return capacity > 0 && byteSize <= capacity
}

// sizeofOperandMatches reports whether a sizeof size expression references the
// destination name (`sizeof(dst)`, `sizeof(*dst)`, `sizeof((dst))`). It does not
// match `sizeof(*src)` (a different object) or `sizeof(T)` (an unmatched type).
func sizeofOperandMatches(sizeText, dstName string) bool {
	sizeText = strings.TrimSpace(sizeText)
	if !strings.HasPrefix(sizeText, "sizeof") {
		return false
	}
	rest := strings.TrimSpace(sizeText[len("sizeof"):])
	rest = strings.Trim(rest, "()")
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "*"))
	return rest == dstName
}

// typeIdentifierOf extracts the type name from a declaration spelling
// (`struct maf_rbl_profile *`, `const maf_rbl_profile_t *` → the identifier).
func typeIdentifierOf(spelling string) string {
	t := strings.TrimSpace(spelling)
	for strings.HasSuffix(t, "*") {
		t = strings.TrimSpace(strings.TrimSuffix(t, "*"))
	}
	for _, kw := range []string{"const ", "volatile ", "struct ", "union ", "enum "} {
		t = strings.TrimSpace(strings.TrimPrefix(t, kw))
	}
	if t == "" || strings.ContainsAny(t, "*()[]") {
		return ""
	}
	return t
}

// structFieldCapacity resolves a member array's capacity by the base root's
// declared TYPE: `struct maf_rbl_profile *rbl_profile` + `->svr` looks up the
// layout under the tag, so a same-named field in another struct cannot shadow
// it. Returns ok=false when the type cannot be resolved (the caller falls back
// to the name-based census).
func structFieldCapacity(bc *bufCtx, f *db.Function, fnDef parser.Node, baseExpr, field string) (int, string, bool) {
	if bc == nil || bc.facts == nil || fnDef.Kind() == "" {
		return 0, "", false
	}
	root := leftmostIdentifierText(baseExpr)
	if root == "" {
		return 0, "", false
	}
	var spelling string
	_, names, types := functionParamNames(fnDef)
	for i, n := range names {
		if n == root && i < len(types) {
			spelling = types[i]
			break
		}
	}
	if spelling == "" {
		for _, decl := range bc.decls {
			if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
				continue
			}
			if !declaresVariable(decl, root) {
				continue
			}
			spelling = typeSpelling(decl)
		}
	}
	tag := typeIdentifierOf(spelling)
	if tag == "" {
		return 0, "", false
	}
	ff, ok := bc.facts.FieldByTag(tag, field)
	if !ok || !ff.Array || ff.Count <= 0 {
		return 0, "", false
	}
	return ff.Count, ff.Symbol, true
}

// leftmostIdentifierText returns the root identifier of a member/subscript chain
// (`rbl_profile->svr` → rbl_profile).
func leftmostIdentifierText(expr string) string {
	base := strings.TrimSpace(expr)
	for _, sep := range []string{"->", ".", "["} {
		if i := strings.Index(base, sep); i > 0 {
			base = base[:i]
		}
	}
	base = strings.TrimSpace(base)
	if base == "" || strings.ContainsAny(base, " ()&*[],") {
		return ""
	}
	return base
}

// declaresVariable reports whether a declaration declares name.
func declaresVariable(decl parser.Node, name string) bool {
	for _, id := range decl.FindAll("identifier") {
		if strings.TrimSpace(id.Text()) == name {
			return true
		}
	}
	return false
}

// mergeMacros layers the tree-wide macro values under the file's own (the local
// definition wins; the tree fills names the file never defines, e.g. a capacity
// macro from an included header).
func mergeMacros(tree, local map[string]int) map[string]int {
	out := make(map[string]int, len(tree)+len(local))
	for k, v := range tree {
		out[k] = v
	}
	for k, v := range local {
		out[k] = v
	}
	return out
}

// castTarget tracks a pointer that was cast to a struct type from an allocation.
type castTarget struct {
	structType string
	allocSize  int
	castLine   int // 赋值行号；只检查此行之后的 field 访问（P0-5）
}

// detectCastObjectOOB detects layout out-of-bounds accesses through a pointer
// cast to a struct type from an undersized allocation (CWD-SUB-1038).
//
// Pattern: `T *p = (T *)malloc(N)` or `raw = malloc(N); T *p = (T *)raw;`
// followed by `p->field` where field.Offset + field.Size > N.
//
// Phase 1 emits only suspected: the Type Layout census uses
// assumed_default_abi provenance (no compile_commands wiring), so the
// computed sizes are not ABI-proven and must not be confirmed.
//
// P0-5: 只检查 cast 赋值行之后的 field 访问；任何重赋值使记录失效。
// P0-6: 数组字段（ArrayCount > 0）跳过——MVP 不支持数组下标越界判断。
func (d *BufferOverflowDetector) detectCastObjectOOB(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, result *DetectResult) {
	if bc.facts == nil {
		return
	}

	type varEvent struct {
		line    int
		varName string
		rhs     parser.Node
		isInit  bool
	}
	var events []varEvent
	for _, init := range bc.inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		lhs, rhs, ok := init.AssignParts()
		if !ok {
			continue
		}
		events = append(events, varEvent{line: init.StartLine(), varName: extractVarFromDeclarator(lhs), rhs: rhs, isInit: true})
	}
	for _, assign := range bc.assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		events = append(events, varEvent{line: assign.StartLine(), varName: strings.TrimSpace(children[0].Text()), rhs: children[1]})
	}

	// P0-5 / flow-sensitivity: interleave assignments and field accesses in line
	// order. A cast/alloc record is resolved against the allocation state at the
	// cast line (not the function's final map), and an access before the cast or
	// after a reassignment is not checked.
	type accessAt struct {
		line int
		node parser.Node
	}
	var accesses []accessAt
	for _, fe := range bc.fieldExprs {
		if !funcLineRange(f, fe.StartLine()) {
			continue
		}
		// Nested member access `o->inner.a`: the intermediate `o->inner` must not
		// be checked against the whole nested-struct extent. MVP supports one-level
		// fields only, so skip the intermediate expression (and the leaf, whose
		// field lives in the nested struct).
		if p := fe.Parent(); p != nil && p.Kind() == "field_expression" {
			continue
		}
		accesses = append(accesses, accessAt{line: fe.StartLine(), node: fe})
	}

	type timelineItem struct {
		line   int
		access bool
		ev     varEvent
		fe     parser.Node
	}
	items := make([]timelineItem, 0, len(events)+len(accesses))
	for _, ev := range events {
		items = append(items, timelineItem{line: ev.line, ev: ev})
	}
	for _, a := range accesses {
		items = append(items, timelineItem{line: a.line, access: true, fe: a.node})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].line != items[j].line {
			return items[i].line < items[j].line
		}
		// Same line: apply the assignment before the access it produces.
		return !items[i].access && items[j].access
	})

	allocSizes := map[string]int{}
	castVars := map[string]castTarget{}
	for _, it := range items {
		if it.access {
			ptrVar, fieldName, ok := fieldExprParts(it.fe)
			if !ok {
				continue
			}
			info, found := castVars[ptrVar]
			if !found || it.line < info.castLine {
				continue
			}
			layout, ok := bc.facts.LayoutOf(typeinfo.LayoutKey{Type: info.structType})
			if !ok || layout.IsUnknown() {
				continue
			}
			field, ok := layout.FieldByName(fieldName)
			if !ok {
				continue
			}
			// MVP 不支持数组下标越界判断：固定数组与柔性/未知长度数组都跳过。
			// 必须用 IsArray 而不是 ArrayCount>0——柔性数组（int buf[]）的
			// ArrayCount 合法地为 0，按 element size 比较会把 p->buf[i] 误报成
			// 整个数组越界（P0-6 / flex-array follow-up）。
			if field.IsArray {
				continue
			}
			accessEnd := field.Offset + field.Size
			if accessEnd > info.allocSize {
				category := "layout_oob_read"
				if isAssignTarget(it.fe) {
					category = "layout_oob_write"
				}
				d.emitLayoutOOB(ctx, f, file, it.line, ptrVar, fieldName, category, it.fe.Text(), info, field, result)
			}
			continue
		}

		ev := it.ev
		if ev.isInit {
			// A declaration rebinds the name; drop any previous record.
			delete(castVars, ev.varName)
			delete(allocSizes, ev.varName)
		}
		structType, sourceVar, directSize, isDirect := parseCastToStruct(ev.rhs)
		if structType != "" {
			target := castTarget{structType: structType, castLine: ev.line}
			if isDirect && directSize > 0 {
				target.allocSize = directSize
			} else if sourceVar != "" {
				target.allocSize = allocSizes[sourceVar]
			}
			delete(allocSizes, ev.varName)
			if target.allocSize > 0 {
				castVars[ev.varName] = target
			} else {
				delete(castVars, ev.varName)
			}
			continue
		}
		// A non-cast reassignment invalidates the cast record; track the new
		// allocation size only when the RHS is a constant byte-size allocation.
		delete(castVars, ev.varName)
		if size, ok := constantMallocByteSize(ev.rhs); ok {
			allocSizes[ev.varName] = size
		} else {
			delete(allocSizes, ev.varName)
		}
	}
}

// emitLayoutOOB emits a layout out-of-bounds event.
func (d *BufferOverflowDetector) emitLayoutOOB(ctx context.Context, f *db.Function, file *db.File, line int, ptrVar, fieldName, category, text string, info castTarget, field typeinfo.FieldLayout, result *DetectResult) {
	props := map[string]string{
		"array":        ptrVar,
		"index":        fieldName,
		"category":     category,
		"expression":   text,
		"struct_type":  info.structType,
		"alloc_size":   strconv.Itoa(info.allocSize),
		"field_offset": strconv.Itoa(field.Offset),
		"field_size":   strconv.Itoa(field.Size),
	}
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: line}, props) {
		result.EventsCreated++
	}
}

// constantMallocByteSize extracts the constant byte size from a malloc/calloc
// call expression, unwrapping any cast. Returns ok=false for variable sizes
// or sizeof expressions (those need the layout to compare).
func constantMallocByteSize(node parser.Node) (int, bool) {
	operand := node
	for operand.Kind() == "cast_expression" || operand.Kind() == "parenthesized_expression" {
		kids := operand.NamedChildren()
		if len(kids) == 0 {
			return 0, false
		}
		operand = kids[len(kids)-1]
	}
	call := unwrapAllocationCall(operand)
	if call == nil {
		return 0, false
	}
	name := extractCallName(*call)
	if !isByteSizeAllocator(name) {
		return 0, false
	}
	args := callNamedArguments(*call)
	if len(args) == 0 {
		return 0, false
	}
	lower := strings.ToLower(name)
	// `calloc(n, size)` and its wrappers: the byte count is the product of the
	// two arguments, not the first alone.
	if strings.Contains(lower, "calloc") {
		if len(args) < 2 {
			return 0, false
		}
		n, ok1 := parseSizeLiteral(args[0].Text())
		m, ok2 := parseSizeLiteral(args[1].Text())
		if !ok1 || !ok2 {
			return 0, false
		}
		const maxInt = int(^uint(0) >> 1)
		if n > maxInt/m {
			return 0, false
		}
		return n * m, true
	}
	// `realloc(p, size)` and aligned-allocation forms put the byte count after a
	// pointer/alignment argument.
	idx := 0
	switch {
	case strings.Contains(lower, "realloc"):
		idx = 1
	case lower == "aligned_alloc" || strings.Contains(lower, "memalign"):
		idx = 1
	}
	if idx >= len(args) {
		return 0, false
	}
	n, ok := parseSizeLiteral(args[idx].Text())
	if !ok {
		return 0, false
	}
	return n, true
}

// parseSizeLiteral parses a C integer literal size argument: decimal, hex/octal
// (base prefix), and a trailing u/U/l/L integer suffix. Non-literal expressions
// (sizeof, variables, arithmetic) return ok=false.
func parseSizeLiteral(text string) (int, bool) {
	t := strings.TrimSpace(text)
	t = strings.TrimRight(t, "uUlL")
	if t == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(t, 0, 0)
	if err != nil || n <= 0 {
		return 0, false
	}
	return int(n), true
}

// isByteSizeAllocator reports whether the call's numeric argument denotes a byte
// count. Only declared allocators (built-in + project-declared + externally
// modeled) and the standard byte-size APIs qualify: apikb.IsAllocator is a
// substring heuristic ("_new", "alloc", "_dup") that would read a proto version
// (`conn_new(4)`) as a 4-byte allocation. String-copying allocators are excluded
// because their argument is a source string, not a size.
func isByteSizeAllocator(name string) bool {
	if name == "" {
		return false
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "strdup") || strings.Contains(lower, "wcsdup") ||
		strings.Contains(lower, "strndup") || lower == "posix_memalign" {
		return false
	}
	switch lower {
	case "malloc", "calloc", "realloc", "aligned_alloc", "memalign", "valloc", "pvalloc":
		return true
	}
	return apikb.IsDeclaredAllocator(name)
}

// parseCastToStruct parses a cast-to-struct expression, returning:
//   - structType: the struct tag name (e.g., "LargeRecord" from `(struct LargeRecord *)raw`)
//   - sourceVar: the source variable name if the cast operand is a variable
//   - directSize: the constant malloc size if the cast operand is a direct malloc call
//   - isDirect: true if the operand is a direct malloc call
func parseCastToStruct(node parser.Node) (structType, sourceVar string, directSize int, isDirect bool) {
	if node.Kind() != "cast_expression" {
		return "", "", 0, false
	}
	kids := node.NamedChildren()
	if len(kids) < 2 {
		return "", "", 0, false
	}
	typeNode := kids[0]
	operand := kids[1]

	structType = extractStructTagFromType(typeNode.Text())
	if structType == "" {
		return "", "", 0, false
	}

	operand = unwrapParens(operand)
	if operand.Kind() == "call_expression" {
		if size, ok := constantMallocByteSize(operand); ok {
			return structType, "", size, true
		}
		return structType, "", 0, true
	}
	if operand.Kind() == "identifier" {
		return structType, strings.TrimSpace(operand.Text()), 0, false
	}
	return structType, "", 0, false
}

// extractStructTagFromType extracts the struct tag from a type spelling like
// "struct LargeRecord *" → "LargeRecord", or a typedef name "MyRecord *" →
// "MyRecord". Returns "" for multi-word primitive spellings or inline definitions.
// A bare typedef name that is not a registered struct layout is harmless:
// LayoutOf will not find it and produce no false positive.
func extractStructTagFromType(spelling string) string {
	spelling = strings.TrimSpace(spelling)
	if strings.HasPrefix(spelling, "struct ") || strings.HasPrefix(spelling, "union ") {
		rest := spelling
		if strings.HasPrefix(rest, "struct ") {
			rest = strings.TrimPrefix(rest, "struct ")
		} else {
			rest = strings.TrimPrefix(rest, "union ")
		}
		rest = strings.TrimSpace(rest)
		rest = strings.TrimRight(rest, "*")
		rest = strings.TrimSpace(rest)
		if rest == "" || strings.ContainsAny(rest, " {}") {
			return ""
		}
		return rest
	}
	rest := strings.TrimRight(spelling, "*")
	rest = strings.TrimSpace(rest)
	if rest == "" || strings.ContainsAny(rest, " {}") {
		return ""
	}
	if strings.ContainsAny(rest, " ") {
		return ""
	}
	return rest
}

// fieldExprParts extracts the pointer variable name and field name from a
// field_expression like `record->value` or `record.value`.
func fieldExprParts(node parser.Node) (ptrVar, fieldName string, ok bool) {
	if node.Kind() != "field_expression" {
		return "", "", false
	}
	kids := node.NamedChildren()
	if len(kids) < 2 {
		return "", "", false
	}
	obj := kids[0]
	field := kids[len(kids)-1]
	if field.Kind() != "field_identifier" {
		return "", "", false
	}
	ptrVar = strings.TrimSpace(obj.Text())
	if ptrVar == "" || strings.ContainsAny(ptrVar, " ()&*[],") {
		return "", "", false
	}
	return ptrVar, strings.TrimSpace(field.Text()), true
}

// unwrapParens unwraps parenthesized_expression nodes.
func unwrapParens(node parser.Node) parser.Node {
	for node.Kind() == "parenthesized_expression" {
		kids := node.NamedChildren()
		if len(kids) == 0 {
			return node
		}
		node = kids[0]
	}
	return node
}
