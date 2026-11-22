package evidence

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// stringLiteralContent returns the inner text of a plain double-quoted string
// literal, or false when the node is not a (single, escape-free) string literal.
func stringLiteralContent(exprText string) (string, bool) {
	t := strings.TrimSpace(exprText)
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return "", false
	}
	return t[1 : len(t)-1], true
}

// scanfConversionKinds parses a scanf format string and returns, per conversion
// in order, whether it is a buffer-consuming conversion (%s / %c / %[...]) that
// requires a following buffer-size argument in the `_s` variants. `%%` is a
// literal and `%*` suppresses assignment (consumes no argument), so neither
// contributes an entry.
func scanfConversionKinds(format string) []bool {
	var kinds []bool
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			i++
			continue
		}
		if i+1 >= len(format) {
			break
		}
		if format[i+1] == '%' { // literal %%
			i += 2
			continue
		}
		j := i + 1
		suppressed := false
		if format[j] == '*' {
			suppressed = true
			j++
		}
		for j < len(format) && isScanfLengthByte(format[j]) {
			j++
		}
		if j >= len(format) {
			break
		}
		conv := format[j]
		if !suppressed {
			switch conv {
			case 's', 'c', '[':
				kinds = append(kinds, true)
			default:
				kinds = append(kinds, false)
			}
		}
		if conv == '[' {
			for j < len(format) && format[j] != ']' {
				j++
			}
		}
		i = j + 1
	}
	return kinds
}

// isScanfLengthByte reports whether b is a scanf conversion flag byte: a width
// digit or a length modifier (h, l, L, j, z, t).
func isScanfLengthByte(b byte) bool {
	return (b >= '0' && b <= '9') || b == 'h' || b == 'l' || b == 'L' || b == 'j' || b == 'z' || b == 't'
}

func parseConstantSize(node parser.Node) int {
	if node.Kind() == "number_literal" {
		if v := parseConstantIndex(node.Text()); v > 0 {
			return v
		}
	}
	// Unwrap a cast ((rsize_t)100) or parentheses, which are the idiomatic way
	// `_s` size arguments are written.
	if node.Kind() == "cast_expression" || node.Kind() == "parenthesized_expression" {
		for _, c := range node.NamedChildren() {
			if v := parseConstantSize(c); v > 0 {
				return v
			}
		}
	}
	return 0
}

func extractArgName(node parser.Node) string {
	if node.Kind() == "identifier" {
		return node.Text()
	}
	return ""
}

// suppressConstantStringCopy reports whether a strcpy call copies a compile-time
// string literal into a destination whose capacity is provably large enough.
// `strcpy(malloc(256), "temporary")` is safe (the literal is 10 bytes, the
// buffer 256), as is `strcpy(dst, "hello")` into `char dst[8]`. The rule is
// deliberately conservative: it only suppresses when the source is a plain
// literal and the destination's capacity (a malloc/calloc/realloc constant or a
// local fixed array) is a known numeric >= literal length + 1. It is restricted
// to strcpy — strcat appends to existing content, so "source fits in total
// capacity" does not prove safety.
func suppressConstantStringCopy(bc *bufCtx, f *db.Function, call parser.Node) bool {
	if extractCallName(call) != "strcpy" {
		return false
	}
	args := callNamedArguments(call)
	if len(args) < 2 {
		return false
	}
	srcLen, ok := constantStringLength(args[1].Text())
	if !ok {
		return false
	}
	dstName := strings.TrimSpace(args[0].Text())
	if size := constantAllocationSize(bc, f, dstName); size > 0 {
		return size >= srcLen+1
	}
	// A local fixed array `char dst[256]; strcpy(dst, "x")` is precise within
	// the function.
	if size := findArraySize(bc, f, dstName, call.StartLine()); size > 0 {
		return size >= srcLen+1
	}
	// A struct field fixed array `char id[4]; strcpy(log->id, "bad")` is safe
	// when the field name has ONE unambiguous size across the file
	// (findFieldArraySize returns 0 when multiple structs disagree).
	if size := findFieldArraySize(bc, dstName); size > 0 {
		return size >= srcLen+1
	}
	return false
}

func callNamedArguments(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

// constantStringLength returns the character length of a plain string literal
// (no escape sequences). Escapes make the length nontrivial to compute, so
// those are rejected (ok=false) and left to be flagged conservatively.
func constantStringLength(exprText string) (int, bool) {
	t := strings.TrimSpace(exprText)
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return 0, false
	}
	inner := t[1 : len(t)-1]
	if strings.Contains(inner, `\`) {
		return 0, false
	}
	return len(inner), true
}

// constantAllocationSize returns the byte count of a malloc/calloc/realloc
// whose size argument is a numeric constant, or 0 when the variable's
// allocation size is not a known constant.
func constantAllocationSize(bc *bufCtx, f *db.Function, varName string) int {
	check := func(node parser.Node) int {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return 0
		}
		if assignedVariable(lhs) != varName {
			return 0
		}
		if rhs.Kind() == "cast_expression" {
			for _, c := range rhs.NamedChildren() {
				if c.Kind() == "call_expression" {
					rhs = c
					break
				}
			}
		}
		if rhs.Kind() != "call_expression" {
			return 0
		}
		name := extractCallName(rhs)
		if !apikb.IsAllocator(name) {
			return 0
		}
		callArgs := callNamedArguments(rhs)
		if len(callArgs) == 0 {
			return 0
		}
		n := parseConstantIndex(strings.TrimSpace(callArgs[0].Text()))
		if n <= 0 {
			return 0
		}
		if name == "calloc" && len(callArgs) >= 2 {
			if m := parseConstantIndex(strings.TrimSpace(callArgs[1].Text())); m > 0 {
				return n * m
			}
		}
		return n
	}

	for _, assign := range bc.assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		if n := check(assign); n > 0 {
			return n
		}
	}
	for _, init := range bc.inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		if n := check(init); n > 0 {
			return n
		}
	}
	return 0
}

func hasPrecedingBoundsCheck(bc *bufCtx, f *db.Function, call parser.Node, callName string) bool {
	args := callNamedArguments(call)
	// The guard must reference the copy's DESTINATION or its SIZE argument; an
	// unrelated `if (x < size) { y = 1; }` must NOT suppress a `memcpy(dst, src,
	// huge)` (BO-04). The previous substring rule ("size"/"len" anywhere in the
	// condition, "=" anywhere in the body) matched `if (x < size)` and `y = 1`.
	var relevant []string
	if len(args) >= 1 {
		relevant = append(relevant, extractArgName(args[0]))
	}
	if idx := boundedCopySizeIdx(callName); idx >= 0 && len(args) > idx {
		relevant = append(relevant, extractArgName(args[idx]))
	}
	for _, ifNode := range bc.ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() >= call.StartLine() {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		if cond == nil || !isRelationalCondition(cond.Text()) {
			continue
		}
		refs := false
		for _, r := range relevant {
			if r != "" && condReferences(cond.Text(), r) {
				refs = true
				break
			}
		}
		if !refs {
			continue
		}
		// The guard must actually exit on overflow (return/break/continue); a body
		// that merely assigns (`y = 1`) is not a guard. AST-based stmtAlwaysExits,
		// not the old bodyExits text search (a string literal or identifier
		// containing "return"/"break" would have been misread as an exit).
		if cons := ifNode.ChildByFieldName("consequence"); cons != nil && stmtAlwaysExits(*cons) {
			return true
		}
	}
	return false
}

// boundedCopySizeIdx returns the argument index of a bounded copy's size
// argument, or -1 for a call with no explicit size.
func boundedCopySizeIdx(callName string) int {
	switch callName {
	case "memcpy", "memmove", "strncpy", "strncat":
		return 2
	}
	return -1
}

// condReferences reports whether a condition text names the identifier, using
// token boundaries (so `n` does not match `next` or `count`).
func condReferences(condText, name string) bool {
	if name == "" {
		return false
	}
	for _, tok := range strings.FieldsFunc(condText, func(r rune) bool {
		return !(r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		if tok == name {
			return true
		}
	}
	return false
}

func isRelationalCondition(text string) bool {
	return strings.Contains(text, " > ") || strings.Contains(text, " >= ") ||
		strings.Contains(text, " < ") || strings.Contains(text, " <= ") ||
		strings.Contains(text, ">=") || strings.Contains(text, "<=") ||
		strings.Contains(text, " >") || strings.Contains(text, " <")
}

// indexGuardedBelowCapacity reports whether a dominating guard proves
// `index < arrSize` on every path that reaches the access (issue #253 P2-1:
// `if (i >= MAX) continue;` before `arr[i]` was ignored and the loop-bound proof
// auto-confirmed an OOB on a path the guard had already eliminated).
//
// Only a bare-identifier index is considered: `arr[i + 1]` is not bounded by a
// guard on `i`. Two shapes are recognized, both requiring the guard to dominate
// the access (same branch/loop body, not a sibling if/else):
//
//	A. `if (idx >= K) { return|break|continue; }` before the access → fall-through
//	   implies `idx < K`.
//	B. `if (idx < K) { ... access ... }`                → the true branch implies
//	   `idx < K`.
//
// The bound is relative to the capacity (`K <= arrSize` for a strict fall-through,
// `K < arrSize` when the guard uses `>`/`<=`). An unparseable condition, a guard
// on another variable, or a bound larger than the capacity keeps the proof
// (conservative: the detector is allowed to flag).
func indexGuardedBelowCapacity(bc *bufCtx, f *db.Function, indexExpr string, accessLine, accessColumn, arrSize int) bool {
	name := bareIdentifierText(indexExpr)
	if name == "" || arrSize <= 0 {
		return false
	}
	for _, ifNode := range bc.ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() > accessLine {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		cons := ifNode.ChildByFieldName("consequence")
		if cond == nil || cons == nil || !guardDominates(ifNode, accessLine, accessColumn) {
			continue
		}
		op, bound, ok := guardBoundForIndex(*cond, name, bc)
		if !ok {
			continue
		}
		if ifNode.StartLine() < accessLine && stmtAlwaysExits(*cons) {
			switch op {
			case ">=":
				if bound <= arrSize {
					return true
				}
			case ">":
				if bound < arrSize {
					return true
				}
			}
		}
		if nodeContainsPosition(*cons, accessLine, accessColumn) {
			switch op {
			case "<":
				if bound <= arrSize {
					return true
				}
			case "<=":
				if bound < arrSize {
					return true
				}
			}
		}
	}
	return false
}

// bareIdentifierText returns expr when it is a single C identifier, else "".
func bareIdentifierText(expr string) string {
	s := strings.TrimSpace(expr)
	if s == "" {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return ""
	}
	return s
}

// guardBoundForIndex extracts `name op K` (or the mirrored `K op name`) from a
// comparison condition, resolving K through the per-file macro table and the
// tree-wide header-macro census.
func guardBoundForIndex(cond parser.Node, name string, bc *bufCtx) (string, int, bool) {
	for cond.Kind() == "parenthesized_expression" {
		kids := cond.NamedChildren()
		if len(kids) == 0 {
			return "", 0, false
		}
		cond = kids[0]
	}
	if cond.Kind() != "binary_expression" {
		return "", 0, false
	}
	op := ""
	for _, c := range cond.Children() {
		switch c.Kind() {
		case ">=", ">", "<=", "<":
			op = c.Kind()
		}
	}
	if op == "" {
		return "", 0, false
	}
	kids := cond.NamedChildren()
	if len(kids) != 2 {
		return "", 0, false
	}
	if guardIdentNode(kids[0], name) {
		if v, ok := constantNodeValue(bc, kids[1]); ok {
			return op, v, true
		}
	}
	if guardIdentNode(kids[1], name) {
		if v, ok := constantNodeValue(bc, kids[0]); ok {
			return mirrorRelationalOp(op), v, true
		}
	}
	return "", 0, false
}

// guardIdentNode unwraps parentheses/casts and reports whether the node is the
// bare identifier name.
func guardIdentNode(n parser.Node, name string) bool {
	for n.Kind() == "parenthesized_expression" || n.Kind() == "cast_expression" {
		kids := n.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		n = kids[0]
	}
	return n.Kind() == "identifier" && n.Text() == name
}

func mirrorRelationalOp(op string) string {
	switch op {
	case "<":
		return ">"
	case "<=":
		return ">="
	case ">":
		return "<"
	case ">=":
		return "<="
	}
	return op
}

// guardDominates reports whether the guard's own branch/loop body also contains
// the access line. A guard nested in a sibling if/else branch, or in a loop the
// access is not inside, does not protect the access.
func guardDominates(ifNode parser.Node, accessLine, accessColumn int) bool {
	child := ifNode
	for parent := ifNode.Parent(); parent != nil; parent = parent.Parent() {
		switch parent.Kind() {
		case "function_definition":
			return true
		case "if_statement", "for_statement", "while_statement", "do_statement", "switch_statement", "case_statement":
			contained := false
			for _, ch := range parent.NamedChildren() {
				if ch.StartLine() <= child.StartLine() && ch.EndLine() >= child.EndLine() &&
					nodeContainsPosition(ch, accessLine, accessColumn) {
					contained = true
					break
				}
			}
			if !contained {
				return false
			}
		}
		child = *parent
	}
	return false
}

// nodeContainsPosition reports whether n covers the source position. Columns
// break the tie on the boundary lines, so a one-line
// `if (c) { if (idx >= 16) return; } arr[idx]` is not treated as if the access
// were inside the guarded block.
func nodeContainsPosition(n parser.Node, line, column int) bool {
	if line < n.StartLine() || line > n.EndLine() {
		return false
	}
	if column <= 0 {
		return true
	}
	if line == n.StartLine() && n.StartColumn() > 0 && column < n.StartColumn() {
		return false
	}
	if line == n.EndLine() && n.EndColumn() > 0 && column > n.EndColumn() {
		return false
	}
	return true
}

// stmtAlwaysExits reports whether the statement unconditionally transfers
// control out of its block. It is AST-based (unlike bodyExits' text search): a
// conditional `if (c) return;` is NOT an unconditional exit, so it cannot turn
// a guarded access into a safe one.
func stmtAlwaysExits(n parser.Node) bool {
	switch n.Kind() {
	case "return_statement", "break_statement", "continue_statement", "goto_statement":
		return true
	case "compound_statement":
		for _, ch := range n.NamedChildren() {
			if stmtAlwaysExits(ch) {
				return true
			}
		}
		return false
	case "if_statement":
		cons := n.ChildByFieldName("consequence")
		alt := n.ChildByFieldName("alternative")
		if cons == nil || alt == nil {
			return false
		}
		return stmtAlwaysExits(*cons) && stmtAlwaysExits(*alt)
	case "else_clause":
		for _, ch := range n.NamedChildren() {
			if stmtAlwaysExits(ch) {
				return true
			}
		}
		return false
	}
	return false
}
