package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func (d *BufferOverflowDetector) detectArrayOOB(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, result *DetectResult) {
	for _, sub := range bc.subs {
		if !funcLineRange(f, sub.StartLine()) {
			continue
		}
		text := sub.Text()
		if strings.Contains(text, "sizeof") {
			continue
		}
		// subscriptBaseIndex recovers the real base + index even when a macro
		// call site glues a call_expression as children[0] and buries the array
		// name in an ERROR child (e.g. `arr[10] = 1` inside a macro loop).
		arrName, indexExpr, ok := subscriptBaseIndex(sub)
		if !ok {
			continue
		}
		kind := subscriptAccessKind(bc, f, sub)
		if isOOB, category, arrSize := d.checkArrayOOB(bc, f, arrName, indexExpr, sub.StartLine(), sub.StartColumn(), kind); isOOB {
			d.emitOOB(ctx, f, file, sub.StartLine(), arrName, indexExpr, category, text, arrSize, result)
		}
	}

	// A pointer dereference `*(p + i)` is the same access as `p[i]` and must be
	// checked too (BO-10). The previous scan only covered subscript_expression,
	// so `*(arr + i)` overruns were missed.
	for _, deref := range bc.derefs {
		if !funcLineRange(f, deref.StartLine()) {
			continue
		}
		if !strings.HasPrefix(strings.TrimSpace(deref.Text()), "*") {
			continue
		}
		arrName, indexExpr, ok := derefBaseIndex(deref)
		if !ok {
			continue
		}
		kind := "read"
		if isAssignTarget(deref) {
			kind = "write"
		}
		if isOOB, category, arrSize := d.checkArrayOOB(bc, f, arrName, indexExpr, deref.StartLine(), deref.StartColumn(), kind); isOOB {
			d.emitOOB(ctx, f, file, deref.StartLine(), arrName, indexExpr, category, deref.Text(), arrSize, result)
		}
	}
}

// checkArrayOOB runs the constant / loop-bound / heap-allocation OOB proof for a
// base + index pair, returning the verdict and category (BO-10: shared by the
// subscript and pointer-dereference scans).
func (d *BufferOverflowDetector) checkArrayOOB(bc *bufCtx, f *db.Function, arrName, indexExpr string, line, column int, kind string) (bool, string, int) {
	arrSize := findArraySize(bc, f, arrName, line)
	isOOB := false
	category := "array_oob_read"
	if kind == "write" {
		category = "array_oob_write"
	}

	if isConstantIndex(indexExpr) {
		idx := parseConstantIndex(indexExpr)
		if arrSize > 0 && idx >= 0 {
			if idx >= arrSize {
				isOOB = true
			}
		} else if arrSize == 0 && idx >= 0 {
			if alloc, ok := heapAllocationSize(bc, f, arrName); ok {
				if constAlloc := parseConstantIndex(alloc); constAlloc > 0 && idx >= constAlloc {
					isOOB = true
					category = "heap_oob_write"
					if kind != "write" {
						category = "heap_oob_read"
					}
				}
			}
		}
	} else if arrSize > 0 {
		// A dominating explicit bounds guard (`if (idx >= arrSize) continue;`
		// or `if (idx < arrSize) { access }`) proves the access on this path is
		// in range; the loop-bound / single-constant proof must not override it
		// (issue #253 P2-1).
		if indexGuardedBelowCapacity(bc, f, indexExpr, line, column, arrSize) {
			return false, category, arrSize
		}
		// A variable index assigned a single constant value before the
		// subscript (`int n = 12; buf[n] = 0`) provably holds that constant,
		// so it is OOB exactly when the constant is.
		if v, ok := constantIndexBefore(bc, f, indexExpr, line); ok && v >= arrSize {
			isOOB = true
		}
		if !isOOB && isLoopBoundOverflow(bc, f, indexExpr, line, arrSize) {
			isOOB = true
		}
	} else if arrSize == 0 {
		// Heap pointer indexed inside a loop: flag only when the loop upper
		// bound provably exceeds the allocation size, e.g.
		// malloc(user_len) with `i < user_len + 10`.
		if alloc, ok := heapAllocationSize(bc, f, arrName); ok && isLoopBoundOverflowForHeap(bc, f, indexExpr, line, alloc) {
			isOOB = true
			category = "heap_oob_write"
			if kind != "write" {
				category = "heap_oob_read"
			}
		}
	}
	return isOOB, category, arrSize
}

func (d *BufferOverflowDetector) emitOOB(ctx context.Context, f *db.Function, file *db.File, line int, arrName, indexExpr, category, text string, arrSize int, result *DetectResult) {
	props := map[string]string{
		"array":      arrName,
		"index":      indexExpr,
		"category":   category,
		"expression": text,
	}
	if arrSize > 0 {
		props["size"] = strconv.Itoa(arrSize)
	}
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: line}, props) {
		result.EventsCreated++
	}
}

// derefBaseIndex returns the (base, index) of a pointer-dereference access
// `*(p + i)` (the same access as `p[i]`), or ok=false for any other deref.
func derefBaseIndex(node parser.Node) (string, string, bool) {
	if !strings.HasPrefix(strings.TrimSpace(node.Text()), "*") {
		return "", "", false
	}
	children := node.NamedChildren()
	if len(children) == 0 {
		return "", "", false
	}
	operand := children[0]
	for operand.Kind() == "parenthesized_expression" || operand.Kind() == "cast_expression" {
		c := operand.NamedChildren()
		if len(c) == 0 {
			return "", "", false
		}
		operand = c[0]
	}
	if operand.Kind() != "binary_expression" {
		return "", "", false
	}
	op := ""
	for _, c := range operand.Children() {
		if c.Kind() == "+" {
			op = "+"
		}
	}
	if op != "+" {
		return "", "", false
	}
	kids := operand.NamedChildren()
	if len(kids) < 2 {
		return "", "", false
	}
	base, index := kids[0].Text(), kids[1].Text()
	if kids[0].Kind() != "identifier" {
		base, index = index, base
	}
	return strings.TrimSpace(base), strings.TrimSpace(index), true
}

// isAssignTarget reports whether a deref node is the target of an assignment
// (`*(p+i) = 0`) by walking its parent chain to the nearest assignment.
func isAssignTarget(node parser.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			children := p.NamedChildren()
			return len(children) >= 1 && sameNode(children[0], node)
		case "binary_expression", "parenthesized_expression", "cast_expression",
			"subscript_expression", "argument_list", "call_expression",
			"field_expression", "unary_expression", "pointer_expression":
			continue
		default:
			return false
		}
	}
	return false
}

// constantIndexBefore returns (value, true) when indexVar is assigned a single
// constant value before useLine and is never reassigned before useLine, so the
// constant definitely holds on every path reaching the subscript. A non-literal
// assignment or a second assignment makes the value ambiguous (ok=false).
func constantIndexBefore(bc *bufCtx, f *db.Function, indexVar string, useLine int) (int, bool) {
	if !isBareIdent(indexVar) {
		return 0, false
	}
	value := -1
	assigned := false
	ambiguous := false

	check := func(node parser.Node) bool {
		if node.StartLine() >= useLine || !funcLineRange(f, node.StartLine()) {
			return false
		}
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return false
		}
		if assignedVariable(lhs) != indexVar {
			return false
		}
		// Any assignment to indexVar before useLine is evidence about its value:
		// a non-literal RHS, an unparsable constant, or a second assignment all
		// make the value ambiguous, so the "constant definitely holds" proof must
		// fail closed instead of silently keeping the earlier constant.
		if assigned {
			ambiguous = true
			return true
		}
		v, ok := constantNodeValue(bc, rhs)
		if !ok {
			ambiguous = true
			return true
		}
		value, assigned = v, true
		return true
	}

	for _, init := range bc.inits {
		check(init)
	}
	for _, assign := range bc.assigns {
		check(assign)
	}
	return value, assigned && !ambiguous
}

// isBareIdent reports whether s is a C identifier (no operator, index, or member).
func isBareIdent(s string) bool {
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return len(s) > 0
}

func findArraySize(bc *bufCtx, f *db.Function, arrName string, useLine int) int {
	best := 0
	bestScopeEnd := 1 << 30
	for _, decl := range bc.decls {
		// Accept the declaration when it is inside f, OR at file scope (a
		// global/static array like `int arr[10]` declared above every function).
		// A declaration inside a DIFFERENT function must not leak its size into
		// f's subscript.
		if !funcLineRange(f, decl.StartLine()) && !isFileScopeDecl(decl) {
			continue
		}
		for _, ad := range decl.FindAll("array_declarator") {
			if extractDeclaratorName(ad) != arrName {
				continue
			}
			size := 0
			for _, child := range ad.NamedChildren() {
				switch child.Kind() {
				case "number_literal":
					if s := parseConstantIndex(child.Text()); s > 0 {
						size = s
					}
				case "identifier":
					// `int arr[MAX]` — resolve the object-like macro.
					if s, ok := bc.macros[child.Text()]; ok && s > 0 {
						size = s
					}
				}
				if size > 0 {
					break
				}
			}
			if size <= 0 {
				continue
			}
			// Scope-sensitive resolution (BO-15): a same-named array in another
			// block, or a file-scope array shadowed by a local, must not leak its
			// size into this use. The declaration's enclosing SCOPE (its block),
			// not its own line, must contain useLine, and the INNERMOST such
			// declaration wins.
			scopeEnd := enclosingScopeEnd(decl)
			if useLine > 0 {
				if !isFileScopeDecl(decl) && (decl.StartLine() > useLine || scopeEnd < useLine) {
					continue
				}
			}
			if scopeEnd < bestScopeEnd {
				best = size
				bestScopeEnd = scopeEnd
			}
		}
	}
	if best <= 0 {
		// A file-scope array declared in a header (`extern char g_buf[256];`) is
		// not in this file's declarations; resolve it from the tree-wide census.
		if g, ok := bc.facts.GlobalArray(arrName); ok {
			return g.Count
		}
	}
	return best
}

// isFileScopeDecl reports whether a declaration node lives at file scope — i.e.
// its ancestor chain reaches the translation unit WITHOUT passing through a
// function body (function_definition / compound_statement). A file-scope array
// initializer is a real constant-bound array, so findArraySize must resolve it
// even though no function's line range contains it.
func isFileScopeDecl(decl parser.Node) bool {
	for p := decl.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "function_definition", "compound_statement":
			return false
		case "translation_unit":
			return true
		}
	}
	return false
}

func isLoopBoundOverflow(bc *bufCtx, f *db.Function, indexExpr string, line int, arrSize int) bool {
	for _, forNode := range bc.fors {
		if forNode.StartLine() < f.StartLine || forNode.EndLine() > f.EndLine {
			continue
		}
		if line < forNode.StartLine() || line > forNode.EndLine() {
			continue
		}
		// Only the loop CONDITION constrains the index. Scanning every named
		// child (including the body) let a comparison inside the body
		// (`if (i < 100)`) masquerade as the loop bound and flag a safe
		// subscript as OOB whenever that body literal exceeded the array size.
		cond := forNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		condText := cond.Text()
		// A compound condition (`i < N && flag > 5`) carries literals that do
		// not bound the loop index; extracting every number would let an
		// unrelated `flag > 5` masquerade as the loop bound and flag a safe
		// subscript. Only a single relational comparison is a trustworthy loop
		// bound; compound conditions are left to the other filters.
		if strings.Contains(condText, "&&") || strings.Contains(condText, "||") {
			continue
		}
		// The subscript index must be the loop variable (possibly offset by a
		// constant: arr[i-1], arr[i+1]); otherwise the loop bound does not prove
		// this subscript's range (BO-11). Modeling the offset fixes the confirmed
		// false positive `for (i=1; i<=10; i++) arr[i-1]` (i-1 ∈ [0,9]).
		loopVar := forLoopIndex(forNode)
		if loopVar == "" {
			continue
		}
		offset, matches := indexOffset(indexExpr, loopVar)
		if !matches {
			continue
		}
		op := ""
		switch {
		case strings.Contains(condText, "<="):
			op = "<="
		case strings.Contains(condText, "<"):
			op = "<"
		default:
			continue
		}
		// The loop bound is a number literal or an object-like macro (`SIZE`),
		// so `for (i=0; i<=SIZE; i++) arr[i]` is provable (BO-05).
		bound := boundValue(bc, extractLoopBound(condText))
		if bound <= 0 {
			continue
		}
		maxIdx := bound + offset
		if op == "<" {
			maxIdx = bound - 1 + offset
		}
		if maxIdx >= arrSize {
			return true
		}
	}
	return false
}

// forLoopIndex returns the loop counter variable of a for statement
// (`for (i = 0; ...)` → "i"), via the initializer field or a child `i = ...`.
func forLoopIndex(forNode parser.Node) string {
	if init := forNode.ChildByFieldName("initializer"); init != nil {
		if idx := extractLoopIndex(init.Text()); idx != "" {
			return idx
		}
	}
	for _, child := range forNode.NamedChildren() {
		text := child.Text()
		if strings.Contains(text, "=") && !strings.Contains(text, "<") &&
			!strings.Contains(text, ">") && !strings.Contains(text, "==") {
			if idx := extractLoopIndex(text); idx != "" {
				return idx
			}
		}
	}
	return ""
}

// indexOffset returns the constant offset of a loop index expression relative to
// the loop variable: `i` → 0, `i - 1` → -1, `i + 1` → +1 (with or without spaces
// around the operator). ok=false when the expression is not loopVar ± constant.
func indexOffset(indexExpr, loopVar string) (int, bool) {
	indexExpr = strings.TrimSpace(indexExpr)
	if indexExpr == loopVar {
		return 0, true
	}
	if !strings.HasPrefix(indexExpr, loopVar) {
		return 0, false
	}
	rest := strings.TrimSpace(indexExpr[len(loopVar):])
	sign := 0
	switch {
	case strings.HasPrefix(rest, "-"):
		sign = -1
	case strings.HasPrefix(rest, "+"):
		sign = 1
	default:
		return 0, false
	}
	if c := parseConstantIndex(strings.TrimSpace(rest[1:])); c >= 0 {
		return sign * c, true
	}
	return 0, false
}

// boundValue resolves a loop-bound expression to its numeric value — a number
// literal (any radix/suffix) or an object-like macro identifier.
func boundValue(bc *bufCtx, expr string) int {
	expr = strings.TrimSpace(expr)
	if v := parseConstantIndex(expr); v > 0 {
		return v
	}
	if v, ok := bc.macros[expr]; ok && v > 0 {
		return v
	}
	return 0
}

func extractNumbers(text string) []int {
	var nums []int
	current := ""
	for _, c := range text {
		if c >= '0' && c <= '9' {
			current += string(c)
		} else {
			if current != "" {
				n := parseConstantIndex(current)
				if n > 0 {
					nums = append(nums, n)
				}
				current = ""
			}
		}
	}
	if current != "" {
		n := parseConstantIndex(current)
		if n > 0 {
			nums = append(nums, n)
		}
	}
	return nums
}

// parseConstantIndex parses a C integer constant expression, handling decimal,
// hexadecimal (0x/0X), octal (leading 0), a leading sign, and the u/U/l/L
// suffixes (`10u`, `0x10`, `010`, `-1`), with optional parentheses. Returns -1
// for anything that is not a compile-time integer constant (BO-06).
func parseConstantIndex(expr string) int {
	s := strings.TrimSpace(expr)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if inner == "" || inner == s {
			break
		}
		s = inner
	}
	s = strings.TrimRight(s, "uUlL")
	if s == "" {
		return -1
	}
	neg := false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		s = s[1:]
		if s == "" {
			return -1
		}
	}
	base := 10
	switch {
	case strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X"):
		base, s = 16, s[2:]
	case len(s) > 1 && s[0] == '0':
		base, s = 8, s[1:]
	}
	if s == "" {
		return -1
	}
	n, err := strconv.ParseInt(s, base, 64)
	if err != nil {
		return -1
	}
	if neg {
		n = -n
	}
	return int(n)
}

func isConstantIndex(expr string) bool {
	return parseConstantIndex(expr) >= 0
}

// constantNodeValue returns the compile-time value of a constant-valued AST node
// — a numeric literal (any radix/suffix), an object-like macro identifier, or a
// cast/parenthesized wrapper of either. A macro declared in an indexed HEADER is
// resolved from the tree-wide repofacts census when the per-file map does not
// know it (issue #253 P2-1: `if (idx >= MAX) continue;` with MAX in a header).
// It reports ok=false for anything else (BO-07: a hex literal or
// `int n = SIZE; buf[n]` is a definite constant).
func constantNodeValue(bc *bufCtx, node parser.Node) (int, bool) {
	switch node.Kind() {
	case "number_literal":
		if v := parseConstantIndex(node.Text()); v >= 0 {
			return v, true
		}
	case "identifier":
		if v, ok := bc.macros[node.Text()]; ok && v >= 0 {
			return v, true
		}
		if bc.facts != nil {
			if v, ok := bc.facts.Macros[node.Text()]; ok && v >= 0 {
				return v, true
			}
		}
	case "parenthesized_expression", "cast_expression":
		for _, c := range node.NamedChildren() {
			if v, ok := constantNodeValue(bc, c); ok {
				return v, true
			}
		}
	}
	return 0, false
}

// formatOverflowAPIs are printf-family calls that write an unboundedly
// formatted string into a caller-provided destination with no size argument.
var formatOverflowAPIs = map[string]bool{
	"sprintf":   true,
	"wsprintfA": true,
	"wsprintfW": true,
}
