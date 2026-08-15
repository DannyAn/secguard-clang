package evidence

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type BufferOverflowDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewBufferOverflowDetector(store db.Store, p *parser.Parser, logger *log.Logger) *BufferOverflowDetector {
	return &BufferOverflowDetector{store: store, parser: p, logger: logger}
}

func (d *BufferOverflowDetector) Name() string { return "buffer_overflow" }

func (d *BufferOverflowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		bc := &bufCtx{
			root:    root,
			calls:   root.FindAll("call_expression"),
			subs:    root.FindAll("subscript_expression"),
			ifs:     root.FindAll("if_statement"),
			decls:   root.FindAll("declaration"),
			assigns: root.FindAll("assignment_expression"),
			updates: root.FindAll("update_expression"),
			fors:    root.FindAll("for_statement"),
			inits:   root.FindAll("init_declarator"),
			fields:  root.FindAll("field_declaration"),
		}

		for _, f := range funcs {
			d.detectUnsafeCalls(ctx, f, file, bc, &result)
			d.detectArrayOOB(ctx, f, file, bc, &result)
			d.detectFormatOverflow(ctx, f, file, bc, &result)
		}
	})
	return result, err
}

// bufCtx holds the per-file node lists a buffer-overflow scan needs, fetched
// once per file instead of once per subscript/call (the previous behavior did a
// whole-tree FindAll inside every per-node helper).
type bufCtx struct {
	root    parser.Node
	calls   []parser.Node
	subs    []parser.Node
	ifs     []parser.Node
	decls   []parser.Node
	assigns []parser.Node
	updates []parser.Node
	fors    []parser.Node
	inits   []parser.Node
	fields  []parser.Node
}

func (d *BufferOverflowDetector) detectUnsafeCalls(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, result *DetectResult) {
	for _, call := range bc.calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName == "" {
			continue
		}
		if apikb.IsSafeFunction(callName) || apikb.IsSafeWrapper(callName) {
			continue
		}
		if apikb.InjectionAPIs[callName] {
			continue
		}
		if !apikb.BufferOverflowAPIs[callName] {
			continue
		}
		if hasPrecedingBoundsCheck(bc.ifs, f, call.StartLine()) {
			continue
		}
		if suppressConstantStringCopy(bc, f, call) {
			continue
		}
		category := "buffer_overflow"

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   category,
			"expression": call.Text(),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "BUFFER_ACCESS",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
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
	if size := findArraySize(bc, f, dstName); size > 0 {
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
		children := node.NamedChildren()
		if len(children) < 2 {
			return 0
		}
		if assignedVariable(children[0]) != varName {
			return 0
		}
		rhs := children[1]
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
		if name != "malloc" && name != "calloc" && name != "realloc" {
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

func hasPrecedingBoundsCheck(ifs []parser.Node, f *db.Function, callLine int) bool {
	for _, ifNode := range ifs {
		if ifNode.StartLine() < f.StartLine || ifNode.StartLine() >= callLine {
			continue
		}
		condText := ""
		bodyHasReturn := false
		for _, child := range ifNode.NamedChildren() {
			if child.Kind() == "parenthesized_expression" || strings.Contains(child.Text(), ">") || strings.Contains(child.Text(), "<") {
				condText = child.Text()
			}
			if child.Kind() == "compound_statement" {
				bodyText := child.Text()
				if strings.Contains(bodyText, "return") || strings.Contains(bodyText, "break") || strings.Contains(bodyText, "continue") {
					bodyHasReturn = true
				}
				if strings.Contains(bodyText, "=") && !strings.Contains(bodyText, "==") {
					bodyHasReturn = true
				}
			}
			if child.Kind() == "expression_statement" {
				bodyText := child.Text()
				if strings.Contains(bodyText, "return") || strings.Contains(bodyText, "=") {
					bodyHasReturn = true
				}
			}
		}
		if condText == "" || !bodyHasReturn {
			continue
		}
		if !isRelationalCondition(condText) {
			continue
		}
		if hasCapacityExpression(condText) {
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

func hasCapacityExpression(text string) bool {
	keywords := []string{"capacity", "size", "len", "sizeof", "MAX_", "BUF_", "LIMIT", "max_", "buf_"}
	lower := strings.ToLower(text)
	for _, kw := range keywords {
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func (d *BufferOverflowDetector) detectArrayOOB(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, result *DetectResult) {
	for _, sub := range bc.subs {
		if !funcLineRange(f, sub.StartLine()) {
			continue
		}
		text := sub.Text()
		if strings.Contains(text, "sizeof") {
			continue
		}
		children := sub.NamedChildren()
		if len(children) < 2 {
			continue
		}
		arrName := children[0].Text()
		indexExpr := children[1].Text()

		arrSize := findArraySize(bc, f, arrName)
		kind := subscriptAccessKind(bc, f, sub)
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
		} else if arrSize > 0 && isLoopBoundOverflow(bc, f, sub, arrSize) {
			isOOB = true
		} else if arrSize == 0 {
			// Heap pointer indexed inside a loop: flag only when the loop upper
			// bound provably exceeds the allocation size, e.g.
			// malloc(user_len) with `i < user_len + 10`.
			if alloc, ok := heapAllocationSize(bc, f, arrName); ok && isLoopBoundOverflowForHeap(bc, f, sub, alloc) {
				isOOB = true
				category = "heap_oob_write"
				if kind != "write" {
					category = "heap_oob_read"
				}
			}
		}
		// A non-constant index (e.g. `buf[i]`, `g_entries[i]`, `p->data[i]`)
		// is not, by itself, evidence of an out-of-bounds access: proving that
		// requires bounds-check dataflow the detector does not yet have. The
		// previous catch-all `else if !isConstantIndex(indexExpr)` flagged every
		// variable-index subscript, emitting ~17 false positives on the
		// benchmark. Only report OOB when it is provable (constant index past a
		// known array size, a loop bound that provably overruns it, or a heap
		// allocation whose loop bound provably overruns the allocation size).

		if !isOOB {
			continue
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: sub.StartLine()})
		props, _ := json.Marshal(map[string]string{
			"array":      arrName,
			"index":      indexExpr,
			"category":   category,
			"expression": text,
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "BUFFER_ACCESS",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func findArraySize(bc *bufCtx, f *db.Function, arrName string) int {
	for _, decl := range bc.decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		for _, ad := range decl.FindAll("array_declarator") {
			if extractDeclaratorName(ad) == arrName {
				for _, child := range ad.NamedChildren() {
					if child.Kind() == "number_literal" || child.Kind() == "identifier" {
						size := parseConstantIndex(child.Text())
						if size > 0 {
							return size
						}
					}
				}
			}
		}
	}
	return 0
}

func isLoopBoundOverflow(bc *bufCtx, f *db.Function, sub parser.Node, arrSize int) bool {
	for _, forNode := range bc.fors {
		if forNode.StartLine() < f.StartLine || forNode.EndLine() > f.EndLine {
			continue
		}
		if sub.StartLine() < forNode.StartLine() || sub.StartLine() > forNode.EndLine() {
			continue
		}
		for _, child := range forNode.NamedChildren() {
			condText := child.Text()
			if strings.Contains(condText, "<=") {
				nums := extractNumbers(condText)
				for _, n := range nums {
					if n >= arrSize {
						return true
					}
				}
			}
			if strings.Contains(condText, "<") && !strings.Contains(condText, "<=") {
				nums := extractNumbers(condText)
				for _, n := range nums {
					if n > arrSize {
						return true
					}
				}
			}
		}
	}
	return false
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

func parseConstantIndex(expr string) int {
	n := 0
	for _, c := range expr {
		if c < '0' || c > '9' {
			return -1
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func isConstantIndex(expr string) bool {
	for _, c := range expr {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(expr) > 0
}

// formatOverflowAPIs are printf-family calls that write an unboundedly
// formatted string into a caller-provided destination with no size argument.
var formatOverflowAPIs = map[string]bool{
	"sprintf":   true,
	"wsprintfA": true,
	"wsprintfW": true,
}

// detectFormatOverflow flags sprintf/wsprintf calls whose destination is a
// fixed-capacity buffer and whose source arguments are not compile-time
// constants (or whose literal output provably exceeds the capacity). It skips
// calls whose formatted buffer feeds an injection sink: there, injection is
// the dominant root cause and reporting the same call as a buffer overflow
// would double-count one defect.
func (d *BufferOverflowDetector) detectFormatOverflow(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, result *DetectResult) {
	for _, call := range bc.calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !formatOverflowAPIs[callName] {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 2 {
			continue
		}
		dst := strings.TrimSpace(args[0])
		capacity := findArraySize(bc, f, dst)
		if capacity <= 0 {
			capacity = findFieldArraySize(bc, dst)
		}
		if capacity <= 0 {
			continue
		}
		if hasPrecedingBoundsCheck(bc.ifs, f, call.StartLine()) {
			continue
		}
		if destFeedsInjectionSink(bc, f, dst, call.StartLine()) {
			continue
		}
		if !formatCanOverflow(args, capacity) {
			continue
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   "format_overflow",
			"expression": call.Text(),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "BUFFER_ACCESS",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func formatCanOverflow(args []string, capacity int) bool {
	nonConst := false
	staticLen := 0
	for i := 2; i < len(args); i++ {
		l, ok := constantStringLength(strings.TrimSpace(args[i]))
		if !ok {
			nonConst = true
			continue
		}
		staticLen += l
	}
	if nonConst {
		return true
	}
	return staticLen >= capacity
}

func destFeedsInjectionSink(bc *bufCtx, f *db.Function, dst string, afterLine int) bool {
	for _, call := range bc.calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if call.StartLine() <= afterLine {
			continue
		}
		if !apikb.InjectionAPIs[extractCallName(call)] {
			continue
		}
		for _, arg := range extractCallArgs(call) {
			if tokenEquals(strings.TrimSpace(arg), dst) {
				return true
			}
		}
	}
	return false
}

func tokenEquals(arg, name string) bool {
	if arg == name {
		return true
	}
	for _, part := range strings.FieldsFunc(arg, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_')
	}) {
		if part == name {
			return true
		}
	}
	return false
}

func findFieldArraySize(bc *bufCtx, dst string) int {
	field := ""
	if idx := strings.LastIndex(dst, "->"); idx >= 0 {
		field = strings.TrimSpace(dst[idx+2:])
	} else if idx := strings.LastIndex(dst, "."); idx >= 0 {
		field = strings.TrimSpace(dst[idx+1:])
	}
	if field == "" {
		return 0
	}
	// Collect every fixed array size declared for this field name across the
	// file. The field name alone does not identify the struct, so suppress only
	// when every match agrees on the size; otherwise return 0 (unknown) and
	// leave the copy flagged conservatively.
	seen := 0
	sizes := make(map[int]bool)
	for _, fd := range bc.fields {
		for _, ad := range fd.FindAll("array_declarator") {
			if arrayDeclaratorName(ad) != field {
				continue
			}
			for _, child := range ad.NamedChildren() {
				if child.Kind() == "number_literal" {
					if n := parseConstantIndex(child.Text()); n > 0 {
						sizes[n] = true
						seen = n
					}
				}
			}
		}
	}
	if len(sizes) == 1 {
		return seen
	}
	return 0
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
	subText := sub.Text()
	for _, assign := range bc.assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		if assign.StartLine() != sub.StartLine() {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if children[0].Text() == subText || strings.Contains(children[0].Text(), subText) {
			return "write"
		}
	}
	for _, upd := range bc.updates {
		if !funcLineRange(f, upd.StartLine()) {
			continue
		}
		if upd.StartLine() == sub.StartLine() && strings.Contains(upd.Text(), subText) {
			return "write"
		}
	}
	return "read"
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
		if name != "malloc" && name != "calloc" && name != "realloc" {
			return "", false
		}
		args := callNamedArguments(*call)
		if len(args) == 0 {
			return "", false
		}
		return strings.TrimSpace(args[0].Text()), true
	}

	for _, decl := range bc.inits {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		children := decl.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if expr, ok := checkRHS(extractVarFromDeclarator(children[0]), children[1]); ok {
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
func isLoopBoundOverflowForHeap(bc *bufCtx, f *db.Function, sub parser.Node, allocExpr string) bool {
	for _, forNode := range bc.fors {
		if forNode.StartLine() < f.StartLine || forNode.EndLine() > f.EndLine {
			continue
		}
		if sub.StartLine() < forNode.StartLine() || sub.StartLine() > forNode.EndLine() {
			continue
		}
		condText := ""
		initText := ""
		for _, child := range forNode.NamedChildren() {
			text := child.Text()
			if isRelationalCondition(text) {
				condText = text
			} else if strings.Contains(text, "=") && !strings.Contains(text, "<") && !strings.Contains(text, ">") {
				initText = text
			}
		}
		if condText == "" {
			continue
		}
		if idx := extractLoopIndex(initText); idx != "" && !strings.Contains(sub.Text(), idx) {
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
