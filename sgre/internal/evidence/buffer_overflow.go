package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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

		// Parameter names per function: a variable copy size that is a function
		// parameter (caller-influenced) is the signal for the variable-length
		// bounded-copy overflow tier (handed to the AI agent to reason about).
		paramsByLine := make(map[int][]string)
		for _, fnNode := range root.FindAll("function_definition") {
			paramsByLine[fnNode.StartLine()] = findParamsInDefinition(fnNode)
		}

		for _, f := range funcs {
			params := make(map[string]bool)
			for _, p := range paramsByLine[f.StartLine] {
				params[p] = true
			}
			d.detectUnsafeCalls(ctx, f, file, bc, params, &result)
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

func (d *BufferOverflowDetector) detectUnsafeCalls(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, params map[string]bool, result *DetectResult) {
	for _, call := range bc.calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName == "" {
			continue
		}
		// Annex K `_s` functions are conditionally safe: they trust the explicit
		// destination-capacity argument, so a lying size (larger than the real
		// buffer) overflows just like the unsafe counterpart, and a required
		// size exceeding the declared capacity is a constraint violation. Check
		// the contract before any safe-function exclusion; the check is
		// authoritative and skips the generic path either way.
		if spec, ok := apikb.SecureFunctionSpec(callName); ok {
			d.checkSecureFunction(ctx, f, file, bc, call, callName, spec, params, result)
			continue
		}
		// scanf_s/sscanf_s/fscanf_s use per-conversion buffer-size arguments, not
		// a single capacity: every %s/%c/%[ conversion is followed by a size that
		// must match the real buffer. Check each conversion before exclusion.
		if fmtIdx, ok := apikb.ScanfSecureFormatArg(callName); ok {
			d.checkScanfSecure(ctx, f, file, bc, call, callName, fmtIdx, params, result)
			continue
		}
		// strncpy/strncat/memcpy/memmove all take an explicit size, so refine the
		// size-vs-capacity before the generic path. checkBoundedCopyOverflow
		// returns true when it handled the call (emitted bounded_copy_overflow /
		// bounded_copy_var_size, or proved it fits); false means "fall through
		// to the conservative generic path" (unknown capacity, append semantics,
		// or a bounded local size).
		if apikb.IsBoundedCopy(callName) {
			if d.checkBoundedCopyOverflow(ctx, f, file, bc, call, callName, params, result) {
				continue
			}
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
		if suppressExactFitCopy(bc, f, call) {
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

// checkBoundedCopyOverflow refines a bounded copy (strncpy/strncat/memcpy/
// memmove) against the destination capacity. It returns true when the call was
// handled (an overflow was emitted, or the copy provably fits), and false when
// the caller should fall through to the conservative generic buffer-overflow
// path (unknown capacity, append semantics, or a bounded local size on an
// otherwise-unsafe API).
//
//   - Constant n > capacity: provable overflow → bounded_copy_overflow (confirmed).
//   - Constant n <= capacity: a copy API (strncpy/memcpy/memmove) provably fits
//     → suppressed; an append API (strncat) is NOT provably safe (existing
//     content may already fill the buffer) → fall through.
//   - Variable n that is a caller-influenced parameter → bounded_copy_var_size
//     (possible), handed to the AI agent.
//   - Unknown capacity, or a bounded local n: strncpy (nominally safe) is
//     suppressed; memcpy/memmove/strncat stay conservative and fall through.
func (d *BufferOverflowDetector) checkBoundedCopyOverflow(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, call parser.Node, callName string, params map[string]bool, result *DetectResult) bool {
	// A nominally-safe bounded copy (strncpy) is suppressed by default; an
	// unsafe one (memcpy/memmove/strncat) stays conservative by falling through.
	safeDefault := apikb.IsSafeFunction(callName)

	args := callNamedArguments(call)
	if len(args) < 3 {
		return safeDefault
	}
	dstArg := args[0]
	sizeArg := args[2]
	dstName := extractArgName(dstArg)
	if dstName == "" {
		return safeDefault
	}
	capacity := findArraySize(bc, f, dstName)
	if capacity <= 0 {
		capacity = constantAllocationSize(bc, f, dstName)
	}
	if capacity <= 0 {
		return safeDefault
	}

	if n := parseConstantSize(sizeArg); n > 0 {
		if n > capacity {
			d.emitBoundedCopy(ctx, f, file, call, callName, "bounded_copy_overflow",
				fmt.Sprintf("%d", n), fmt.Sprintf("%d", capacity), result)
			return true
		}
		// n fits, but append semantics make "fits" insufficient for strncat.
		if callName == "strncat" {
			return false
		}
		return true
	}

	// Variable copy size: only meaningful when caller-influenced.
	if sizeArg.Kind() == "identifier" && params[sizeArg.Text()] {
		if callName == "strncat" {
			return false // append: keep the conservative generic path
		}
		// A preceding bounds check (if (n >= sizeof(dst)) return;) already
		// guards the copy, so the caller-influenced size cannot overflow.
		if hasPrecedingBoundsCheck(bc.ifs, f, call.StartLine()) {
			return true
		}
		d.emitBoundedCopy(ctx, f, file, call, callName, "bounded_copy_var_size",
			sizeArg.Text(), fmt.Sprintf("%d", capacity), result)
		return true
	}
	return safeDefault
}

func (d *BufferOverflowDetector) emitBoundedCopy(ctx context.Context, f *db.Function, file *db.File, call parser.Node, callName, category, copySize, dstCapacity string, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
	props, _ := json.Marshal(map[string]string{
		"function":     callName,
		"category":     category,
		"expression":   call.Text(),
		"copy_size":    copySize,
		"dst_capacity": dstCapacity,
	})
	if _, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  "BUFFER_ACCESS",
		EntityID:   f.ID,
		LocationID: locID,
		Properties: string(props),
	}); err == nil {
		result.EventsCreated++
	}
}

// checkSecureFunction evaluates an Annex K `_s` function against its contract:
// the declared destination_capacity (arg 1) must be truthful about the real
// buffer, and the required size (source length / copy count) must fit in the
// declared capacity. Two failure modes are detected:
//
//   - capacity-lie:   declared capacity (constant) > real array/malloc capacity
//     → the function trusts a lying size and writes past the buffer (CWE-787).
//   - constraint-hit: required size (constant count, or a literal source) >
//     declared capacity → the runtime constraint handler fires (truncation or
//     abort, an implementation-defined correctness bug).
//
// A caller-influenced variable capacity is handed to the AI agent (possible).
func (d *BufferOverflowDetector) checkSecureFunction(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, call parser.Node, callName string, spec apikb.SecureFuncSpec, params map[string]bool, result *DetectResult) {
	args := callNamedArguments(call)
	if len(args) <= spec.CapArgIdx {
		return
	}
	dstName := extractArgName(args[0])
	if dstName == "" {
		return
	}
	capacity := findArraySize(bc, f, dstName)
	if capacity <= 0 {
		capacity = constantAllocationSize(bc, f, dstName)
	}
	if capacity <= 0 {
		return
	}

	capArg := args[spec.CapArgIdx]
	declaredCap := d.evaluateSizeArg(capArg, bc, f)

	// capacity-lie: the declared capacity exceeds the real buffer.
	if declaredCap > 0 && declaredCap > capacity {
		d.emitSecure(ctx, f, file, call, callName, "secure_copy_overflow",
			fmt.Sprintf("%d", declaredCap), fmt.Sprintf("%d", capacity), result)
		return
	}

	// constraint-hit: the required size exceeds the DECLARED capacity (the
	// function will truncate or trigger its constraint handler).
	if declaredCap > 0 {
		if required := d.secureRequiredSize(call, callName, spec, args, bc, f); required > 0 && required > declaredCap {
			d.emitSecure(ctx, f, file, call, callName, "secure_constraint_violation",
				fmt.Sprintf("%d", required), fmt.Sprintf("%d", declaredCap), result)
		}
		return
	}

	// Variable capacity argument: only meaningful when caller-influenced.
	if capArg.Kind() == "identifier" && params[capArg.Text()] {
		d.emitSecure(ctx, f, file, call, callName, "secure_copy_var_size",
			capArg.Text(), fmt.Sprintf("%d", capacity), result)
	}
}

// secureRequiredSize returns the number of bytes an `_s` function needs to
// write, when statically computable: the copy-count argument for the n-variants
// (memcpy_s/memset_s/strncpy_s/...), or the length+1 of a literal source for
// strcpy_s/strcat_s. It returns 0 when the required size is not a constant.
func (d *BufferOverflowDetector) secureRequiredSize(call parser.Node, callName string, spec apikb.SecureFuncSpec, args []parser.Node, bc *bufCtx, f *db.Function) int {
	if spec.CountArgIdx >= 0 && spec.CountArgIdx < len(args) {
		if n := d.evaluateSizeArg(args[spec.CountArgIdx], bc, f); n > 0 {
			return n
		}
	}
	if len(args) < 3 {
		return 0
	}
	switch callName {
	case "strcpy_s", "strcat_s":
		if l, ok := constantStringLength(args[2].Text()); ok {
			return l + 1
		}
	}
	return 0
}

// evaluateSizeArg returns the constant byte count of a size argument: a numeric
// literal, `(rsize_t)N`, or `sizeof(array)` / `sizeof(*p)`-style expressions
// that resolve to a known array/allocation size. Returns 0 when not constant.
func (d *BufferOverflowDetector) evaluateSizeArg(node parser.Node, bc *bufCtx, f *db.Function) int {
	if n := parseConstantSize(node); n > 0 {
		return n
	}
	cur := node
	for cur.Kind() == "cast_expression" || cur.Kind() == "parenthesized_expression" {
		children := cur.NamedChildren()
		if len(children) == 0 {
			return 0
		}
		cur = children[0]
	}
	if cur.Kind() == "sizeof_expression" {
		// `sizeof(dst)` nests the identifier inside a parenthesized_expression,
		// so walk every identifier descendant and pick the first known array/
		// allocation size.
		for _, id := range cur.FindAll("identifier") {
			if s := findArraySize(bc, f, id.Text()); s > 0 {
				return s
			}
			if s := constantAllocationSize(bc, f, id.Text()); s > 0 {
				return s
			}
		}
	}
	return 0
}

func (d *BufferOverflowDetector) emitSecure(ctx context.Context, f *db.Function, file *db.File, call parser.Node, callName, category, sizeArg, dstCapacity string, result *DetectResult) {
	locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
	props, _ := json.Marshal(map[string]string{
		"function":      callName,
		"category":      category,
		"expression":    call.Text(),
		"size_argument": sizeArg,
		"dst_capacity":  dstCapacity,
	})
	if _, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
		EventType:  "BUFFER_ACCESS",
		EntityID:   f.ID,
		LocationID: locID,
		Properties: string(props),
	}); err == nil {
		result.EventsCreated++
	}
}

// checkScanfSecure evaluates an `_s` input function's per-conversion contract:
// every %s/%c/%[ conversion that reads into a buffer is followed by a
// buffer-size argument that must not exceed the real buffer. It parses a
// constant format string, walks the (buffer, size) vararg pairs, and flags a
// lying size (constant > real capacity) or a caller-influenced variable size.
func (d *BufferOverflowDetector) checkScanfSecure(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, call parser.Node, callName string, fmtIdx int, params map[string]bool, result *DetectResult) {
	args := callNamedArguments(call)
	if len(args) <= fmtIdx {
		return
	}
	format, ok := stringLiteralContent(args[fmtIdx].Text())
	if !ok {
		return
	}
	kinds := scanfConversionKinds(format)
	if len(kinds) == 0 {
		return
	}

	argIdx := fmtIdx + 1
	for _, isBuffer := range kinds {
		if !isBuffer {
			argIdx++
			continue
		}
		if argIdx+1 >= len(args) {
			return // missing buffer or size argument — malformed call
		}
		bufArg := args[argIdx]
		sizeArg := args[argIdx+1]
		argIdx += 2
		d.checkScanfBuffer(ctx, f, file, bc, call, callName, bufArg, sizeArg, params, result)
	}
}

// checkScanfBuffer compares one %s/%c/%[ conversion's buffer-size argument
// against the real capacity of its buffer.
func (d *BufferOverflowDetector) checkScanfBuffer(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, call parser.Node, callName string, bufArg, sizeArg parser.Node, params map[string]bool, result *DetectResult) {
	bufName := extractArgName(bufArg)
	if bufName == "" {
		return
	}
	capacity := findArraySize(bc, f, bufName)
	if capacity <= 0 {
		capacity = constantAllocationSize(bc, f, bufName)
	}
	if capacity <= 0 {
		return
	}
	if k := parseConstantSize(sizeArg); k > 0 {
		if k > capacity {
			d.emitSecure(ctx, f, file, call, callName, "secure_scanf_overflow",
				fmt.Sprintf("%d", k), fmt.Sprintf("%d", capacity), result)
		}
		return
	}
	if sizeArg.Kind() == "identifier" && params[sizeArg.Text()] {
		d.emitSecure(ctx, f, file, call, callName, "secure_scanf_var_size",
			sizeArg.Text(), fmt.Sprintf("%d", capacity), result)
	}
}

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
		v, err := strconv.Atoi(node.Text())
		if err == nil {
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
	return false
}
