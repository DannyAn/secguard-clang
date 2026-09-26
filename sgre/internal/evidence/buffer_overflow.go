package evidence

import (
	"context"
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

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		bc := &bufCtx{
			root:    root,
			calls:   root.FindAll("call_expression"),
			subs:    root.FindAll("subscript_expression"),
			derefs:  root.FindAll("pointer_expression"),
			ifs:     root.FindAll("if_statement"),
			decls:   root.FindAll("declaration"),
			assigns: root.FindAll("assignment_expression"),
			updates: root.FindAll("update_expression"),
			fors:    root.FindAll("for_statement"),
			inits:   root.FindAll("init_declarator"),
			fields:  root.FindAll("field_declaration"),
			macros:  buildMacroValues(root),
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
	derefs  []parser.Node
	ifs     []parser.Node
	decls   []parser.Node
	assigns []parser.Node
	updates []parser.Node
	fors    []parser.Node
	inits   []parser.Node
	fields  []parser.Node
	macros  map[string]int
}

// buildMacroValues resolves object-like `#define NAME 10` macros to their
// numeric value, so an array sized by a macro (`int arr[MAX]`) is not silently
// treated as unknown-size. Function-like macros are ignored.
func buildMacroValues(root parser.Node) map[string]int {
	macros := make(map[string]int)
	for _, def := range root.FindAll("preproc_def") {
		var name string
		value := -1
		for _, child := range def.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				if name == "" {
					name = child.Text()
				}
			case "number_literal":
				if v := parseConstantIndex(child.Text()); v >= 0 {
					value = v
				}
			case "preproc_arg":
				if v := parseConstantIndex(strings.TrimSpace(child.Text())); v >= 0 {
					value = v
				}
			}
		}
		if name != "" && value >= 0 {
			macros[name] = value
		}
	}
	return macros
}

func (d *BufferOverflowDetector) detectUnsafeCalls(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, params map[string]bool, result *DetectResult) {
	bounds := AnalyzeBounds(IfsInFunc(bc.ifs, f.StartLine, f.EndLine), assignsInFunc(bc.assigns, f.StartLine, f.EndLine))
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
			if d.checkBoundedCopyOverflow(ctx, f, file, bc, call, callName, params, bounds, result) {
				continue
			}
		}
		// read/recv/fread write at most `count` bytes into the buffer, so
		// `read(fd, buf, sizeof(buf))` is safe — the previous generic path flagged
		// the sizeof(buf) idiom as a buffer overflow (BO-12).
		if callName == "read" || callName == "recv" || callName == "fread" {
			if d.suppressReadFamily(bc, f, call, callName) {
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
		if hasPrecedingBoundsCheck(bc, f, call, callName) {
			continue
		}
		if suppressConstantStringCopy(bc, f, call) {
			continue
		}
		if suppressExactFitCopy(bc, f, call) {
			continue
		}
		category := "buffer_overflow"

		if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
			"function":   callName,
			"category":   category,
			"expression": call.Text(),
		}) {
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
func (d *BufferOverflowDetector) checkBoundedCopyOverflow(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, call parser.Node, callName string, params map[string]bool, bounds *RangeFacts, result *DetectResult) bool {
	// A nominally-safe bounded copy (strncpy) is suppressed by default; an
	// unsafe one (memcpy/memmove/strncat) stays conservative by falling through.
	safeDefault := apikb.IsSafeFunction(callName)

	args := callNamedArguments(call)
	if len(args) < 3 {
		return safeDefault
	}
	dstArg := args[0]
	sizeArg := args[2]
	// `memcpy(&var, src, sizeof(var))` / `sizeof(*var)` copies exactly the
	// destination object's own size (a value copy), so it cannot overflow. The
	// size must reference the DESTINATION: `memcpy(&dst, src, sizeof(*src))`
	// copies the SOURCE's size into dst and overflows whenever *src is larger
	// than dst, so it is NOT a value copy and falls through (BO-09). A `sizeof(T)`
	// type-name form cannot be matched to dst without a type table and is kept
	// conservative (falls through).
	if strings.HasPrefix(strings.TrimSpace(dstArg.Text()), "&") &&
		strings.HasPrefix(strings.TrimSpace(sizeArg.Text()), "sizeof") {
		dstName := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(dstArg.Text()), "&"))
		dstName = strings.Trim(dstName, "()")
		if dstName != "" && sizeofOperandMatches(sizeArg.Text(), dstName) {
			return true
		}
	}
	dstName := extractArgName(dstArg)
	if dstName == "" {
		return safeDefault
	}
	capacity := findArraySize(bc, f, dstName, call.StartLine())
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

	// Variable copy size.
	if sizeArg.Kind() == "identifier" {
		// A guard bounding the copy size above by the destination capacity
		// (`if (n <= sizeof(dst)) memcpy(dst, src, n)`) makes the copy safe
		// regardless of whether n is a parameter or a local.
		if bounds != nil && capacity > 0 {
			if hi := bounds.UpperBoundAt(sizeArg.Text(), call.StartLine()); hi > 0 && hi <= capacity {
				return true
			}
		}
		if params[sizeArg.Text()] {
			if callName == "strncat" {
				return false // append: keep the conservative generic path
			}
			// A preceding bounds check (if (n >= sizeof(dst)) return;) already
			// guards the copy, so the caller-influenced size cannot overflow.
			if hasPrecedingBoundsCheck(bc, f, call, callName) {
				return true
			}
			d.emitBoundedCopy(ctx, f, file, call, callName, "bounded_copy_var_size",
				sizeArg.Text(), fmt.Sprintf("%d", capacity), result)
			return true
		}
	}
	return safeDefault
}

func (d *BufferOverflowDetector) emitBoundedCopy(ctx context.Context, f *db.Function, file *db.File, call parser.Node, callName, category, copySize, dstCapacity string, result *DetectResult) {
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
		"function":     callName,
		"category":     category,
		"expression":   call.Text(),
		"copy_size":    copySize,
		"dst_capacity": dstCapacity,
	}) {
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
	capacity := findArraySize(bc, f, dstName, call.StartLine())
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
			if s := findArraySize(bc, f, id.Text(), node.StartLine()); s > 0 {
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
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
		"function":      callName,
		"category":      category,
		"expression":    call.Text(),
		"size_argument": sizeArg,
		"dst_capacity":  dstCapacity,
	}) {
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
	capacity := findArraySize(bc, f, bufName, call.StartLine())
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
		// that merely assigns (`y = 1`) is not a guard.
		if cons := ifNode.ChildByFieldName("consequence"); cons != nil && bodyExits(*cons) {
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

// bodyExits reports whether an if consequence exits the current control flow
// (return/break/continue) — a true error-exit guard, not a mere assignment.
func bodyExits(node parser.Node) bool {
	text := node.Text()
	return strings.Contains(text, "return") || strings.Contains(text, "break") || strings.Contains(text, "continue")
}

func isRelationalCondition(text string) bool {
	return strings.Contains(text, " > ") || strings.Contains(text, " >= ") ||
		strings.Contains(text, " < ") || strings.Contains(text, " <= ") ||
		strings.Contains(text, ">=") || strings.Contains(text, "<=") ||
		strings.Contains(text, " >") || strings.Contains(text, " <")
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
		// subscriptBaseIndex recovers the real base + index even when a macro
		// call site glues a call_expression as children[0] and buries the array
		// name in an ERROR child (e.g. `arr[10] = 1` inside a macro loop).
		arrName, indexExpr, ok := subscriptBaseIndex(sub)
		if !ok {
			continue
		}
		kind := subscriptAccessKind(bc, f, sub)
		if isOOB, category, arrSize := d.checkArrayOOB(bc, f, arrName, indexExpr, sub.StartLine(), kind); isOOB {
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
		if isOOB, category, arrSize := d.checkArrayOOB(bc, f, arrName, indexExpr, deref.StartLine(), kind); isOOB {
			d.emitOOB(ctx, f, file, deref.StartLine(), arrName, indexExpr, category, deref.Text(), arrSize, result)
		}
	}
}

// checkArrayOOB runs the constant / loop-bound / heap-allocation OOB proof for a
// base + index pair, returning the verdict and category (BO-10: shared by the
// subscript and pointer-dereference scans).
func (d *BufferOverflowDetector) checkArrayOOB(bc *bufCtx, f *db.Function, arrName, indexExpr string, line int, kind string) (bool, string, int) {
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
		children := node.NamedChildren()
		if len(children) < 2 {
			return false
		}
		if assignedVariable(children[0]) != indexVar {
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
		v, ok := constantNodeValue(bc, children[1])
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
// cast/parenthesized wrapper of either. It reports ok=false for anything else
// (BO-07: a hex literal or `int n = SIZE; buf[n]` is a definite constant).
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
		capacity := findArraySize(bc, f, dst, call.StartLine())
		if capacity <= 0 {
			capacity = findFieldArraySize(bc, dst)
		}
		if capacity <= 0 {
			continue
		}
		if hasPrecedingBoundsCheck(bc, f, call, callName) {
			continue
		}
		if destFeedsInjectionSink(bc, f, dst, call.StartLine()) {
			continue
		}
		if overflow := classifyFormatOverflow(args, capacity); overflow != formatNoOverflow {
			category := "format_overflow"
			if overflow == formatOverflowPossible {
				// A non-constant format argument can overflow, but is not
				// provable: `sprintf(buf, "%d", n)` cannot exceed a 64-byte
				// buffer even though `n` is unknown. Keep it suspected so the
				// AI reads the actual argument width before confirming.
				category = "format_overflow_var"
			}
			if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
				"function":   callName,
				"category":   category,
				"expression": call.Text(),
			}) {
				result.EventsCreated++
			}
		}
	}
}

// formatOverflowKind classifies a formatted write against a fixed capacity:
// formatNoOverflow — provably fits; formatOverflowDefinite — the literal
// (constant) output length provably equals or exceeds capacity; and
// formatOverflowPossible — a non-constant argument makes overflow possible but
// not certain. The definite tier is what may safely be marked "confirmed"; the
// possible tier stays "suspected" because `sprintf(buf, "%d", n)` never
// overflows a 64-byte buffer for any int n.
type formatOverflowKind int

const (
	formatNoOverflow formatOverflowKind = iota
	formatOverflowDefinite
	formatOverflowPossible
)

func classifyFormatOverflow(args []string, capacity int) formatOverflowKind {
	nonConst := false
	staticLen := 0
	// The format string's literal characters are ALWAYS output (BO-16): a pure
	// literal `sprintf(buf, "very long literal...")` has no arguments to sum, so
	// the previous args[2:]-only loop reported formatNoOverflow even when the
	// literal provably exceeds capacity.
	if len(args) >= 2 {
		if l, ok := formatLiteralLength(strings.TrimSpace(args[1])); ok {
			staticLen += l
		} else {
			nonConst = true
		}
	}
	for i := 2; i < len(args); i++ {
		l, ok := constantStringLength(strings.TrimSpace(args[i]))
		if !ok {
			nonConst = true
			continue
		}
		staticLen += l
	}
	if staticLen >= capacity {
		return formatOverflowDefinite
	}
	if nonConst {
		return formatOverflowPossible
	}
	return formatNoOverflow
}

// formatLiteralLength returns the number of literal (non-conversion) characters
// a printf format string emits. `%` conversions are skipped (their output comes
// from the arguments, counted separately); `%%` counts as one literal `%`.
// Escapes make the length nontrivial and are rejected (ok=false).
func formatLiteralLength(fmt string) (int, bool) {
	t := strings.TrimSpace(fmt)
	if len(t) < 2 || t[0] != '"' || t[len(t)-1] != '"' {
		return 0, false
	}
	inner := t[1 : len(t)-1]
	if strings.Contains(inner, `\`) {
		return 0, false
	}
	lit := 0
	for i := 0; i < len(inner); i++ {
		if inner[i] != '%' {
			lit++
			continue
		}
		if i+1 < len(inner) && inner[i+1] == '%' {
			lit++
			i++
			continue
		}
		i++ // skip the '%'
		for i < len(inner) && !strings.ContainsRune("diouxXfFeEgGcsaApn", rune(inner[i])) {
			i++
		}
	}
	return lit, true
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
	// Decide read vs write by the AST parent relationship, not a same-line text
	// match. The previous `strings.Contains(children[0].Text(), subText)` matched
	// both subscripts of `a[i] = a[i] + 1` on one line and mis-categorized the
	// read side as a write, routing it to the wrong vuln type (BO-14).
	for p := sub.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "assignment_expression", "init_declarator":
			children := p.NamedChildren()
			if len(children) >= 1 && sameNode(children[0], sub) {
				return "write"
			}
			return "read"
		case "update_expression":
			return "write"
		case "binary_expression", "parenthesized_expression", "cast_expression",
			"subscript_expression", "argument_list", "call_expression",
			"field_expression", "pointer_expression", "unary_expression":
			continue // nested inside a larger expression; keep walking up
		default:
			return "read"
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
	byteSize := -1 // -1 unknown, -2 = sizeof(dst) (always fits)
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
