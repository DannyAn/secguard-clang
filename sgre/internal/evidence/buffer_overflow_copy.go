package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

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
	// A nominally-safe bounded copy (strncpy) is suppressed by default when the
	// destination capacity is unknown, while a size-vs-capacity mismatch is still
	// checked above. The other bounded copies stay conservative by falling through.
	safeDefault := callName == "strncpy" || apikb.IsSafeFunction(callName)

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
		// `memcpy(&packet->header, src, sizeof(PacketHeader))` — a struct-field
		// exact-fit: the size names a TYPE, and the field is declared with that
		// same type. Without a full type table this resolves via the field's
		// declaration in the file (unambiguous only when every match agrees).
		if typeName := sizeofTypeName(sizeArg.Text()); typeName != "" {
			if field := fieldAccessName(dstName); field != "" && findFieldTypeName(bc, field) == typeName {
				return true
			}
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
				dstName, fmt.Sprintf("%d", n), fmt.Sprintf("%d", capacity), result)
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
				dstName, sizeArg.Text(), fmt.Sprintf("%d", capacity), result)
			return true
		}
	}
	return safeDefault
}

func (d *BufferOverflowDetector) emitBoundedCopy(ctx context.Context, f *db.Function, file *db.File, call parser.Node, callName, category, dstName, copySize, dstCapacity string, result *DetectResult) {
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
		"function":     callName,
		"category":     category,
		"expression":   call.OriginalText(),
		"copy_size":    copySize,
		"dst_capacity": dstCapacity,
		"array":        dstName,
		"size":         dstCapacity,
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
			dstName, fmt.Sprintf("%d", declaredCap), fmt.Sprintf("%d", capacity), result)
		return
	}

	// constraint-hit: the required size exceeds the DECLARED capacity (the
	// function will truncate or trigger its constraint handler).
	if declaredCap > 0 {
		if required := d.secureRequiredSize(call, callName, spec, args, bc, f); required > 0 && required > declaredCap {
			d.emitSecure(ctx, f, file, call, callName, "secure_constraint_violation",
				dstName, fmt.Sprintf("%d", required), fmt.Sprintf("%d", declaredCap), result)
		}
		return
	}

	// Variable capacity argument: only meaningful when caller-influenced.
	if capArg.Kind() == "identifier" && params[capArg.Text()] {
		d.emitSecure(ctx, f, file, call, callName, "secure_copy_var_size",
			dstName, capArg.Text(), fmt.Sprintf("%d", capacity), result)
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

func (d *BufferOverflowDetector) emitSecure(ctx context.Context, f *db.Function, file *db.File, call parser.Node, callName, category, dstName, sizeArg, dstCapacity string, result *DetectResult) {
	if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
		"function":      callName,
		"category":      category,
		"expression":    call.OriginalText(),
		"size_argument": sizeArg,
		"dst_capacity":  dstCapacity,
		"array":         dstName,
		"size":          dstCapacity,
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
				bufName, fmt.Sprintf("%d", k), fmt.Sprintf("%d", capacity), result)
		}
		return
	}
	if sizeArg.Kind() == "identifier" && params[sizeArg.Text()] {
		d.emitSecure(ctx, f, file, call, callName, "secure_scanf_var_size",
			bufName, sizeArg.Text(), fmt.Sprintf("%d", capacity), result)
	}
}
