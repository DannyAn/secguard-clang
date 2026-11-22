package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
)

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
			// Attach the resolved destination capacity and name so the hint
			// carries buf@/cap@: a format-overflow row used to show only
			// api@sprintf, forcing the classifier to open the source just to
			// learn the destination is a bounded 128-byte global.
			props := map[string]string{
				"function":   callName,
				"category":   category,
				"expression": call.OriginalText(),
				"array":      dst,
				"size":       strconv.Itoa(capacity),
			}
			// The format's variable arguments are the overflow contributors; a
			// %s conversion whose operand is a bounded global is the common
			// "both sides bounded" safe shape (sprintf(g_dst, "%s", g_src)).
			if len(args) >= 3 {
				if srcCap := findArraySize(bc, f, strings.TrimSpace(args[2]), call.StartLine()); srcCap > 0 {
					props["src_capacity"] = strconv.Itoa(srcCap)
				}
			}
			if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
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
	if g, ok := bc.facts.GlobalArray(field); ok && g.Count > 0 {
		return g.Count
	}
	return 0
}
