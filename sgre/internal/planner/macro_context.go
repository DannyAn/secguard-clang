package planner

import (
	"context"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
)

// macroCallRe matches a function-like call identifier immediately followed by
// "(". The captured name is tested against the ALL_CAPS convention and the known
// macro-name set; C keywords (if/for/while/return/sizeof, all lowercase) are
// never flagged because they are neither ALL_CAPS nor a known macro name.
var macroCallRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\(`)

// macroContextWindow is how many source lines on each side of the reported
// statement are scanned for a macro call. It matches candidateContextLines so a
// guard macro a few lines BEFORE the deref (DBM_CHECK_RET) and an accessor macro
// ON the deref line (DBM_TAILQ_FIRST) are both caught.
const macroContextWindow = 8

// macroContextDetector detects whether a candidate's source region involves a
// function-like macro. It is shared across concurrent Plan() calls, so the
// file-line cache is mutex-guarded: each source file is read at most once per
// scan regardless of how many vuln types reference it.
type macroContextDetector struct {
	mu    sync.Mutex
	lines map[string][]string
	known map[string]bool

	// definedFuncs holds the names of every function DEFINED in the current
	// scan, loaded once from the function index. The ALL_CAPS convention is
	// only a heuristic: a static function named like a macro (POOL_SECT) is
	// a real function, and flagging its call as macro context wrongly
	// blocks the auto-confirm gate. Names in the explicit `known` config
	// sets keep priority — user intent beats the index.
	funcsLoaded  bool
	definedFuncs map[string]bool
	// funcSpans bounds each function's body (ID -> [start, end]) from the same
	// index load. The context window must never leak across a function
	// boundary: an ALL_CAPS macro call in a NEIGHBOURING function 8 lines away
	// is not part of this dereference's context, and treating it as such both
	// demoted honestly confirmed candidates and fed the "no concrete source
	// line" dismissal an unrelated macro.
	funcSpans map[int64][2]int
}

func newMacroContextDetector() *macroContextDetector {
	known := map[string]bool{}
	cfg := config.Load()
	for _, n := range cfg.TrustedMacroNames() {
		known[n] = true
	}
	for _, n := range cfg.BannedFunctionNames() {
		known[n] = true
	}
	for n := range cfg.IteratorMacroArgs() {
		known[n] = true
	}
	// Built-in iterator macros (list_for_each_entry & friends) are lower-case and
	// already modeled by the pipeline, but a candidate involving one is still
	// macro-context: the deterministic model may have mis-fired, so the AI gets a
	// look before anything is auto-confirmed.
	for n := range apikb.IteratorMacros {
		known[n] = true
	}
	return &macroContextDetector{lines: map[string][]string{}, known: known}
}

func (d *macroContextDetector) fileLines(path string) []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if l, ok := d.lines[path]; ok {
		return l
	}
	data, err := os.ReadFile(path)
	if err != nil {
		d.lines[path] = nil
		return nil
	}
	all := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if n := len(all); n > 0 && all[n-1] == "" {
		all = all[:n-1]
	}
	d.lines[path] = all
	return all
}

// ensureDefinedFuncs loads the scan's function-definition names into the
// detector once. Best-effort like fileLines: on a store failure the detector
// falls back to the pure ALL_CAPS heuristic (the flag is an AI-routing hint,
// not a proof, and the seed stage has already failed loudly on a broken store
// long before this point).
func (d *macroContextDetector) ensureDefinedFuncs(ctx context.Context, store db.Store) {
	if store == nil {
		return
	}
	d.mu.Lock()
	if d.funcsLoaded {
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return
	}
	names := make(map[string]bool, len(funcs))
	spans := make(map[int64][2]int, len(funcs))
	for _, fn := range funcs {
		names[fn.Name] = true
		spans[fn.ID] = [2]int{fn.StartLine, fn.EndLine}
	}

	d.mu.Lock()
	if !d.funcsLoaded {
		d.definedFuncs = names
		d.funcSpans = spans
		d.funcsLoaded = true
	}
	d.mu.Unlock()
}

// macroContextAt is the function-scoped entry point: the context window is
// clamped to the candidate function's own body (from the function index) so a
// macro call in a NEIGHBOURING function can never be mistaken for this
// dereference's macro context. When the span is unknown (a function missing
// from the index) it falls back to the file-wide window.
func (d *macroContextDetector) macroContextAt(ctx context.Context, store db.Store, funcID int64, path string, line int) bool {
	d.ensureDefinedFuncs(ctx, store)
	d.mu.Lock()
	span, ok := d.funcSpans[funcID]
	d.mu.Unlock()
	if !ok || span[0] <= 0 || span[1] < span[0] {
		return d.hasMacroContext(path, line)
	}
	return d.hasMacroContextIn(path, line, span[0], span[1])
}

// hasMacroContext reports whether the source region around line (the statement
// at line plus ±macroContextWindow) contains a function-like macro call.
func (d *macroContextDetector) hasMacroContext(path string, line int) bool {
	return d.hasMacroContextIn(path, line, 0, 0)
}

// hasMacroContextIn is hasMacroContext with the scan window clamped to
// [lo, hi] (inclusive); 0/0 means "no clamp" (the whole file).
func (d *macroContextDetector) hasMacroContextIn(path string, line, lo, hi int) bool {
	context, _ := d.scanWindow(path, line, lo, hi, "")
	return context
}

// macroContextMentions reports whether a function-like macro call in the
// context window of line mentions variable (as a whole identifier, in its own
// text or its argument text). This is the narrow signal behind the cfg-proof
// demotion: a macro that does not even name the variable cannot have reassigned
// it, so the CFG proof still stands; a macro that receives it (`SLL_Scan(sll,
// car_policy, ...)`, `LOG_PTR(p)`) may assign it, and without expansion the
// proof is unverifiable.
func (d *macroContextDetector) macroContextMentions(ctx context.Context, store db.Store, funcID int64, path string, line int, variable string) bool {
	name := variableRoot(variable)
	if name == "" {
		return false
	}
	d.ensureDefinedFuncs(ctx, store)
	d.mu.Lock()
	span, ok := d.funcSpans[funcID]
	d.mu.Unlock()
	lo, hi := 0, 0
	if ok && span[0] > 0 && span[1] >= span[0] {
		lo, hi = span[0], span[1]
	}
	_, mentions := d.scanWindow(path, line, lo, hi, name)
	return mentions
}

// variableRoot strips a member/subscript chain to the pointer variable that owns
// it: `p->a.b` -> "p", `arr[i]` -> "arr". A macro can only reassign the root
// pointer, so that is the name worth looking for.
func variableRoot(name string) string {
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '-', '.', '[', ' ', '(', ')':
			return strings.TrimSpace(name[:i])
		}
	}
	return strings.TrimSpace(name)
}

// scanWindow walks the context window and reports (a) whether it contains a
// function-like macro CALLS (not a #define), and (b) whether any such call site
// mentions the identifier name.
func (d *macroContextDetector) scanWindow(path string, line, lo, hi int, name string) (bool, bool) {
	if path == "" || line <= 0 {
		return false, false
	}
	all := d.fileLines(path)
	if all == nil || line > len(all) {
		return false, false
	}
	// Snapshot the defined-name set: the writer replaces the map wholesale
	// (never mutates a published one), so the reference is stable for the
	// scan below without holding the mutex per regex match.
	d.mu.Lock()
	defined := d.definedFuncs
	d.mu.Unlock()

	start := line - macroContextWindow
	end := line + macroContextWindow
	if lo > 0 && lo > start {
		start = lo
	}
	if hi > 0 && hi < end {
		end = hi
	}
	if start < 1 {
		start = 1
	}
	if end > len(all) {
		end = len(all)
	}
	if start > end {
		return false, false
	}
	context := false
	for i, l := range all[start-1 : end] {
		// A preprocessor line (#define FOO(x) ...) DECLARES a macro, it does
		// not CALL one: the dereference does not involve FOO just because
		// its definition sits in the window.
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		for _, m := range macroCallRe.FindAllStringSubmatchIndex(l, -1) {
			macroName := l[m[2]:m[3]]
			isMacro := d.known[macroName]
			if !isMacro {
				// An ALL_CAPS name that the function index knows as a scanned
				// DEFINITION is a function, not a #define: the convention
				// heuristic yields to the index.
				isMacro = isAllCapsMacroName(macroName) && (defined == nil || !defined[macroName])
			}
			if !isMacro {
				continue
			}
			context = true
			if name == "" {
				continue
			}
			// Only the macro's ARGUMENT LIST can pass the variable into the
			// macro. Testing the whole line would match the variable's own use
			// site (`return a + 1 + MYMACRO(0)`) and demote a proof the macro
			// cannot touch.
			if mentionsIdentifier(macroArgsText(all, start-1+i, m[1]-1), name) {
				return context, true
			}
		}
	}
	return context, false
}

// macroArgsText returns the text of the argument list starting at the "(" in
// line lines[idx][openCol], following backslash continuations. It stops at the
// matching ")" (balanced) or at the end of the continued lines. A truncated
// result is harmless for its only consumer: a missed argument match can only
// keep a machine verdict that a full read would have demoted, never demote one
// a macro cannot touch.
func macroArgsText(lines []string, idx, openCol int) string {
	if idx < 0 || idx >= len(lines) || openCol < 0 || openCol >= len(lines[idx]) {
		return ""
	}
	var b strings.Builder
	depth := 0
	for ; idx < len(lines); idx++ {
		line := lines[idx]
		for i := openCol; i < len(line); i++ {
			ch := line[i]
			b.WriteByte(ch)
			switch ch {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					return b.String()
				}
			}
		}
		openCol = 0
		// A macro invocation spans lines only via a trailing backslash.
		if !strings.HasSuffix(strings.TrimSpace(line), "\\") {
			break
		}
	}
	return b.String()
}

func mentionsIdentifier(line, name string) bool {
	if name == "" {
		return false
	}
	for idx := 0; ; {
		j := strings.Index(line[idx:], name)
		if j < 0 {
			return false
		}
		pos := idx + j
		before := byte(' ')
		if pos > 0 {
			before = line[pos-1]
		}
		after := byte(' ')
		if pos+len(name) < len(line) {
			after = line[pos+len(name)]
		}
		if !isIdentByte(before) && !isIdentByte(after) {
			return true
		}
		idx = pos + len(name)
	}
}

// isAllCapsMacroName reports whether name follows the C convention for a
// function-like macro: at least two characters, at least one uppercase letter,
// and no lowercase letter (so C keywords and ordinary lower-case function calls
// never match). Digits and underscores are allowed.
func isAllCapsMacroName(name string) bool {
	if len(name) < 2 {
		return false
	}
	hasLetter := false
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			return false
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		}
	}
	return hasLetter
}
