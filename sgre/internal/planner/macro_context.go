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
	for _, fn := range funcs {
		names[fn.Name] = true
	}

	d.mu.Lock()
	if !d.funcsLoaded {
		d.definedFuncs = names
		d.funcsLoaded = true
	}
	d.mu.Unlock()
}

// hasMacroContext reports whether the source region around line (the statement
// at line plus ±macroContextWindow) contains a function-like macro call.
func (d *macroContextDetector) hasMacroContext(path string, line int) bool {
	if path == "" || line <= 0 {
		return false
	}
	all := d.fileLines(path)
	if all == nil || line > len(all) {
		return false
	}
	// Snapshot the defined-name set: the writer replaces the map wholesale
	// (never mutates a published one), so the reference is stable for the
	// scan below without holding the mutex per regex match.
	d.mu.Lock()
	defined := d.definedFuncs
	d.mu.Unlock()

	start := line - macroContextWindow
	if start < 1 {
		start = 1
	}
	end := line + macroContextWindow
	if end > len(all) {
		end = len(all)
	}
	for _, l := range all[start-1 : end] {
		// A preprocessor line (#define FOO(x) ...) DECLARES a macro, it does
		// not CALL one: the dereference does not involve FOO just because
		// its definition sits in the window.
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		for _, m := range macroCallRe.FindAllStringSubmatch(l, -1) {
			name := m[1]
			if d.known[name] {
				return true
			}
			// An ALL_CAPS name that the function index knows as a scanned
			// DEFINITION is a function, not a #define: the convention
			// heuristic yields to the index.
			if isAllCapsMacroName(name) && (defined == nil || !defined[name]) {
				return true
			}
		}
	}
	return false
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
