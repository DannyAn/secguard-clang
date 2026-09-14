package planner

import (
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/config"
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
	start := line - macroContextWindow
	if start < 1 {
		start = 1
	}
	end := line + macroContextWindow
	if end > len(all) {
		end = len(all)
	}
	for _, l := range all[start-1 : end] {
		for _, m := range macroCallRe.FindAllStringSubmatch(l, -1) {
			if name := m[1]; isAllCapsMacroName(name) || d.known[name] {
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
