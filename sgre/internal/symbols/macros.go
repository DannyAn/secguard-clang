// Package symbols turns source-level identifiers into the definition facts an
// evidence package needs: project macro bodies (#define) and the root that
// bounds the header census. It is shared by the planner (which embeds macros
// into candidate evidence) and the `secguard def` CLI, so a symbol resolved one
// way is resolved the same way everywhere.
package symbols

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	maxMacroBodyLines = 60
	maxMacroBodyBytes = 8192
	maxIndexedMacros  = 50000
	maxMacroRefs      = 32
)

var (
	macroDefRe = regexp.MustCompile(`^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?\s*(.*)$`)
	identRe    = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// MacroDef is one project #define: the name, its parameter list ("" for an
// object-like macro), the full replacement text, and where it lives.
type MacroDef struct {
	Name      string `json:"name"`
	Params    string `json:"params,omitempty"`
	Signature string `json:"signature,omitempty"`
	Body      string `json:"body,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// MacroIndex is a name -> definitions map built once per scan. A name may have
// several definitions (a config-header override); Lookup returns all of them.
type MacroIndex struct {
	byName map[string][]MacroDef
	files  int
}

// Files is the number of header files the census actually read.
func (idx *MacroIndex) Files() int {
	if idx == nil {
		return 0
	}
	return idx.files
}

// Lookup returns every definition of name.
func (idx *MacroIndex) Lookup(name string) []MacroDef {
	if idx == nil {
		return nil
	}
	return idx.byName[name]
}

// Resolve maps referenced names to definitions, preserving reference order and
// de-duplicating by (file, line). limit <= 0 means no cap.
func (idx *MacroIndex) Resolve(refs []string, limit int) []MacroDef {
	if idx == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []MacroDef
	for _, ref := range refs {
		for _, m := range idx.byName[ref] {
			key := m.File + ":" + strconv.Itoa(m.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, m)
			if limit > 0 && len(out) >= limit {
				return out
			}
		}
	}
	return out
}

// BuildMacroIndex reads every project header under root (plus extraFiles) and
// indexes the #define bodies. Headers only: a macro that is local to a .c is
// resolved with ScanMacrosInFile on that file, so a scan never pays a .c pass.
func BuildMacroIndex(root string, extraFiles []string) *MacroIndex {
	idx := &MacroIndex{byName: map[string][]MacroDef{}}
	seen := map[string]bool{}
	var paths []string
	add := func(p string) {
		if p == "" {
			return
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return
		}
		if seen[abs] {
			return
		}
		seen[abs] = true
		paths = append(paths, abs)
	}
	for _, p := range extraFiles {
		add(p)
	}
	if root != "" {
		for _, p := range HeaderFiles(root) {
			add(p)
		}
	}
	for _, p := range paths {
		defs, err := parseMacros(p, "")
		if err != nil {
			continue
		}
		idx.files++
		for _, m := range defs {
			if len(idx.byName) >= maxIndexedMacros {
				break
			}
			idx.byName[m.Name] = append(idx.byName[m.Name], m)
		}
	}
	return idx
}

// ScanMacrosInFile returns the definitions of name in one file. It is the
// name-filtered path used by `secguard def --in` and avoids building an index.
func ScanMacrosInFile(path, name string) []MacroDef {
	defs, err := parseMacros(path, name)
	if err != nil {
		return nil
	}
	return defs
}

// HeaderFiles lists the project headers under root (sorted, excluding vendored
// and generated directories). It is the census every macro lookup shares.
func HeaderFiles(root string) []string {
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return nil
	}
	var out []string
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			name := entry.Name()
			if path != root && strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			if path != root && excludeDirs[strings.ToLower(name)] {
				return fs.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".h", ".hpp", ".hh", ".hxx", ".inc":
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

var excludeDirs = map[string]bool{
	".git": true, "deps": true, "third_party": true, "third-party": true,
	"vendor": true, "external": true, "node_modules": true, "tests": true,
	"test": true, "fuzzing": true, "contrib": true, "examples": true,
	"build": true, "dist": true,
}

// ExtractMacroRefs returns the identifiers in text that can plausibly name a
// macro: function-like calls (next non-space char is "(") and ALL_CAPS
// object-like names. The caller resolves them against the project index, so a
// standard library name that is not #defined in the tree simply misses.
func ExtractMacroRefs(text string) []string {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, loc := range identRe.FindAllStringIndex(text, -1) {
		name := text[loc[0]:loc[1]]
		if len(name) < 2 || seen[name] || cKeywords[name] {
			continue
		}
		next := loc[1]
		for next < len(text) && (text[next] == ' ' || text[next] == '\t' || text[next] == '\n' || text[next] == '\r') {
			next++
		}
		functionLike := next < len(text) && text[next] == '('
		if !functionLike && !isAllCaps(name) {
			continue
		}
		// A member access (`p->MAX`) or a field designator (`.MAX =`) is not a
		// macro reference at the use site we care about.
		if prev := previousNonSpace(text, loc[0]); prev == '.' || prev == '>' {
			continue
		}
		seen[name] = true
		out = append(out, name)
		if len(out) >= maxMacroRefs {
			break
		}
	}
	return out
}

// ReadLines returns lines [start,end] (1-based, inclusive) of path, capped at
// maxLines. It is the shared source-range read for callee/macro closure.
func ReadLines(path string, start, end, maxLines int) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if start < 1 || start > len(lines) {
		return "", false, nil
	}
	if end < start {
		end = start
	}
	if end > len(lines) {
		end = len(lines)
	}
	truncated := false
	if maxLines > 0 && end-start+1 > maxLines {
		end = start + maxLines - 1
		truncated = true
	}
	return strings.TrimRight(strings.Join(lines[start-1:end], "\n"), "\n"), truncated, nil
}

// RootFor derives the header-census root from indexed file paths. It starts at
// the common dir of the indexed files and walks up (at most 3 levels) to the
// nearest directory holding include/ or inc/ — the standard `src` + `include`
// layout. Deliberately NOT the git worktree: a monorepo scan must not pull in a
// sibling project's headers (same-named macros there would poison the evidence).
func RootFor(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	root := CommonDir(paths)
	dir := root
	for i := 0; i < 3; i++ {
		if hasChildDir(dir, "include") || hasChildDir(dir, "inc") {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return root
}

// CommonDir returns the deepest directory containing every path.
func CommonDir(paths []string) string {
	root := filepath.Dir(paths[0])
	for _, p := range paths[1:] {
		dir := filepath.Dir(p)
		for !strings.HasPrefix(dir+string(filepath.Separator), root+string(filepath.Separator)) {
			parent := filepath.Dir(root)
			if parent == root {
				return root
			}
			root = parent
		}
	}
	return root
}

func parseMacros(path, only string) ([]MacroDef, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var defs []MacroDef
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !strings.Contains(line, "#") {
			continue
		}
		m := macroDefRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name := m[1]
		if only != "" && name != only {
			continue
		}
		end := i
		for end < len(lines)-1 && end-i+1 < maxMacroBodyLines &&
			strings.HasSuffix(strings.TrimRight(lines[end], " \t"), "\\") {
			end++
		}
		truncated := end-i+1 >= maxMacroBodyLines && end < len(lines)-1 &&
			strings.HasSuffix(strings.TrimRight(lines[end], " \t"), "\\")
		body := strings.TrimRight(strings.Join(lines[i:end+1], "\n"), "\n")
		if len(body) > maxMacroBodyBytes {
			body = body[:maxMacroBodyBytes]
			truncated = true
		}
		defs = append(defs, MacroDef{
			Name:      name,
			Params:    m[2],
			Signature: "#define " + name + m[2],
			Body:      body,
			File:      path,
			Line:      i + 1,
			EndLine:   end + 1,
			Truncated: truncated,
		})
	}
	return defs, nil
}

var cKeywords = map[string]bool{
	"if": true, "else": true, "for": true, "while": true, "do": true,
	"switch": true, "case": true, "default": true, "break": true,
	"continue": true, "return": true, "goto": true, "sizeof": true,
	"typedef": true, "struct": true, "union": true, "enum": true,
	"static": true, "extern": true, "const": true, "volatile": true,
	"inline": true, "register": true, "auto": true, "void": true,
	"char": true, "short": true, "int": true, "long": true, "float": true,
	"double": true, "signed": true, "unsigned": true, "defined": true,
}

func isAllCaps(name string) bool {
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

func previousNonSpace(text string, pos int) byte {
	for i := pos - 1; i >= 0; i-- {
		switch text[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return text[i]
		}
	}
	return 0
}

func hasChildDir(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && info.IsDir()
}
