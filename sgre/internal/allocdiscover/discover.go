// Package allocdiscover discovers project-specific allocator/deallocator
// functions from an indexed secguard database and renders them as a suggested
// secguard.toml. It is a side-channel: its output is advisory and never feeds
// back into the scan pipeline.
package allocdiscover

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/symbols"
)

const (
	ConfHigh   = "high"
	ConfMedium = "medium"
	ConfLow    = "low"
)

// Entry is one suggested allocator or deallocator.
type Entry struct {
	Name       string
	Confidence string
	Reasons    []string
}

// Result is the discovered suggestion set.
type Result struct {
	Allocators         []Entry
	Deallocators       []Entry
	OwnershipTransfers []Entry
	IteratorMacros     []Entry
}

type symbol struct {
	name         string
	returnType   string
	signature    string
	callsAlloc   []string
	callsDealloc []string
}

type calleeInfo struct {
	name    string
	alloc   bool
	dealloc bool
}

type macroEntry struct {
	name         string
	bodies       []string
	functionLike bool
}

var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)

// Discover scans the indexed functions, declarations and CALL edges and returns
// the suggested allocator/deallocator lists. A symbol already known to apikb
// (a built-in, an external-API model, or a name declared in secguard.toml) is
// skipped. The call-edge probe is best-effort: when it fails the discovery still
// returns name-pattern and signature candidates.
func Discover(ctx context.Context, store db.Store) (*Result, error) {
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return nil, err
	}
	decls, err := store.ListFunctionDeclarations(ctx)
	if err != nil {
		return nil, err
	}

	syms := map[string]*symbol{}
	for _, f := range funcs {
		s := syms[f.Name]
		if s == nil {
			s = &symbol{name: f.Name, returnType: f.ReturnType, signature: f.Signature}
			syms[f.Name] = s
		}
	}
	for _, d := range decls {
		if syms[d.Name] == nil {
			syms[d.Name] = &symbol{name: d.Name, returnType: d.ReturnType, signature: d.Signature}
		}
	}

	if calls, cerr := allocDeallocCalls(ctx, store); cerr == nil {
		byID := map[int64]string{}
		for _, f := range funcs {
			byID[f.ID] = f.Name
		}
		for fid, callsFor := range calls {
			s := syms[byID[fid]]
			if s == nil {
				continue
			}
			for _, c := range callsFor {
				if c.alloc {
					s.callsAlloc = append(s.callsAlloc, c.name)
				}
				if c.dealloc {
					s.callsDealloc = append(s.callsDealloc, c.name)
				}
			}
		}
	}

	res := &Result{}
	emitted := map[string]bool{}
	for name, s := range syms {
		if apikb.IsDeclaredAllocator(name) || apikb.IsDeclaredDeallocator(name) {
			continue
		}
		if e, ok := classifyOwnershipTransfer(*s); ok && e.Confidence != ConfLow {
			res.OwnershipTransfers = append(res.OwnershipTransfers, e)
			emitted[name] = true
			continue
		}
		if e, kind, ok := classify(*s); ok {
			appendEntry(res, e, kind)
			emitted[name] = true
			continue
		}
		if e, ok := classifyOwnershipTransfer(*s); ok {
			res.OwnershipTransfers = append(res.OwnershipTransfers, e)
			emitted[name] = true
		}
	}
	for _, m := range discoverMacros(ctx, store) {
		if emitted[m.name] || apikb.IsDeclaredAllocator(m.name) || apikb.IsDeclaredDeallocator(m.name) {
			continue
		}
		if e, kind, ok := classifyMacro(m); ok {
			appendEntry(res, e, kind)
			emitted[m.name] = true
			continue
		}
		if e, ok := classifyIteratorMacro(m); ok {
			res.IteratorMacros = append(res.IteratorMacros, e)
			emitted[m.name] = true
		}
	}
	sortEntries(res.Allocators)
	sortEntries(res.Deallocators)
	sortEntries(res.OwnershipTransfers)
	sortEntries(res.IteratorMacros)
	return res, nil
}

func appendEntry(res *Result, e Entry, kind string) {
	switch kind {
	case "allocator":
		res.Allocators = append(res.Allocators, e)
	case "deallocator":
		res.Deallocators = append(res.Deallocators, e)
	}
}

// discoverMacros builds the project header #define census and returns one entry
// per macro name (merging the bodies of every definition of the name). It is a
// best-effort census: an unreadable file is skipped by BuildMacroIndex, and no
// error aborts the discovery.
func discoverMacros(ctx context.Context, store db.Store) []macroEntry {
	files, err := store.ListFiles(ctx)
	if err != nil {
		return nil
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	idx := symbols.BuildMacroIndex(symbols.RootFor(paths), nil)
	out := make([]macroEntry, 0, len(idx.Names()))
	for _, name := range idx.Names() {
		var bodies []string
		for _, d := range idx.Lookup(name) {
			bodies = append(bodies, d.Body)
		}
		functionLike := false
		for _, d := range idx.Lookup(name) {
			if strings.TrimSpace(d.Params) != "" {
				functionLike = true
				break
			}
		}
		out = append(out, macroEntry{name: name, bodies: bodies, functionLike: functionLike})
	}
	return out
}

// classifyMacro classifies a #define by its name pattern and the allocator/
// deallocator names its replacement text expands to. Macros have no C return
// type or parameter signature, so only the name and body signals apply.
func classifyMacro(m macroEntry) (Entry, string, bool) {
	allocPattern, allocStrong := allocatorNamePattern(m.name)
	deallocPattern, deallocStrong := deallocatorNamePattern(m.name)

	callsAlloc, callsDealloc := macroBodyCallees(m.bodies)
	allText := strings.Join(m.bodies, " ")

	// Body evidence is authoritative: a macro that expands to a known
	// allocator/release IS one regardless of its name.
	if len(callsDealloc) > 0 && len(callsAlloc) == 0 {
		e := Entry{Name: m.name, Confidence: ConfHigh, Reasons: []string{"expands to " + joinCallees(callsDealloc)}}
		if deallocPattern != "" {
			e.Reasons = append(e.Reasons, "macro name pattern "+deallocPattern)
		}
		return e, "deallocator", true
	}
	if len(callsAlloc) > 0 && len(callsDealloc) == 0 {
		e := Entry{Name: m.name, Confidence: ConfHigh, Reasons: []string{"expands to " + joinCallees(callsAlloc)}}
		if allocPattern != "" {
			e.Reasons = append(e.Reasons, "macro name pattern "+allocPattern)
		}
		return e, "allocator", true
	}
	if len(callsAlloc) > 0 && len(callsDealloc) > 0 {
		return Entry{Name: m.name, Confidence: ConfLow, Reasons: []string{"macro body contains both an allocation and a release — ambiguous"}}, "allocator", true
	}

	// Name-only evidence. An object-like macro with no body evidence is not a
	// function call at all (`#define FREE 0`), and a function-like predicate
	// (`#define IS_FREE(s) ((s)==FREE)`) is not a release either; both are
	// downgraded to "needs review" instead of High.
	predicate := strings.Contains(allText, "==") || strings.Contains(allText, "!=") ||
		strings.Contains(allText, "&&") || strings.Contains(allText, "||")
	if deallocPattern != "" {
		if !m.functionLike || predicate {
			return Entry{Name: m.name, Confidence: ConfLow, Reasons: []string{"name pattern " + deallocPattern + "; no release call in body"}}, "deallocator", true
		}
		e := Entry{Name: m.name, Confidence: ConfHigh, Reasons: []string{"macro name pattern " + deallocPattern}}
		if !deallocStrong {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "no direct free in body")
		}
		return e, "deallocator", true
	}

	if allocPattern != "" {
		if !m.functionLike || predicate {
			return Entry{Name: m.name, Confidence: ConfLow, Reasons: []string{"name pattern " + allocPattern + "; no allocator call in body"}}, "allocator", true
		}
		e := Entry{Name: m.name, Confidence: ConfHigh, Reasons: []string{"macro name pattern " + allocPattern}}
		if !allocStrong {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "no direct allocator in body")
		}
		return e, "allocator", true
	}

	return Entry{}, "", false
}

// macroBodyCallees returns the known allocator and deallocator names a macro
// replacement text references (e.g. "malloc(n)" -> malloc, "free(p)" -> free).
func macroBodyCallees(bodies []string) (alloc []string, dealloc []string) {
	for _, body := range bodies {
		for _, id := range identRe.FindAllString(body, -1) {
			if apikb.IsDeclaredAllocator(id) {
				alloc = append(alloc, id)
			}
			if apikb.IsDeclaredDeallocator(id) {
				dealloc = append(dealloc, id)
			}
		}
	}
	return alloc, dealloc
}

// allocDeallocCalls maps a function ID to the built-in/declared allocator and
// deallocator names it calls (direct external calls only), by reading the CALL
// edges into external_function graph nodes.
func allocDeallocCalls(ctx context.Context, store db.Store) (map[int64][]calleeInfo, error) {
	funcNodeToFunc := map[int64]int64{}
	nodes, err := store.ListGraphNodesByEntityType(ctx, "function")
	if err != nil {
		return nil, err
	}
	for _, n := range nodes {
		funcNodeToFunc[n.ID] = n.EntityID
	}

	extNodes, err := store.ListGraphNodesByEntityType(ctx, "external_function")
	if err != nil {
		return nil, err
	}
	calleeByNode := map[int64]calleeInfo{}
	for _, n := range extNodes {
		var props struct {
			Name string `json:"name"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		alloc := apikb.IsDeclaredAllocator(props.Name)
		dealloc := apikb.IsDeclaredDeallocator(props.Name)
		if !alloc && !dealloc {
			continue
		}
		calleeByNode[n.ID] = calleeInfo{name: props.Name, alloc: alloc, dealloc: dealloc}
	}

	out := map[int64][]calleeInfo{}
	for cn, info := range calleeByNode {
		edges, err := store.ListGraphEdgesToNode(ctx, cn, "CALL")
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			fid, ok := funcNodeToFunc[e.SrcID]
			if !ok {
				continue
			}
			out[fid] = append(out[fid], info)
		}
	}
	return out, nil
}

// classify turns one symbol into a suggested entry. It returns the entry, the
// list kind ("allocator"/"deallocator") and whether the symbol is a candidate
// at all.
func classify(s symbol) (Entry, string, bool) {
	allocPattern, allocStrong := allocatorNamePattern(s.name)
	deallocPattern, deallocStrong := deallocatorNamePattern(s.name)

	if deallocPattern != "" {
		e := Entry{Name: s.name, Confidence: ConfHigh}
		e.Reasons = append(e.Reasons, "name pattern "+deallocPattern)
		if len(s.callsDealloc) > 0 {
			e.Reasons = append(e.Reasons, "calls "+joinCallees(s.callsDealloc))
		} else if !deallocStrong {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "no direct free call")
		}
		return e, "deallocator", true
	}

	if allocPattern != "" {
		e := Entry{Name: s.name, Confidence: ConfHigh}
		e.Reasons = append(e.Reasons, "name pattern "+allocPattern)
		if len(s.callsAlloc) > 0 {
			e.Reasons = append(e.Reasons, "calls "+joinCallees(s.callsAlloc))
		} else if !allocStrong {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "no direct allocator call")
		}
		return e, "allocator", true
	}

	if deallocatorSignature(s.returnType, s.signature) {
		e := Entry{Name: s.name}
		e.Reasons = append(e.Reasons, "void return, pointer parameter")
		if len(s.callsDealloc) > 0 {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "calls "+joinCallees(s.callsDealloc))
		} else {
			e.Confidence = ConfLow
		}
		return e, "deallocator", true
	}

	if allocatorSignature(s.returnType, s.signature) {
		e := Entry{Name: s.name}
		e.Reasons = append(e.Reasons, "pointer return, size_t parameter")
		if len(s.callsAlloc) > 0 {
			e.Confidence = ConfMedium
			e.Reasons = append(e.Reasons, "calls "+joinCallees(s.callsAlloc))
		} else {
			e.Confidence = ConfLow
		}
		return e, "allocator", true
	}

	// Call-relation evidence is an independent trigger (Issue #230): a function
	// that directly calls a known release/allocator is a high-confidence
	// candidate even when its name/signature are unremarkable. Gate on the return
	// shape so an unrelated `int f(...){free(x); return rc;}` is not registered as
	// a release (the declared-deallocator path can auto-confirm release defects).
	if len(s.callsDealloc) > 0 && strings.TrimSpace(s.returnType) == "void" {
		return Entry{Name: s.name, Confidence: ConfHigh, Reasons: []string{"calls " + joinCallees(s.callsDealloc)}}, "deallocator", true
	}
	if len(s.callsAlloc) > 0 && strings.Contains(s.returnType, "*") {
		return Entry{Name: s.name, Confidence: ConfHigh, Reasons: []string{"calls " + joinCallees(s.callsAlloc)}}, "allocator", true
	}

	return Entry{}, "", false
}

// allocatorNamePattern returns the display pattern and whether it is a strong
// (high-confidence) match. Strong suffixes are the malloc-family spellings;
// wrapper forms without an underscore prefix (xmalloc, xrealloc) also match.
func allocatorNamePattern(name string) (string, bool) {
	lower := strings.ToLower(name)
	for _, p := range []struct{ suffix, display string }{
		{"_malloc_f", "*_malloc_f"},
		{"_calloc_f", "*_calloc_f"},
		{"_realloc_f", "*_realloc_f"},
		{"_alloc_f", "*_alloc_f"},
		{"_malloc", "*_malloc"},
		{"_calloc", "*_calloc"},
		{"_realloc", "*_realloc"},
		{"_alloc", "*_alloc"},
		{"malloc", "*malloc"},
		{"calloc", "*calloc"},
		{"realloc", "*realloc"},
	} {
		if strings.HasSuffix(lower, p.suffix) {
			return p.display, true
		}
	}
	for _, p := range []struct{ suffix, display string }{
		{"_new", "*_new"},
		{"_mem_create", "*_mem_create"},
		{"_strdup", "*_strdup"},
		{"_dup", "*_dup"},
	} {
		if strings.HasSuffix(lower, p.suffix) {
			return p.display, false
		}
	}
	return "", false
}

// deallocatorNamePattern mirrors allocatorNamePattern. It is consulted first in
// classify because "_dealloc" also contains "alloc".
func deallocatorNamePattern(name string) (string, bool) {
	lower := strings.ToLower(name)
	for _, p := range []struct{ suffix, display string }{
		{"_free_f", "*_free_f"},
		{"_free", "*_free"},
		{"free", "*free"},
	} {
		if strings.HasSuffix(lower, p.suffix) {
			return p.display, true
		}
	}
	for _, p := range []struct{ infix, display string }{
		{"_dealloc", "*_dealloc"},
		{"_release", "*_release"},
		{"_destroy", "*_destroy"},
		{"_delete", "*_delete"},
		{"_cleanup", "*_cleanup"},
		{"_recycle", "*_recycle"},
	} {
		if strings.Contains(lower, p.infix) {
			return p.display, false
		}
	}
	return "", false
}

func allocatorSignature(returnType, signature string) bool {
	if !strings.Contains(returnType, "*") {
		return false
	}
	for _, p := range splitParams(signature) {
		if strings.Contains(p, "size_t") {
			return true
		}
	}
	return false
}

func deallocatorSignature(returnType, signature string) bool {
	if strings.TrimSpace(returnType) != "void" {
		return false
	}
	params := splitParams(signature)
	if len(params) == 0 {
		return false
	}
	return strings.Contains(params[0], "*")
}

// splitParams extracts the comma-separated parameter spellings from a stored
// function_declarator signature ("name(size_t n, char *s)"). It is a string
// heuristic, not a parser: nested parentheses/brackets are respected so a
// function-pointer parameter is not split on its inner commas.
func splitParams(signature string) []string {
	open := strings.IndexByte(signature, '(')
	closeIdx := strings.LastIndexByte(signature, ')')
	if open < 0 || closeIdx <= open {
		return nil
	}
	inner := strings.TrimSpace(signature[open+1 : closeIdx])
	if inner == "" || inner == "void" {
		return nil
	}
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	return append(out, strings.TrimSpace(inner[start:]))
}

func joinCallees(names []string) string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

func confidenceRank(c string) int {
	switch c {
	case ConfHigh:
		return 0
	case ConfMedium:
		return 1
	default:
		return 2
	}
}

func sortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		ri, rj := confidenceRank(es[i].Confidence), confidenceRank(es[j].Confidence)
		if ri != rj {
			return ri < rj
		}
		return strings.ToLower(es[i].Name) < strings.ToLower(es[j].Name)
	})
}

// classifyOwnershipTransfer identifies functions that take ownership of a
// pointer argument (container/queue/registry inserts, send paths). These are
// the project-specific entries for secguard.toml [ownership_transfer_calls].
// A pointer passed to such a function escapes rather than leaks.
func classifyOwnershipTransfer(s symbol) (Entry, bool) {
	pattern := ownershipTransferNamePattern(s.name)
	if pattern == "" {
		return Entry{}, false
	}
	hasPtr := hasPointerParameter(s.signature)
	e := Entry{Name: s.name, Confidence: ConfHigh}
	e.Reasons = append(e.Reasons, "name pattern "+pattern)
	if hasPtr {
		e.Reasons = append(e.Reasons, "pointer parameter")
	} else {
		e.Confidence = ConfMedium
		e.Reasons = append(e.Reasons, "no pointer parameter detected from signature")
	}
	if len(s.callsDealloc) > 0 {
		e.Confidence = ConfLow
		e.Reasons = append(e.Reasons, "calls "+joinCallees(s.callsDealloc)+" — may release rather than transfer")
	}
	return e, true
}

// ownershipTransferNamePattern returns the display pattern for an ownership-
// transfer name, or "" if the name does not match. The token set mirrors
// apikb.IsEscapeFunction's naming heuristic so the suggestion captures exactly
// the functions the leak detector already treats as escapes on a fail-open
// basis — declaring them makes the behavior explicit and reviewable.
func ownershipTransferNamePattern(name string) string {
	lower := strings.ToLower(name)
	for _, token := range []string{
		"_put", "_push", "_queue", "_enqueue", "_register", "_insert", "_append", "_store", "_send", "_add",
	} {
		if strings.Contains(lower, token) {
			return "*" + token
		}
	}
	for _, word := range []string{"Add", "Insert", "Push", "Put", "Append", "Store", "Enqueue", "Register", "Send", "Queue"} {
		if containsCamelWord(name, word) {
			return "*" + word
		}
	}
	return ""
}

// containsCamelWord mirrors apikb.containsCamelWord: a capitalized CamelCase
// token matched at a boundary (followed by uppercase or end).
func containsCamelWord(name, word string) bool {
	idx := 0
	for {
		i := strings.Index(name[idx:], word)
		if i < 0 {
			return false
		}
		i += idx
		after := i + len(word)
		if after >= len(name) {
			return true
		}
		if c := name[after]; c >= 'A' && c <= 'Z' {
			return true
		}
		idx = after
	}
}

// hasPointerParameter reports whether the function signature has a pointer
// parameter, using the same splitParams heuristic as the allocator/deallocator
// classifier.
func hasPointerParameter(signature string) bool {
	for _, p := range splitParams(signature) {
		if strings.Contains(p, "*") {
			return true
		}
	}
	return false
}

// classifyIteratorMacro identifies function-like macros that implement iterator
// loops (for_each, scan, walk, traverse). These are the project-specific entries
// for secguard.toml [iterator_macros.macros]. The iterator parameter index
// cannot be inferred from the macro body alone, so every entry is emitted
// COMMENTED OUT with a placeholder index — the user fills in the correct index.
func classifyIteratorMacro(m macroEntry) (Entry, bool) {
	pattern := iteratorMacroNamePattern(m.name)
	if pattern == "" {
		return Entry{}, false
	}
	if !m.functionLike {
		return Entry{}, false
	}
	allText := strings.Join(m.bodies, " ")
	hasLoop := strings.Contains(allText, "for") || strings.Contains(allText, "while")
	hasGuard := strings.Contains(allText, "NULL") || strings.Contains(allText, "!=") || strings.Contains(allText, "next")
	e := Entry{Name: m.name, Confidence: ConfHigh}
	e.Reasons = append(e.Reasons, "macro name pattern "+pattern)
	if hasLoop {
		e.Reasons = append(e.Reasons, "body contains loop construct")
	} else if hasGuard {
		e.Reasons = append(e.Reasons, "body contains NULL/next guard")
	} else {
		e.Confidence = ConfMedium
	}
	return e, true
}

// iteratorMacroNamePattern returns the display pattern for an iterator-macro
// name, or "" if the name does not match.
func iteratorMacroNamePattern(name string) string {
	lower := strings.ToLower(name)
	for _, token := range []string{
		"_for_each", "_foreach", "_scan", "_iter", "_walk", "_traverse", "_next",
	} {
		if strings.Contains(lower, token) {
			return "*" + token
		}
	}
	return ""
}
