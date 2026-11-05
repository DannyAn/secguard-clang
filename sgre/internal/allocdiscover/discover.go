// Package allocdiscover discovers project-specific allocator/deallocator
// functions from an indexed secguard database and renders them as a suggested
// secguard.toml. It is a side-channel: its output is advisory and never feeds
// back into the scan pipeline.
package allocdiscover

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
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
	Allocators   []Entry
	Deallocators []Entry
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
	for name, s := range syms {
		if apikb.IsDeclaredAllocator(name) || apikb.IsDeclaredDeallocator(name) {
			continue
		}
		e, kind, ok := classify(*s)
		if !ok {
			continue
		}
		switch kind {
		case "allocator":
			res.Allocators = append(res.Allocators, e)
		case "deallocator":
			res.Deallocators = append(res.Deallocators, e)
		}
	}
	sortEntries(res.Allocators)
	sortEntries(res.Deallocators)
	return res, nil
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

	return Entry{}, "", false
}

// allocatorNamePattern returns the display pattern and whether it is a strong
// (high-confidence) match. Strong suffixes are the malloc-family spellings;
// wrapper forms without an underscore prefix (xmalloc, xrealloc) also match.
func allocatorNamePattern(name string) (string, bool) {
	lower := strings.ToLower(name)
	for _, p := range []struct{ suffix, display string }{
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
