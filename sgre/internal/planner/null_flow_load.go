package planner

import (
	"context"
	"encoding/json"
)

func (a *flowAnalyzer) loadVarRefMaps(ctx context.Context, funcIDs []int64) (map[int64]string, map[int64]int, map[int64]int64) {
	want := make(map[int64]bool, len(funcIDs))
	for _, fid := range funcIDs {
		want[fid] = true
	}
	nameByNode := make(map[int64]string)
	lineByNode := make(map[int64]int)
	funcByNode := make(map[int64]int64)
	nodes, err := a.store.ListGraphNodesByEntityType(ctx, "variable_ref")
	if err != nil {
		return nil, nil, nil
	}
	for _, n := range nodes {
		if !want[n.EntityID] {
			continue
		}
		var props struct {
			Name string `json:"name"`
			Line int    `json:"line"`
		}
		if json.Unmarshal([]byte(n.Properties), &props) != nil || props.Name == "" {
			continue
		}
		nameByNode[n.ID] = props.Name
		lineByNode[n.ID] = props.Line
		funcByNode[n.ID] = n.EntityID
	}
	return nameByNode, lineByNode, funcByNode
}

// loadDFGCopies resolves all stored DATA_FLOW edges into per-function, per-line
// copy pairs. It is a best-effort read of the graph layer: on any error it
// returns an empty map and the analysis continues on CFG + events alone.
func (a *flowAnalyzer) loadDFGCopies(ctx context.Context, funcIDs []int64) map[int64]map[int][]copyPair {
	result := make(map[int64]map[int][]copyPair)
	edges, err := a.store.ListGraphEdgesByType(ctx, "DATA_FLOW")
	if err != nil {
		return result
	}

	// Resolve variable_ref node IDs to (function, name, line), but only for
	// functions we actually analyze.
	nameByNode, lineByNode, funcByNode := a.loadVarRefMaps(ctx, funcIDs)

	for _, e := range edges {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		rhs, ok := nameByNode[e.SrcID]
		if !ok {
			continue
		}
		fid, ok := funcByNode[e.SrcID]
		if !ok {
			continue
		}
		lhs, ok := nameByNode[e.DstID]
		if !ok || lhs == "" {
			lhs = props.Variable
		}
		if lhs == "" || lhs == rhs {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[int][]copyPair)
		}
		line := lineByNode[e.SrcID]
		result[fid][line] = append(result[fid][line], copyPair{lhs: lhs, rhs: rhs})
	}

	return result
}

// aliasSite is one whole-variable alias assignment: the aliasing variable was
// assigned `base` (`alias = base`) at line. The line is what makes the freed-
// state alias propagation flow-sensitive: an alias only dangles a freed source
// when its MOST RECENT assignment on or before the free still aliases the freed
// variable (a later `alias = other` breaks the alias and must not propagate it).
type aliasSite struct {
	base string
	line int
}

// loadAliases resolves stored ALIAS edges into a per-function map from aliasing
// variable to the list of (base, line) it was assigned. The freed-state flow
// filters use this to propagate a freed source from a variable to the variables
// that STILL alias it at the free line (freeing p dangles a q that is currently
// p; a q reassigned to something else before the free is not dangled). Best-
// effort: on any error it returns an empty map and the analysis continues on the
// AST-level copy step alone.
func (a *flowAnalyzer) loadAliases(ctx context.Context, funcIDs []int64) map[int64]map[string][]aliasSite {
	result := make(map[int64]map[string][]aliasSite)
	edges, err := a.store.ListGraphEdgesByType(ctx, "ALIAS")
	if err != nil {
		return result
	}

	nameByNode, lineByNode, funcByNode := a.loadVarRefMaps(ctx, funcIDs)

	for _, e := range edges {
		// A field/element alias (q = p->f, q = p[i]) copies a FIELD value, not the
		// base pointer itself, so freeing p does NOT dangle q. Only whole-variable
		// aliases (field == "") must propagate the freed state. Treating field
		// aliases as whole-variable aliases produced use-after-free false
		// positives (e.g. q = p->f; free(p); use(q) when p->f is a plain int).
		var props struct {
			Field string `json:"field"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Field != "" {
			continue
		}
		alias := nameByNode[e.SrcID]
		base := nameByNode[e.DstID]
		fid := funcByNode[e.SrcID]
		if alias == "" || base == "" || alias == base {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[string][]aliasSite)
		}
		result[fid][alias] = append(result[fid][alias], aliasSite{base: base, line: lineByNode[e.SrcID]})
	}
	return result
}

// expandGenToAliases adds, for every variable that generates a source, the
// variables that STILL alias it at the source line. Used only by the freed-state
// analyses (use-after-free / double-free): free(p) invalidates the OBJECT p
// points to, so a variable q that currently aliases p is also dangling. The
// "currently" is the key word: an alias q = p established at line 10 is broken
// by a later q = other at line 20, so a free(p) at line 25 must NOT dangle q.
// The flow-sensitive check is latestAliasBase: among q's alias assignments on
// or before the free line, the most recent one's base must equal p for q to be
// dangled. It is deliberately NOT applied to null-deref, where nullness is a
// property of the pointer's current VALUE (q = p; p = NULL leaves q non-null).
func expandGenToAliases(genByLine map[int][]string, aliasesOf map[string][]aliasSite) {
	if len(aliasesOf) == 0 {
		return
	}
	for line, vars := range genByLine {
		var extra []string
		for _, v := range vars {
			for alias, sites := range aliasesOf {
				if base, ok := latestAliasBase(sites, line); ok && base == v {
					extra = append(extra, alias)
				}
			}
		}
		if len(extra) > 0 {
			genByLine[line] = append(genByLine[line], extra...)
		}
	}
}

// latestAliasBase returns the base of the most recent alias assignment at or
// before line. An alias assignment (alias = base) at line 10 is superseded by a
// later one at line 20, so only the last one on or before the query line
// determines what alias currently names. If no assignment is on or before line,
// the variable did not yet alias anything and the second return is false.
func latestAliasBase(sites []aliasSite, line int) (string, bool) {
	var best *aliasSite
	for i := range sites {
		s := &sites[i]
		if s.line > line {
			continue
		}
		if best == nil || s.line > best.line {
			best = s
		}
	}
	if best == nil {
		return "", false
	}
	return best.base, true
}

// loadFreeSites resolves stored RELEASE edges with release_fn == "free" into a
// per-function, per-line map of directly-freed variables. It is the graph-native
// source of DIRECT memory free sites for the freed-state flow filters (UAF /
// double-free), so the semantic graph's RELEASE edges are finally consumed. The
// release_fn filter is what makes the consumption precise: memory free (free)
// is routed to the memory flow, while resource releases (fclose/close) are left
// to the resource-leak pipeline.
//
// Indirect free sites (a callee frees a parameter) have no RELEASE edge, so the
// filters keep seeding those from the detector's event properties.
func (a *flowAnalyzer) loadFreeSites(ctx context.Context, funcIDs []int64) map[int64]map[int][]string {
	result := make(map[int64]map[int][]string)
	edges, err := a.store.ListGraphEdgesByType(ctx, "RELEASE")
	if err != nil {
		return result
	}

	nameByNode, lineByNode, funcByNode := a.loadVarRefMaps(ctx, funcIDs)

	for _, e := range edges {
		var props struct {
			ReleaseFn string `json:"release_fn"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) != nil || props.ReleaseFn != "free" {
			continue
		}
		name := nameByNode[e.SrcID]
		fid := funcByNode[e.SrcID]
		if name == "" || fid == 0 {
			continue
		}
		if result[fid] == nil {
			result[fid] = make(map[int][]string)
		}
		result[fid][lineByNode[e.SrcID]] = append(result[fid][lineByNode[e.SrcID]], name)
	}
	return result
}

// freeAlreadySeeded reports whether genByLine already records variable as freed
// at line — used to avoid double-seeding a direct free site that both the
// RELEASE edges and the detector's event properties capture.
func freeAlreadySeeded(genByLine map[int][]string, line int, variable string) bool {
	for _, v := range genByLine[line] {
		if v == variable {
			return true
		}
	}
	return false
}
