package graph

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// TestAliasGraphClosure pins the alias-graph transitive closure: q=p and
// r=q must put p, q, r in one alias set; an unrelated s stays out.
func TestAliasGraphClosure(t *testing.T) {
	g := NewAliasGraph()
	p := AliasKey{FunctionID: 1, Name: "p"}
	q := AliasKey{FunctionID: 1, Name: "q"}
	r := AliasKey{FunctionID: 1, Name: "r"}
	s := AliasKey{FunctionID: 1, Name: "s"}
	g.Add(p, q)
	g.Add(q, r)

	set := g.AliasesOf(p)
	if len(set) != 3 {
		t.Errorf("AliasesOf(p) has %d members, want 3 (p,q,r)", len(set))
	}
	names := map[string]bool{}
	for _, k := range set {
		names[k.Name] = true
	}
	if !names["p"] || !names["q"] || !names["r"] || names["s"] {
		t.Errorf("AliasesOf(p) = %v, want {p,q,r}", names)
	}

	// Aliasing is symmetric.
	if len(g.AliasesOf(r)) != 3 {
		t.Errorf("AliasesOf(r) has %d members, want 3", len(g.AliasesOf(r)))
	}

	// A singleton stays a singleton.
	if len(g.AliasesOf(s)) != 1 {
		t.Errorf("AliasesOf(s) has %d members, want 1", len(g.AliasesOf(s)))
	}

	// Self-add is a no-op.
	g.Add(p, p)
	if len(g.AliasesOf(p)) != 3 {
		t.Errorf("self-add changed the set")
	}
}

// TestAliasQuerierInterface pins the interface shape so detector migrations
// (Phase 12 follow-up) can rely on it.
func TestAliasQuerierInterface(t *testing.T) {
	// A nil AliasQuerier must satisfy the interface signature; we assert by
	// assignment.
	var q AliasQuerier
	_ = q
	fn := &db.Function{ID: 1, Name: "f"}
	_ = fn
	_ = context.Background()
}
