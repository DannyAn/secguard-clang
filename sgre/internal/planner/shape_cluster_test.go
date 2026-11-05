package planner

import (
	"reflect"
	"testing"
)

// TestClusterShapeCandidates pins shape-level clustering (issue #216): one
// representative per shape, the highest-confidence member wins (then the
// earliest line), every folded sink line and site is preserved, candidates the
// type declines to shape (empty key) stay independent, and single-member groups
// pass through untouched.
func TestClusterShapeCandidates(t *testing.T) {
	spec := &VulnTypeSpec{ShapeKey: func(c Candidate) string { return c.Category }}
	in := []Candidate{
		{FunctionName: "b", Line: 20, Category: "shape", SuspicionLevel: "suspected"},
		{FunctionName: "a", Line: 10, Category: "shape", SuspicionLevel: "suspected"},
		{FunctionName: "c", Line: 30, Category: "other", SuspicionLevel: "suspected"},
		{FunctionName: "d", Line: 40, Category: "", SuspicionLevel: "suspected"},
		{FunctionName: "e", Line: 5, Category: "shape", SuspicionLevel: "possible"},
	}

	out, folded := clusterShapeCandidates(in, spec)
	if folded != 2 {
		t.Errorf("folded = %d, want 2 (b and e absorbed by a)", folded)
	}
	if len(out) != 3 {
		t.Fatalf("got %d groups, want 3 (shape / other / unshaped)", len(out))
	}

	rep := out[0]
	if rep.FunctionName != "a" || rep.Line != 10 {
		t.Errorf("representative = %s@%d, want a@10 (earliest suspected member)", rep.FunctionName, rep.Line)
	}
	if want := []int{5, 10, 20}; !reflect.DeepEqual(rep.DerefLines, want) {
		t.Errorf("DerefLines = %v, want %v", rep.DerefLines, want)
	}
	if want := []string{"b:20", "e:5"}; !reflect.DeepEqual(rep.ClusterSites, want) {
		t.Errorf("ClusterSites = %v, want %v", rep.ClusterSites, want)
	}
	if rep.SuspicionLevel != "suspected" {
		t.Errorf("representative suspicion = %q, want suspected (never downgraded by a weaker member)", rep.SuspicionLevel)
	}
	if out[1].FunctionName != "c" || out[1].ClusterSites != nil {
		t.Errorf("single-member group must pass through unchanged, got %+v", out[1])
	}
	if out[2].FunctionName != "d" || out[2].ClusterSites != nil {
		t.Errorf("unshaped candidate must pass through unchanged, got %+v", out[2])
	}
}

// TestClusterShapeCandidatesConfirmedWins pins the merge rule: a machine-proved
// member becomes the representative even when a weaker member has an earlier
// line, so clustering never costs the pipeline its certainty claim.
func TestClusterShapeCandidatesConfirmedWins(t *testing.T) {
	spec := &VulnTypeSpec{ShapeKey: func(c Candidate) string { return c.Category }}
	in := []Candidate{
		{FunctionName: "early", Line: 3, Category: "shape", SuspicionLevel: "possible"},
		{FunctionName: "proved", Line: 9, Category: "shape", SuspicionLevel: "confirmed"},
	}
	out, folded := clusterShapeCandidates(in, spec)
	if folded != 1 || len(out) != 1 {
		t.Fatalf("folded=%d groups=%d, want 1/1", folded, len(out))
	}
	if out[0].FunctionName != "proved" || out[0].SuspicionLevel != "confirmed" {
		t.Errorf("representative = %s/%s, want proved/confirmed", out[0].FunctionName, out[0].SuspicionLevel)
	}
}

// TestClusterShapeCandidatesNoShapeKey pins the opt-out: a type that declares no
// ShapeKey keeps every deduped candidate.
func TestClusterShapeCandidatesNoShapeKey(t *testing.T) {
	in := []Candidate{{FunctionName: "a", Line: 1, Category: "shape"}, {FunctionName: "b", Line: 2, Category: "shape"}}
	out, folded := clusterShapeCandidates(in, &VulnTypeSpec{})
	if folded != 0 || len(out) != 2 {
		t.Errorf("no ShapeKey must not cluster: folded=%d groups=%d", folded, len(out))
	}
}
