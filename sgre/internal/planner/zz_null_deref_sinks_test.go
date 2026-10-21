//go:build !nosqlite

package planner

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// A variable-converged type keeps ONE candidate per (function, variable) — that
// is the candidate-volume contract — but the same nullable pointer is often
// dereferenced on several paths. The single candidate must still carry every
// sink line, or the reported line reads as the whole blast radius and a fix
// applied only there leaves the other dereferences unguarded.
func TestDeduplicateCandidates_MergesEverySinkLine(t *testing.T) {
	spec, err := GetVulnTypeSpec("null-deref")
	if err != nil {
		t.Fatalf("GetVulnTypeSpec: %v", err)
	}
	cands := []Candidate{
		{FileID: 1, FunctionName: "f", VariableName: "tree", Line: 30, SuspicionLevel: "suspected"},
		{FileID: 1, FunctionName: "f", VariableName: "tree", Line: 49, SuspicionLevel: "suspected"},
		{FileID: 1, FunctionName: "f", VariableName: "tree", Line: 41, SuspicionLevel: "suspected"},
		// A different variable is a different root cause and must not merge.
		{FileID: 1, FunctionName: "f", VariableName: "resp", Line: 12, SuspicionLevel: "suspected"},
	}
	got := deduplicateCandidates(cands, spec)
	if len(got) != 2 {
		t.Fatalf("deduped to %d candidates, want 2 (tree + resp): %+v", len(got), got)
	}
	if got[0].VariableName != "tree" || got[0].Line != 30 {
		t.Fatalf("tree candidate must anchor at the earliest sink (30), got line %d", got[0].Line)
	}
	if want := []int{30, 41, 49}; !reflect.DeepEqual(got[0].DerefLines, want) {
		t.Fatalf("tree sink lines = %v, want %v", got[0].DerefLines, want)
	}
	if want := []int{12}; !reflect.DeepEqual(got[1].DerefLines, want) {
		t.Fatalf("resp sink lines = %v, want %v", got[1].DerefLines, want)
	}
}

// A type that converges by line must NOT merge sink lines: two distinct
// (line, variable) candidates are two different findings for it.
func TestDeduplicateCandidates_LineConvergedKeepsSinksSeparate(t *testing.T) {
	spec := &VulnTypeSpec{}
	cands := []Candidate{
		{FileID: 1, FunctionName: "f", VariableName: "p", Line: 10, SuspicionLevel: "suspected"},
		{FileID: 1, FunctionName: "f", VariableName: "p", Line: 20, SuspicionLevel: "suspected"},
	}
	got := deduplicateCandidates(cands, spec)
	if len(got) != 2 {
		t.Fatalf("line-converged type must keep both candidates, got %d", len(got))
	}
	for _, c := range got {
		if len(c.DerefLines) != 0 {
			t.Fatalf("line-converged candidates must not carry sink lists, got %v", c.DerefLines)
		}
	}
}

// End to end on the report form: `tree` is dereferenced twice (inside the
// branch and after it). One candidate, both sink lines in the evidence — and the
// guard that protects the first branch must not hide the second dereference.
func TestNullDeref_ConvergedCandidateCarriesBothSinks(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{"ack.c": `int import_dn_group_tree_refresh(
    Nac_LdapSearchAckMsg_t *resp,
    import_para_ext_t *para)
{
    ldap_usrgroup_node_t *tree =
        (ldap_usrgroup_node_t *)(resp->group_data);

    if (para->search_index != INVALID_SEARCHDN_IDX) {
        strcpy_s((char *)tree[0].group_name,
                 sizeof(tree[0].group_name),
                 para->basepath);
    }
    strcpy_s((char *)tree[0].group_name,
             sizeof(tree[0].group_name),
             para->path);
    return 0;
}
`})
	var tree *EvidenceItem
	for i := range r.Candidates {
		if r.Candidates[i].Target.Variable == "tree" {
			tree = &r.Candidates[i]
			break
		}
	}
	if tree == nil {
		t.Fatalf("no tree candidate; got %+v", r.Candidates)
	}
	if len(tree.DerefLines) != 2 {
		t.Fatalf("tree sink lines = %v, want 2 (inside the branch and after it)", tree.DerefLines)
	}
	if tree.DerefLines[0] != tree.Target.Line {
		t.Fatalf("the reported line must be the first sink, got line %d with %v", tree.Target.Line, tree.DerefLines)
	}
	var sinkDetail string
	for _, e := range tree.Evidence {
		if e.Type == "dereference" && e.Role == "sink" {
			sinkDetail = e.Detail
		}
	}
	if !strings.Contains(sinkDetail, "also dereferenced") {
		t.Fatalf("evidence must list the additional sink line(s), got %q", sinkDetail)
	}
	for _, l := range tree.DerefLines {
		if l != tree.Target.Line && !strings.Contains(sinkDetail, strconv.Itoa(l)) {
			t.Fatalf("sink detail %q must name line %d", sinkDetail, l)
		}
	}
}
