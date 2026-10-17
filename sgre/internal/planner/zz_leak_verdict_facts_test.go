package planner

import (
	"strings"
	"testing"
)

// B3 rollout: the leak verdict basis is the acquire line, the certainty tier,
// and the ownership-release channel state. escape@none + leak@definite is a
// machine-proved loss; a channel that exists alongside a surviving candidate
// means the CFG proved a bypass path — that path is the classifier's target.
func TestBuildVerdictFacts_Leaks(t *testing.T) {
	ml, err := GetVulnTypeSpec("memory-leak")
	if err != nil {
		t.Fatal(err)
	}
	rl, err := GetVulnTypeSpec("resource-leak")
	if err != nil {
		t.Fatal(err)
	}

	def := ml.BuildVerdictFacts(Candidate{Line: 12, DefiniteLeak: true, LeakEscapeKind: "none", APIName: "malloc", FunctionName: "f"})
	if len(def) != 3 {
		t.Fatalf("definite facts = %d, want 3 (alloc/leak/escape): %+v", len(def), def)
	}
	if def[0].Token != "alloc@12" || def[1].Token != "leak@definite" || def[2].Token != "escape@none" {
		t.Errorf("token sequence = %q %q %q", def[0].Token, def[1].Token, def[2].Token)
	}
	if !strings.Contains(def[0].Detail, "line 12") || !strings.Contains(def[0].Detail, "malloc") {
		t.Errorf("alloc fact must name the line and the API:\n%s", def[0].Detail)
	}
	if !strings.Contains(def[1].Detail, "ANY path") || !strings.Contains(def[1].Detail, "machine-proved") {
		t.Errorf("definite fact must state machine-proved loss:\n%s", def[1].Detail)
	}

	cond := ml.BuildVerdictFacts(Candidate{Line: 12, LeakEscapeKind: "store", LeakFreeLines: "30,45", FunctionName: "g"})
	if len(cond) != 4 {
		t.Fatalf("conditional facts = %d, want 4 (alloc/leak/escape/free): %+v", len(cond), cond)
	}
	if cond[1].Token != "leak@conditional" || !strings.Contains(cond[1].Detail, "bypasses") {
		t.Errorf("conditional fact must name the bypass:\n%s", cond[1].Detail)
	}
	if cond[2].Token != "escape@store" || !strings.Contains(cond[2].Detail, "non-local") {
		t.Errorf("store channel fact:\n%s", cond[2].Detail)
	}
	if cond[3].Token != "free@30,45" || !strings.Contains(cond[3].Detail, "Code Context") {
		t.Errorf("free-lines fact must point at the covered window:\n%s", cond[3].Detail)
	}

	res := rl.BuildVerdictFacts(Candidate{Line: 8, LeakEscapeKind: "return", LeakFreeLines: "22", Category: "resource_acquire", APIName: "fopen", FunctionName: "h"})
	if len(res) != 4 {
		t.Fatalf("resource facts = %d, want 4: %+v", len(res), res)
	}
	if res[0].Token != "acquire@8" {
		t.Errorf("resource-leak uses acquire@, got %q", res[0].Token)
	}
	if res[2].Token != "escape@return" || !strings.Contains(res[2].Detail, "NON-returning") {
		t.Errorf("return channel fact:\n%s", res[2].Detail)
	}
}
