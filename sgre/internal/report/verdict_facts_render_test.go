package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

// verdictFactPackages is the Evidence Contract v2 rendering fixture: a
// candidate whose pipeline carried tokens and whose type declared decisive
// facts.
func verdictFactPackages() []*planner.PlanResult {
	return []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			SuspicionLevel: "suspected",
			Target: planner.TargetInfo{
				File: "/repo/src/p5.c", Function: "g", Line: 121, Variable: "t",
			},
			Hint:       "src@119 maybe-null",
			HintTokens: []string{"src@119", "maybe-null"},
			VerdictFacts: []planner.VerdictFact{
				{Token: "null@caller-arg", Detail: "parameter `t` — caller `dispatch(t)` passes it unproven non-null (src/p5.c:119)"},
				{Detail: "no same-function NULL check dominates the dereference at line 121"},
			},
			Evidence: []planner.EvidenceFragment{
				{Role: "source", Detail: "variable t is assigned a possibly-null value"},
			},
		}},
	}}
}

// The candidate file must carry the pipeline tokens (the same machine facts
// the _index.md Hint column showed) with their registry descriptions — the
// re-review/deep-dive entry point previously lost them entirely.
func TestWriteCandidates_PipelineTokensSection(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(verdictFactPackages()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_p5_c_121.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "## Pipeline Tokens") {
		t.Errorf("candidate file must carry the Pipeline Tokens section:\n%s", content)
	}
	if !strings.Contains(content, "`src@119 maybe-null`") {
		t.Errorf("Pipeline Tokens must open with the full joined sequence:\n%s", content)
	}
	if !strings.Contains(content, "- `src@119` — the null/taint source is assigned at line 119") {
		t.Errorf("each token must be annotated with its registry description:\n%s", content)
	}
	if !strings.Contains(content, "- `maybe-null` — the source is possibly null") {
		t.Errorf("bare tokens must be annotated too:\n%s", content)
	}
}

// The Verdict Facts section renders the type contract's distilled facts and
// sits before the Evidence narrative.
func TestWriteCandidates_VerdictFactsSection(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(verdictFactPackages()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_p5_c_121.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)

	if !strings.Contains(content, "## Verdict Facts") {
		t.Errorf("candidate file must carry the Verdict Facts section:\n%s", content)
	}
	if !strings.Contains(content, "- `null@caller-arg`: parameter `t` — caller `dispatch(t)` passes it unproven non-null (src/p5.c:119)") {
		t.Errorf("a tokened fact renders as `- `token`: detail`:\n%s", content)
	}
	if !strings.Contains(content, "- no same-function NULL check dominates the dereference at line 121") {
		t.Errorf("a tokenless fact renders as a bare line:\n%s", content)
	}
	factsIdx := strings.Index(content, "## Verdict Facts")
	tokensIdx := strings.Index(content, "## Pipeline Tokens")
	evidenceIdx := strings.Index(content, "## Evidence")
	if tokensIdx == -1 || factsIdx == -1 || evidenceIdx == -1 {
		t.Fatalf("missing sections: tokens=%d facts=%d evidence=%d", tokensIdx, factsIdx, evidenceIdx)
	}
	if !(tokensIdx < factsIdx && factsIdx < evidenceIdx) {
		t.Errorf("section order must be Pipeline Tokens → Verdict Facts → Evidence (tokens=%d facts=%d evidence=%d)", tokensIdx, factsIdx, evidenceIdx)
	}
}

// A type whose contract has not rolled out (no VerdictFacts, no HintTokens)
// must not render empty sections — the section's absence is the rollout
// signal, not a render gap.
func TestWriteCandidates_NoEmptyContractSections(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test"}
	if err := o.writeCandidates(candidatePackages()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, CandidatesDir, "null-deref", "001_src_a_c_13.md"))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if strings.Contains(content, "## Pipeline Tokens") || strings.Contains(content, "## Verdict Facts") {
		t.Errorf("empty contract must not render empty sections:\n%s", content)
	}
}

// The _index.md legend must be GENERATED from the registry: passing every
// registered key renders every token, and the header names the single source.
// The per-type legend scopes to the tokens a type actually emits (see
// TestTypeIndexLegendScoped), but the full-registry render must never be
// hand-written either.
func TestTypeIndexLegendGenerated(t *testing.T) {
	legend := typeIndexLegend(planner.RegisteredHintKeys())
	if !strings.Contains(legend, "sgre/internal/planner/hint_tokens.go") {
		t.Errorf("legend must name the single-source registry:\n%s", legend)
	}
	for _, key := range planner.RegisteredHintKeys() {
		if !strings.Contains(legend, "`"+key) {
			t.Errorf("legend is missing registered key %q — the legend must be generated from the registry, not hand-written", key)
		}
	}
	if !strings.Contains(legend, "Classify each candidate as confirmed / dismissed (BINARY)") {
		t.Errorf("legend must keep the workflow framing:\n%s", legend)
	}
}

// The per-type legend must be scoped to the tokens that type emits: a
// null-deref index must not carry the deadlock/race/leak vocabulary (the
// pre-scoping legend bloat that pushed the classifier to skim the Hint column).
func TestTypeIndexLegendScoped(t *testing.T) {
	legend := typeIndexLegend([]string{"null@cfg-proof", "guard@none", "api@malloc", "src@44"})
	if strings.Contains(legend, "locks@") || strings.Contains(legend, "leak@") ||
		strings.Contains(legend, "threads@") || strings.Contains(legend, "divisor@") {
		t.Errorf("per-type legend must not carry unrelated types' tokens:\n%s", legend)
	}
	for _, want := range []string{"null@", "guard@none", "api@", "src@"} {
		if !strings.Contains(legend, "`"+want) {
			t.Errorf("per-type legend is missing %q for the emitted tokens:\n%s", want, legend)
		}
	}
}
