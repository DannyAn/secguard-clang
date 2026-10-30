package worker

import (
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func fixtureBatch() Batch {
	return Batch{
		Type:       "null-deref",
		RangeStart: 0,
		RangeEnd:   2,
		Candidates: []planner.EvidenceItem{
			{
				Type:              "null_deref",
				VulnerabilityType: "null-deref",
				SuspicionLevel:    "suspected",
				Target:            planner.TargetInfo{File: "/repo/src/a.c", Function: "f", Line: 42, Variable: "p"},
				Hint:              "—",
				Signature:         "void f(T *q)",
				Expression:        "p = q->next;",
			},
			{
				Type:              "null_deref",
				VulnerabilityType: "null-deref",
				SuspicionLevel:    "possible",
				Target:            planner.TargetInfo{File: "/repo/src/b.c", Function: "g", Line: 7, Variable: "r"},
				Hint:              "—",
				Signature:         "int g(void)",
				Expression:        "return *r;",
			},
		},
	}
}

func TestAssembleGolden(t *testing.T) {
	p := Assemble(fixtureBatch(), Options{SkillText: "SKILL BODY\nline2"})

	var want strings.Builder
	want.WriteString("# worker batch: null-deref #1-2 (2 candidates)\n")
	want.WriteString("\n## skill\n\n")
	want.WriteString("SKILL BODY\nline2\n")
	want.WriteString("\n## candidates\n")
	want.WriteString("\n### #1 f (a.c:42) p (suspected)\n")
	want.WriteString("- signature: `void f(T *q)`\n")
	want.WriteString("- source: `p = q->next;`\n")
	want.WriteString("- hint: `—`\n")
	want.WriteString("\n### #2 g (b.c:7) r (possible)\n")
	want.WriteString("- signature: `int g(void)`\n")
	want.WriteString("- source: `return *r;`\n")
	want.WriteString("- hint: `—`\n")
	want.WriteString("\n## output contract\n\n")
	want.WriteString("Return a JSON array of verdicts, exactly one object per candidate `#` above, with fields:\n")
	want.WriteString("{\"seq\": <int>, \"status\": \"confirmed|dismissed|inconclusive\", \"cwe\": \"<CWE>\", \"reason\": \"<one-line citation>\"}\n")
	want.WriteString("Every candidate MUST appear once; use status \"inconclusive\" when the preloaded facts cannot settle it (the executor escalates those batches).")

	if p.Text != want.String() {
		t.Errorf("prompt mismatch:\n--- got ---\n%s\n--- want ---\n%s", p.Text, want.String())
	}
	if p.Type != "null-deref" || p.Range != "1-2" || p.CandidateCount != 2 {
		t.Errorf("batch metadata mismatch: type=%q range=%q count=%d", p.Type, p.Range, p.CandidateCount)
	}
	if len(p.Expected) != 2 || p.Expected[0].Function != "f" || p.Expected[1].Variable != "r" {
		t.Errorf("expected identities wrong: %+v", p.Expected)
	}
}

func TestAssembleDeterministic(t *testing.T) {
	b := fixtureBatch()
	a := Assemble(b, Options{SkillText: "S"})
	c := Assemble(b, Options{SkillText: "S"})
	if a.Text != c.Text {
		t.Errorf("assemble is not deterministic")
	}
}

func TestAssembleRangeSlicing(t *testing.T) {
	b := fixtureBatch()
	b.RangeStart = 1 // only the 2nd candidate
	b.RangeEnd = 99  // clamps to len
	p := Assemble(b, Options{})
	if p.CandidateCount != 1 || p.Range != "2-2" {
		t.Errorf("range slicing wrong: count=%d range=%q", p.CandidateCount, p.Range)
	}
	if len(p.Expected) != 1 || p.Expected[0].Seq != 2 || p.Expected[0].Function != "g" {
		t.Errorf("expected identities wrong after slice: %+v", p.Expected)
	}
}

func TestAssembleHintLegend(t *testing.T) {
	b := fixtureBatch()
	b.Candidates[0].Hint = "guard@none"
	b.Candidates[0].HintTokens = []string{"guard@none"}
	p := Assemble(b, Options{})
	if !strings.Contains(p.Text, "## hint legend") || !strings.Contains(p.Text, "guard@none") {
		t.Errorf("hint legend not rendered for a real token:\n%s", p.Text)
	}
}

func TestAssembleVerdictFactsAndEvidence(t *testing.T) {
	b := fixtureBatch()
	b.Candidates = b.Candidates[:1]
	b.Candidates[0].VerdictFacts = []planner.VerdictFact{{Token: "null@caller-arg", Detail: "param q passed unproven"}}
	b.Candidates[0].Evidence = []planner.EvidenceFragment{{Role: "sink", Detail: "deref at line 42"}}
	p := Assemble(b, Options{})
	for _, sub := range []string{"- verdict facts:", "`null@caller-arg`: param q passed unproven", "- sink: deref at line 42"} {
		if !strings.Contains(p.Text, sub) {
			t.Errorf("missing %q in prompt:\n%s", sub, p.Text)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("abcde", 3); got != "abc\n…[truncated]" {
		t.Errorf("truncateRunes = %q", got)
	}
	if got := truncateRunes("abc", 3); got != "abc" {
		t.Errorf("truncateRunes under limit = %q", got)
	}
	// multi-byte runes must not be split
	if got := truncateRunes("你好世界", 2); got != "你好\n…[truncated]" {
		t.Errorf("truncateRunes multibyte = %q", got)
	}
}
