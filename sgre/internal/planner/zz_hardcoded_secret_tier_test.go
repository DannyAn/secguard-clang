//go:build !nosqlite

package planner

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planHardcodedSecret runs the hardcoded-secret pipeline over one testdata
// fixture and returns the converged candidates keyed by variable name.
func planHardcodedSecret(t *testing.T, fixture string) map[string]EvidenceItem {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewHardcodedSecretDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect %s: %v", fixture, err)
	}

	result, err := NewPlanner(store, p, logger).Plan(ctx, "hardcoded-secret")
	if err != nil {
		t.Fatalf("plan %s: %v", fixture, err)
	}
	byVar := make(map[string]EvidenceItem, len(result.Candidates))
	for _, c := range result.Candidates {
		byVar[c.Target.Variable] = c
	}
	return byVar
}

// TestHardcodedSecret_NameOnlyStaysSuspected pins the fix for a skill whose
// rules were unreachable: a name-only match (`password = "admin123"`) used to be
// seeded `confirmed`, so the scan auto-confirmed it without AI review and the
// skill's placeholder / test-credential false-positive rules could never run.
// It must stay suspected; only a value-proven literal is auto-confirmed.
func TestHardcodedSecret_NameOnlyStaysSuspected(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	for _, v := range []string{"password", "db_password"} {
		c, ok := cands[v]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", v)
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("%s (name-only match) suspicion = %q, want suspected (AI must judge the value)", v, c.SuspicionLevel)
		}
	}
}

// TestHardcodedSecret_FileScopeCandidateHasLocation pins the file-scope
// location fallback in seedCandidatesByType: a secret declared at file scope
// (no enclosing function, so EntityID == 0) used to be seeded with FileID 0
// because the file was taken only from the (missing) function, producing a
// candidate with an empty Target.File that auto-confirm re-flowed to the AI.
// The location carries the real file, so the candidate must now surface it.
func TestHardcodedSecret_FileScopeCandidateHasLocation(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	for _, v := range []string{"high_entropy", "password", "conn"} {
		c, ok := cands[v]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", v)
		}
		if c.Target.File == "" {
			t.Errorf("%s (file-scope) has empty Target.File; want the fixture path", v)
		}
		if c.Target.Line <= 0 {
			t.Errorf("%s (file-scope) has non-positive Target.Line = %d", v, c.Target.Line)
		}
	}
}

// TestHardcodedSecret_ValueProvenIsConfirmed is the direction guard: a literal
// proven by its value stays auto-confirmed, so the fix does not drag every
// hardcoded-secret candidate into an AI review turn.
func TestHardcodedSecret_ValueProvenIsConfirmed(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	for _, v := range []string{"high_entropy", "conn"} {
		c, ok := cands[v]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", v)
		}
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("%s (proven by its value) suspicion = %q, want confirmed", v, c.SuspicionLevel)
		}
	}
}

// TestHardcodedSecret_NameOnlyCarriesMaskedValue pins E-10: a name-only
// candidate's evidence used to carry NO literal at all, so the AI was asked to
// judge "placeholder vs test value vs real credential" without seeing the
// value. The secret_value fragment must now surface the literal MASKED — first
// 4 chars + length, never the full text — for both the suspected (name-only)
// and the confirmed (value-proven) tier, so a report file never echoes the
// secret it reports.
func TestHardcodedSecret_NameOnlyCarriesMaskedValue(t *testing.T) {
	cands := planHardcodedSecret(t, "tc95_hardcoded_secret_value_only.c")

	cases := []struct {
		variable  string
		prefix    string
		fullValue string
		suspicion string
	}{
		{"password", "admi", "admin123", "suspected"},
		{"db_password", "admi", "admin123", "suspected"},
		{"high_entropy", "xJ9k", "xJ9kL2mN8pQ4rS6tU8vW0yA3bC5dE7fG", "confirmed"},
		{"conn", "mysq", "mysql://root:hunter2@db", "confirmed"},
	}
	for _, tc := range cases {
		c, ok := cands[tc.variable]
		if !ok {
			t.Fatalf("no hardcoded-secret candidate for %s", tc.variable)
		}
		if c.SuspicionLevel != tc.suspicion {
			t.Errorf("%s suspicion = %q, want %s", tc.variable, c.SuspicionLevel, tc.suspicion)
		}
		var frag *EvidenceFragment
		for i := range c.Evidence {
			if c.Evidence[i].Type == "secret_value" {
				frag = &c.Evidence[i]
				break
			}
		}
		if frag == nil {
			t.Errorf("%s: no secret_value fragment in evidence (E-10 regression: the AI cannot judge the literal it never sees)", tc.variable)
			continue
		}
		if !strings.Contains(frag.Detail, tc.prefix) {
			t.Errorf("%s: secret_value fragment %q does not show the value prefix %q", tc.variable, frag.Detail, tc.prefix)
		}
		if strings.Contains(frag.Detail, tc.fullValue) {
			t.Errorf("%s: secret_value fragment %q echoes the FULL literal — the evidence file must not leak the secret it reports", tc.variable, frag.Detail)
		}
		if !strings.Contains(frag.Detail, fmt.Sprintf("(%d chars)", len(tc.fullValue))) {
			t.Errorf("%s: secret_value fragment %q does not state the value length", tc.variable, frag.Detail)
		}
	}
}

// TestMaskSecret pins the masking rule itself: short values are fully hidden
// (a 4-char PIN reveals nothing), longer values show the first 4 characters
// (enough to separate REPLACE_ME / test123 / admin123 classes), and the length
// is always stated so the classifier can weigh it.
func TestMaskSecret(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "\"\" (0 chars)"},
		{"abc", "\"***\" (3 chars)"},
		{"test123", "\"test…\" (7 chars)"},
		{"admin123", "\"admi…\" (8 chars)"},
		{"REPLACE_ME", "\"REPL…\" (10 chars)"},
	}
	for _, tc := range cases {
		if got := maskSecret(tc.in); got != tc.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
