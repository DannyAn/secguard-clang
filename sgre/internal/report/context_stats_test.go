package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

// Context-assembly telemetry (issue #330 §7): a scan records, per candidate,
// which context layer won (L1 local / L2 function / source→sink span), whether
// the source was unavailable, whether L3 callee/macro evidence was embedded, and
// the raw line volume — so the ±20 default and L2 whole-function embedding are
// measurable, not assumed bounded.
func TestWriteCandidates_ContextStats(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.c")
	if err := os.WriteFile(small, []byte("int f(char *p) {\n    p = get();\n    return p->x;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	withCallee := filepath.Join(dir, "callee.c")
	if err := os.WriteFile(withCallee, []byte("char *get(void) { return g(); }\n"), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{
			{
				// Small function → L2 whole function.
				FunctionStartLine: 1,
				FunctionEndLine:   4,
				Target:            planner.TargetInfo{File: "small.c", Function: "f", Line: 3, Variable: "p"},
			},
			{
				// No function span → L1 local window.
				Target: planner.TargetInfo{File: "small.c", Function: "f", Line: 2, Variable: "p"},
			},
			{
				// Missing file → source unavailable.
				Target: planner.TargetInfo{File: "gone.c", Function: "f", Line: 1, Variable: "p"},
			},
		},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}

	stats := o.ContextStats()
	if stats.Total.Candidates != 3 {
		t.Fatalf("total candidates = %d, want 3", stats.Total.Candidates)
	}
	if stats.Total.L2Function != 1 || stats.Total.L1Local != 1 || stats.Total.SourceUnavailable != 1 {
		t.Fatalf("layer split = l2:%d l1:%d unavailable:%d, want 1/1/1 (full: %+v)",
			stats.Total.L2Function, stats.Total.L1Local, stats.Total.SourceUnavailable, stats.Total)
	}
	if stats.Total.ContextLines == 0 {
		t.Fatalf("context lines should be counted, got 0")
	}

	// The sidecar is the persisted per-type breakdown.
	if err := o.writeContextStats(stats); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, contextStatsFile))
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	var parsed ContextStats
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("sidecar is not valid ContextStats JSON: %v", err)
	}
	if parsed.Total.Candidates != 3 {
		t.Fatalf("sidecar total candidates = %d, want 3", parsed.Total.Candidates)
	}
	if _, ok := parsed.ByType["null-deref"]; !ok {
		t.Fatalf("sidecar missing per-type null-deref entry: %s", data)
	}

	// The scan-envelope summary carries the same aggregate.
	sum := stats.Summary()
	total, ok := sum["total"].(ContextTypeStat)
	if !ok || total.Candidates != 3 {
		t.Fatalf("summary total = %#v, want candidates 3", sum["total"])
	}
}

// The L2 fallback must be visible in the telemetry: a candidate whose function
// span is known but too large to embed is counted under function_too_large, not
// silently collapsed into the local window.
func TestWriteCandidates_ContextStatsFunctionTooLarge(t *testing.T) {
	dir := t.TempDir()
	var body []string
	body = append(body, "int f(char *p) {")
	for i := 0; i < 70; i++ {
		body = append(body, "    pad();")
	}
	cand := len(body) + 1
	body = append(body, "    return p->x;", "}")
	src := filepath.Join(dir, "large.c")
	if err := os.WriteFile(src, []byte(joinLines(body)), 0644); err != nil {
		t.Fatal(err)
	}

	o := &ScanOutput{ScanDir: dir, ScanID: "sc_test", RootDir: dir}
	pkgs := []*planner.PlanResult{{
		VulnerabilityType: "null-deref",
		Candidates: []planner.EvidenceItem{{
			FunctionStartLine: 1,
			FunctionEndLine:   len(body),
			Target:            planner.TargetInfo{File: "large.c", Function: "f", Line: cand, Variable: "p"},
		}},
	}}
	if err := o.writeCandidates(pkgs); err != nil {
		t.Fatal(err)
	}
	stats := o.ContextStats()
	if stats.Total.FunctionTooLarge != 1 {
		t.Fatalf("function_too_large = %d, want 1 (L2 fallback must be visible): %+v", stats.Total.FunctionTooLarge, stats.Total)
	}
	if stats.Total.L2Function != 0 || stats.Total.L1Local != 1 {
		t.Fatalf("large function should fall back to L1, not L2: %+v", stats.Total)
	}
}

func joinLines(lines []string) string {
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	return out
}
