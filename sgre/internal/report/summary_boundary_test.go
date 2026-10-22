package report

import (
	"strings"
	"testing"
)

// A boundary scan (no main) inside a git worktree is usually a SUBTREE scan:
// every zero-in-caller pointer parameter is fail-open, which is the single
// largest source of null-deref contract candidates in production. The summary
// must state it (and name the worktree to re-scan) so the AI judges the boundary
// contract once per function instead of re-deriving it row by row.
func TestBuildScanSummaryBoundaryWorktreeWarning(t *testing.T) {
	md := BuildScanSummary(SummaryData{
		ScanID:            "sc_test",
		TargetPath:        "/repo/src",
		TotalCandidates:   201,
		ScanMode:          "boundary",
		EnclosingWorktree: "/repo",
		TypeBreakdown:     []TypeBreakdownEntry{{Type: "null-deref", CWE: "CWE-476", Count: 201}},
	})
	if !strings.Contains(md, "Boundary scan") {
		t.Fatalf("a boundary scan must be announced in the summary:\n%s", md)
	}
	if !strings.Contains(md, "/repo") {
		t.Fatalf("the enclosing worktree must be named so the user can re-scan it:\n%s", md)
	}
	if !strings.Contains(md, "**201** null-deref candidates in boundary mode") {
		t.Fatalf("the null-deref volume must be tied to the boundary fact:\n%s", md)
	}
}

func TestBuildScanSummaryCompleteProgramHasNoWarning(t *testing.T) {
	md := BuildScanSummary(SummaryData{
		ScanID:          "sc_test",
		TargetPath:      "/repo",
		TotalCandidates: 3,
		ScanMode:        "complete-program",
		TypeBreakdown:   []TypeBreakdownEntry{{Type: "null-deref", CWE: "CWE-476", Count: 3}},
	})
	if strings.Contains(md, "Boundary scan") {
		t.Fatalf("a complete-program scan must not carry the boundary warning:\n%s", md)
	}
}
