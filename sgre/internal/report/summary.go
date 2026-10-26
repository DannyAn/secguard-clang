package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

type SummaryData struct {
	ScanID           string
	TargetPath       string
	ScanDir          string
	TotalCandidates  int
	AutoConfirmed    int
	FilesIndexed     int
	FunctionsIndexed int
	FunctionsInIndex int
	// LinesOfCode completes the scan-scale trio (files / functions / lines)
	// reported alongside report.md's `## Scan Overview`.
	LinesOfCode   int
	// ScanMode / EnclosingWorktree come from the scan-scope diagnostic
	// ("complete-program" when the tree defines main, "boundary" when it does
	// not). A boundary scan inside a git worktree is very likely a subtree scan,
	// where every zero-in-caller pointer parameter is fail-open — the single
	// largest source of null-deref contract candidates in production. The AI
	// needs that fact to dismiss them as a group instead of judging 200 rows.
	ScanMode          string
	EnclosingWorktree string
	TypeBreakdown     []TypeBreakdownEntry
	ReportPath    string
	SarifPath     string
	LatestPath    string
}

type TypeBreakdownEntry struct {
	Type  string
	CWE   string
	Count int
}

func BuildScanSummary(data SummaryData) string {
	var b strings.Builder

	b.WriteString("## SecGuard Scan Summary\n\n")

	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	fmt.Fprintf(&b, "| Scan ID | %s |\n", data.ScanID)
	fmt.Fprintf(&b, "| Target | %s |\n", data.TargetPath)
	fmt.Fprintf(&b, "| Scan Dir | %s |\n", data.ScanDir)
	fmt.Fprintf(&b, "| Total Candidates | %d |\n", data.TotalCandidates)
	if data.AutoConfirmed > 0 {
		fmt.Fprintf(&b, "| Auto-confirmed (pipeline-proved) | %d |\n", data.AutoConfirmed)
	}
	fmt.Fprintf(&b, "| Files Indexed | %d |\n", data.FilesIndexed)
	fmt.Fprintf(&b, "| Functions Indexed | %d |\n", data.FunctionsIndexed)
	fmt.Fprintf(&b, "| Functions In Index | %d |\n", data.FunctionsInIndex)
	if data.LinesOfCode > 0 {
		fmt.Fprintf(&b, "| Lines Of Code | %d |\n", data.LinesOfCode)
	}
	b.WriteString("\n")

	if data.ScanMode == "boundary" {
		b.WriteString("> **Boundary scan: no entry point (`main`) in the scanned tree.**\n")
		if data.EnclosingWorktree != "" {
			fmt.Fprintf(&b, "> The target is a subtree of the git worktree `%s`. Every zero-in-caller\n", data.EnclosingWorktree)
			b.WriteString("> pointer parameter is therefore treated as an external caller's argument\n")
			b.WriteString("> (fail-open), which inflates null-deref with external-contract candidates.\n")
			fmt.Fprintf(&b, "> Scan `%s` for a complete-program result if the callers live there.\n", data.EnclosingWorktree)
		} else {
			b.WriteString("> Every zero-in-caller pointer parameter is treated as an external\n")
			b.WriteString("> caller's argument (fail-open); judge those tiers as one boundary\n")
			b.WriteString("> contract per function, not per row.\n")
		}
		// The declaration mechanism is the only way to close a boundary scan
		// WITHOUT editing code: declaring the program's entry point flips the
		// scan to complete-program mode, and the other sections declare the
		// framework contracts the tree cannot see. Name them here — a reader of
		// "N null-deref candidates in boundary mode" is exactly the reader who
		// needs the knob.
		b.WriteString("> To close this boundary without editing code, declare the program entry\n")
		b.WriteString("> in `[scan] entry_points` of `secguard.toml` (a firmware task/thread\n")
		b.WriteString("> body, an SDK callback entry), and declare the framework contracts the\n")
		b.WriteString("> tree cannot see: `[nullability.non_null_params]` (framework-guaranteed\n")
		b.WriteString("> pointer parameters), `[iterator_macros.macros]`, `[trusted_macros]`,\n")
		b.WriteString("> `[nullability.non_null_returns]`.\n")
		if n := typeCount(data.TypeBreakdown, "null-deref"); n > 0 {
			fmt.Fprintf(&b, "> This scan has **%d** null-deref candidates in boundary mode.\n\n", n)
		} else {
			b.WriteString("\n")
		}
	}

	b.WriteString("### Candidates by Skill\n\n")
	if len(data.TypeBreakdown) == 0 || data.TotalCandidates == 0 {
		b.WriteString("No issues found.\n\n")
	} else {
		b.WriteString("| Skill | CWE | Count |\n")
		b.WriteString("|-------|-----|-------|\n")
		for _, entry := range data.TypeBreakdown {
			fmt.Fprintf(&b, "| %s | %s | %d |\n", entry.Type, entry.CWE, entry.Count)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Output Files\n\n")
	fmt.Fprintf(&b, "- Report: %s\n", data.ReportPath)
	fmt.Fprintf(&b, "- SARIF (candidate stage, unclassified): %s\n", data.SarifPath)
	if data.ScanDir != "" {
		fmt.Fprintf(&b, "- Candidate evidence: %s (unclassified pipeline leads)\n", filepath.Join(data.ScanDir, CandidatesDir))
		fmt.Fprintf(&b, "- Findings to review: %s (AI-confirmed verdicts only)\n", filepath.Join(data.ScanDir, FindingsDir))
	}
	fmt.Fprintf(&b, "- Latest: %s\n", data.LatestPath)

	return b.String()
}

func PrintScanSummary(w io.Writer, data SummaryData) {
	if data.ScanID == "" && data.TargetPath == "" && data.TotalCandidates == 0 && len(data.TypeBreakdown) == 0 {
		fmt.Fprint(w, "warning: summary generation skipped: invalid metadata\n")
		return
	}
	fmt.Fprint(w, BuildScanSummary(data))
}

type PlanSummaryData struct {
	VulnType   string
	CWE        string
	SeedCount  int
	FinalCount int
	Filters    []PlanFilterStat
	Candidates []PlanCandidateEntry
}

type PlanFilterStat struct {
	Name        string
	InputCount  int
	OutputCount int
}

type PlanCandidateEntry struct {
	Function  string
	File      string
	Line      int
	Variable  string
	Suspicion string
}

func BuildPlanSummary(data PlanSummaryData) string {
	var b strings.Builder

	b.WriteString("## SecGuard Plan Summary\n\n")

	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	fmt.Fprintf(&b, "| Vulnerability Type | %s |\n", data.VulnType)
	fmt.Fprintf(&b, "| CWE | %s |\n", data.CWE)
	fmt.Fprintf(&b, "| Seed Count | %d |\n", data.SeedCount)
	fmt.Fprintf(&b, "| Final Count | %d |\n\n", data.FinalCount)

	if len(data.Filters) > 0 {
		b.WriteString("### Filter Chain\n\n")
		b.WriteString("| Filter | Input | Output |\n")
		b.WriteString("|--------|-------|--------|\n")
		for _, f := range data.Filters {
			fmt.Fprintf(&b, "| %s | %d | %d |\n", f.Name, f.InputCount, f.OutputCount)
		}
		b.WriteString("\n")
	}

	b.WriteString("### Candidates\n\n")
	if len(data.Candidates) == 0 {
		b.WriteString("No candidates after convergence.\n")
	} else {
		b.WriteString("| # | Function | File:Line | Variable | Suspicion |\n")
		b.WriteString("|---|----------|-----------|----------|-----------|\n")
		for i, c := range data.Candidates {
			fmt.Fprintf(&b, "| %d | %s | %s:%d | %s | %s |\n", i+1, c.Function, c.File, c.Line, c.Variable, c.Suspicion)
		}
	}

	return b.String()
}

func PrintPlanSummary(w io.Writer, data PlanSummaryData) {
	if data.VulnType == "" {
		fmt.Fprint(w, "warning: plan summary generation skipped: invalid metadata\n")
		return
	}
	fmt.Fprint(w, BuildPlanSummary(data))
}

// typeCount returns the candidate count for one vuln type in the breakdown.
func typeCount(entries []TypeBreakdownEntry, vulnType string) int {
	for _, e := range entries {
		if e.Type == vulnType {
			return e.Count
		}
	}
	return 0
}
