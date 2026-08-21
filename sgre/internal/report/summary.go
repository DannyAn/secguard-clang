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
	FilesIndexed     int
	FunctionsIndexed int
	FunctionsInIndex int
	TypeBreakdown    []TypeBreakdownEntry
	ReportPath       string
	SarifPath        string
	LatestPath       string
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
	fmt.Fprintf(&b, "| Files Indexed | %d |\n", data.FilesIndexed)
	fmt.Fprintf(&b, "| Functions Indexed | %d |\n", data.FunctionsIndexed)
	fmt.Fprintf(&b, "| Functions In Index | %d |\n\n", data.FunctionsInIndex)

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
		fmt.Fprintf(&b, "- Findings to review: %s (AI verdicts, confirmed/suspected only)\n", filepath.Join(data.ScanDir, FindingsDir))
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
