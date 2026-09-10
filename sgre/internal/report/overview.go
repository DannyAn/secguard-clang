package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// ScanOverview is the scan-scale + result-aggregate block that every
// human-facing artifact (report.md, audit-report.md, the CLI's `summary`
// envelope) opens with. Before it existed, the verdict-stage report.md carried
// counts only — a reader could not tell how large the scanned codebase was, how
// many candidates the pipeline converged, how much of the confirmed number came
// from the pipeline rather than the AI, or what the scan's own ID was (the
// report --audit rewrite dropped it). The console showed per-type
// confirmed/suspected counts with no aggregate; the same numbers now have ONE
// definition here, so console and report can never disagree.
//
// Zero values are treated as "unknown" and are omitted / rendered "n/a" rather
// than printed as a misleading 0: a scan predating scan_runs metrics has no
// files/functions figure, which is different from a codebase with none.
type ScanOverview struct {
	ScanID       string
	Tool         string
	TargetPath   string
	StartedAt    time.Time
	DurationMs   int64
	AIDurationMs int64

	FilesIndexed     int
	FunctionsIndexed int
	LinesOfCode      int
	// FunctionsInIndex / FilesInIndex describe the whole program graph, which is
	// what a reader falls back to when this scan wrote no `scan_runs` metrics row
	// (an older scan, or a review run). HasScanMetrics says which pair applies —
	// without it, a missing metrics row renders as "0 functions scanned", which
	// reads as an empty codebase instead of "not measured".
	FunctionsInIndex int
	FilesInIndex     int
	HasScanMetrics   bool

	// RawSeeds is the detector-level evidence count before convergence;
	// Candidates is what survived convergence (including the pipeline's
	// auto-confirmed rows), so RawSeeds -> Candidates is the reduction a reader
	// can check against `secguard metrics`.
	RawSeeds      int
	Candidates    int
	AutoConfirmed int
	AIConfirmed   int
	AISuspected   int
	AIDismissed   int
	Unclassified  int

	TypesScanned      int
	TypesWithFindings int
	SeverityCounts    map[string]SeverityCount
}

// SeverityCount is the actionable (confirmed + suspected) breakdown per
// severity. Dismissed findings are excluded — they are not defects.
type SeverityCount struct {
	Confirmed int
	Suspected int
}

func (s SeverityCount) Total() int { return s.Confirmed + s.Suspected }

// ConfirmedTotal counts every confirmed finding: the pipeline's machine
// verdicts plus the AI's. report.md's "Confirmed findings" row is this number —
// keeping the two apart in the breakdown below is what stops a reader from
// comparing `ls findings/` against a subagent's reported count.
func (o ScanOverview) ConfirmedTotal() int { return o.AutoConfirmed + o.AIConfirmed }

func (o ScanOverview) SuspectedTotal() int { return o.AISuspected }

func (o ScanOverview) ActionableTotal() int { return o.ConfirmedTotal() + o.AISuspected }

func (o ScanOverview) DismissedTotal() int { return o.AIDismissed }

// Headline is the one-sentence verdict a reader (or the console) leads with.
func (o ScanOverview) Headline() string {
	if o.ActionableTotal() == 0 {
		if o.AIDismissed > 0 {
			return fmt.Sprintf("This scan reported no actionable issue: all %d converged %s reviewed and dismissed as false positives.",
				o.AIDismissed, plural(o.AIDismissed, "candidate was", "candidates were"))
		}
		return "This scan reported no actionable issue."
	}
	s := fmt.Sprintf("This scan reported %d actionable %s: %d confirmed, %d suspected.",
		o.ActionableTotal(), plural(o.ActionableTotal(), "issue", "issues"), o.ConfirmedTotal(), o.AISuspected)
	if o.AutoConfirmed > 0 {
		s += fmt.Sprintf(" Of the confirmed ones, %d auto-confirmed by the pipeline (no AI review) and %d classified by the AI.",
			o.AutoConfirmed, o.AIConfirmed)
	}
	return s
}

func plural(n int, singular, pluralForm string) string {
	if n == 1 {
		return singular
	}
	return pluralForm
}

// ScaleText is the "how big was this scan" line: files / functions / lines.
func (o ScanOverview) ScaleText() string {
	parts := []string{}
	switch {
	case o.HasScanMetrics:
		if o.FilesIndexed > 0 {
			parts = append(parts, fmt.Sprintf("%d files", o.FilesIndexed))
		}
		if o.FunctionsIndexed > 0 {
			parts = append(parts, fmt.Sprintf("%d functions", o.FunctionsIndexed))
		} else if o.FunctionsInIndex > 0 {
			parts = append(parts, fmt.Sprintf("%d functions (in index)", o.FunctionsInIndex))
		}
	default:
		// No scan metrics row: report the index instead of a misleading zero,
		// and label it so the difference is visible.
		if o.FilesInIndex > 0 {
			parts = append(parts, fmt.Sprintf("%d files (in index)", o.FilesInIndex))
		} else if o.FilesIndexed > 0 {
			parts = append(parts, fmt.Sprintf("%d files", o.FilesIndexed))
		}
		if o.FunctionsInIndex > 0 {
			parts = append(parts, fmt.Sprintf("%d functions (in index)", o.FunctionsInIndex))
		}
	}
	if o.LinesOfCode > 0 {
		parts = append(parts, fmt.Sprintf("%d lines", o.LinesOfCode))
	}
	if len(parts) == 0 {
		return "n/a"
	}
	return strings.Join(parts, " / ")
}

// scaleRows renders the scale rows for a summary table, choosing between this
// scan's figures and the whole-index fallback.
func (o ScanOverview) scaleRows() string {
	var b strings.Builder
	if o.HasScanMetrics {
		fmt.Fprintf(&b, "| Files scanned | %d |\n", o.FilesIndexed)
		fmt.Fprintf(&b, "| Functions scanned | %d |\n", o.FunctionsIndexed)
		if o.FunctionsInIndex > 0 {
			fmt.Fprintf(&b, "| Functions in index | %d |\n", o.FunctionsInIndex)
		}
	} else if o.FilesInIndex > 0 || o.FunctionsInIndex > 0 {
		fmt.Fprintf(&b, "| Files in index | %d |\n", o.FilesInIndex)
		fmt.Fprintf(&b, "| Functions in index | %d |\n", o.FunctionsInIndex)
	}
	if o.LinesOfCode > 0 {
		fmt.Fprintf(&b, "| Lines of code | %d |\n", o.LinesOfCode)
	}
	return b.String()
}

// MetadataMarkdown renders the shared "## Scan Overview" header table. Rows
// whose value is unknown are omitted instead of printed as 0.
func (o ScanOverview) MetadataMarkdown() string {
	var b strings.Builder
	b.WriteString("## Scan Overview\n\n")
	b.WriteString("| Field | Value |\n")
	b.WriteString("|-------|-------|\n")
	if o.ScanID != "" {
		fmt.Fprintf(&b, "| Scan ID | `%s` |\n", o.ScanID)
	}
	tool := o.Tool
	if tool == "" {
		tool = "secguard-clang v" + ToolVersion
	}
	fmt.Fprintf(&b, "| Tool | %s |\n", tool)
	if o.TargetPath != "" {
		fmt.Fprintf(&b, "| Target | `%s` |\n", o.TargetPath)
	}
	if !o.StartedAt.IsZero() {
		fmt.Fprintf(&b, "| Scan time | %s |\n", o.StartedAt.Format("2006-01-02 15:04:05"))
	}
	if o.DurationMs > 0 {
		fmt.Fprintf(&b, "| Automated analysis | %s (index + graph + detectors + convergence + auto-confirm) |\n", humanDuration(o.DurationMs))
	}
	if o.AIDurationMs > 0 {
		fmt.Fprintf(&b, "| AI classification | %s |\n", humanDuration(o.AIDurationMs))
	}
	fmt.Fprintf(&b, "| Codebase scale | %s |\n", o.ScaleText())
	if o.TypesScanned > 0 {
		fmt.Fprintf(&b, "| Vulnerability types scanned | %d |\n", o.TypesScanned)
	}
	b.WriteString("\n")
	return b.String()
}

// HeadlineMarkdown renders just the one-sentence verdict. The audit report uses
// this instead of VerdictMarkdown: its own "AI Value Summary" table already
// carries the funnel, and printing the same counts twice in one document is how
// a reader learns to distrust both.
func (o ScanOverview) HeadlineMarkdown() string {
	return "**" + o.Headline() + "**\n\n"
}

// VerdictMarkdown renders the post-classification aggregate: the headline
// sentence, the counts funnel, and the severity breakdown.
func (o ScanOverview) VerdictMarkdown() string {
	var b strings.Builder
	b.WriteString("## Result Summary\n\n")
	b.WriteString(o.HeadlineMarkdown())
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(o.scaleRows())
	fmt.Fprintf(&b, "| Raw evidence seeds | %d |\n", o.RawSeeds)
	fmt.Fprintf(&b, "| Converged candidates | %d |\n", o.Candidates)
	fmt.Fprintf(&b, "| Confirmed findings | %d |\n", o.ConfirmedTotal())
	fmt.Fprintf(&b, "| — proved by the pipeline (auto-confirmed, no AI review) | %d |\n", o.AutoConfirmed)
	fmt.Fprintf(&b, "| — classified by the AI | %d |\n", o.AIConfirmed)
	fmt.Fprintf(&b, "| Suspected findings | %d |\n", o.SuspectedTotal())
	fmt.Fprintf(&b, "| Dismissed (false positives) | %d |\n", o.DismissedTotal())
	fmt.Fprintf(&b, "| Actionable findings (confirmed + suspected) | %d |\n", o.ActionableTotal())
	if o.Unclassified > 0 {
		fmt.Fprintf(&b, "| Candidates without a persisted verdict | %d |\n", o.Unclassified)
	}
	fmt.Fprintf(&b, "| Vulnerability types with findings | %d |\n\n", o.TypesWithFindings)

	b.WriteString(severityMarkdown(o.SeverityCounts))
	return b.String()
}

// CandidateMarkdown renders the pre-classification aggregate for the
// candidate-stage report.md: what was scanned, what converged, and what still
// awaits the AI. It never uses verdict language — candidates are leads.
func (o ScanOverview) CandidateMarkdown() string {
	var b strings.Builder
	b.WriteString("## Result Summary\n\n")
	awaiting := o.Candidates - o.AutoConfirmed
	if awaiting < 0 {
		awaiting = 0
	}
	fmt.Fprintf(&b, "**%d converged %s awaiting AI classification", awaiting, plural(awaiting, "candidate is", "candidates are"))
	if o.AutoConfirmed > 0 {
		fmt.Fprintf(&b, " (%d already proved and auto-confirmed by the pipeline)", o.AutoConfirmed)
	}
	b.WriteString(".**\n\n")
	b.WriteString("| Metric | Value |\n")
	b.WriteString("|--------|-------|\n")
	b.WriteString(o.scaleRows())
	fmt.Fprintf(&b, "| Raw evidence seeds | %d |\n", o.RawSeeds)
	fmt.Fprintf(&b, "| Converged candidates | %d |\n", o.Candidates)
	fmt.Fprintf(&b, "| Auto-confirmed by pipeline | %d |\n", o.AutoConfirmed)
	fmt.Fprintf(&b, "| Awaiting AI classification | %d |\n", awaiting)
	fmt.Fprintf(&b, "| Vulnerability types with candidates | %d |\n\n", o.TypesWithFindings)
	return b.String()
}

// SummaryFields is the machine-readable aggregate returned in the
// `report --audit` JSON envelope. The console reads these instead of adding up
// the per-type `audits` array, so the aggregate line can never disagree with
// report.md.
func (o ScanOverview) SummaryFields() map[string]interface{} {
	m := map[string]interface{}{
		"scan_id":       o.ScanID,
		"headline":      o.Headline(),
		"scale":         o.ScaleText(),
		"files_indexed": o.FilesIndexed,
		// functions_indexed is this scan's figure; functions_in_index is the
		// whole program graph. A scan with no metrics row has no meaningful
		// "scanned" figure, so both are exposed and `scale` carries the label.
		"functions_indexed":       o.FunctionsIndexed,
		"files_in_index":          o.FilesInIndex,
		"functions_in_index":      o.FunctionsInIndex,
		"scan_metrics_available":  o.HasScanMetrics,
		"lines_of_code":           o.LinesOfCode,
		"raw_seeds":               o.RawSeeds,
		"converged_candidates":    o.Candidates,
		"auto_confirmed":          o.AutoConfirmed,
		"ai_confirmed":            o.AIConfirmed,
		"ai_suspected":            o.AISuspected,
		"ai_dismissed":            o.AIDismissed,
		"confirmed_total":         o.ConfirmedTotal(),
		"suspected_total":         o.SuspectedTotal(),
		"dismissed_total":         o.DismissedTotal(),
		"actionable_total":        o.ActionableTotal(),
		"unclassified_candidates": o.Unclassified,
		"types_scanned":           o.TypesScanned,
		"types_with_findings":     o.TypesWithFindings,
	}
	if o.DurationMs > 0 {
		m["automated_analysis_ms"] = o.DurationMs
	}
	if o.AIDurationMs > 0 {
		m["ai_classification_ms"] = o.AIDurationMs
	}
	if len(o.SeverityCounts) > 0 {
		sev := map[string]interface{}{}
		for _, k := range sortedSeverities(o.SeverityCounts) {
			c := o.SeverityCounts[k]
			sev[k] = map[string]int{"confirmed": c.Confirmed, "suspected": c.Suspected, "total": c.Total()}
		}
		m["severity_breakdown"] = sev
	}
	return m
}

// CountSeverities aggregates actionable (confirmed + suspected) findings by
// severity. It is exported so the audit report and report.md derive the
// breakdown from the same rule: auto-confirmed counts as confirmed, dismissed
// never counts.
func CountSeverities(findings []*db.Finding) map[string]SeverityCount {
	counts := map[string]SeverityCount{}
	for _, f := range findings {
		sev := normalizeSeverity(strings.ToLower(strings.TrimSpace(f.Severity)))
		c := counts[sev]
		switch f.FinalStatus() {
		case "confirmed":
			c.Confirmed++
		case "suspected":
			c.Suspected++
		default:
			continue
		}
		counts[sev] = c
	}
	return counts
}

func normalizeSeverity(s string) string {
	switch s {
	case "critical", "high", "medium", "low", "info":
		return s
	default:
		return "unknown"
	}
}

var severityOrder = []string{"critical", "high", "medium", "low", "info", "unknown"}

func sortedSeverities(counts map[string]SeverityCount) []string {
	out := make([]string, 0, len(counts))
	for _, s := range severityOrder {
		if _, ok := counts[s]; ok {
			out = append(out, s)
		}
	}
	// Any severity spelling outside the enum (a hand-written finding) still gets
	// a row, sorted after the known ones so the table stays deterministic.
	extra := make([]string, 0)
	for s := range counts {
		known := false
		for _, k := range severityOrder {
			if k == s {
				known = true
				break
			}
		}
		if !known {
			extra = append(extra, s)
		}
	}
	sort.Strings(extra)
	return append(out, extra...)
}

func severityMarkdown(counts map[string]SeverityCount) string {
	if len(counts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("### Findings by Severity\n\n")
	b.WriteString("| Severity | Confirmed | Suspected | Total |\n")
	b.WriteString("|----------|-----------|-----------|-------|\n")
	total := SeverityCount{}
	for _, s := range sortedSeverities(counts) {
		c := counts[s]
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", s, c.Confirmed, c.Suspected, c.Total())
		total.Confirmed += c.Confirmed
		total.Suspected += c.Suspected
	}
	fmt.Fprintf(&b, "| **TOTAL** | **%d** | **%d** | **%d** |\n\n", total.Confirmed, total.Suspected, total.Total())
	return b.String()
}

// humanDuration renders milliseconds the way a report reader expects: seconds
// with one decimal under a minute, m/s above it.
func humanDuration(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	if ms < 60000 {
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	}
	m := ms / 60000
	s := (ms % 60000) / 1000
	return fmt.Sprintf("%d m %d s", m, s)
}
