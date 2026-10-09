package review

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

type ReportSummarizer struct{}

func NewReportSummarizer() *ReportSummarizer {
	return &ReportSummarizer{}
}

func (s *ReportSummarizer) Summarize(records []ReviewRecord) *RunResult {
	r := &RunResult{
		Total:           len(records),
		ByVerdict:       map[string]int{},
		ByDetector:      map[string]map[string]int{},
		EvidenceSources: map[string]int{},
	}
	for _, rec := range records {
		r.ByVerdict[rec.Verdict]++
		detector := planner.TypeForCWE(rec.RuleID)
		if detector == "" {
			detector = rec.RuleID
		}
		if _, ok := r.ByDetector[detector]; !ok {
			r.ByDetector[detector] = map[string]int{}
		}
		r.ByDetector[detector][rec.Verdict]++
		if rec.DurationMs > 0 {
			r.AIStats.TotalCalls++
			if rec.Verdict == VerdictReviewError {
				r.AIStats.Failed++
			} else {
				r.AIStats.Successful++
			}
			r.AIStats.TotalDurationMs += rec.DurationMs
		}
	}
	return r
}

func (s *ReportSummarizer) RenderReport(r *RunResult) string {
	var buf strings.Builder
	buf.WriteString("AI Review Summary\n")
	buf.WriteString("=================\n\n")
	fmt.Fprintf(&buf, "Total findings reviewed: %d\n", r.Total)
	fmt.Fprintf(&buf, "Duration: %d ms\n\n", r.DurationMs)

	buf.WriteString("Verdict distribution:\n")
	verdicts := sortedKeys(r.ByVerdict)
	for _, v := range verdicts {
		fmt.Fprintf(&buf, "  %s: %d\n", v, r.ByVerdict[v])
	}

	buf.WriteString("\nBy detector:\n")
	detectors := sortedKeys2(r.ByDetector)
	for _, det := range detectors {
		fmt.Fprintf(&buf, "  %s:\n", det)
		vs := sortedKeys(r.ByDetector[det])
		for _, v := range vs {
			fmt.Fprintf(&buf, "    %s: %d\n", v, r.ByDetector[det][v])
		}
	}

	buf.WriteString("\nAI call statistics:\n")
	fmt.Fprintf(&buf, "  Total calls: %d\n", r.AIStats.TotalCalls)
	fmt.Fprintf(&buf, "  Successful: %d\n", r.AIStats.Successful)
	fmt.Fprintf(&buf, "  Failed: %d\n", r.AIStats.Failed)
	fmt.Fprintf(&buf, "  Total duration: %d ms\n", r.AIStats.TotalDurationMs)

	if len(r.EvidenceSources) > 0 {
		buf.WriteString("\nEvidence sources:\n")
		sources := sortedKeys(r.EvidenceSources)
		for _, src := range sources {
			fmt.Fprintf(&buf, "  %s: %d\n", src, r.EvidenceSources[src])
		}
	}

	if r.RevisionMismatches > 0 {
		fmt.Fprintf(&buf, "\nRevision mismatches: %d\n", r.RevisionMismatches)
	}

	buf.WriteString("\nWARNING: AI verdict 未经人工验证前不是 ground truth。\n")
	return buf.String()
}

func (s *ReportSummarizer) ExportJSON(records []ReviewRecord) ([]byte, error) {
	return json.MarshalIndent(records, "", "  ")
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys2(m map[string]map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
