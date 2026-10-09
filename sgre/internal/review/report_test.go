package review

import (
	"testing"
)

func TestSummarize_VerdictDistribution(t *testing.T) {
	records := []ReviewRecord{
		{Verdict: VerdictAIConfirmed, RuleID: "CWE-476", DurationMs: 100},
		{Verdict: VerdictAIConfirmed, RuleID: "CWE-476", DurationMs: 200},
		{Verdict: VerdictFalsePositive, RuleID: "CWE-787", DurationMs: 150},
		{Verdict: VerdictReviewError, RuleID: "CWE-476", DurationMs: 50},
	}
	s := NewReportSummarizer()
	r := s.Summarize(records)
	if r.Total != 4 {
		t.Errorf("Total = %d, want 4", r.Total)
	}
	if r.ByVerdict[VerdictAIConfirmed] != 2 {
		t.Errorf("ByVerdict[ai_confirmed] = %d, want 2", r.ByVerdict[VerdictAIConfirmed])
	}
	if r.ByVerdict[VerdictFalsePositive] != 1 {
		t.Errorf("ByVerdict[false_positive] = %d, want 1", r.ByVerdict[VerdictFalsePositive])
	}
	if r.ByVerdict[VerdictReviewError] != 1 {
		t.Errorf("ByVerdict[review_error] = %d, want 1", r.ByVerdict[VerdictReviewError])
	}
}

func TestSummarize_ByDetector(t *testing.T) {
	records := []ReviewRecord{
		{Verdict: VerdictAIConfirmed, RuleID: "CWE-476"},
		{Verdict: VerdictFalsePositive, RuleID: "CWE-476"},
		{Verdict: VerdictAIConfirmed, RuleID: "CWE-787"},
	}
	s := NewReportSummarizer()
	r := s.Summarize(records)
	if r.ByDetector["null-deref"][VerdictAIConfirmed] != 1 {
		t.Errorf("null-deref ai_confirmed = %d, want 1", r.ByDetector["null-deref"][VerdictAIConfirmed])
	}
	if r.ByDetector["null-deref"][VerdictFalsePositive] != 1 {
		t.Errorf("null-deref false_positive = %d, want 1", r.ByDetector["null-deref"][VerdictFalsePositive])
	}
}

func TestSummarize_AIStats(t *testing.T) {
	records := []ReviewRecord{
		{Verdict: VerdictAIConfirmed, DurationMs: 100},
		{Verdict: VerdictReviewError, DurationMs: 50},
		{Verdict: VerdictFalsePositive, DurationMs: 200},
	}
	s := NewReportSummarizer()
	r := s.Summarize(records)
	if r.AIStats.TotalCalls != 3 {
		t.Errorf("TotalCalls = %d, want 3", r.AIStats.TotalCalls)
	}
	if r.AIStats.Successful != 2 {
		t.Errorf("Successful = %d, want 2", r.AIStats.Successful)
	}
	if r.AIStats.Failed != 1 {
		t.Errorf("Failed = %d, want 1", r.AIStats.Failed)
	}
	if r.AIStats.TotalDurationMs != 350 {
		t.Errorf("TotalDurationMs = %d, want 350", r.AIStats.TotalDurationMs)
	}
}

func TestSummarize_EmptyRecords(t *testing.T) {
	s := NewReportSummarizer()
	r := s.Summarize(nil)
	if r.Total != 0 {
		t.Errorf("Total = %d, want 0", r.Total)
	}
}

func TestRenderReport_GroundTruthWarning(t *testing.T) {
	s := NewReportSummarizer()
	r := &RunResult{
		Total:      1,
		ByVerdict:  map[string]int{VerdictAIConfirmed: 1},
		ByDetector: map[string]map[string]int{"null-deref": {VerdictAIConfirmed: 1}},
	}
	report := s.RenderReport(r)
	if report == "" {
		t.Error("RenderReport should not return empty string")
	}
}
