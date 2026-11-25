package report

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// ContextStats is the per-scan context-assembly telemetry (issue #330 §7): how
// each candidate's Code Context was assembled — which layer won, whether the
// decisive L3 evidence was embedded, and the raw line volume. It is the "did the
// configurable ±20 window and the L2 whole-function embedding stay bounded, or
// did they bloat the classifier's input" measurement, kept as metadata + counts
// only (never source content — the source already travels through the report
// artifacts, so this sidecar adds nothing sensitive).
type ContextStats struct {
	Total  ContextTypeStat            `json:"total"`
	ByType map[string]ContextTypeStat `json:"by_type"`
}

// ContextTypeStat is the per-type (or aggregate) slice of the context telemetry.
type ContextTypeStat struct {
	Candidates        int   `json:"candidates"`
	L1Local           int   `json:"l1_local"`           // local ±CandidateContextLines window
	L2Function        int   `json:"l2_function"`        // whole enclosing function embedded
	SourceSink        int   `json:"source_sink"`        // widened decisive source→sink span
	SourceUnavailable int   `json:"source_unavailable"` // file could not be read at report time
	FunctionTooLarge  int   `json:"function_too_large"` // function span present but not embedded
	CalleeEmbedded    int   `json:"callee_embedded"`    // ## Callee Definition / ## Second Callee Definition
	MacroEmbedded     int   `json:"macro_embedded"`     // ## Macro Definition
	ContextLines      int64 `json:"context_lines"`      // total Code Context source lines rendered
}

func newContextStats() ContextStats {
	return ContextStats{ByType: map[string]ContextTypeStat{}}
}

func (s *ContextStats) typeStat(vulnType string) *ContextTypeStat {
	t, ok := s.ByType[vulnType]
	if !ok {
		s.ByType[vulnType] = ContextTypeStat{}
		t = s.ByType[vulnType]
	}
	return &t
}

// record resolves one candidate's Code Context into its layer bucket. A nil ctx
// is the "source unavailable" degradation; functionSpanPresent marks a candidate
// whose enclosing function span was known but not embedded (the L2 fallback).
func (s *ContextStats) record(vulnType string, ctx *codeContext, functionSpanPresent bool) {
	s.Total.Candidates++
	st := s.typeStat(vulnType)
	st.Candidates++
	if ctx == nil {
		s.Total.SourceUnavailable++
		st.SourceUnavailable++
		return
	}
	s.Total.ContextLines += int64(len(ctx.Lines))
	st.ContextLines += int64(len(ctx.Lines))
	switch ctx.Reason {
	case "enclosing function":
		s.Total.L2Function++
		st.L2Function++
	case "source→sink span":
		s.Total.SourceSink++
		st.SourceSink++
	default:
		s.Total.L1Local++
		st.L1Local++
	}
	if functionSpanPresent && ctx.Reason != "enclosing function" {
		s.Total.FunctionTooLarge++
		st.FunctionTooLarge++
	}
}

// recordEmbeddings counts the L3 symbol evidence (callee body / macro body)
// embedded beside the Code Context.
func (s *ContextStats) recordEmbeddings(vulnType string, callee, macro bool) {
	st := s.typeStat(vulnType)
	if callee {
		s.Total.CalleeEmbedded++
		st.CalleeEmbedded++
	}
	if macro {
		s.Total.MacroEmbedded++
		st.MacroEmbedded++
	}
}

// contextStatsFile is the sidecar name, beside candidates.sarif in the scan dir.
const contextStatsFile = "context-stats.json"

// writeContextStats persists the context-assembly telemetry as a JSON sidecar.
func (o *ScanOutput) writeContextStats(s ContextStats) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(filepath.Join(o.ScanDir, contextStatsFile), b, 0644)
}

// Summary returns the compact form surfaced in the scan envelope: the aggregate
// plus a per-type distribution (the full per-type body lives in the sidecar).
func (s ContextStats) Summary() map[string]interface{} {
	return map[string]interface{}{
		"total":   s.Total,
		"by_type": s.ByType,
	}
}
