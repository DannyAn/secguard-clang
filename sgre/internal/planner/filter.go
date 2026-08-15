package planner

import (
	"context"
)

// Dismissed records a candidate removed by a filter, with the reason it was
// removed. The planner aggregates these into the pipeline summary and the
// persisted dismissed ledger, so convergence is auditable rather than a silent
// hard truncation.
type Dismissed struct {
	FunctionName string `json:"function_name"`
	VariableName string `json:"variable_name"`
	Line         int    `json:"line"`
	Filter       string `json:"filter"`
	Reason       string `json:"reason"`
}

// Filter is a single refinement stage in a vulnerability's filter chain.
// Apply keeps the candidates that pass and returns the candidates it dropped,
// each with a human-readable reason, so the planner can build an explicit
// convergence trail. A filter that cannot make a decision must return its
// error and a nil kept/dropped pair; the planner then preserves the input
// candidates and records the degradation rather than silently dropping them.
type Filter interface {
	Name() string
	Apply(ctx context.Context, candidates []Candidate) (kept []Candidate, dropped []Dismissed, err error)
}

// partition splits candidates into kept and dropped by keep, recording a
// per-candidate reason under filterName. reason is evaluated only for dropped
// candidates.
func partition(candidates []Candidate, keep func(Candidate) bool, reason func(Candidate) string, filterName string) ([]Candidate, []Dismissed) {
	kept := make([]Candidate, 0, len(candidates))
	dropped := make([]Dismissed, 0)
	for _, c := range candidates {
		if keep(c) {
			kept = append(kept, c)
			continue
		}
		dropped = append(dropped, Dismissed{
			FunctionName: c.FunctionName,
			VariableName: c.VariableName,
			Line:         c.Line,
			Filter:       filterName,
			Reason:       reason(c),
		})
	}
	return kept, dropped
}

// dismiss is a convenience for filters that mutate candidates before keeping
// them and need to record a drop inline rather than via a pure predicate.
func dismiss(dropped []Dismissed, c Candidate, filterName, reason string) []Dismissed {
	return append(dropped, Dismissed{
		FunctionName: c.FunctionName,
		VariableName: c.VariableName,
		Line:         c.Line,
		Filter:       filterName,
		Reason:       reason,
	})
}

type Candidate struct {
	DerefEventID      int64   `json:"deref_event_id"`
	FunctionID        int64   `json:"function_id"`
	FunctionName      string  `json:"function_name"`
	VariableName      string  `json:"variable_name"`
	APIName           string  `json:"api_name,omitempty"`
	Category          string  `json:"category,omitempty"`
	LocationID        int64   `json:"location_id"`
	FileID            int64   `json:"file_id"`
	Line              int     `json:"line"`
	HasNullableSource bool    `json:"has_nullable_source"`
	HasDefiniteNull   bool    `json:"has_definite_null"`
	IsReachable       bool    `json:"is_reachable"`
	HasDataFlow       bool    `json:"has_data_flow"`
	IsGuarded         bool    `json:"is_guarded"`
	GuardStrength     string  `json:"guard_strength"`
	SuspicionLevel    string  `json:"suspicion_level"`
	NonNullable       bool    `json:"non_nullable"`
	IsTypeExpr        bool    `json:"is_type_expr"`
	QualityScore      float64 `json:"quality_score"`
}
