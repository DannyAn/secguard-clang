package planner

import (
	"context"
)

type Filter interface {
	Name() string
	Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error)
}

type Candidate struct {
	DerefEventID      int64   `json:"deref_event_id"`
	FunctionID        int64   `json:"function_id"`
	FunctionName      string  `json:"function_name"`
	VariableName      string  `json:"variable_name"`
	LocationID        int64   `json:"location_id"`
	FileID            int64   `json:"file_id"`
	Line              int     `json:"line"`
	HasNullableSource bool    `json:"has_nullable_source"`
	IsReachable       bool    `json:"is_reachable"`
	HasDataFlow       bool    `json:"has_data_flow"`
	IsGuarded         bool    `json:"is_guarded"`
	GuardStrength     string  `json:"guard_strength"`
	SuspicionLevel    string  `json:"suspicion_level"`
	NonNullable       bool    `json:"non_nullable"`
	QualityScore      float64 `json:"quality_score"`
}
