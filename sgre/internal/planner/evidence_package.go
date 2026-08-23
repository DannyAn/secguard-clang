package planner

import (
	"encoding/json"
)

type EvidenceItem struct {
	Type              string             `json:"type"`
	VulnerabilityType string             `json:"vulnerability_type"`
	SuspicionLevel    string             `json:"suspicion_level,omitempty"`
	HasDefiniteNull   bool               `json:"has_definite_null,omitempty"`
	Target            TargetInfo         `json:"target"`
	SourceLine        int                `json:"source_line,omitempty"`
	Evidence          []EvidenceFragment `json:"evidence"`
}

type TargetInfo struct {
	File     string `json:"file,omitempty"`
	Function string `json:"function"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
}

type EvidenceFragment struct {
	Type string `json:"type"`
	// Role classifies the fragment in the source→sink→path→condition chain so
	// the report can render a structured evidence narrative rather than a flat
	// list. Empty for generic fragments (rendered by Type).
	Role   string `json:"role,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type PipelineSummary struct {
	SeedCount       int            `json:"seed_count"`
	Filters         []FilterStats  `json:"filters"`
	FinalCount      int            `json:"final_count"`
	DedupedCount    int            `json:"deduped_count"`
	ShortCircuited  bool           `json:"short_circuited"`
	Dropped         []Dismissed    `json:"dropped,omitempty"`
	DroppedByReason map[string]int `json:"dropped_by_reason,omitempty"`
}

type FilterStats struct {
	Name        string `json:"name"`
	InputCount  int    `json:"input_count"`
	OutputCount int    `json:"output_count"`
}

type PlanResult struct {
	VulnerabilityType string          `json:"vulnerability_type"`
	Candidates        []EvidenceItem  `json:"candidates"`
	Summary           PipelineSummary `json:"summary"`
}

func (r *PlanResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r *PlanResult) CandidateCount() int {
	return len(r.Candidates)
}

func newEvidenceItem(c Candidate, spec *VulnTypeSpec, fileName string) EvidenceItem {
	item := EvidenceItem{
		Type:              spec.EvidenceType,
		VulnerabilityType: spec.Name,
		HasDefiniteNull:   c.HasDefiniteNull,
		Target: TargetInfo{
			File:     fileName,
			Function: c.FunctionName,
			Line:     c.Line,
			Variable: c.VariableName,
		},
		SourceLine: c.SourceLine,
		Evidence:   spec.BuildEvidence(c),
	}
	if c.SuspicionLevel != "" {
		item.SuspicionLevel = c.SuspicionLevel
	} else {
		item.SuspicionLevel = spec.DefaultSuspicion
	}
	if c.GuardStrength == "weak" {
		item.Evidence = append(item.Evidence, EvidenceFragment{
			Type:   "weak_guard",
			Detail: "guard exists but is insufficient (partial protection, needs AI review)",
		})
	}
	return item
}
