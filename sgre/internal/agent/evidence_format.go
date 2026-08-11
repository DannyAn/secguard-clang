package agent

import (
	"encoding/json"
	"fmt"
)

type EvidencePackage struct {
	VulnerabilityType string        `json:"vulnerability_type"`
	Candidates        []interface{} `json:"candidates"`
	Summary           interface{}   `json:"summary"`
}

func FormatEvidencePackage(data []byte) ([]byte, error) {
	var pkg EvidencePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("agent: format evidence package: %w", err)
	}
	return json.MarshalIndent(pkg, "", "  ")
}

func ParseEvidencePackage(data []byte) (*EvidencePackage, error) {
	var pkg EvidencePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("agent: parse evidence package: %w", err)
	}
	return &pkg, nil
}
