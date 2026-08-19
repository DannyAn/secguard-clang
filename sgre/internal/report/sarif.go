package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	Rules   []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type sarifResult struct {
	RuleID              string             `json:"ruleId"`
	Level               string             `json:"level"`
	Message             sarifMessage       `json:"message"`
	Locations           []sarifLocation    `json:"locations"`
	CodeFlows           []sarifCodeFlow    `json:"codeFlows,omitempty"`
	PartialFingerprints map[string]string  `json:"partialFingerprints,omitempty"`
	Fingerprints        map[string]string  `json:"fingerprints,omitempty"`
	Suppressions        []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// VulnToCWE returns the canonical CWE identifier for a vulnerability type,
// or "CWE-Other" if the type is not registered. The mapping is derived from
// planner.VulnTypeSpec.CWE — the single source of truth in planner/registry.go.
func VulnToCWE(vulnType string) string {
	cwe := planner.CWEForType(vulnType)
	if cwe == "" {
		return "CWE-Other"
	}
	return cwe
}

func (o *ScanOutput) writeSarif(packages []*planner.PlanResult) error {
	rules := []sarifRule{}
	results := []sarifResult{}

	rulesSeen := map[string]bool{}
	for _, pkg := range packages {
		cwe := planner.CWEForType(pkg.VulnerabilityType)
		if cwe == "" {
			cwe = "CWE-Other"
		}
		if !rulesSeen[cwe] {
			rulesSeen[cwe] = true
			rules = append(rules, sarifRule{
				ID:   cwe,
				Name: pkg.VulnerabilityType,
			})
		}

		for _, c := range pkg.Candidates {
			level := "warning"
			if c.SuspicionLevel == "confirmed" {
				level = "error"
			}

			uri := c.Target.File
			if o.RootDir != "" && strings.HasPrefix(uri, o.RootDir) {
				uri = strings.TrimPrefix(uri, o.RootDir)
				uri = strings.TrimPrefix(uri, "/")
			}

			evidenceParts := []string{}
			for _, e := range c.Evidence {
				evidenceParts = append(evidenceParts, e.Detail)
			}

			result := sarifResult{
				RuleID: cwe,
				Level:  level,
				Message: sarifMessage{
					Text: fmt.Sprintf("%s in %s: %s", pkg.VulnerabilityType, c.Target.Function, strings.Join(evidenceParts, "; ")),
				},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: uri},
						Region:           sarifRegion{StartLine: c.Target.Line},
					},
				}},
				PartialFingerprints: map[string]string{
					"primaryLocationLineHash": fmt.Sprintf("%s:%d", c.Target.Function, c.Target.Line),
				},
				Fingerprints: map[string]string{
					"ruleId:location": fmt.Sprintf("%s:%s:%d", cwe, c.Target.Function, c.Target.Line),
				},
			}

			if c.SourceLine > 0 && c.SourceLine != c.Target.Line {
				result.CodeFlows = []sarifCodeFlow{{
					ThreadFlows: []sarifThreadFlow{{
						Locations: []sarifThreadFlowLocation{
							{
								Location: sarifLocation{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{URI: uri},
										Region:           sarifRegion{StartLine: c.SourceLine},
									},
								},
							},
							{
								Location: sarifLocation{
									PhysicalLocation: sarifPhysicalLocation{
										ArtifactLocation: sarifArtifactLocation{URI: uri},
										Region:           sarifRegion{StartLine: c.Target.Line},
									},
								},
							},
						},
					}},
				}}
			}

			results = append(results, result)
		}
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "zhuque-secguard",
					Version: ToolVersion,
					Rules:   rules,
				},
			},
			Results: results,
		}},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(o.SarifPath, data, 0644)
}
