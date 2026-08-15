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
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
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

var vulnToCWE = map[string]string{
	"null-deref":       "CWE-476",
	"buffer-overflow":  "CWE-787",
	"memory-leak":      "CWE-401",
	"injection":        "CWE-78",
	"resource-leak":    "CWE-404",
	"uninit":           "CWE-457",
	"use-after-free":   "CWE-416",
	"double-free":      "CWE-415",
	"format-string":    "CWE-134",
	"integer-overflow": "CWE-190",
	"race-condition":   "CWE-362",
	"hardcoded-secret": "CWE-798",
	"deadlock":         "CWE-667",
	"crypto-misuse":    "CWE-327",
	"out-of-bounds":    "CWE-125",
	"divide-by-zero":   "CWE-369",
	"unchecked-return": "CWE-252",
	"path-traversal":   "CWE-22",
	"sizeof-misuse":    "CWE-467",
	"signed-compare":   "CWE-681",
}

func VulnToCWE(vulnType string) string {
	cwe := vulnToCWE[vulnType]
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
		cwe := vulnToCWE[pkg.VulnerabilityType]
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

			results = append(results, sarifResult{
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
			})
		}
	}

	report := sarifReport{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:    "zhuque-secguard",
					Version: "0.1.0",
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
