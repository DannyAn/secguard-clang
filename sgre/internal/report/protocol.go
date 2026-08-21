package report

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

const (
	CodeagentDir  = ".codeagent"
	ProductDir    = "secguard-clang"
	ScansDir      = "scans"
	SgreDir       = ".sgre"
	DbName        = "sgre.db"
	// SarifFile is the VERDICT-stage machine-readable report: it exists only
	// after the AI classification is persisted (`report --audit` regenerates
	// it from the findings table). A consumer that reads it is guaranteed to
	// see classified findings, never unclassified candidates.
	SarifFile = "result.sarif"
	// CandidatesSarifFile is the CANDIDATE-stage machine-readable report the
	// scan writes. It carries converged-but-unclassified leads at SARIF level
	// "note"; keeping it under its own name is what stops a CI gate from
	// treating the candidate explosion as defects.
	CandidatesSarifFile = "candidates.sarif"
	ReportFile    = "report.md"
	LatestName    = "latest"
	LatestTxtName = "latest.txt"
	ScanLogFile   = "scan.log"
	DismissedFile = "dismissed.json"
	// FindingsDir holds the AI's classified verdicts — the human review
	// surface. Only actionable verdicts (confirmed/suspected) ever get a file
	// here; see CandidatesDir for the pre-classification evidence.
	FindingsDir = "findings"
	// CandidatesDir holds the convergence pipeline's evidence packages, one
	// file per converged candidate, written before any AI classification. A
	// candidate is NOT a defect, so these must never be mixed into FindingsDir.
	CandidatesDir = "candidates"
)

// ToolVersion is the version stamped into SARIF and markdown reports.
// It is a var so cli/root.go can inject the release version at startup
// (keeping report free of a cli import, which would be a cycle).
var ToolVersion = "0.3.7"

type ScanOutput struct {
	RootDir string
	ScanDir string
	// SarifPath is where the verdict-stage report will live (written later by
	// `report --audit`); the scan itself never writes it.
	SarifPath string
	// CandidatesSarifPath is the candidate-stage report the scan writes.
	CandidatesSarifPath string
	ReportPath          string
	ScanID              string
}

func generateScanID() string {
	ts := time.Now().Format("2006-01-02_150405")
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "sc_" + ts
	}
	return "sc_" + ts + "_" + hex.EncodeToString(b)
}

func NewScanOutput(projectRoot string) *ScanOutput {
	scanID := generateScanID()
	scanDir := filepath.Join(projectRoot, CodeagentDir, ProductDir, ScansDir, scanID)
	return &ScanOutput{
		RootDir:             projectRoot,
		ScanDir:             scanDir,
		SarifPath:           filepath.Join(scanDir, SarifFile),
		CandidatesSarifPath: filepath.Join(scanDir, CandidatesSarifFile),
		ReportPath:          filepath.Join(scanDir, ReportFile),
		ScanID:              scanID,
	}
}

func GetDbPath(projectRoot string) string {
	return filepath.Join(projectRoot, CodeagentDir, ProductDir, SgreDir, DbName)
}

func EnsureSgreDir(projectRoot string) error {
	dir := filepath.Join(projectRoot, CodeagentDir, ProductDir, SgreDir)
	return os.MkdirAll(dir, 0755)
}

func (o *ScanOutput) EnsureDirs() error {
	return os.MkdirAll(o.ScanDir, 0755)
}

func (o *ScanOutput) Write(packages []*planner.PlanResult, indexSummary IndexSummary) error {
	if err := o.EnsureDirs(); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}

	// candidates/ and findings/ are derived entirely from one scan run, so a
	// re-scan into the same directory must start from a clean slate: stale
	// candidate files (whose NNN sequence has shifted) and verdict files for
	// candidates that no longer exist would otherwise survive as ghosts.
	// Persisted verdicts are never lost — `report --audit` re-derives findings/
	// from the database.
	for _, dir := range []string{CandidatesDir, FindingsDir} {
		if err := os.RemoveAll(filepath.Join(o.ScanDir, dir)); err != nil {
			return fmt.Errorf("reset %s dir: %w", dir, err)
		}
	}

	if err := o.writeCandidatesSarif(packages); err != nil {
		return fmt.Errorf("write candidates sarif: %w", err)
	}

	if err := o.writeReport(packages, indexSummary); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	if err := o.writeCandidates(packages); err != nil {
		return fmt.Errorf("write candidate evidence: %w", err)
	}

	return nil
}

type IndexSummary struct {
	FilesIndexed     int `json:"files_indexed"`
	FunctionsIndexed int `json:"functions_indexed"`
	FunctionsInIndex int `json:"functions_in_index"`
	FilesSkipped     int `json:"files_skipped"`
}

// DismissedSummary is the persisted ledger of every candidate a filter dropped,
// keyed by vulnerability type. It turns the convergence pipeline's hard
// truncation into an auditable trail: each drop carries a filter name and a
// human-readable reason, so "~600 raw candidates → ~10 findings" can be
// explained rather than asserted.
type DismissedSummary struct {
	ScanID       string              `json:"scan_id"`
	TotalDropped int                 `json:"total_dropped"`
	ByVulnType   []VulnTypeDismissed `json:"by_vuln_type"`
}

type VulnTypeDismissed struct {
	VulnerabilityType string              `json:"vulnerability_type"`
	DroppedCount      int                 `json:"dropped_count"`
	DroppedByReason   map[string]int      `json:"dropped_by_reason,omitempty"`
	Dropped           []planner.Dismissed `json:"dropped"`
}

// WriteDismissed writes the dismissed ledger to DismissedFile inside scanDir.
func WriteDismissed(scanDir string, summary DismissedSummary) error {
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		return fmt.Errorf("create scan dir: %w", err)
	}
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal dismissed: %w", err)
	}
	if err := os.WriteFile(filepath.Join(scanDir, DismissedFile), data, 0644); err != nil {
		return fmt.Errorf("write dismissed: %w", err)
	}
	return nil
}
