package report

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kongan/secguard-lite/internal/planner"
)

const (
	CodeagentDir  = ".codeagent"
	ProductDir    = "zhuque-secguard"
	ScansDir      = "scans"
	SgreDir       = ".sgre"
	DbName        = "sgre.db"
	SarifFile     = "sarif.sarif"
	ReportFile    = "report.md"
	LatestName    = "latest"
	LatestTxtName = "latest.txt"
	ScanLogFile   = "scan.log"
)

type ScanOutput struct {
	RootDir    string
	ScanDir    string
	SarifPath  string
	ReportPath string
	ScanID     string
}

func generateScanID() string {
	ts := time.Now().Format("2006-01-02_150405")
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		return ts
	}
	return ts + "_" + hex.EncodeToString(b)
}

func NewScanOutput(projectRoot string) *ScanOutput {
	scanID := generateScanID()
	scanDir := filepath.Join(projectRoot, CodeagentDir, ProductDir, ScansDir, scanID)
	return &ScanOutput{
		RootDir:    projectRoot,
		ScanDir:    scanDir,
		SarifPath:  filepath.Join(scanDir, SarifFile),
		ReportPath: filepath.Join(scanDir, ReportFile),
		ScanID:     scanID,
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

	if err := o.writeSarif(packages); err != nil {
		return fmt.Errorf("write sarif: %w", err)
	}

	if err := o.writeReport(packages, indexSummary); err != nil {
		return fmt.Errorf("write report: %w", err)
	}

	if err := o.writePerFinding(packages); err != nil {
		return fmt.Errorf("write per-finding: %w", err)
	}

	return nil
}

type IndexSummary struct {
	FilesIndexed     int `json:"files_indexed"`
	FunctionsIndexed int `json:"functions_indexed"`
	FilesSkipped     int `json:"files_skipped"`
}
