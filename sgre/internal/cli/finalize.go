package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/DannyAn/secguard-clang/internal/report"
)

// runFinalizeCmd is the one-shot recovery entry point that decouples result
// generation from a live host shell (issue #283 R6): after a scan's AI
// classification is interrupted — e.g. the CodeAgentCLI long-session spawn
// failure (posix_spawn E2BIG / exit 126) that leaves verdict JSON staged under
// `.sgre/.tmp/` but not persisted — the user runs `secguard finalize <scan_id>`
// in an ordinary terminal and gets `result.sarif` / `findings/` / `report.md`
// from the data that already exists. It is the productized form of the
// recover-scan.sh prototype: idempotently replay every staged verdict array,
// settle each type, audit, and self-check the artifact.
func runFinalizeCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)
	if !rejectConcatenatedArgs(remaining) {
		return 1
	}
	scanID := parseStringFlag(remaining, "scan-id")
	outputDir := parseStringFlag(remaining, "output-dir")
	allowPartial := hasFlag(remaining, "allow-partial")

	dbPath, found := resolveExistingDBPath(dbExplicit, dbPath)
	if !found {
		WriteErrorJSON("no sgre.db found; run 'secguard scan <path>' first")
		return 1
	}

	store, err := openStore(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer store.Close()

	if scanID == "" {
		scanID, err = store.GetLatestScanID(ctx)
		if err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to get latest scan_id: %v", err))
			return 1
		}
	}
	if scanID == "" {
		WriteErrorJSON("no scan stats found; run 'secguard scan' first, or pass --scan-id")
		return 1
	}
	if verr := validateAuditScanID(ctx, store, scanID); verr != nil {
		WriteErrorJSON(verr.Error())
		return 1
	}

	// The scan directory is derived from the canonical DB layout unless the
	// caller pins it with --output-dir (an interrupted scan that wrote artifacts
	// to a non-canonical directory still finalizes correctly).
	scanDir := outputDir
	if scanDir == "" {
		scanDir = filepath.Join(report.ScansRootFromDBPath(dbPath), scanID)
	}
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to ensure scan directory: %v", err))
		return 1
	}

	// Replay every staged verdict array under .sgre/.tmp/. Each is a bare JSON
	// array of finding objects (the same shape --write-json accepts); settlement
	// reports/chunks (`*-report*.json`, `*-chunk-*.json`) are objects and are
	// excluded, and an object envelope is never mistaken for a verdict array.
	staged := listStagedVerdictFiles(dbPath)
	replay := replayResult{Files: []string{}}
	var replayErrs []string
	for _, path := range staged {
		sub, code := runReportSub(ctx, []string{
			"--write-json", path,
			"--scan-id", scanID,
			"--db", dbPath,
			"--output-dir", scanDir,
		})
		replay.Files = append(replay.Files, filepath.Base(path))
		replay.FindingsWritten += intValue(sub, "findings_written")
		replay.DismissedWritten += intValue(sub, "dismissed_written")
		if code != 0 {
			replay.Failed = append(replay.Failed, filepath.Base(path))
			if e, ok := sub["error"].(string); ok {
				replayErrs = append(replayErrs, fmt.Sprintf("%s: %s", filepath.Base(path), e))
			} else {
				replayErrs = append(replayErrs, filepath.Base(path))
			}
		}
	}

	// Settle every type that has a scan_stats row. complete-type proves
	// completion from the verdict ledger (unclassified == 0), so a type whose
	// staged verdicts just replayed converges here; a type still missing
	// verdicts is reported incomplete rather than silently skipped.
	stats, err := store.ListScanStats(ctx, scanID)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to list scan stats: %v", err))
		return 1
	}
	var completedTypes []string
	type incompleteType struct {
		VulnType     string   `json:"vuln_type"`
		Unclassified int      `json:"unclassified"`
		Uncovered    []string `json:"uncovered_ranges,omitempty"`
	}
	var incompleteTypes []incompleteType
	for _, st := range stats {
		sub, code := runReportSub(ctx, []string{
			"--complete-type", st.VulnType,
			"--scan-id", scanID,
			"--db", dbPath,
		})
		if code == 0 {
			completedTypes = append(completedTypes, st.VulnType)
			continue
		}
		if st.FinalCount <= 0 {
			continue
		}
		it := incompleteType{VulnType: st.VulnType, Unclassified: intValue(sub, "unclassified")}
		if ranges, ok := sub["uncovered_ranges"].([]interface{}); ok {
			for _, r := range ranges {
				if s, ok := r.(string); ok {
					it.Uncovered = append(it.Uncovered, s)
				}
			}
		}
		incompleteTypes = append(incompleteTypes, it)
	}

	// The terminal audit regenerates result.sarif / report.md / findings/ from
	// the now-complete DB. --allow-partial is passed through so a caller that
	// explicitly accepts a partial verdict set still gets labelled artifacts.
	auditArgs := []string{
		"--audit",
		"--scan-id", scanID,
		"--db", dbPath,
		"--output-dir", scanDir,
	}
	if allowPartial {
		auditArgs = append(auditArgs, "--allow-partial")
	}
	audit, auditCode := runReportSub(ctx, auditArgs)

	// Self-check the artifact that the whole command exists to guarantee: a
	// non-empty result.sarif. If it is missing, the verdict data did not reach
	// the report layer and finalize must say so instead of claiming success.
	sarifPath := filepath.Join(scanDir, report.SarifFile)
	sarifOK, sarifBytes := nonEmptyFile(sarifPath)
	findingsCount := countFindingsFiles(filepath.Join(scanDir, report.FindingsDir))

	out := map[string]interface{}{
		"scan_id":              scanID,
		"pending_replay_files": len(staged),
		"replayed":             replay,
		"completed_types":      completedTypes,
		"incomplete_types":     incompleteTypes,
		"result_sarif": map[string]interface{}{
			"path":   sarifPath,
			"exists": sarifOK,
			"bytes":  sarifBytes,
		},
		"findings_count": findingsCount,
	}
	if len(replayErrs) > 0 {
		out["replay_errors"] = replayErrs
	}
	if auditCode != 0 {
		if e, ok := audit["error"].(string); ok {
			out["audit_error"] = e
		} else {
			out["audit_error"] = "report --audit failed"
		}
	} else if s, ok := audit["summary"]; ok {
		out["summary"] = s
	}

	switch {
	case !sarifOK:
		out["status"] = "failed"
		out["error"] = "result.sarif was not produced: the scan's verdict data is incomplete or failed to reach the report layer (see incomplete_types / audit_error)"
		WriteJSON(out)
		return 1
	case len(incompleteTypes) > 0:
		out["status"] = "partial"
		WriteJSON(out)
		return 0
	default:
		out["status"] = "ok"
		WriteJSON(out)
		return 0
	}
}

// replayResult is the aggregate of every staged verdict array replayed by
// finalize. Files lists the base names attempted; Failed lists those whose
// --write-json replay exited non-zero.
type replayResult struct {
	Files            []string `json:"files"`
	FindingsWritten  int      `json:"findings_written"`
	DismissedWritten int      `json:"dismissed_written"`
	Failed           []string `json:"failed_files,omitempty"`
}

// listStagedVerdictFiles returns the absolute paths of replayable verdict
// arrays under the database's `.sgre/.tmp/` directory, sorted by name. A file
// qualifies when it ends in .json, is NOT a settlement report/chunk
// (`-report` / `-chunk-`), and its first non-whitespace byte is `[` — the bare
// array shape --write-json accepts. A missing directory yields an empty list
// (finalize still runs: the DB may already be complete and only missing the
// terminal artifacts).
func listStagedVerdictFiles(dbPath string) []string {
	dir := filepath.Join(filepath.Dir(dbPath), ".tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if strings.Contains(name, "-report") || strings.Contains(name, "-chunk-") {
			continue
		}
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		head := make([]byte, 4096)
		n, _ := f.Read(head)
		_ = f.Close()
		trimmed := bytes.TrimLeftFunc(head[:n], unicode.IsSpace)
		if len(trimmed) == 0 || trimmed[0] != '[' {
			continue
		}
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// runReportSub re-enters the report command with captured stdout so finalize
// can fold each sub-result into its own envelope. The return value is the
// sub-command's parsed JSON envelope (nil when it emitted none) and its exit
// code. Warnings the report command prints to stderr still reach the terminal.
func runReportSub(ctx context.Context, args []string) (map[string]interface{}, int) {
	var buf bytes.Buffer
	prev := cliStdout
	cliStdout = &buf
	code := runReportCmd(ctx, args)
	cliStdout = prev
	var parsed map[string]interface{}
	_ = json.Unmarshal(buf.Bytes(), &parsed)
	return parsed, code
}

// intValue reads an integer field from a captured sub-command envelope without
// panicking on a missing key or a JSON number decoding to float64.
func intValue(m map[string]interface{}, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return 0
	}
}

// nonEmptyFile reports whether path exists and is non-empty, returning its size
// in bytes when it does. It is the result.sarif self-check.
func nonEmptyFile(path string) (bool, int64) {
	info, err := os.Stat(path)
	if err != nil {
		return false, 0
	}
	if info.IsDir() {
		return false, 0
	}
	return info.Size() > 0, info.Size()
}

// countFindingsFiles counts the actionable verdict files under findings/ —
// the `*_confirmed.md` entries ReconcileFindings produces. A missing directory
// counts as zero (an audit that produced no confirmed findings is legitimate,
// not an error).
func countFindingsFiles(findingsDir string) int {
	n := 0
	_ = filepath.WalkDir(findingsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), "_confirmed.md") {
			n++
		}
		return nil
	})
	return n
}
