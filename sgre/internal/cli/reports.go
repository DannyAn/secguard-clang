package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// subagentReport is one `<subagent_id>-report.json` settled file written by a
// security-auditor subagent per the O2 contract. The orchestrator uses it as the
// completion signal when the host's synchronous Agent call is force-rejected at
// its 660s ceiling but the subagent keeps running and finishes in the background.
type subagentReport struct {
	SubagentID   string            `json:"subagent_id"`
	ScanID       string            `json:"scan_id"`
	File         string            `json:"file"`
	ModTime      string            `json:"mtime"`
	Valid        bool              `json:"valid"`
	Error        string            `json:"error,omitempty"`
	Processed    []reportTypeCount `json:"processed_types,omitempty"`
	Failed       []reportFailed    `json:"failed_types,omitempty"`
	NeedsContext []json.RawMessage `json:"needs_context,omitempty"`
}

type reportTypeCount struct {
	Type          string `json:"type"`
	Range         string `json:"range,omitempty"`
	CWE           string `json:"cwe"`
	Written       int    `json:"written"`
	Dismissed     int    `json:"dismissed"`
	SourceReads   int    `json:"source_reads"`
	EvidenceOpens int    `json:"evidence_opens"`
	RepoGreps     int    `json:"repo_greps"`
}

type reportFailed struct {
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type reportsResult struct {
	ScanID  string           `json:"scan_id,omitempty"`
	Count   int              `json:"count"`
	Reports []subagentReport `json:"reports"`
}

// listSubagentReports reads the `.sgre/.tmp/*-report*.json` settlement files.
// The directory is derived from the DB path (`<project>/.codeagent/
// secguard-clang/.sgre/sgre.db` -> `<...>/.sgre/.tmp`). A missing directory is
// an empty result, not an error: the orchestrator must be able to run this
// before the first subagent has finished.
func listSubagentReports(dbPath, scanID string) reportsResult {
	res := reportsResult{ScanID: scanID, Reports: []subagentReport{}}
	dir := filepath.Join(filepath.Dir(dbPath), ".tmp")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return res
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".json") || !(strings.Contains(name, "-report") || strings.Contains(name, "-chunk-")) {
			continue
		}
		isChunk := strings.Contains(name, "-chunk-")
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var raw struct {
			FormatVersion int               `json:"format_version"`
			SubagentID    string            `json:"subagent_id"`
			ScanID        string            `json:"scan_id"`
			Processed     []reportTypeCount `json:"processed_types"`
			Failed        []reportFailed    `json:"failed_types"`
			NeedsContext  []json.RawMessage `json:"needs_context"`
		}
		rep := subagentReport{File: path, SubagentID: subagentIDFromFile(name)}
		if info, ierr := entry.Info(); ierr == nil {
			rep.ModTime = info.ModTime().Format(time.RFC3339)
		}
		if err := json.Unmarshal(data, &raw); err != nil {
			rep.Error = "unparseable report (partial write or truncated JSON)"
		} else {
			if raw.SubagentID != "" {
				rep.SubagentID = raw.SubagentID
			}
			rep.ScanID = raw.ScanID
			rep.Processed = raw.Processed
			rep.Failed = raw.Failed
			rep.NeedsContext = raw.NeedsContext
			rep.Valid = raw.FormatVersion == 1 && (len(raw.Processed) > 0 || len(raw.Failed) > 0)
			if !rep.Valid {
				rep.Error = "report is valid JSON but incomplete (no processed_types/failed_types yet)"
			}
		}
		// A chunk file is a partial settlement snapshot: it carries the
		// dismissed/needs_context accounting so far but is NOT a completion
		// signal. Downgrade it to valid:false so the orchestrator reads its
		// partial accounting without treating the range as fully covered.
		if isChunk && rep.Valid {
			rep.Valid = false
			rep.Error = "chunk (partial settlement snapshot, not a completion signal)"
		}
		// A partial/unparseable write often lacks scan_id; keep it visible
		// (valid:false) so the orchestrator can see "still writing" instead of
		// mistaking it for "no report". A parseable report for a different scan
		// is excluded.
		if scanID != "" && rep.ScanID != "" && rep.ScanID != scanID {
			continue
		}
		res.Reports = append(res.Reports, rep)
	}
	sort.Slice(res.Reports, func(i, j int) bool {
		if res.Reports[i].ModTime != res.Reports[j].ModTime {
			return res.Reports[i].ModTime > res.Reports[j].ModTime
		}
		return res.Reports[i].File < res.Reports[j].File
	})
	res.Count = len(res.Reports)
	return res
}

func subagentIDFromFile(name string) string {
	base := strings.TrimSuffix(name, ".json")
	for _, sep := range []string{"-report", "-chunk-"} {
		if i := strings.Index(base, sep); i > 0 {
			return base[:i]
		}
	}
	return base
}
