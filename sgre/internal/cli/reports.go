package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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
	DispatchedAt string            `json:"dispatched_at,omitempty"`
	StartedAt    string            `json:"started_at,omitempty"`
	Valid        bool              `json:"valid"`
	Error        string            `json:"error,omitempty"`
	Processed    []reportTypeCount `json:"processed_types,omitempty"`
	Failed       []reportFailed    `json:"failed_types,omitempty"`
	NeedsContext []json.RawMessage `json:"needs_context,omitempty"`
	// HeartbeatAgeMS is how long the settlement file has gone without an mtime
	// update; Stalled turns true past settlementHeartbeatStall. A running worker
	// refreshes its chunk file every ~10 candidates, so this is the liveness
	// signal that replaces guessing from an output file's mtime by hand.
	HeartbeatAgeMS int64 `json:"heartbeat_age_ms"`
	Stalled        bool  `json:"stalled"`
	// Progress is the batch's classified/total snapshot: written+dismissed
	// against the assigned candidate range (or the type's candidate_count when
	// the range is "all"). A chunk snapshot shows partial progress; the final
	// report shows it at 100%.
	Progress *reportProgress `json:"progress,omitempty"`
	// mtime is the raw (nanosecond-resolution) file modification time used to
	// pick the newest report for dedup; ModTime above is only its RFC3339
	// rendering for the JSON consumer (second resolution, too coarse to order
	// reports written in the same second).
	mtime time.Time
}

// reportProgress is the machine-readable classified/total heartbeat.
type reportProgress struct {
	Classified int     `json:"classified"`
	Total      int     `json:"total"`
	Percent    float64 `json:"percent"`
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

// stripJSONFence tolerates a settlement file written as a markdown fenced code
// block (```json ... ```) by an older worker build. The current contract is a
// BARE JSON object on disk (fences belong to the chat message only); this shim
// exists so an in-flight fenced report still absorbs instead of stalling its
// claim until the claim TTL.
func stripJSONFence(data []byte) []byte {
	trimmed := []byte(strings.TrimSpace(string(data)))
	if !strings.HasPrefix(string(trimmed), "```") {
		return data
	}
	s := string(trimmed)
	if nl := strings.Index(s, "\n"); nl >= 0 {
		s = s[nl+1:]
	}
	if idx := strings.LastIndex(s, "```"); idx >= 0 {
		s = s[:idx]
	}
	return []byte(strings.TrimSpace(s))
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
			DispatchedAt  string            `json:"dispatched_at"`
			StartedAt     string            `json:"started_at"`
			Processed     []reportTypeCount `json:"processed_types"`
			Failed        []reportFailed    `json:"failed_types"`
			NeedsContext  []json.RawMessage `json:"needs_context"`
		}
		rep := subagentReport{File: path, SubagentID: subagentIDFromFile(name)}
		if info, ierr := entry.Info(); ierr == nil {
			rep.mtime = info.ModTime()
			rep.ModTime = info.ModTime().Format(time.RFC3339)
			rep.HeartbeatAgeMS = time.Since(rep.mtime).Milliseconds()
			if rep.HeartbeatAgeMS < 0 {
				rep.HeartbeatAgeMS = 0
			}
		}
		if err := json.Unmarshal(stripJSONFence(data), &raw); err != nil {
			rep.Error = "unparseable report (partial write or truncated JSON)"
		} else {
			if raw.SubagentID != "" {
				rep.SubagentID = raw.SubagentID
			}
			rep.ScanID = raw.ScanID
			rep.DispatchedAt = raw.DispatchedAt
			rep.StartedAt = raw.StartedAt
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
		// A settled report is done, not stalled; an unfinished snapshot whose
		// mtime stopped advancing past the heartbeat window is the "worker looks
		// dead" signal the orchestrator used to infer from file timestamps.
		if !rep.Valid && rep.HeartbeatAgeMS >= int64(settlementHeartbeatStall/time.Millisecond) {
			rep.Stalled = true
		}
		res.Reports = append(res.Reports, rep)
	}
	// A retry / supplement writes another report for the SAME (subagent, type,
	// range); list one authoritative record per batch instead of N competing
	// snapshots. A VALID report always beats a newer invalid one: a mid-batch
	// chunk is written after a per-type checkpoint but is only a partial
	// snapshot, so letting it win by mtime would hide the completed checkpoint
	// and make the orchestrator re-dispatch an already-settled range. Among
	// reports of the same validity the newest (highest nanosecond mtime) wins.
	sort.SliceStable(res.Reports, func(i, j int) bool {
		if res.Reports[i].Valid != res.Reports[j].Valid {
			return res.Reports[i].Valid
		}
		if !res.Reports[i].mtime.Equal(res.Reports[j].mtime) {
			return res.Reports[i].mtime.After(res.Reports[j].mtime)
		}
		return res.Reports[i].File < res.Reports[j].File
	})
	seen := make(map[string]bool, len(res.Reports))
	deduped := res.Reports[:0]
	for _, rep := range res.Reports {
		keys := settlementReportKeys(rep)
		fresh := false
		for _, k := range keys {
			if !seen[k] {
				fresh = true
			}
		}
		if !fresh {
			continue
		}
		for _, k := range keys {
			seen[k] = true
		}
		deduped = append(deduped, rep)
	}
	res.Reports = deduped
	// Presentation order is newest first; the selection above used validity
	// priority only to decide which snapshot is authoritative.
	sort.SliceStable(res.Reports, func(i, j int) bool {
		if !res.Reports[i].mtime.Equal(res.Reports[j].mtime) {
			return res.Reports[i].mtime.After(res.Reports[j].mtime)
		}
		return res.Reports[i].File < res.Reports[j].File
	})
	res.Count = len(res.Reports)
	return res
}

// settlementReportKeys returns the dedup identity keys for a report: one
// (subagent_id, type, range) tuple per processed type. A report with no
// processed_types (failed-only or partial) dedups by subagent_id alone.
func settlementReportKeys(rep subagentReport) []string {
	if len(rep.Processed) == 0 {
		return []string{rep.SubagentID + "\x00\x00"}
	}
	keys := make([]string, 0, len(rep.Processed))
	for _, pt := range rep.Processed {
		keys = append(keys, rep.SubagentID+"\x00"+pt.Type+"\x00"+normalizeSettlementRange(pt.Range))
	}
	return keys
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

// enrichReportProgress attaches the classified/total heartbeat to every listed
// report. totalsByScan maps a scan id to its per-type candidate_count; a report
// whose `range` is a concrete candidate range ("1-69") derives its total from
// the range itself, so a split batch's progress is measured against its own
// slice instead of the whole type.
func enrichReportProgress(res *reportsResult, totalsByScan map[string]map[string]int) {
	for i := range res.Reports {
		rep := &res.Reports[i]
		totals := totalsByScan[rep.ScanID]
		classified, total := 0, 0
		for _, pt := range rep.Processed {
			classified += pt.Written + pt.Dismissed
			total += rangeCandidateTotal(pt.Range, totals[pt.Type])
		}
		if total <= 0 {
			continue
		}
		pct := float64(classified) / float64(total) * 100
		if pct > 100 {
			pct = 100
		}
		rep.Progress = &reportProgress{Classified: classified, Total: total, Percent: round1(pct)}
	}
}

// rangeCandidateTotal returns the number of candidates a settlement report's
// range covers. A numeric "first-last" range (the form the orchestrator assigns,
// e.g. "1-69") is self-describing; "all" (or an unparseable range) falls back to
// the type's candidate_count.
func rangeCandidateTotal(r string, typeTotal int) int {
	r = normalizeSettlementRange(r)
	if r == "all" || r == "" {
		return typeTotal
	}
	loStr, hiStr, ok := strings.Cut(r, "-")
	if !ok {
		return typeTotal
	}
	lo, lerr := strconv.Atoi(strings.TrimSpace(loStr))
	hi, herr := strconv.Atoi(strings.TrimSpace(hiStr))
	if lerr != nil || herr != nil || lo < 1 || hi < lo {
		return typeTotal
	}
	return hi - lo + 1
}
