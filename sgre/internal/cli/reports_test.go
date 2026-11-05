package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeReport(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestListSubagentReports(t *testing.T) {
	project := t.TempDir()
	dbPath := filepath.Join(project, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")

	writeReport(t, tmp, "sub-a-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","cwe":"CWE-476","written":0,"dismissed":69,"source_reads":1,"evidence_opens":2,"repo_greps":0}],
	  "failed_types": []
	}`)
	writeReport(t, tmp, "sub-b-report.json", `{
	  "format_version": 1, "subagent_id": "sub-b", "scan_id": "sc_test",
	  "processed_types": [{"type":"uninit","cwe":"CWE-457","written":1,"dismissed":5}],
	  "needs_context": [{"candidate": 7, "reason": "leak@conditional"}]
	}`)
	writeReport(t, tmp, "sub-old-report.json", `{
	  "format_version": 1, "subagent_id": "sub-old", "scan_id": "sc_old",
	  "processed_types": [{"type":"integer-overflow","cwe":"CWE-190","written":0,"dismissed":19}]
	}`)
	writeReport(t, tmp, "sub-c-report.json", `{"format_version":1,"subagent_id":"sub-c","scan_id":"sc_test"`)
	writeReport(t, tmp, "noise.json", `{"format_version":1}`)

	res := listSubagentReports(dbPath, "sc_test")
	if res.Count != 3 {
		t.Fatalf("count = %d, want 3 (valid + partial + malformed, old scan excluded): %+v", res.Count, res.Reports)
	}
	byID := map[string]subagentReport{}
	for _, r := range res.Reports {
		byID[r.SubagentID] = r
	}
	if !byID["sub-a"].Valid || byID["sub-a"].Processed[0].Dismissed != 69 {
		t.Errorf("sub-a not parsed correctly: %+v", byID["sub-a"])
	}
	if len(byID["sub-b"].NeedsContext) != 1 {
		t.Errorf("sub-b needs_context lost: %+v", byID["sub-b"])
	}
	if byID["sub-c"].Valid || byID["sub-c"].Error == "" {
		t.Errorf("a partial write must be invalid with an error: %+v", byID["sub-c"])
	}
	if _, ok := byID["sub-old"]; ok {
		t.Errorf("a report from another scan leaked into the filtered result")
	}

	all := listSubagentReports(dbPath, "")
	if all.Count != 4 {
		t.Fatalf("unfiltered count = %d, want 4 (old scan included): %+v", all.Count, all.Reports)
	}
}

func TestListSubagentReportsMissingDir(t *testing.T) {
	project := t.TempDir()
	dbPath := filepath.Join(project, ".sgre", "sgre.db")
	res := listSubagentReports(dbPath, "sc_test")
	if res.Count != 0 || res.Reports == nil {
		t.Fatalf("missing dir must be an empty non-nil result: %+v", res)
	}
}

func TestListSubagentReports_ChunkFiles(t *testing.T) {
	project := t.TempDir()
	dbPath := filepath.Join(project, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")

	// A chunk with no final report is a partial settlement snapshot: it stays
	// visible (valid:false) so the orchestrator sees "still writing".
	writeReport(t, tmp, "sub-a-chunk-1.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":1,"dismissed":40,"evidence_opens":5}],
	  "needs_context": [{"candidate": 7, "reason": "leak@conditional"}]
	}`)

	res := listSubagentReports(dbPath, "sc_test")
	if res.Count != 1 {
		t.Fatalf("count = %d, want 1 (chunk listed): %+v", res.Count, res.Reports)
	}
	chunk := res.Reports[0]
	if chunk.Valid {
		t.Errorf("chunk must be valid:false (it is a partial snapshot, not a completion signal)")
	}
	if chunk.SubagentID != "sub-a" {
		t.Errorf("chunk subagent_id = %q, want sub-a", chunk.SubagentID)
	}
	if len(chunk.Processed) != 1 || chunk.Processed[0].Dismissed != 40 {
		t.Errorf("chunk processed accounting lost: %+v", chunk.Processed)
	}
	if len(chunk.NeedsContext) != 1 {
		t.Errorf("chunk needs_context lost: %+v", chunk.NeedsContext)
	}
}

func TestListSubagentReports_DedupRetries(t *testing.T) {
	project := t.TempDir()
	dbPath := filepath.Join(project, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")

	writeReport(t, tmp, "sub-a-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":2,"dismissed":98,"evidence_opens":12}]
	}`)
	writeReport(t, tmp, "sub-a-report-2.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":3,"dismissed":99,"evidence_opens":13}]
	}`)
	// The retry (-report-2) is newer and must supersede the first write.
	older := filepath.Join(tmp, "sub-a-report.json")
	newer := filepath.Join(tmp, "sub-a-report-2.json")
	if err := os.Chtimes(older, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newer, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	res := listSubagentReports(dbPath, "sc_test")
	if res.Count != 1 {
		t.Fatalf("count = %d, want 1 (retry supersedes the first report): %+v", res.Count, res.Reports)
	}
	if got := filepath.Base(res.Reports[0].File); got != "sub-a-report-2.json" {
		t.Errorf("kept report = %q, want the newest (sub-a-report-2.json)", got)
	}
	if !res.Reports[0].Valid || res.Reports[0].Processed[0].Dismissed != 99 {
		t.Errorf("newest report accounting lost: %+v", res.Reports[0])
	}
}

// TestListSubagentReports_ValidCheckpointBeatsNewerChunk pins the #217 dedup
// rule: a mid-batch chunk is a partial snapshot (valid:false) and may be newer
// than the per-type checkpoint for the same type/range, but it must not
// supersede that completed checkpoint — otherwise the orchestrator re-dispatches
// a range that already finished.
func TestListSubagentReports_ValidCheckpointBeatsNewerChunk(t *testing.T) {
	project := t.TempDir()
	dbPath := filepath.Join(project, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	tmp := filepath.Join(filepath.Dir(dbPath), ".tmp")

	writeReport(t, tmp, "sub-a-null-deref-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":2,"dismissed":98,"evidence_opens":12}]
	}`)
	writeReport(t, tmp, "sub-a-chunk-9.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":1,"dismissed":40,"evidence_opens":5}]
	}`)
	checkpoint := filepath.Join(tmp, "sub-a-null-deref-report.json")
	chunk := filepath.Join(tmp, "sub-a-chunk-9.json")
	if err := os.Chtimes(checkpoint, time.Now().Add(-time.Minute), time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(chunk, time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}

	res := listSubagentReports(dbPath, "sc_test")
	if res.Count != 1 {
		t.Fatalf("count = %d, want 1 (one authoritative record): %+v", res.Count, res.Reports)
	}
	if got := filepath.Base(res.Reports[0].File); got != "sub-a-null-deref-report.json" {
		t.Errorf("kept report = %q, want the valid checkpoint (not the newer chunk)", got)
	}
	if !res.Reports[0].Valid {
		t.Error("the kept checkpoint must stay valid so the range counts as covered")
	}
}
