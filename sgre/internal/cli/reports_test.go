package cli

import (
	"os"
	"path/filepath"
	"testing"
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

	writeReport(t, tmp, "sub-a-chunk-1.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":1,"dismissed":40,"evidence_opens":5}],
	  "needs_context": [{"candidate": 7, "reason": "leak@conditional"}]
	}`)
	writeReport(t, tmp, "sub-a-report.json", `{
	  "format_version": 1, "subagent_id": "sub-a", "scan_id": "sc_test",
	  "processed_types": [{"type":"null-deref","range":"1-100","cwe":"CWE-476","written":2,"dismissed":98,"evidence_opens":12}]
	}`)

	res := listSubagentReports(dbPath, "sc_test")
	byName := map[string]subagentReport{}
	for _, r := range res.Reports {
		byName[filepath.Base(r.File)] = r
	}

	chunk, ok := byName["sub-a-chunk-1.json"]
	if !ok {
		t.Fatalf("chunk file not listed: %+v", res.Reports)
	}
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

	final := byName["sub-a-report.json"]
	if !final.Valid {
		t.Errorf("final report must be valid:true")
	}
}
