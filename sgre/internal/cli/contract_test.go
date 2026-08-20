package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestScanCmd_RejectsBadOutputDirBasename(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	cases := []struct{ name, dirname string }{
		{"plain_word", "evil"},
		{"path_traversal", ".."},
		{"no_timestamp", "my-scan-dir"},
	}
	for _, c := range cases {
		badDir := filepath.Join(root, c.dirname)
		stdout, _, exitCode := captureOutput(func() int {
			return runScanCmd(ctx, []string{"--db", dbPath, "--output-dir", badDir, cPath})
		})
		if exitCode != 1 {
			t.Errorf("%s: expected exit 1, got %d", c.name, exitCode)
		}
		if !bytes.Contains([]byte(stdout), []byte("does not match scan_id format")) {
			t.Errorf("%s: stdout should mention format mismatch, got: %s", c.name, stdout)
		}
	}
}

func TestScanCmd_AcceptsWellFormedOutputDir(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	cPath := writeTestCFile(t, root)
	scansRoot := filepath.Join(root, ".codeagent", "secguard-clang", "scans")
	goodDir := filepath.Join(scansRoot, "sc_2026-08-11_140000_aaaaaa")
	os.MkdirAll(goodDir, 0755)
	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	os.MkdirAll(filepath.Dir(dbPath), 0755)

	stdout, _, exitCode := captureOutput(func() int {
		return runScanCmd(ctx, []string{"--db", dbPath, "--output-dir", goodDir, cPath})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit 0 for well-formed output-dir, got %d; stdout=%s", exitCode, stdout)
	}
}

func TestDbCmd_SecurityEventsBlocked(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	cases := []struct{ name, query string }{
		{"direct_table", "SELECT * FROM security_events"},
		{"schema_qualified", "SELECT * FROM main.security_events"},
		{"double_quoted", `SELECT * FROM "security_events"`},
		{"pragma_table_info", "SELECT * FROM pragma_table_info('security_events')"},
		{"mixed_case_table", "select * from Security_Events"},
		{"column_from_events", "SELECT event_type FROM security_events LIMIT 1"},
	}
	for _, c := range cases {
		stdout, _, exitCode := captureOutput(func() int {
			return runDbCmd(ctx, []string{"--db", dbPath, c.query})
		})
		if exitCode != 1 {
			t.Errorf("%s: expected exit 1, got %d", c.name, exitCode)
		}
		if !bytes.Contains([]byte(stdout), []byte("prohibited")) {
			t.Errorf("%s: stdout should say prohibited, got: %s", c.name, stdout)
		}
	}
}

func TestDbCmd_AllowsFindingsTable(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	stdout, _, exitCode := captureOutput(func() int {
		return runDbCmd(ctx, []string{"--db", dbPath, "SELECT COUNT(*) FROM findings"})
	})
	if exitCode != 0 {
		t.Fatalf("findings query should succeed, got exit %d", exitCode)
	}
	if !bytes.Contains([]byte(stdout), []byte("count")) {
		t.Errorf("expected JSON with count field, got: %s", stdout)
	}
}

func TestReportCmd_RejectsUnknownScanID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	_, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_2026-01-01_000000_aaaaaa", VulnType: "null-deref", SeedCount: 1, FinalCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--write",
			"--rule-id", "CWE-476",
			"--severity", "high",
			"--status", "confirmed",
			"--file", "x.c", "--line", "1",
			"--function", "f", "--evidence", "e",
			"--scan-id", "sc_2026-01-01_000000_bbbb",
		})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit 1 for unknown scan_id, got %d", exitCode)
	}
	if !bytes.Contains([]byte(stdout), []byte("unknown scan_id")) {
		t.Errorf("stdout should say unknown scan_id, got: %s", stdout)
	}
}

func TestReportCmd_AcceptsKnownScanID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_aaaaaa"
	_, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--write",
			"--rule-id", "CWE-476",
			"--severity", "high",
			"--status", "confirmed",
			"--file", "x.c", "--line", "1",
			"--function", "f", "--evidence", "e",
			"--scan-id", scanID,
		})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit 0 for known scan_id, got %d", exitCode)
	}
	if !bytes.Contains([]byte(stdout), []byte("ok")) {
		t.Errorf("expected status ok, got: %s", stdout)
	}
}

func TestFinding_ApplyStructuredFromProperties(t *testing.T) {
	f := &db.Finding{
		Properties: `{"variable":"buf","suggestion":"short","summary":"heap overflow","reasoning":"source is user_size, no clamp, reaches strcpy","fix_strategy":"if (user_size < 12) return -1;","exception_check":"no RAII, no safe wrapper"}`,
	}
	f.ApplyStructuredFromProperties()
	if f.Summary != "heap overflow" {
		t.Errorf("Summary = %q, want %q", f.Summary, "heap overflow")
	}
	if f.Reasoning != "source is user_size, no clamp, reaches strcpy" {
		t.Errorf("Reasoning not extracted from properties")
	}
	if f.FixStrategy != "if (user_size < 12) return -1;" {
		t.Errorf("FixStrategy not extracted from properties")
	}
	if f.ExceptionCheck != "no RAII, no safe wrapper" {
		t.Errorf("ExceptionCheck not extracted from properties")
	}

	// Dedicated fields take precedence over the properties JSON.
	g := &db.Finding{
		Summary:    "explicit summary",
		Properties: `{"summary":"from props"}`,
	}
	g.ApplyStructuredFromProperties()
	if g.Summary != "explicit summary" {
		t.Errorf("dedicated Summary should win, got %q", g.Summary)
	}
}

func TestEffectiveStatus(t *testing.T) {
	cases := []struct{ status, review, want string }{
		{"suspected", "confirmed", "confirmed"},
		{"suspected", "dismissed", "dismissed"},
		{"suspected", "suspected-kept", "suspected"},
		{"suspected", "", "suspected"},
		{"confirmed", "", "confirmed"},
		{"dismissed", "", "dismissed"},
		{"open", "confirmed", "confirmed"},
	}
	for _, c := range cases {
		f := &db.Finding{Status: c.status, ReviewStatus: c.review}
		if got := effectiveStatus(f); got != c.want {
			t.Errorf("effectiveStatus(status=%q, review=%q) = %q, want %q", c.status, c.review, got, c.want)
		}
	}
}

func TestReportCmd_ReviewFlow(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	const scanID = "sc_2026-01-01_000000_aaaaaa"

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "unchecked-return", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--write",
			"--rule-id", "CWE-252", "--severity", "high", "--status", "suspected",
			"--file", "x.c", "--line", "1", "--function", "f", "--evidence", "e",
			"--scan-id", scanID,
		})
	})
	if exitCode != 0 {
		t.Fatalf("write failed: %s", stdout)
	}
	var wrote struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(stdout), &wrote); err != nil || wrote.ID == 0 {
		t.Fatalf("expected finding id in write response, got %s", stdout)
	}

	stdout, _, exitCode = captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--review",
			"--id", strconv.FormatInt(wrote.ID, 10),
			"--review-status", "confirmed", "--review-reasoning", "real null-deref",
		})
	})
	if exitCode != 0 {
		t.Fatalf("review failed: %s", stdout)
	}

	d2, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s2 := db.NewStore(d2)
	defer s2.Close()
	f, err := s2.GetFindingByID(ctx, wrote.ID)
	if err != nil {
		t.Fatal(err)
	}
	if f.ReviewStatus != "confirmed" {
		t.Errorf("review_status = %q, want confirmed", f.ReviewStatus)
	}
	if effectiveStatus(f) != "confirmed" {
		t.Errorf("effectiveStatus after review = %q, want confirmed", effectiveStatus(f))
	}
}
