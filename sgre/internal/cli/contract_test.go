package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
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

	// `secguard db` 是只读查询，不建 schema：先模拟 scan 已落库（写连接建表），
	// 再验证只读查询能读到 findings 表。
	if d, err := db.Open(ctx, dbPath); err != nil {
		t.Fatalf("open (init schema): %v", err)
	} else if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

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

func TestDbCmd_WriteRejected(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	if d, err := db.Open(ctx, dbPath); err != nil {
		t.Fatalf("open (init schema): %v", err)
	} else if err := d.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 数据修改 CTE 以 WITH 开头，能绕过 SELECT/WITH 前缀检查；真正的只读边界
	// 必须由 SQLite 引擎（PRAGMA query_only=1）兜住。
	cases := []struct{ name, query string }{
		{"delete", "DELETE FROM findings"},
		{"data_modifying_cte", "WITH d AS (DELETE FROM findings RETURNING id) SELECT count(*) FROM d"},
	}
	for _, c := range cases {
		stdout, _, exitCode := captureOutput(func() int {
			return runDbCmd(ctx, []string{"--db", dbPath, c.query})
		})
		if exitCode == 0 {
			t.Errorf("%s: expected write to be rejected, got exit 0; stdout=%s", c.name, stdout)
		}
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

// --write-json must enforce the SAME scan_id validation as the single --write,
// so a batch can never be silently attached to a typo'd/nonexistent scan.
func TestReportCmd_WriteJsonRejectsUnknownScanID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: "sc_2026-01-01_000000_aaaaaa", VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	writeFile := filepath.Join(root, "findings.json")
	payload, _ := json.Marshal([]map[string]interface{}{
		{"rule_id": "CWE-476", "severity": "high", "confidence": 90, "status": "confirmed", "file": "x.c", "line": 1, "function": "f"},
	})
	if err := os.WriteFile(writeFile, payload, 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--write-json", writeFile,
			"--scan-id", "sc_2026-01-01_000000_bbbb",
		})
	})
	if exitCode != 1 {
		t.Fatalf("expected exit 1 for unknown scan_id, got %d; stdout=%s", exitCode, stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte("unknown scan_id")) {
		t.Errorf("stdout should say unknown scan_id, got: %s", stdout)
	}
}

func TestReportCmd_WriteJsonAcceptsKnownScanID(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_aaaaaa"
	if _, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	writeFile := filepath.Join(root, "findings.json")
	payload, _ := json.Marshal([]map[string]interface{}{
		{"rule_id": "CWE-476", "severity": "high", "confidence": 90, "status": "confirmed", "file": "x.c", "line": 1, "function": "f"},
	})
	if err := os.WriteFile(writeFile, payload, 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--write-json", writeFile,
			"--scan-id", scanID,
		})
	})
	if exitCode != 0 {
		t.Fatalf("expected exit 0 for known scan_id, got %d; stdout=%s", exitCode, stdout)
	}
	if !bytes.Contains([]byte(stdout), []byte("findings_written")) {
		t.Errorf("expected findings_written in response, got: %s", stdout)
	}
}

func TestReportCmd_WriteJsonFieldValidation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	const scanID = "sc_2026-01-01_000000_aaaaaa"
	if _, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	run := func(payload string) (int, string) {
		writeFile := filepath.Join(root, "findings.json")
		if err := os.WriteFile(writeFile, []byte(payload), 0644); err != nil {
			t.Fatal(err)
		}
		stdout, _, code := captureOutput(func() int {
			return runReportCmd(ctx, []string{"--db", dbPath, "--write-json", writeFile, "--scan-id", scanID})
		})
		return code, stdout
	}

	// confidence 为数字字符串应被接受（worker 常见笔误）。
	if code, stdout := run(`[{"rule_id":"CWE-476","severity":"high","confidence":"55","status":"confirmed","file":"x.c","line":1,"function":"f"}]`); code != 0 {
		t.Errorf("string confidence should be accepted, got exit %d; stdout=%s", code, stdout)
	}

	// status 非法值（pipeline 中间态 open）应整批拒绝，而非 partial 跳过。
	if code, stdout := run(`[{"rule_id":"CWE-476","severity":"high","confidence":55,"status":"open","file":"x.c","line":1,"function":"f"}]`); code == 0 {
		t.Errorf("status=open should be rejected, got exit 0; stdout=%s", stdout)
	} else if !bytes.Contains([]byte(stdout), []byte("invalid status")) {
		t.Errorf("expected 'invalid status' error, got: %s", stdout)
	}

	// status=false-positive 应归一化为 dismissed（技能文件用 false-positive 表示误报）。
	if code, stdout := run(`[{"rule_id":"CWE-476","severity":"high","confidence":55,"status":"false-positive","file":"x.c","line":1,"function":"f"}]`); code != 0 {
		t.Errorf("status=false-positive should be accepted (normalized to dismissed), got exit %d; stdout=%s", code, stdout)
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
		{"auto-confirmed", "", "confirmed"},
		{"dismissed", "", "dismissed"},
		{"open", "confirmed", "confirmed"},
	}
	for _, c := range cases {
		f := &db.Finding{Status: c.status, ReviewStatus: c.review}
		if got := f.EffectiveStatus(); got != c.want {
			t.Errorf("effectiveStatus(status=%q, review=%q) = %q, want %q", c.status, c.review, got, c.want)
		}
	}
}

// FinalStatus is the export gate: a plain suspected finding (never A5-reviewed)
// must NOT reach result.sarif/result.xlsx/report.md/findings/ — only
// suspected-kept (the A5 "still suspicious" decision) survives, as "suspected".
func TestFinalStatus(t *testing.T) {
	cases := []struct{ status, review, want string }{
		{"confirmed", "", "confirmed"},
		{"auto-confirmed", "", "confirmed"},
		{"suspected", "confirmed", "confirmed"},
		{"suspected", "dismissed", "dismissed"},
		{"suspected", "suspected-kept", "suspected"},
		{"suspected", "", ""},
		{"dismissed", "", "dismissed"},
		{"open", "", ""},
	}
	for _, c := range cases {
		f := &db.Finding{Status: c.status, ReviewStatus: c.review}
		if got := f.FinalStatus(); got != c.want {
			t.Errorf("finalStatus(status=%q, review=%q) = %q, want %q", c.status, c.review, got, c.want)
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
	if f.EffectiveStatus() != "confirmed" {
		t.Errorf("effectiveStatus after review = %q, want confirmed", f.EffectiveStatus())
	}
}

// --review-json must record a whole A5 batch in one call and one transaction,
// the fast path that replaces the per-id `--review` loop.
func TestReportCmd_ReviewJsonFlow(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	dbPath := filepath.Join(root, "test.db")
	const scanID = "sc_2026-01-01_000000_aaaaaa"

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err = s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "unchecked-return", SeedCount: 2, FinalCount: 2}); err != nil {
		t.Fatal(err)
	}
	ids := make([]int64, 0, 2)
	for i, line := range []int{1, 2} {
		id, ierr := s.UpsertFinding(ctx, &db.Finding{
			RuleID: "CWE-252", Severity: "high", Confidence: 0.5,
			Status: "suspected", FilePath: "x.c", LineNumber: line,
			FunctionName: "f", ScanID: scanID,
		})
		if ierr != nil {
			t.Fatal(ierr)
		}
		ids = append(ids, id)
		_ = i
	}
	s.Close()

	reviewsFile := filepath.Join(root, "reviews.json")
	payload, _ := json.Marshal([]map[string]interface{}{
		{"id": ids[0], "review_status": "confirmed", "review_reasoning": "real"},
		{"id": ids[1], "review_status": "suspected-kept", "review_reasoning": "unbounded"},
	})
	if err := os.WriteFile(reviewsFile, payload, 0644); err != nil {
		t.Fatal(err)
	}

	stdout, _, exitCode := captureOutput(func() int {
		return runReportCmd(ctx, []string{
			"--db", dbPath, "--review-json", reviewsFile,
		})
	})
	if exitCode != 0 {
		t.Fatalf("review-json failed: %s", stdout)
	}
	var res struct {
		Reviewed []struct {
			ID           int64  `json:"id"`
			ReviewStatus string `json:"review_status"`
		} `json:"reviewed"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("unmarshal review-json response: %v", err)
	}
	if len(res.Reviewed) != 2 {
		t.Fatalf("reviewed count = %d, want 2", len(res.Reviewed))
	}

	d2, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s2 := db.NewStore(d2)
	defer s2.Close()
	want := map[int64]string{ids[0]: "confirmed", ids[1]: "suspected-kept"}
	for id, w := range want {
		f, err := s2.GetFindingByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if f.ReviewStatus != w {
			t.Errorf("finding %d review_status = %q, want %q", id, f.ReviewStatus, w)
		}
	}
}

func TestSplitBySuspicion(t *testing.T) {
	candidates := []planner.EvidenceItem{
		{SuspicionLevel: "confirmed", Target: planner.TargetInfo{File: "a.c", Line: 1}},
		{SuspicionLevel: "suspected", Target: planner.TargetInfo{File: "b.c", Line: 2}},
		{SuspicionLevel: "possible", Target: planner.TargetInfo{File: "c.c", Line: 3}},
		{SuspicionLevel: "confirmed", Target: planner.TargetInfo{File: "d.c", Line: 4}},
	}
	confirmed, needsReview := splitBySuspicion(candidates)
	if len(confirmed) != 2 || len(needsReview) != 2 {
		t.Fatalf("split = %d confirmed / %d review, want 2/2", len(confirmed), len(needsReview))
	}
	for _, c := range confirmed {
		if c.SuspicionLevel != "confirmed" {
			t.Errorf("confirmed bucket leaked %q", c.SuspicionLevel)
		}
	}
}

func TestAutoConfirmFindings_WritesMachineVerdict(t *testing.T) {
	ctx := context.Background()
	d, err := db.OpenInMemory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	defer s.Close()
	const scanID = "sc_2026-01-01_000000_aaaaaa"
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{ScanID: scanID, VulnType: "null-deref", SeedCount: 1, FinalCount: 1}); err != nil {
		t.Fatal(err)
	}

	confirmed := []planner.EvidenceItem{{
		SuspicionLevel: "confirmed",
		Target:         planner.TargetInfo{File: "src/a.c", Line: 42, Function: "f", Variable: "p"},
		Evidence:       []planner.EvidenceFragment{{Role: "condition", Detail: "p assigned NULL and dereferenced"}},
	}}
	n, unwritten, err := autoConfirmFindings(ctx, s, scanID, "null-deref", confirmed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("autoConfirmFindings wrote %d, want 1", n)
	}
	if len(unwritten) != 0 {
		t.Fatalf("autoConfirmFindings unwritten = %d, want 0", len(unwritten))
	}

	findings, err := s.ListFindingsByScanID(ctx, scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f := findings[0]
	if f.Status != db.StatusAutoConfirmed {
		t.Errorf("status = %q, want %q", f.Status, db.StatusAutoConfirmed)
	}
	if f.FinalStatus() != "confirmed" {
		t.Errorf("FinalStatus = %q, want confirmed", f.FinalStatus())
	}
	if f.RuleID != "CWE-476" {
		t.Errorf("rule_id = %q, want CWE-476", f.RuleID)
	}
	if !strings.Contains(f.Reasoning, "auto-confirmed") {
		t.Errorf("reasoning should mark the machine verdict: %q", f.Reasoning)
	}
}
