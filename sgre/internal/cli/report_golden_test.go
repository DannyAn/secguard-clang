//go:build !nosqlite

package cli

// U7b-1: golden feature tests for runReportCmd.
//
// These tests pin the CURRENT observable behaviour of every report mode
// (--list, --list-auto-confirmed, --write, --write-json, --audit, --review,
// --review-json, --stats) before that 1,472-line command is split up. They are
// deliberately test-only: no production file is touched, so the goldens are a
// behaviour baseline, not a refactor.
//
// Each case seeds one deterministic, hermetic SQLite fixture (fixed scan id,
// fixed finding ids, fixed created_at) and asserts against checked-in
// golden files under testdata/report_golden/. Volatile facts — the t.TempDir()
// root, epoch timestamps and content hashes — are normalised before comparing.
//
// Regenerate the goldens (then inspect `git diff` before committing):
//
//	cd sgre && go test ./internal/cli -run TestReportGolden -update-report-golden
//
// The checked-in golden files are the feature contract: a change to a CSV/JSON
// field, a SARIF key, a markdown row, or the DB write order shows up as a diff.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

var updateReportGolden = flag.Bool("update-report-golden", false,
	"rewrite the runReportCmd golden files under internal/cli/testdata/report_golden")

var (
	goldenSHA256Re = regexp.MustCompile(`\b[0-9a-f]{64}\b`)
	goldenEpochRe  = regexp.MustCompile(`"created_at": \d+`)
	goldenTimeRe   = regexp.MustCompile(`\| Scan time \| [^|]+ \|`)
	goldenToolRe   = regexp.MustCompile(`secguard-clang v[0-9][0-9A-Za-z.+-]*`)
	goldenSarifVer = regexp.MustCompile(`("name": "secguard-clang",\s*"version": ")[^"]+(")`)
)

const (
	reportGoldenScanID = "sc_2026-11-22_010000_abcdef"
	// reportGoldenCreatedAt is a fixed epoch so a fixture row's created_at can
	// never leak wall-clock time into a golden.
	reportGoldenCreatedAt = int64(1700000000)
	reportGoldenDir       = "testdata/report_golden"
)

// reportGoldenFixture is one isolated project root + SQLite database + scan
// directory. Every mode test builds its own fixture so finding ids and the
// findings/ numbering are deterministic.
type reportGoldenFixture struct {
	root    string
	dbPath  string
	scanDir string
	srcA    string
	srcB    string

	autoConfirmedID int64 // finding 2: CWE-787 buffer-overflow, a.c:9, unreviewed
	reviewedOutID   int64 // finding 3: CWE-401 memory-leak, a.c:14, review-dismissed
}

func newReportGoldenFixture(t *testing.T) *reportGoldenFixture {
	t.Helper()
	ctx := context.Background()

	root := t.TempDir()
	srcDir := filepath.Join(root, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	f := &reportGoldenFixture{root: root}
	f.srcA = filepath.Join(srcDir, "a.c")
	f.srcB = filepath.Join(srcDir, "b.c")
	// Line numbers are load-bearing: findings live at a.c:4/9/14/19 and b.c:4,
	// and the snippet/context/SARIF/Code Context assertions all read them.
	if err := os.WriteFile(f.srcA, []byte(`#include <stdlib.h>

int read_value(const char *p) {
    return *p;
}

int use_buffer(int n) {
    char buf[4];
    buf[n] = 'x';
    return buf[0];
}

int leak_fd(void) {
    int fd = 3;
    return fd;
}

int unchecked(int *p) {
    return p[0];
}
`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.srcB, []byte(`#include <string.h>

void copy_all(char *dst, const char *src) {
    strcpy(dst, src);
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	dbPath := filepath.Join(root, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	f.dbPath = dbPath
	f.scanDir = filepath.Join(root, ".codeagent", "secguard-clang", "scans", reportGoldenScanID)
	if err := os.MkdirAll(f.scanDir, 0755); err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	for _, file := range []struct {
		path string
		loc  int
	}{
		{f.srcA, 20},
		{f.srcB, 5},
	} {
		if _, err := s.InsertFile(ctx, &db.File{
			Path: file.path, Language: "c", Checksum: "fixture-" + filepath.Base(file.path),
			LOC: file.loc, CreatedAt: reportGoldenCreatedAt,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// The alpha order of vuln_type is the order ListScanStats returns, so the
	// --stats rows and the audit's per-skill table are deterministic.
	stats := []*db.ScanStat{
		{
			ScanID: reportGoldenScanID, VulnType: "buffer-overflow",
			SeedCount: 10, FinalCount: 1, AIStageStatus: "done",
		},
		{
			ScanID: reportGoldenScanID, VulnType: "out-of-bounds",
			SeedCount: 2, FinalCount: 1, AIStageStatus: "done",
		},
		{
			ScanID: reportGoldenScanID, VulnType: "memory-leak",
			SeedCount: 5, FinalCount: 1, AIStageStatus: "done",
		},
		{
			ScanID: reportGoldenScanID, VulnType: "null-deref",
			SeedCount: 4, FinalCount: 1, AIStageStatus: "done",
			FilterChain: `[{"name":"nullable-source","input_count":4,"output_count":1},{"name":"dedupe","input_count":1,"output_count":1}]`,
		},
		{
			ScanID: reportGoldenScanID, VulnType: "unchecked-return",
			SeedCount: 3, FinalCount: 1, AIStageStatus: "done",
		},
	}
	for _, st := range stats {
		st.CreatedAt = reportGoldenCreatedAt
		if _, err := s.InsertScanStat(ctx, st); err != nil {
			t.Fatal(err)
		}
		// InsertScanStat always writes ai_stage_status='pending'; the audit's
		// final-artifact gate requires 'done' for every type with candidates.
		if err := s.MarkAIStageDone(ctx, reportGoldenScanID, st.VulnType); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertScanRun(ctx, &db.ScanRun{
		ScanID: reportGoldenScanID, DurationMs: 1234, FilesIndexed: 2, FunctionsIndexed: 5,
		SeedCount: 24, FinalCount: 6, CreatedAt: reportGoldenCreatedAt,
		CompletionState: "complete", ScanMode: "full",
	}); err != nil {
		t.Fatal(err)
	}

	findings := []*db.Finding{
		{
			RuleID: "CWE-476", VulnType: "null-deref", Severity: "high", Confidence: 0.9,
			Status: "confirmed", FilePath: f.srcA, LineNumber: 4,
			FunctionName: "read_value", Variable: "p",
			Summary:        "p is dereferenced without a NULL check",
			Reasoning:      "get_ptr may return NULL on the negative path",
			FixStrategy:    "Return early when p is NULL.",
			ExceptionCheck: "none", ScanID: reportGoldenScanID,
			Fingerprint: "fixture-null-deref", CreatedAt: reportGoldenCreatedAt,
		},
		{
			RuleID: "CWE-787", VulnType: "buffer-overflow", Severity: "high", Confidence: 1.0,
			Status: db.StatusAutoConfirmed, FilePath: f.srcA, LineNumber: 9,
			FunctionName: "use_buffer", Variable: "buf",
			Summary:   "index n is not bounds-checked against buf[4]",
			Reasoning: "detector proved the write reaches buf with an unguarded index",
			Properties: `{"auto_confirm_hint_tokens":["heap_alloc","unguarded_index"],` +
				`"auto_confirm_verdict_facts":[{"Token":"sink","Detail":"write to buf with unchecked n"}]}`,
			ScanID: reportGoldenScanID, Fingerprint: "fixture-buffer-overflow",
			CreatedAt: reportGoldenCreatedAt,
		},
		{
			RuleID: "CWE-401", VulnType: "memory-leak", Severity: "medium", Confidence: 1.0,
			Status: db.StatusAutoConfirmed, ReviewStatus: "dismissed",
			ReviewReasoning: "fd is returned to the caller, ownership transfers",
			FilePath:        f.srcA, LineNumber: 14,
			FunctionName: "leak_fd", Variable: "fd",
			Summary: "fd is never closed", ScanID: reportGoldenScanID,
			Fingerprint: "fixture-memory-leak", CreatedAt: reportGoldenCreatedAt,
		},
		{
			RuleID: "CWE-125", VulnType: "out-of-bounds", Severity: "low", Confidence: 0.7,
			Status: "confirmed", FilePath: f.srcB, LineNumber: 4,
			FunctionName: "copy_all", Variable: "dst",
			Summary:     "strcpy may write past dst",
			Reasoning:   "no destination size is available at the call site",
			FixStrategy: "Use strlcpy with the destination capacity.",
			ScanID:      reportGoldenScanID, Fingerprint: "fixture-out-of-bounds",
			CreatedAt: reportGoldenCreatedAt,
		},
		{
			RuleID: "CWE-252", VulnType: "unchecked-return", Severity: "medium", Confidence: 0.6,
			Status: "confirmed", FilePath: f.srcA, LineNumber: 19,
			FunctionName: "unchecked", Variable: "p",
			Summary:     "p is indexed without validating the callee return",
			Reasoning:   "the caller never checks the returned pointer",
			FixStrategy: "Check the allocation result before indexing.",
			ScanID:      reportGoldenScanID, Fingerprint: "fixture-unchecked-return",
			CreatedAt: reportGoldenCreatedAt,
		},
	}
	for _, finding := range findings {
		id, err := s.UpsertFinding(ctx, finding)
		if err != nil {
			t.Fatal(err)
		}
		switch finding.RuleID {
		case "CWE-787":
			f.autoConfirmedID = id
		case "CWE-401":
			f.reviewedOutID = id
		}
	}
	if _, err := s.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
		ScanID: reportGoldenScanID, VulnType: "buffer-overflow", RuleID: "CWE-787",
		FilePath: f.srcA, LineNumber: 10, FunctionName: "use_buffer", Variable: "buf",
		Verdict: "dismissed", Reason: "the caller validates n before the call",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertCandidateVerdict(ctx, &db.CandidateVerdict{
		ScanID: reportGoldenScanID, VulnType: "memory-leak", RuleID: "CWE-401",
		FilePath: f.srcA, LineNumber: 15, FunctionName: "leak_fd", Variable: "fd",
		Verdict: "dismissed", Reason: "fd is returned to the caller, ownership transfers",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

// run invokes runReportCmd against the fixture DB with stdout/stderr captured.
func (f *reportGoldenFixture) run(t *testing.T, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	argv := append([]string{"--db", f.dbPath}, args...)
	stdout, stderr, exitCode = captureOutput(func() int {
		return runReportCmd(context.Background(), argv)
	})
	return stdout, stderr, exitCode
}

// normalizeGolden strips the facts that legitimately differ run to run: the
// random t.TempDir() root, epoch timestamps (and their local-time rendering),
// content-addressed SHA-256 hashes (a fingerprint hashes the absolute path, so
// it can never be a stable literal in a golden), and the release version (a
// version bump must not force every golden to be regenerated). Everything else
// is compared byte for byte.
func (f *reportGoldenFixture) normalizeGolden(data []byte) []byte {
	s := string(data)
	rootSlash := filepath.ToSlash(f.root)
	// Replace the slash form first: an absolute path embedded in a markdown
	// code span or a SARIF file:// URI is slash-separated even on Windows.
	s = strings.ReplaceAll(s, rootSlash, "<ROOT>")
	s = strings.ReplaceAll(s, f.root, "<ROOT>")
	s = goldenSHA256Re.ReplaceAllString(s, "<SHA256>")
	s = goldenEpochRe.ReplaceAllString(s, `"created_at": <EPOCH>`)
	// The scan's local-time rendering depends on the test host's TZ; the
	// epoch itself is the fixture's fixed CreatedAt.
	s = goldenTimeRe.ReplaceAllString(s, "| Scan time | <TIMESTAMP> |")
	s = goldenToolRe.ReplaceAllString(s, "secguard-clang v<VERSION>")
	s = goldenSarifVer.ReplaceAllString(s, "${1}<VERSION>${2}")
	// The markdown renderer puts a trailing space after an empty gutter line and
	// some docs end with a blank line; invisible whitespace in a checked-in
	// golden is diff noise (git diff --check) and not part of the contract.
	// This only ever strips spaces/tabs/newlines — no printable byte changes.
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	s = strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\n"
	return []byte(s)
}

func (f *reportGoldenFixture) golden(t *testing.T, rel string, got []byte) {
	t.Helper()
	got = f.normalizeGolden(got)
	path := filepath.Join(reportGoldenDir, rel)
	if *updateReportGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Fatalf("missing golden %s; regenerate with:\n  cd sgre && go test ./internal/cli -run TestReportGolden -update-report-golden", path)
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n%s", path, goldenFirstDiff(got, want))
	}
}

func goldenFirstDiff(got, want []byte) string {
	gotLines := strings.Split(string(got), "\n")
	wantLines := strings.Split(string(want), "\n")
	for i := 0; i < len(gotLines) || i < len(wantLines); i++ {
		var g, w string
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if g == w {
			continue
		}
		return fmt.Sprintf("first difference at line %d:\n  got:  %s\n  want: %s",
			i+1, goldenClip(g), goldenClip(w))
	}
	return "outputs differ only in trailing bytes"
}

func goldenClip(line string) string {
	const max = 240
	if len(line) <= max {
		return line
	}
	return line[:max] + "…"
}

// goldenTree pins every text artifact under dir. On update it first deletes the
// golden subtree so a removed artifact cannot leave a stale file behind.
func (f *reportGoldenFixture) goldenTree(t *testing.T, dir, relPrefix string) {
	t.Helper()
	if *updateReportGolden {
		if err := os.RemoveAll(filepath.Join(reportGoldenDir, relPrefix)); err != nil {
			t.Fatal(err)
		}
	}
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		// result.xlsx is an OOXML zip whose internal timestamps are not part of
		// the report contract; its presence/row count is asserted separately.
		if strings.HasSuffix(path, ".xlsx") {
			continue
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			t.Fatal(err)
		}
		// *.sarif is gitignored in this repository (it is scan output). Keep the
		// golden under a tracked .sarif.txt suffix so the machine-readable
		// report is still part of the checked-in contract.
		relSlash := filepath.ToSlash(rel)
		if strings.HasSuffix(relSlash, ".sarif") {
			relSlash += ".txt"
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		f.golden(t, filepath.Join(relPrefix, relSlash), data)
	}
}

// dbState renders the rows the write paths are responsible for, ordered by
// primary key. created_at/fingerprint are omitted (a batch --write mints them
// from the wall clock and the absolute path); the id order and the updated
// summary/review columns are what pin write order + idempotent update.
func (f *reportGoldenFixture) dbState(t *testing.T) []byte {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	s := db.NewStore(d)
	findings, err := s.ListFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	verdicts, err := s.ListCandidateVerdicts(ctx, reportGoldenScanID)
	if err != nil {
		t.Fatal(err)
	}

	var b strings.Builder
	b.WriteString("findings:\n")
	for _, fd := range findings {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			fd.ID, fd.RuleID, fd.VulnType, fd.Status, fd.ReviewStatus,
			filepath.ToSlash(fd.FilePath), fd.LineNumber, fd.FunctionName, fd.Variable,
			fd.Summary, fd.Reasoning)
	}
	b.WriteString("candidate_verdicts:\n")
	for _, v := range verdicts {
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n",
			v.ID, v.VulnType, v.RuleID, filepath.ToSlash(v.FilePath),
			v.LineNumber, v.FunctionName, v.Variable, v.Verdict, v.Reason)
	}
	return []byte(b.String())
}

// addPendingType appends an unfinished, never-classified type so the
// --allow-partial audit path can be pinned (the complete-audit fixture has no
// unfinished type and no unclassified candidate).
func (f *reportGoldenFixture) addPendingType(t *testing.T, vulnType string, seed, final int) {
	t.Helper()
	ctx := context.Background()
	d, err := db.Open(ctx, f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s := db.NewStore(d)
	if _, err := s.InsertScanStat(ctx, &db.ScanStat{
		ScanID: reportGoldenScanID, VulnType: vulnType,
		SeedCount: seed, FinalCount: final, CreatedAt: reportGoldenCreatedAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func requireExit(t *testing.T, stdout, stderr string, got, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("exit code = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, want, stdout, stderr)
	}
}

func TestReportGolden_List(t *testing.T) {
	f := newReportGoldenFixture(t)

	stdout, stderr, code := f.run(t, "--list", "--scan-id", reportGoldenScanID)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "list/stdout.json", []byte(stdout))

	// The --status filter matches the POST-review effective verdict: the
	// machine verdict on finding 3 is still stored as auto-confirmed, but the
	// dismissed review must be what the filter (and the row) reports.
	stdout, stderr, code = f.run(t, "--list", "--scan-id", reportGoldenScanID, "--status", "dismissed")
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "list/stdout_status_dismissed.json", []byte(stdout))

	// An unknown scan is an empty, stable envelope (not every scan's rows).
	stdout, stderr, code = f.run(t, "--list", "--scan-id", "sc_DOES_NOT_EXIST")
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "list/stdout_unknown_scan.json", []byte(stdout))
}

func TestReportGolden_ListAutoConfirmed(t *testing.T) {
	f := newReportGoldenFixture(t)

	stdout, stderr, code := f.run(t, "--list-auto-confirmed", "--scan-id", reportGoldenScanID)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "list_auto_confirmed/stdout.json", []byte(stdout))

	// The type filter scopes the re-review to one type's CWE set.
	stdout, stderr, code = f.run(t, "--list-auto-confirmed", "--scan-id", reportGoldenScanID, "--type", "buffer-overflow")
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "list_auto_confirmed/stdout_type_buffer_overflow.json", []byte(stdout))
}

func TestReportGolden_Write(t *testing.T) {
	f := newReportGoldenFixture(t)

	writeArgs := []string{
		"--scan-id", reportGoldenScanID,
		"--output-dir", f.scanDir,
		"--rule-id", "CWE-476", "--vuln-type", "null-deref",
		"--severity", "HIGH", "--confidence", "90", "--status", "confirmed",
		"--file", "src/a.c", "--line", "19", "--function", "unchecked", "--variable", "q",
		"--summary", "p is indexed without a bounds check",
		"--reasoning", "the index is not validated before the read",
		"--fix-strategy", "Validate the index against the allocation size.",
		"--exception-check", "no exception path covers the read",
	}

	stdout, stderr, code := f.run(t, append([]string{"--write"}, writeArgs...)...)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "write/stdout.json", []byte(stdout))

	// A retry at the same location updates in place: duplicate=true, same id,
	// and the changed summary lands on the single row (idempotent write).
	retryArgs := append([]string{}, writeArgs...)
	for i, a := range retryArgs {
		if a == "p is indexed without a bounds check" {
			retryArgs[i] = "p is indexed without a bounds check (retry)"
		}
	}
	stdout, stderr, code = f.run(t, append([]string{"--write"}, retryArgs...)...)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "write/stdout_duplicate.json", []byte(stdout))
	f.golden(t, "write/stderr_duplicate.txt", []byte(stderr))

	f.golden(t, "write/db_after_retry.txt", f.dbState(t))
	f.goldenTree(t, f.scanDir, "write/artifacts")
}

func TestReportGolden_WriteJSON(t *testing.T) {
	f := newReportGoldenFixture(t)

	payload := `[
  {"rule_id":"CWE-476","vuln_type":"null-deref","severity":"high","confidence":0.92,
   "status":"confirmed","file":"src/a.c","line":19,"function":"unchecked","variable":"q",
   "summary":"p is indexed without a bounds check","reasoning":"the index is not validated before the read",
   "fix_strategy":"Validate the index against the allocation size.","exception_check":"no exception path covers the read"},
  {"rule_id":"CWE-787","vuln_type":"buffer-overflow","severity":"critical","confidence":"95",
   "status":"confirmed","file":"src/b.c","line":3,"function":"copy_all","variable":"dst",
   "summary":"strcpy copies an unbounded source into dst","reasoning":"no destination capacity is checked",
   "fix_strategy":"Use strlcpy with sizeof(dst)."},
  {"rule_id":"CWE-401","vuln_type":"memory-leak","severity":"medium","confidence":0.5,
   "status":"dismissed","file":"src/b.c","line":4,"function":"copy_all","variable":"src",
   "reasoning":"src is borrowed, not owned"}
]`
	batchPath := filepath.Join(f.root, "batch.json")
	if err := os.WriteFile(batchPath, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--write-json", batchPath,
		"--scan-id", reportGoldenScanID,
		"--output-dir", f.scanDir,
	}

	stdout, stderr, code := f.run(t, args...)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "write_json/stdout.json", []byte(stdout))

	// The whole batch is idempotent: the retry reports duplicates, writes no
	// second row, and the dismissed verdict stays a candidate_verdict only.
	stdout, stderr, code = f.run(t, args...)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "write_json/stdout_retry.json", []byte(stdout))

	f.golden(t, "write_json/db_after_retry.txt", f.dbState(t))
	f.goldenTree(t, f.scanDir, "write_json/artifacts")
}

func TestReportGolden_Review(t *testing.T) {
	f := newReportGoldenFixture(t)

	stdout, stderr, code := f.run(t,
		"--review", "--id", fmt.Sprintf("%d", f.autoConfirmedID),
		"--review-status", "confirmed",
		"--review-reasoning", "machine proof verified against the guard-free path",
		"--output-dir", f.scanDir)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "review/stdout.json", []byte(stdout))
	f.golden(t, "review/db_after_review.txt", f.dbState(t))
	f.goldenTree(t, f.scanDir, "review/artifacts")
}

func TestReportGolden_ReviewJSON(t *testing.T) {
	f := newReportGoldenFixture(t)

	payload := fmt.Sprintf(`[
  {"id":%d,"review_status":"confirmed","review_reasoning":"machine proof verified"},
  {"id":%d,"review_status":"dismissed","review_reasoning":"fd is returned to the caller"}
]`, f.autoConfirmedID, f.reviewedOutID)
	batchPath := filepath.Join(f.root, "reviews.json")
	if err := os.WriteFile(batchPath, []byte(payload), 0644); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := f.run(t,
		"--review-json", batchPath,
		"--output-dir", f.scanDir)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "review_json/stdout.json", []byte(stdout))
	f.golden(t, "review_json/db_after_review.txt", f.dbState(t))
	f.goldenTree(t, f.scanDir, "review_json/artifacts")
}

func TestReportGolden_Stats(t *testing.T) {
	f := newReportGoldenFixture(t)

	stdout, stderr, code := f.run(t, "--stats", "--scan-id", reportGoldenScanID)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "stats/stdout.json", []byte(stdout))
}

// TestReportGolden_Audit pins the complete audit envelope AND every artifact
// `report --audit` regenerates: audit-report.md, result.sarif, report.md,
// pipeline-dismissed.json and the findings/ projection. One auto-confirmed
// finding is deliberately left unreviewed so the audit's "machine verdicts not
// re-reviewed" warning is part of the contract.
func TestReportGolden_Audit(t *testing.T) {
	f := newReportGoldenFixture(t)

	stdout, stderr, code := f.run(t,
		"--audit", "--scan-id", reportGoldenScanID, "--output-dir", f.scanDir)
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "audit/stdout.json", []byte(stdout))

	// xlsx is binary: assert it exists and is non-empty instead of golden-ing
	// an OOXML zip whose container bytes are not part of the contract.
	xlsxPath := filepath.Join(f.scanDir, "result.xlsx")
	if info, err := os.Stat(xlsxPath); err != nil {
		t.Errorf("audit must write result.xlsx: %v", err)
	} else if info.Size() == 0 {
		t.Errorf("audit wrote an empty result.xlsx")
	}

	f.goldenTree(t, f.scanDir, "audit/artifacts")
}

// TestReportGolden_AuditPartial pins the --allow-partial contract: an unfinished
// type blocks the terminal artifact set unless the caller opts in, and then
// every artifact is explicitly labelled PARTIAL and the unclassified candidate
// is surfaced as a warning instead of being counted as dismissed.
func TestReportGolden_AuditPartial(t *testing.T) {
	f := newReportGoldenFixture(t)
	f.addPendingType(t, "use-after-free", 2, 1)

	stdout, stderr, code := f.run(t,
		"--audit", "--scan-id", reportGoldenScanID, "--output-dir", f.scanDir, "--allow-partial")
	requireExit(t, stdout, stderr, code, 0)
	f.golden(t, "audit_partial/stdout.json", []byte(stdout))
	f.goldenTree(t, f.scanDir, "audit_partial/artifacts")
}

// TestReportGolden_JSONEnvelopeFields documents the field-set contract that the
// goldens pin wholesale, so a reviewer can see the required keys without
// reading a 300-line golden diff.
func TestReportGolden_JSONEnvelopeFields(t *testing.T) {
	f := newReportGoldenFixture(t)
	cases := []struct {
		name string
		args []string
		keys []string
	}{
		{"list", []string{"--list", "--scan-id", reportGoldenScanID}, []string{"count", "findings"}},
		{"list_auto_confirmed", []string{"--list-auto-confirmed", "--scan-id", reportGoldenScanID}, []string{"count", "findings"}},
		{"stats", []string{"--stats", "--scan-id", reportGoldenScanID}, []string{"scan_id", "types"}},
		{"audit", []string{"--audit", "--scan-id", reportGoldenScanID}, []string{"scan_id", "audits", "summary"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := f.run(t, tc.args...)
			requireExit(t, stdout, stderr, code, 0)
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal([]byte(stdout), &envelope); err != nil {
				t.Fatalf("%s output is not a JSON object: %v\n%s", tc.name, err, stdout)
			}
			for _, key := range tc.keys {
				if _, ok := envelope[key]; !ok {
					t.Errorf("%s envelope is missing %q: %s", tc.name, key, stdout)
				}
			}
		})
	}
}
