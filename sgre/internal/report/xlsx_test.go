package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/xuri/excelize/v2"
)

// writeXlsxFixture writes result.xlsx into dir from findings and opens it back,
// returning the workbook plus any write error.
func writeXlsxFixture(t *testing.T, dir string, findings []*db.Finding) (*excelize.File, error) {
	t.Helper()
	path := filepath.Join(dir, ResultXlsxFile)
	if err := WriteXlsxFromFindings(path, "", findings); err != nil {
		return nil, err
	}
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", ResultXlsxFile, err)
	}
	return f, nil
}

func TestWriteXlsxFromFindings_ExcludesDismissed(t *testing.T) {
	findings := []*db.Finding{
		{
			RuleID: "CWE-476", Severity: "high", Confidence: 0.9,
			Status: "confirmed", FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
			Summary: "malloc 未判空即解引用", Reasoning: "分配后立即解引用",
			FixStrategy: "if (p == NULL) return -1;",
		},
		{
			RuleID: "CWE-190", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/b.c", LineNumber: 35, FunctionName: "g",
			Summary: "n+1 可溢出", Reasoning: "仅 n==SIZE_MAX 时回绕",
		},
		{
			RuleID: "CWE-787", Severity: "high", Confidence: 0.5,
			Status: "suspected", ReviewStatus: "dismissed",
			FilePath: "src/c.c", LineNumber: 7, FunctionName: "dismissed_fn",
			Summary: "误报", Reasoning: "已有边界检查",
		},
	}

	f, err := writeXlsxFixture(t, t.TempDir(), findings)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if idx, err := f.GetSheetIndex("Findings"); err != nil || idx == -1 {
		t.Fatalf("sheet Findings missing (idx=%d, err=%v)", idx, err)
	}

	// Header row must match the shared column contract exactly.
	for i, want := range xlsxHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		if got, _ := f.GetCellValue("Findings", cell); got != want {
			t.Errorf("header %s = %q, want %q", cell, got, want)
		}
	}

	rows, err := f.GetRows("Findings")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected header + 2 data rows (dismissed excluded), got %d rows", len(rows))
	}

	// Sorted by vuln type: integer-overflow (CWE-190) before null-deref (CWE-476).
	if got, _ := f.GetCellValue("Findings", "B2"); got != "integer-overflow" {
		t.Errorf("B2 vuln type = %q, want integer-overflow", got)
	}
	if got, _ := f.GetCellValue("Findings", "E2"); got != "suspected" {
		t.Errorf("E2 status = %q, want suspected", got)
	}
	if got, _ := f.GetCellValue("Findings", "B3"); got != "null-deref" {
		t.Errorf("B3 vuln type = %q, want null-deref", got)
	}
	if got, _ := f.GetCellValue("Findings", "E3"); got != "confirmed" {
		t.Errorf("E3 status = %q, want confirmed", got)
	}
	if got, _ := f.GetCellValue("Findings", "L3"); got != "if (p == NULL) return -1;" {
		t.Errorf("L3 fix strategy = %q, want the confirmed finding's fix", got)
	}

	// The dismissed finding must not leak into the export.
	for _, row := range rows {
		for _, cell := range row {
			if strings.Contains(cell, "dismissed_fn") {
				t.Errorf("dismissed finding leaked into result.xlsx: %q", cell)
			}
		}
	}
}

func TestWriteXlsxFromFindings_EmptyFindings(t *testing.T) {
	f, err := writeXlsxFixture(t, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rows, err := f.GetRows("Findings")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected only the header row, got %d rows", len(rows))
	}
	if got, _ := f.GetCellValue("Findings", "A1"); got != xlsxHeaders[0] {
		t.Errorf("A1 = %q, want %q", got, xlsxHeaders[0])
	}
}

func TestWriteXlsxFromFindings_MissingSourceOmitsSnippet(t *testing.T) {
	findings := []*db.Finding{{
		RuleID: "CWE-476", Severity: "high", Confidence: 0.9,
		Status: "confirmed", FilePath: "src/does-not-exist.c", LineNumber: 13,
		FunctionName: "f", Summary: "x",
	}}

	f, err := writeXlsxFixture(t, t.TempDir(), findings)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if got, _ := f.GetCellValue("Findings", "B2"); got != "null-deref" {
		t.Errorf("row must still be written with no source file; B2 = %q", got)
	}
	if got, _ := f.GetCellValue("Findings", "M2"); got != "" {
		t.Errorf("M2 snippet = %q, want empty when source is missing", got)
	}
}

func TestWriteXlsxFromFindings_EmbedsCodeContext(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.c")
	var b strings.Builder
	for i := 1; i <= 40; i++ {
		fmt.Fprintf(&b, "int line_%d = %d;\n", i, i)
	}
	if err := os.WriteFile(src, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}

	findings := []*db.Finding{{
		RuleID: "CWE-476", Severity: "high", Confidence: 0.9,
		Status: "confirmed", FilePath: src, LineNumber: 20,
		FunctionName: "f", Summary: "x",
	}}

	f, err := writeXlsxFixture(t, dir, findings)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	snippet, _ := f.GetCellValue("Findings", "M2")
	if !strings.Contains(snippet, "> 20 |") {
		t.Errorf("M2 snippet missing the finding-line marker `> 20 |`:\n%s", snippet)
	}
	if !strings.Contains(snippet, "int line_5") || !strings.Contains(snippet, "int line_35") {
		t.Errorf("M2 snippet should carry ±%d context, got:\n%s", ContextLines, snippet)
	}
}
