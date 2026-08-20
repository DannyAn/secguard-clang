package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestWriteSarifFromFindings(t *testing.T) {
	dir := t.TempDir()
	sarifPath := filepath.Join(dir, "result.sarif")

	findings := []*db.Finding{
		{
			RuleID: "CWE-252", Severity: "high", Confidence: 0.9,
			Status: "confirmed", ReviewStatus: "",
			FilePath: "src/a.c", LineNumber: 13, FunctionName: "f",
			Summary: "malloc 未判空即解引用", Reasoning: "分配后立即解引用",
			ExceptionCheck: "无 safe wrapper", FixStrategy: "if (p == NULL) return -1;",
		},
		{
			RuleID: "CWE-190", Severity: "medium", Confidence: 0.6,
			Status: "suspected", ReviewStatus: "suspected-kept",
			FilePath: "src/b.c", LineNumber: 35, FunctionName: "g",
			Summary: "n+1 可溢出", Reasoning: "仅 n==SIZE_MAX 时回绕",
		},
		{
			RuleID: "CWE-476", Severity: "high", Confidence: 0.5,
			Status: "suspected", ReviewStatus: "dismissed",
			FilePath: "src/c.c", LineNumber: 7, FunctionName: "h",
			Summary: "误报", Reasoning: "已有 NULL 守卫",
		},
	}

	if err := WriteSarifFromFindings(sarifPath, "", findings); err != nil {
		t.Fatalf("WriteSarifFromFindings: %v", err)
	}

	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("read result.sarif: %v", err)
	}
	var rep sarifReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("unmarshal sarif: %v", err)
	}

	results := rep.Runs[0].Results
	if len(results) != 2 {
		t.Fatalf("expected 2 results (dismissed excluded), got %d", len(results))
	}

	// First result is confirmed with fix + properties.
	if results[0].Level != "error" {
		t.Errorf("confirmed finding level = %q, want error", results[0].Level)
	}
	if len(results[0].Fixes) != 1 || results[0].Fixes[0].Description.Text != "if (p == NULL) return -1;" {
		t.Errorf("confirmed finding should carry fix_strategy, got %+v", results[0].Fixes)
	}
	if results[0].Properties["reasoning"] != "分配后立即解引用" {
		t.Errorf("properties.reasoning not carried, got %+v", results[0].Properties)
	}

	// Second result is suspected-kept -> warning, no fix.
	if results[1].Level != "warning" {
		t.Errorf("suspected finding level = %q, want warning", results[1].Level)
	}
	if len(results[1].Fixes) != 0 {
		t.Errorf("suspected finding without fix_strategy should have no fixes, got %+v", results[1].Fixes)
	}
}
