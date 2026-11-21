package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func TestWriteSecondCalleeDefinition(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "callee.c")
	if err := os.WriteFile(src, []byte("void a(void) {\n}\nvoid b(void) {\n  a();\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	o := &ScanOutput{RootDir: dir}
	c := planner.EvidenceItem{
		SecondCalleeDefFile:    src,
		SecondCalleeDefLine:    3,
		SecondCalleeDefEndLine: 5,
	}
	var b strings.Builder
	writeSecondCalleeDefinition(&b, c, o, "cleanup helper")
	out := b.String()
	for _, want := range []string{"## Second Callee Definition", "callee.c:3-5", "cleanup helper", "void b(void)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestWriteSecondCalleeDefinition_Missing(t *testing.T) {
	dir := t.TempDir()
	o := &ScanOutput{RootDir: dir}
	c := planner.EvidenceItem{
		SecondCalleeDefFile: filepath.Join(dir, "missing.c"),
		SecondCalleeDefLine: 1,
	}
	var b strings.Builder
	writeSecondCalleeDefinition(&b, c, o, "cleanup helper")
	if !strings.Contains(b.String(), "Body unavailable") {
		t.Fatalf("expected unavailable notice, got:\n%s", b.String())
	}
}
