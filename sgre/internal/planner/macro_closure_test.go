package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/symbols"
)

func TestMacroDefsHint(t *testing.T) {
	c := Candidate{
		Category:  "unsigned_sub_underflow",
		MacroDefs: []symbols.MacroDef{{Name: "MAX_LEN"}, {Name: "GET_STR_LEN"}},
	}
	parts := buildHintParts(c, &VulnTypeSpec{Name: "integer-overflow"})
	got := map[string]bool{}
	for _, p := range parts {
		got[p] = true
	}
	if !got["macro@MAX_LEN"] || !got["macro@GET_STR_LEN"] {
		t.Fatalf("macro@ tokens missing: %v", parts)
	}
}

func TestMacroDefsForClosesOverExpressionAndCallee(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "include"), 0755); err != nil {
		t.Fatal(err)
	}
	header := filepath.Join(dir, "include", "defs.h")
	if err := os.WriteFile(header, []byte("#define MAX_LEN 16\n#define GET_STR_LEN(s) ((s) == NULL ? 0 : (int)strlen(s))\n"), 0644); err != nil {
		t.Fatal(err)
	}
	callee := filepath.Join(dir, "callee.c")
	if err := os.WriteFile(callee, []byte("int wrap(char *s) {\n    return GET_STR_LEN(s);\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}

	idx := symbols.BuildMacroIndex(dir, nil)
	c := Candidate{
		Expression:       "consume(MAX_LEN - n)",
		CalleeDefFile:    callee,
		CalleeDefLine:    1,
		CalleeDefEndLine: 3,
	}
	p := &Planner{}
	defs := p.macroDefsFor(c, idx)
	got := map[string]bool{}
	for _, d := range defs {
		got[d.Name] = true
	}
	if !got["MAX_LEN"] || !got["GET_STR_LEN"] {
		t.Fatalf("macro closure missed a definition: %v", defs)
	}
}
