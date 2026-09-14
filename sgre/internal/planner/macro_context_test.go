package planner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsAllCapsMacroName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"DBM_CHECK_RET", true},
		{"DBM_TAILQ_FIRST", true},
		{"SAFE_FREE", true},
		{"A", false},                   // single letter is ambiguous
		{"list_for_each_entry", false}, // lower-case iterator — known set, not all-caps
		{"if", false},                  // keyword
		{"sizeof", false},              // keyword
		{"malloc", false},              // ordinary function
		{"_Static_assert", false},
		{"DBM2", true}, // digit is allowed
	}
	for _, c := range cases {
		if got := isAllCapsMacroName(c.in); got != c.want {
			t.Errorf("isAllCapsMacroName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMacroContextDetector(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.c")
	content := `#include <sdk.h>
uint32_t f(uint32_t id) {
    const DBM_VSYS_CTRL *ctrl = DBM_GetVsysCtrl(id);
    DBM_CHECK_RET(ctrl == NULL, 0);

    for (p = DBM_TAILQ_FIRST(&(ctrl->heads)); p != NULL; p = DBM_TAILQ_NEXT(p, link)) {
        p->x = 1;
    }
    return 0;
}
`
	if err := os.WriteFile(file, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	d := newMacroContextDetector()
	// Line 4 is the deref inside DBM_TAILQ_FIRST; line 3 is the guard macro.
	// Both are within the ±8 window, so the region must be flagged.
	if !d.hasMacroContext(file, 5) {
		t.Errorf("expected macro context around the DBM_* dereference, got false")
	}

	// A file with no macro calls must not be flagged.
	plain := filepath.Join(dir, "plain.c")
	if err := os.WriteFile(plain, []byte("int g(int *p) { return p ? *p : 0; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if d.hasMacroContext(plain, 1) {
		t.Errorf("plain file without macros must not be flagged")
	}
}
