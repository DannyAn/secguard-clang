package symbols

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestBuildMacroIndexAndLookup(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "include", "defs.h"),
		"#define GET_STR_LEN(s) ((s) == NULL ? 0 : (int)strlen(s))\n"+
			"#define MULTI(a, b) \\\n    do { (a) += (b); } while (0)\n"+
			"#define TICKS_IN_SECOND 1000\n")

	idx := BuildMacroIndex(dir, nil)
	if idx.Files() != 1 {
		t.Fatalf("files = %d, want 1", idx.Files())
	}

	defs := idx.Lookup("GET_STR_LEN")
	if len(defs) != 1 {
		t.Fatalf("GET_STR_LEN defs = %d", len(defs))
	}
	if defs[0].Params != "(s)" || defs[0].Signature != "#define GET_STR_LEN(s)" {
		t.Errorf("unexpected def: %+v", defs[0])
	}
	if defs[0].File != filepath.Join(dir, "include", "defs.h") || defs[0].Line != 1 {
		t.Errorf("unexpected location: %+v", defs[0])
	}

	multi := idx.Lookup("MULTI")
	if len(multi) != 1 || multi[0].EndLine != 3 || multi[0].Line != 2 {
		t.Fatalf("continuation not captured: %+v", multi)
	}
	if got := idx.Lookup("TICKS_IN_SECOND"); len(got) != 1 || got[0].Body != "#define TICKS_IN_SECOND 1000" {
		t.Fatalf("object-like macro not captured: %+v", got)
	}
	if got := idx.Lookup("NOT_THERE"); len(got) != 0 {
		t.Fatalf("unexpected lookup hit: %+v", got)
	}
}

func TestScanMacrosInFileFiltersByName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "local.c")
	writeFile(t, path, "#define LOCAL_A 1\n#define LOCAL_B 2\n")

	defs := ScanMacrosInFile(path, "LOCAL_B")
	if len(defs) != 1 || defs[0].Name != "LOCAL_B" {
		t.Fatalf("name filter failed: %+v", defs)
	}
}

func TestExtractMacroRefs(t *testing.T) {
	text := `if (len < MAX_LEN) { len += GET_STR_LEN(buf); p->FIELD = TICKS_IN_SECOND; memcpy(dst, src, n); }`
	refs := ExtractMacroRefs(text)
	want := map[string]bool{"MAX_LEN": true, "GET_STR_LEN": true, "TICKS_IN_SECOND": true, "memcpy": true}
	got := map[string]bool{}
	for _, r := range refs {
		got[r] = true
	}
	for name := range want {
		if !got[name] {
			t.Errorf("missing ref %q in %v", name, refs)
		}
	}
	if got["FIELD"] || got["if"] || got["len"] {
		t.Errorf("unexpected refs: %v", refs)
	}
}

func TestRootForSrcIncludeLayout(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "symbols-root-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	writeFile(t, filepath.Join(dir, "src", "a.c"), "int f(void){return 0;}\n")
	if err := os.MkdirAll(filepath.Join(dir, "include"), 0755); err != nil {
		t.Fatal(err)
	}
	root := RootFor([]string{filepath.Join(dir, "src", "a.c")})
	if root != dir {
		t.Fatalf("root = %q, want %q", root, dir)
	}
}

func TestReadLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.c")
	writeFile(t, path, "one\ntwo\nthree\nfour\n")
	body, truncated, err := ReadLines(path, 2, 3, 10)
	if err != nil || truncated || body != "two\nthree" {
		t.Fatalf("ReadLines = %q, %v, %v", body, truncated, err)
	}
	body, truncated, err = ReadLines(path, 1, 4, 2)
	if err != nil || !truncated || body != "one\ntwo" {
		t.Fatalf("truncated ReadLines = %q, %v, %v", body, truncated, err)
	}
}
