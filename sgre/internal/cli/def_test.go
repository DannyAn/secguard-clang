//go:build !nosqlite

package cli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func defTestDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.OpenInMemory(context.Background())
	if err != nil {
		t.Fatalf("open in-memory db: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func defInsertFile(t *testing.T, d *sql.DB, path string) int64 {
	t.Helper()
	res, err := d.Exec(`INSERT INTO files (path, language) VALUES (?, 'c')`, path)
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("file id: %v", err)
	}
	return id
}

func defInsertFunction(t *testing.T, d *sql.DB, fileID int64, name, sig string, start, end int) {
	t.Helper()
	_, err := d.Exec(`INSERT INTO functions (file_id, name, signature, return_type, is_static, start_line, end_line) VALUES (?, ?, ?, 'int', 0, ?, ?)`,
		fileID, name, sig, start, end)
	if err != nil {
		t.Fatalf("insert function: %v", err)
	}
}

func TestLookupSymbol_FunctionBody(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.c")
	if err := os.WriteFile(src, []byte("int foo(int x)\n{\n    return x;\n}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := defTestDB(t)
	fid := defInsertFile(t, d, src)
	defInsertFunction(t, d, fid, "foo", "int foo(int x)", 1, 4)

	res, err := lookupSymbol(context.Background(), d, "foo", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !res.Found || len(res.Definitions) != 1 {
		t.Fatalf("expected one definition, got %+v", res)
	}
	def := res.Definitions[0]
	if def.Kind != "function" || def.Line != 1 || def.EndLine != 4 {
		t.Errorf("unexpected definition header: %+v", def)
	}
	if !strings.Contains(def.Body, "return x;") || !strings.Contains(def.Signature, "foo") {
		t.Errorf("body/signature missing: %+v", def)
	}
	if res.Search.Headers != 0 {
		t.Errorf("a DB hit must not scan headers, got %d", res.Search.Headers)
	}
}

func TestLookupSymbol_MultipleDefinitions(t *testing.T) {
	dir := t.TempDir()
	d := defTestDB(t)
	for _, name := range []string{"a.c", "b.c"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("static int dup(void) { return 0; }\n"), 0644); err != nil {
			t.Fatal(err)
		}
		fid := defInsertFile(t, d, path)
		defInsertFunction(t, d, fid, "dup", "static int dup(void)", 1, 1)
	}

	res, err := lookupSymbol(context.Background(), d, "dup", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(res.Definitions) != 2 {
		t.Fatalf("expected both static definitions, got %d: %+v", len(res.Definitions), res.Definitions)
	}
}

func TestLookupSymbol_DeclarationFallback(t *testing.T) {
	dir := t.TempDir()
	header := filepath.Join(dir, "api.h")
	if err := os.WriteFile(header, []byte("int external_api(int x);\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := defTestDB(t)
	fid := defInsertFile(t, d, header)
	if _, err := d.Exec(`INSERT INTO function_declarations (file_id, name, signature, return_type, start_line) VALUES (?, 'external_api', 'int external_api(int x)', 'int', 1)`, fid); err != nil {
		t.Fatalf("insert declaration: %v", err)
	}

	res, err := lookupSymbol(context.Background(), d, "external_api", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(res.Definitions) != 1 || res.Definitions[0].Kind != "declaration" {
		t.Fatalf("expected declaration fallback, got %+v", res.Definitions)
	}
	if res.Definitions[0].Line != 1 {
		t.Errorf("declaration line = %d, want 1", res.Definitions[0].Line)
	}
}

func TestLookupSymbol_MacroInHeader(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "include", "defs.h")
	if err := os.MkdirAll(filepath.Dir(inc), 0755); err != nil {
		t.Fatal(err)
	}
	content := "#define GET_STR_LEN(s) ((s) == NULL ? 0 : (int)strlen(s))\n" +
		"#define MULTI(a, b) \\\n    do { (a) += (b); } while (0)\n"
	if err := os.WriteFile(inc, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	d := defTestDB(t)

	res, err := lookupSymbol(context.Background(), d, "GET_STR_LEN", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !res.Found || len(res.Definitions) != 1 || res.Definitions[0].Kind != "macro" {
		t.Fatalf("expected macro definition, got %+v", res)
	}
	def := res.Definitions[0]
	if def.Line != 1 || def.Signature != "#define GET_STR_LEN(s)" || !strings.Contains(def.Body, "strlen") {
		t.Errorf("unexpected macro: %+v", def)
	}
	if res.Search.Headers != 1 {
		t.Errorf("headers searched = %d, want 1", res.Search.Headers)
	}

	res, err = lookupSymbol(context.Background(), d, "MULTI", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup multi: %v", err)
	}
	if !res.Found || !strings.Contains(res.Definitions[0].Body, "while (0)") {
		t.Fatalf("continuation body not captured: %+v", res.Definitions)
	}
	if res.Definitions[0].EndLine != 3 {
		t.Errorf("continuation end line = %d, want 3", res.Definitions[0].EndLine)
	}
}

func TestLookupSymbol_MacroInCandidateFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src", "local.c")
	if err := os.MkdirAll(filepath.Dir(src), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("#define LOCAL_FLAG 1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := defTestDB(t)

	res, err := lookupSymbol(context.Background(), d, "LOCAL_FLAG", defOptions{Root: dir, InFile: "src/local.c"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !res.Found || res.Definitions[0].Kind != "macro" {
		t.Fatalf("expected the --in file macro, got %+v", res)
	}
}

func TestLookupSymbol_NotFoundIsExternal(t *testing.T) {
	dir := t.TempDir()
	d := defTestDB(t)

	res, err := lookupSymbol(context.Background(), d, "TICKS_IN_SECOND", defOptions{Root: dir})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if res.Found || !res.External || len(res.Definitions) != 0 {
		t.Fatalf("expected not-found/external, got %+v", res)
	}
}

func TestLookupSymbol_KindMacroSkipsFunctionIndex(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.c")
	if err := os.WriteFile(src, []byte("int same_name(void) { return 0; }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	d := defTestDB(t)
	fid := defInsertFile(t, d, src)
	defInsertFunction(t, d, fid, "same_name", "int same_name(void)", 1, 1)

	res, err := lookupSymbol(context.Background(), d, "same_name", defOptions{Root: dir, Kind: "macro"})
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if res.Found {
		t.Fatalf("--kind macro must not accept a function hit: %+v", res)
	}
}

func TestParseDefArgs(t *testing.T) {
	syms, opts, err := parseDefArgs([]string{"GET_STR_LEN", "TICKS_IN_SECOND", "--kind=macro", "--in", "src/a.c", "--root=/repo"})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(syms) != 2 || syms[0] != "GET_STR_LEN" || syms[1] != "TICKS_IN_SECOND" {
		t.Fatalf("unexpected symbols: %v", syms)
	}
	if opts.Kind != "macro" || opts.InFile != "src/a.c" || opts.Root != "/repo" {
		t.Fatalf("unexpected opts: %+v", opts)
	}
	if _, _, err := parseDefArgs([]string{"bad-name"}); err == nil {
		t.Error("expected invalid identifier error")
	}
	if _, _, err := parseDefArgs([]string{"ok", "--kind", "bogus"}); err == nil {
		t.Error("expected invalid kind error")
	}
}
