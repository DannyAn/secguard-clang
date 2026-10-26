//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestDangerousFunction_BannedCalls pins CWE-676: calls to the built-in ban
// table are flagged (across categories), while the `_s` variants and the
// recommended replacements are not. Second run-through of the
// ADDING_A_VULN_TYPE.md standard.
func TestDangerousFunction_BannedCalls(t *testing.T) {
	store, p := setupDetector(t, "tc109_dangerous_function.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(context.Background(), "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			flagged[props.Variable] = true
		}
	}

	for _, banned := range []string{"gets", "mktemp", "gethostbyname", "memmove", "memcpy", "strcpy", "sprintf", "atoi"} {
		if !flagged[banned] {
			t.Errorf("%s should be flagged as banned, got %v", banned, flagged)
		}
	}
	for _, safe := range []string{"memcpy_s", "strcpy_s", "sprintf_s", "strtol"} {
		if flagged[safe] {
			t.Errorf("%s is a safe/replacement API and must NOT be flagged, got %v", safe, flagged)
		}
	}
	// The deprecated BSD trio has no `_s` counterpart and is routinely absent
	// from a project's own banned-function guideline, so the DEFAULT policy must
	// not assert it (production reported `bzero` as an out-of-scope CWE-676
	// finding whose verdict read "可修改可不修改"). A project that bans them
	// adds [banned_functions] names.
	for _, deprecated := range []string{"bzero", "bcopy", "bcmp"} {
		if flagged[deprecated] {
			t.Errorf("%s is deprecated but not memory-unsafe and is not in the default ban table; it must NOT be flagged, got %v", deprecated, flagged)
		}
	}
}

// TestDangerousFunction_CategoriesAndMainContext pins the two layered rules:
// each banned call carries its category, and a nonMainOnly rule (exit) fires
// only OUTSIDE the program entry point.
func TestDangerousFunction_CategoriesAndMainContext(t *testing.T) {
	dir := t.TempDir()
	src := `#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

static void helper(void) { exit(1); }

int helper2(const char *s) { return atoi(s); }

// assert on a caller PARAMETER is the caller-input-validation defect.
void assert_param(const char *s) { assert(s != NULL); }

int main(void) {
    char b[8];
    void *p;
    memcpy(b, b, 8);
    p = alloca(8);
    assert(p != 0); /* local sanity check — NOT a caller-input defect */
    abort();
    pthread_exit(0);
    exit(0);
    return 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "dm.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	byVar := map[string]int{}
	cat := map[string]string{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Category string `json:"category"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			byVar[props.Variable]++
			cat[props.Variable] = props.Category
		}
	}

	wantCat := map[string]string{
		"exit":         "process_exit",
		"pthread_exit": "process_exit",
		"atoi":         "unchecked_conversion",
		"memcpy":       "unsafe_memory",
		"alloca":       "stack_allocation",
		"assert":       "assert_usage",
		"abort":        "process_exit",
	}
	for name, c := range wantCat {
		if byVar[name] == 0 {
			t.Errorf("%s should be flagged, got %v", name, byVar)
			continue
		}
		if cat[name] != c {
			t.Errorf("%s category = %q, want %q", name, cat[name], c)
		}
	}
	if byVar["exit"] != 1 {
		t.Errorf("exit must be reported once (only the non-main helper), got %d", byVar["exit"])
	}
	if byVar["pthread_exit"] != 1 {
		t.Errorf("pthread_exit must be reported even inside main (banned unconditionally), got %d", byVar["pthread_exit"])
	}
}

// TestDangerousFunction_StringMacroConstant pins the string-valued-macro fix:
// `inet_addr(NLOG_HOST_IP)` with `#define NLOG_HOST_IP "192.168.0.1"` is a
// compile-time constant (no INADDR_NONE / injection risk) and must NOT be
// flagged, while `inet_addr(host)` with a runtime variable must still be.
func TestDangerousFunction_StringMacroConstant(t *testing.T) {
	dir := t.TempDir()
	src := `#define NLOG_HOST_IP "192.168.0.1"
int use_const(void) { return (int)inet_addr(NLOG_HOST_IP); }
int use_var(const char *host) { return (int)inet_addr(host); }
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "inet.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	// The constant-macro call is safe and suppressed; only the runtime-variable
	// call should surface.
	if len(events) != 1 {
		t.Errorf("expected 1 dangerous-function event (runtime-variable inet_addr), got %d", len(events))
	}
}

// TestDangerousFunction_ConfigExtension pins the enterprise-policy extension: a
// name listed in secguard.toml [banned_functions] is banned on top of the
// built-in list, so a project-specific deprecated wrapper is also flagged.
func TestDangerousFunction_ConfigExtension(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(tomlPath, []byte("[banned_functions]\nnames = [\"my_legacy_alloc\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `void *my_legacy_alloc(size_t n) { return 0; }

int use_legacy(void) {
    void *p = my_legacy_alloc(16);
    return p == 0;
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	path := filepath.Join(dir, "legacy.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list DANGEROUS_FUNCTION: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Variable == "my_legacy_alloc" {
			found = true
		}
	}
	if !found {
		t.Errorf("config-banned my_legacy_alloc should be flagged, got %d events", len(events))
	}
}

// [banned_functions] exclude lets a project remove a BUILT-IN name its own
// security guideline does not ban. The built-in table is a default policy, not
// the project's authoritative list: production flagged `bzero`, whose verdict
// was "not a false positive, but not in our guideline either" — with no way to
// trim the table the finding had to be dismissed on every scan.
func TestDangerousFunction_ConfigExcludeRemovesBuiltin(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(cfgPath, []byte(`[banned_functions]
exclude = ["memset"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(cfgPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := filepath.Join(dir, "ex.c")
	if err := os.WriteFile(src, []byte(`#include <string.h>
void f(char *dst, const char *src) {
    memset(dst, 0, 16);
    strcpy(dst, src);
}
`), 0644); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, src); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			flagged[props.Variable] = true
		}
	}
	if flagged["memset"] {
		t.Errorf("memset is excluded by [banned_functions] exclude and must not be flagged, got %v", flagged)
	}
	if !flagged["strcpy"] {
		t.Errorf("excluding one built-in must not disable the rest (strcpy), got %v", flagged)
	}
}
