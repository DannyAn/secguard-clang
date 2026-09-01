//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planNullDerefGuardMacroFiles runs the full null-deref pipeline (index → graph
// → null-source / null-guard / dereference detectors → planner) on a set of
// files. It is the multi-file companion to planNullDerefGuardMacro, used to
// exercise a null-check predicate helper defined in one file (a .h header) and
// called in another (a .c source).
func planNullDerefGuardMacroFiles(t *testing.T, files map[string]string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()

	dir := t.TempDir()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(files[name]), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	idx := indexer.NewIndexer(store, logger)
	for _, name := range names {
		if _, err := idx.Index(ctx, filepath.Join(dir, name)); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

const guardHelperCommon = `#include <stdlib.h>

typedef struct { char *content; size_t length; } string_data_t;

static string_data_t *get_string_data(void) { return NULL; }
`

// TestNullDeref_GuardHelperSubFunction: the predicate helper is a private
// sub-function in the SAME .c file. `if (is_empty_string(p)) goto out;`
// establishes p != NULL on the fall-through, so the later deref is guarded.
func TestNullDeref_GuardHelperSubFunction(t *testing.T) {
	src := guardHelperCommon + `
static bool is_empty_string(string_data_t *data)
{
    return (data == NULL || data->content == NULL || data->length == 0) ? true : false;
}

int format_string(char *buffer, char *end_buffer, const char *format) {
    char *current_ptr = buffer;
    string_data_t *string_data = NULL;
    while (*format && current_ptr < end_buffer) {
        if (*format != '%') { *(current_ptr++) = *(format++); continue; }
        if (*(format + 1) == 'V') {
            string_data = get_string_data();
            if (is_empty_string(string_data)) { goto finished; }
            current_ptr += string_data->length;
        }
    }
finished:
    return 0;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "format_string"); c != nil {
		t.Errorf("format_string should NOT be flagged (string_data is null-guarded by is_empty_string), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestNullDeref_GuardHelperHeaderFile: the predicate helper is defined in a
// separate .h header (a static inline) and called from the .c source. The
// cross-file helper collection must see the definition in the header and
// apply the guard at the call site in the source file.
func TestNullDeref_GuardHelperHeaderFile(t *testing.T) {
	header := `#ifndef HELPER_H
#define HELPER_H
#include <stddef.h>

typedef struct { char *content; size_t length; } string_data_t;

static inline bool is_empty_string(string_data_t *data)
{
    return (data == NULL || data->content == NULL || data->length == 0) ? true : false;
}
#endif
`
	src := `#include <stdlib.h>
#include "helper.h"

static string_data_t *get_string_data(void) { return NULL; }

int format_string(char *buffer, char *end_buffer, const char *format) {
    char *current_ptr = buffer;
    string_data_t *string_data = NULL;
    while (*format && current_ptr < end_buffer) {
        if (*format != '%') { *(current_ptr++) = *(format++); continue; }
        if (*(format + 1) == 'V') {
            string_data = get_string_data();
            if (is_empty_string(string_data)) { goto finished; }
            current_ptr += string_data->length;
        }
    }
finished:
    return 0;
}
`
	result := planNullDerefGuardMacroFiles(t, map[string]string{"helper.h": header, "caller.c": src})
	if c := candidateForFunc(t, result, "format_string"); c != nil {
		t.Errorf("format_string should NOT be flagged (string_data is null-guarded by header-defined is_empty_string), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// TestNullDeref_GuardHelperSimpleForms covers the two canonical helper bodies
// not exercised by the ternary form above: `return p == NULL;` and `return !p;`.
func TestNullDeref_GuardHelperSimpleForms(t *testing.T) {
	src := guardHelperCommon + `
static bool is_null_eq(string_data_t *p) { return p == NULL; }
static bool is_null_bang(string_data_t *p) { return !p; }

int use_eq(char *buf, char *end, const char *fmt) {
    char *cur = buf;
    string_data_t *sd = NULL;
    while (*fmt && cur < end) {
        sd = get_string_data();
        if (is_null_eq(sd)) { goto done; }
        cur += sd->length;
    }
done:
    return 0;
}

int use_bang(char *buf, char *end, const char *fmt) {
    char *cur = buf;
    string_data_t *sd = NULL;
    while (*fmt && cur < end) {
        sd = get_string_data();
        if (is_null_bang(sd)) { goto done; }
        cur += sd->length;
    }
done:
    return 0;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "use_eq"); c != nil {
		t.Errorf("use_eq should NOT be flagged (guarded by is_null_eq), got var=%s", c.Target.Variable)
	}
	if c := candidateForFunc(t, result, "use_bang"); c != nil {
		t.Errorf("use_bang should NOT be flagged (guarded by is_null_bang), got var=%s", c.Target.Variable)
	}
}

// TestNullDeref_GuardHelperDoesNotHideRealBug: a bare NULL deref with no
// helper guard must still be reported — the helper-guard suppression must not
// over-fire and silence real null-deref findings.
func TestNullDeref_GuardHelperDoesNotHideRealBug(t *testing.T) {
	src := guardHelperCommon + `
static bool is_empty_string(string_data_t *data)
{
    return (data == NULL || data->content == NULL || data->length == 0) ? true : false;
}

int real_bug(void) {
    string_data_t *sd = NULL;
    if (is_empty_string(sd)) { return 1; }
    return (int)sd->length;
}

int real_bug_no_guard(void) {
    string_data_t *sd = get_string_data();
    return (int)sd->length;
}
`
	result := planNullDerefGuardMacro(t, src)
	// real_bug: sd is NULL, then is_empty_string(sd) returns true → return 1,
	// so the fall-through never reaches sd->length. This is genuinely guarded;
	// not flagged is correct.
	if c := candidateForFunc(t, result, "real_bug"); c != nil {
		t.Errorf("real_bug should NOT be flagged (sd is NULL → helper returns true → early return), got var=%s", c.Target.Variable)
	}
	// real_bug_no_guard: sd = get_string_data() (nullable), no guard before deref.
	if c := candidateForFunc(t, result, "real_bug_no_guard"); c == nil {
		t.Errorf("real_bug_no_guard must be flagged (no guard before deref), got: %s", candidateNames(result))
	}
}

// TestNullDeref_GuardHelperNegatedNotAGuard: `if (!is_empty(p)) return;`
// returns on the NON-empty branch, so the fall-through is the empty (NULL)
// branch — p may be null there, so this must NOT be treated as a guard.
func TestNullDeref_GuardHelperNegatedNotAGuard(t *testing.T) {
	src := guardHelperCommon + `
static bool is_empty_string(string_data_t *data)
{
    return (data == NULL || data->content == NULL || data->length == 0) ? true : false;
}

int negated_guard(void) {
    string_data_t *sd = get_string_data();
    if (!is_empty_string(sd)) { return 1; }
    return (int)sd->length;
}
`
	result := planNullDerefGuardMacro(t, src)
	if c := candidateForFunc(t, result, "negated_guard"); c == nil {
		t.Errorf("negated_guard must be flagged (!helper leaves the NULL branch live), got: %s", candidateNames(result))
	}
}