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

// runDangerDetect indexes src in a temp file and runs only the
// dangerous-function detector, returning the DANGEROUS_FUNCTION events.
func runDangerDetect(t *testing.T, src string) []*db.SecurityEvent {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "danger.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
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
		t.Fatalf("list events: %v", err)
	}
	return events
}

type dangerProps struct {
	Variable    string `json:"variable"`
	Category    string `json:"category"`
	Policy      string `json:"policy"`
	Replacement string `json:"replacement"`
}

// TestDangerousFunction_Issue263_FailStopAbort pins the issue #263 P0-1 fix:
// an abort() inside an invariant-check branch of a fail-stop context function
// (obj_free, timer_del, ...) IS the defensive design and is suppressed; every
// other abort() shape stays reported so the detector cannot go silent.
func TestDangerousFunction_Issue263_FailStopAbort(t *testing.T) {
	events := runDangerDetect(t, `#include <stdlib.h>

#define OBJ_MAGIC 0x5a5a

struct obj { int magic; int v; };

/* issue skeleton: invariant-check abort in a *_free helper — suppressed */
void obj_free(struct obj *p)
{
    if (p->magic != OBJ_MAGIC) {
        abort();
    }
    free(p);
}

/* timer teardown helper, single-statement branch — suppressed */
void timer_del(int linked)
{
    if (linked) abort();
}

/* control: an abort in a NON-fail-stop function stays reported */
void plain_abort(int bad)
{
    if (bad) {
        abort();
    }
}

/* control: an UNCONDITIONAL abort in a fail-stop helper is not an
 * invariant branch — stays reported for the AI */
void obj_abort_always(struct obj *p)
{
    abort();
}
`)

	// Exactly the two control calls remain: obj_free and timer_del aborts are
	// suppressed, plain_abort and obj_abort_always are still flagged.
	abortCount := 0
	for _, e := range events {
		var props dangerProps
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Variable == "abort" {
			abortCount++
		}
	}
	if abortCount != 2 {
		t.Fatalf("fail-stop suppression: want exactly 2 abort() events (the two controls), got %d", abortCount)
	}
}

// TestDangerousFunction_Issue263_PolicyProps pins the policy-tier marking:
// process-exit events carry policy=true so the AI judges them at the LOW
// tier, and _exit is in the ban table alongside exit.
func TestDangerousFunction_Issue263_PolicyProps(t *testing.T) {
	events := runDangerDetect(t, `#include <stdlib.h>

static void teardown(void) { _exit(1); }
static void bail(void) { abort(); }
static void copy(char *d, const char *s) { strcpy(d, s); }
`)
	byVar := map[string]dangerProps{}
	for _, e := range events {
		var props dangerProps
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			byVar[props.Variable] = props
		}
	}
	for _, policyName := range []string{"_exit", "abort"} {
		props, ok := byVar[policyName]
		if !ok {
			t.Fatalf("%s must be flagged (process_exit category)", policyName)
		}
		if props.Category != "process_exit" {
			t.Errorf("%s category = %q, want process_exit", policyName, props.Category)
		}
		if props.Policy != "true" {
			t.Errorf("%s must carry policy=true for the LOW-tier judgment, got %q", policyName, props.Policy)
		}
	}
	// A security-shaped ban (strcpy) must NOT carry the policy marker.
	if props, ok := byVar["strcpy"]; ok && props.Policy == "true" {
		t.Error("strcpy is a security-shaped ban and must not carry policy=true")
	}
}

// TestDangerousFunction_Issue263_FailStopConfigOverride pins the
// [dangerous_function] fail_stop_contexts override: a project context the
// built-ins do not know (my_module_check) suppresses after being declared,
// and a declared override REPLACES the built-in list.
func TestDangerousFunction_Issue263_FailStopConfigOverride(t *testing.T) {
	dir := t.TempDir()
	toml := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(toml, []byte("[dangerous_function]\nfail_stop_contexts = [\"*_check\"]\n"), 0644); err != nil {
		t.Fatalf("write toml: %v", err)
	}
	config.SetExplicitPath(toml)
	t.Cleanup(func() { config.SetExplicitPath("") })

	events := runDangerDetect(t, `#include <stdlib.h>

/* custom context: suppressed via the override */
void my_module_check(int bad)
{
    if (bad) abort();
}

/* built-in *_free is REPLACED by the override, so this one is reported */
void obj_free(struct obj *p)
{
    if (p == 0) abort();
}
`)
	abortCount := 0
	for _, e := range events {
		var props dangerProps
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props.Variable == "abort" {
			abortCount++
		}
	}
	if abortCount != 1 {
		t.Fatalf("config override: want exactly 1 abort() event (obj_free, whose built-in pattern was replaced), got %d", abortCount)
	}
}
