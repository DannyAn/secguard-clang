package evidence

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func indexFixtureForInjection(t *testing.T, fixture string) db.Store {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath(fixture)); err != nil {
		t.Fatalf("index failed for %s: %v", fixture, err)
	}
	return store
}

func runArgumentInjectionDetector(t *testing.T, store db.Store) {
	t.Helper()
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	det := NewArgumentInjectionDetector(store, p, logger)
	if _, err := det.Detect(ctx); err != nil {
		t.Fatalf("argument injection detect failed: %v", err)
	}
}

func assertHasInjectionEventWithCategory(t *testing.T, store db.Store, category string) {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "INJECTION")
	if err != nil {
		t.Fatalf("list events failed: %v", err)
	}
	for _, e := range events {
		if strings.Contains(e.Properties, `"category":"`+category+`"`) {
			return
		}
	}
	t.Errorf("expected INJECTION event with category %q, not found among %d events", category, len(events))
}

func assertNoInjectionEventWithCategory(t *testing.T, store db.Store, category string) {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "INJECTION")
	if err != nil {
		t.Fatalf("list events failed: %v", err)
	}
	for _, e := range events {
		if strings.Contains(e.Properties, `"category":"`+category+`"`) {
			t.Errorf("unexpected INJECTION event with category %q: %s", category, e.Properties)
		}
	}
}

func TestArgumentInjection_TP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_arg_injection_tp.c")
	runArgumentInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "argument_injection")
}

func TestArgumentInjection_FP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_arg_injection_fp.c")
	runArgumentInjectionDetector(t, store)
	assertNoInjectionEventWithCategory(t, store, "argument_injection")
}
