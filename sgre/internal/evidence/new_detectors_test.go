package evidence

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// runOneDetector indexes fixture, constructs det from the real store/parser,
// runs it, and returns the store for event assertions.
func runOneDetector(t *testing.T, fixture string, factory DetectorFactory) db.Store {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", fixture)); err != nil {
		t.Fatalf("index failed for %s: %v", fixture, err)
	}
	if _, err := factory(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect failed for %s: %v", fixture, err)
	}
	return store
}

func eventCount(t *testing.T, store db.Store, eventType string) int {
	t.Helper()
	events, err := store.ListEventsByType(context.Background(), eventType)
	if err != nil {
		t.Fatalf("list %s events: %v", eventType, err)
	}
	return len(events)
}

func TestNewDetector_DivideByZero(t *testing.T) {
	store := runOneDetector(t, "tc59_divide_by_zero.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	if got := eventCount(t, store, "DIVIDE_BY_ZERO"); got != 2 {
		t.Errorf("expected 2 DIVIDE_BY_ZERO events, got %d", got)
	}
}

func TestNewDetector_DivideByZero_ReassignmentGuard(t *testing.T) {
	store := runOneDetector(t, "tc71_divide_by_zero_guard.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	if got := eventCount(t, store, "DIVIDE_BY_ZERO"); got != 1 {
		t.Errorf("expected 1 DIVIDE_BY_ZERO event (clamp/negate/compound guards suppressed), got %d", got)
	}
}

func TestNewDetector_SQLInjectionLiteralSafe(t *testing.T) {
	store := runOneDetector(t, "tc72_sql_literal_safe.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewInjectionDetector(s, p, l) })
	if got := eventCount(t, store, "INJECTION"); got != 3 {
		t.Errorf("expected 3 INJECTION events (literal/placeholder/constant-copy suppressed), got %d", got)
	}
}

func TestNewDetector_UncheckedReturn(t *testing.T) {
	store := runOneDetector(t, "tc60_unchecked_return.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })
	if got := eventCount(t, store, "UNCHECKED_RETURN"); got != 2 {
		t.Errorf("expected 2 UNCHECKED_RETURN events, got %d", got)
	}
}

func TestNewDetector_PathTraversal(t *testing.T) {
	store := runOneDetector(t, "tc61_path_traversal.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewPathTraversalDetector(s, p, l) })
	if got := eventCount(t, store, "PATH_TRAVERSAL"); got != 2 {
		t.Errorf("expected 2 PATH_TRAVERSAL events, got %d", got)
	}
}

func TestPathTraversal_SinkList(t *testing.T) {
	// Content-traversal sinks stay; query/permission/dir sinks are dropped so
	// the detector no longer floods the developer with every file operation.
	for _, keep := range []string{"fopen", "open", "openat", "opendir", "unlink", "remove", "rename"} {
		if !pathSinks[keep] {
			t.Errorf("%s should be a path-traversal sink", keep)
		}
	}
	for _, drop := range []string{"stat", "lstat", "access", "chmod", "chown", "mkdir", "rmdir"} {
		if pathSinks[drop] {
			t.Errorf("%s should NOT be a path-traversal sink (query/permission/dir op)", drop)
		}
	}
}

func TestNewDetector_SizeofMisuse(t *testing.T) {
	store := runOneDetector(t, "tc62_sizeof_misuse.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSizeofMisuseDetector(s, p, l) })
	if got := eventCount(t, store, "SIZEOF_MISUSE"); got != 2 {
		t.Errorf("expected 2 SIZEOF_MISUSE events, got %d", got)
	}
}

func TestNewDetector_SignedCompare(t *testing.T) {
	store := runOneDetector(t, "tc63_signed_compare.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignedCompareDetector(s, p, l) })
	if got := eventCount(t, store, "SIGNED_COMPARE"); got != 3 {
		t.Errorf("expected 3 SIGNED_COMPARE events, got %d", got)
	}
}
