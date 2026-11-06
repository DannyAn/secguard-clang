package evidence

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// feedbackWatchPath resolves a fixture from the Issue #226 capability directory.
func feedbackWatchPath(subdir, name string) string {
	return fixturePath(filepath.Join("feedback_watch", subdir, name))
}

func indexAndDetect(t *testing.T, fixture, detector string) db.Store {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixture); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	switch detector {
	case "null_source":
		_, _ = NewNullSourceDetector(store, p, logger).Detect(ctx)
	case "uninit":
		_, _ = NewUninitVariableDetector(store, p, logger).Detect(ctx)
	default:
		t.Fatalf("unknown detector %s", detector)
	}
	return store
}

// TestNullSource_StaticNullGlobal pins the CWD-SUB-1031 sample A capability: a
// file-scope `static T *g = NULL;` that is never reassigned seeds a NULL_VALUE
// source (origin global_null) for the function that dereferences it. A global
// assigned from a parameter in the same file must NOT become such a source.
func TestNullSource_StaticNullGlobal(t *testing.T) {
	ctx := context.Background()
	store := indexAndDetect(t,
		feedbackWatchPath("CWD-SUB-1031-global-null-deref", "01_global_pointer_deref.c"),
		"null_source")

	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		t.Fatalf("list functions: %v", err)
	}
	byID := make(map[int64]string, len(funcs))
	for _, f := range funcs {
		byID[f.ID] = f.Name
	}

	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list NULL_VALUE: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g_session" && props.Origin == "global_null" {
			if byID[e.EntityID] != "get_session_state" {
				t.Errorf("global_null source attached to %q, want get_session_state", byID[e.EntityID])
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no global_null NULL_VALUE source for g_session in %d events", len(events))
	}

	// CWD-SUB-1031 sample C: the global is written from a parameter, so the
	// value is not "always NULL" and must not seed a source.
	store = indexAndDetect(t,
		feedbackWatchPath("CWD-SUB-1031-global-null-deref", "03_interprocedural_global_deref.c"),
		"null_source")
	events, err = store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list NULL_VALUE: %v", err)
	}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g_session" && props.Origin == "global_null" {
			t.Errorf("g_session is reassigned from a parameter; global_null source is unsound")
		}
	}

	// A function-local pointer that shadows the file-scope name must not be read
	// as a dereference of the NULL static (soundness: the local's value is not
	// the global's). This is a false-positive guard for the shadowing case.
	store = indexAndDetect(t,
		feedbackWatchPath("CWD-SUB-1031-global-null-deref", "05_shadowed_global.c"),
		"null_source")
	events, err = store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list NULL_VALUE: %v", err)
	}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g_session" && props.Origin == "global_null" {
			t.Errorf("a function-local g_session shadows the NULL static; global_null source is unsound")
		}
	}
}

// TestUninit_UninitializedPointerCondition pins the CWD-SUB-1140 sample B fix:
// a pointer local read in `if (node != 0)` was invisible to the uninit analysis
// because the declarator is wrapped in a pointer_declarator.
func TestUninit_UninitializedPointerCondition(t *testing.T) {
	ctx := context.Background()
	store := indexAndDetect(t,
		feedbackWatchPath("CWD-SUB-1140-uninitialized-condition", "02_uninitialized_pointer_condition.c"),
		"uninit")

	events, err := store.ListEventsByType(ctx, "VALUE_USE")
	if err != nil {
		t.Fatalf("list VALUE_USE: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "node" && props.Origin == "stack_uninit" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no stack_uninit VALUE_USE for the uninitialized pointer node in %d events", len(events))
	}
}
