package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestArrayOOB_LoopBoundOverflow(t *testing.T) {
	store := runIndexAndDetect(t, "tc22_off_by_one.c")
	assertHasEvent(t, store, "BUFFER_ACCESS", "LoopBoundOverflow")
}

func TestBufferOverflow_HeapOOBWrite(t *testing.T) {
	store := runIndexAndDetect(t, "tc35_heap_oob_write.c")
	assertEventCategory(t, store, "BUFFER_ACCESS", "heap_oob_write", "tc35_heap_oob_write")
}

func TestBufferOverflow_FormatOverflow(t *testing.T) {
	store := runIndexAndDetect(t, "tc36_format_overflow.c")
	// tc36's format string is `"Task[%s]"` with a non-constant `%s` argument:
	// overflow is possible but not provable, so it must land in the
	// format_overflow_var (suspected) tier, not the confirmed format_overflow.
	assertEventCategory(t, store, "BUFFER_ACCESS", "format_overflow_var", "tc36_format_overflow")
}

func TestBufferOverflow_FormatOverflowSuppressedByInjectionSink(t *testing.T) {
	// sprintf feeding sqlite3_exec is one SQL-injection defect; the same call
	// must not also surface as a buffer-overflow candidate (double counting).
	store := runIndexAndDetect(t, "tc40_sprintf_sql_sink.c")
	assertNoEvent(t, store, "BUFFER_ACCESS", "tc40_sprintf_sql_sink")
	assertHasEvent(t, store, "INJECTION", "tc40_sprintf_sql_sink")
}

// TestBufferOverflow_ConstantStrCpyScope locks in the constant-string-copy
// suppression boundaries: strcpy of a short literal into a local fixed array is
// suppressed, while strcat (which appends) is never suppressed by source-size
// alone and must still be flagged.
func TestBufferOverflow_ConstantStrCpyScope(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc47_const_strcpy_local_array.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Expression string `json:"expression"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Expression] = true
	}

	if !flagged[`strcat(dst, "hello")`] {
		t.Errorf("expected strcat to be flagged, got events %v", flagged)
	}
	if flagged[`strcpy(dst, "hello")`] {
		t.Errorf("expected strcpy (local fixed array, short literal) to be suppressed, got events %v", flagged)
	}
}

// TestBufferOverflow_StrCpyFieldArray locks in the struct-field fixed-array
// suppression: strcpy of a short literal into a uniquely-sized field is safe,
// while a literal that provably overflows the field is still flagged.
func TestBufferOverflow_StrCpyFieldArray(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc57_strcpy_field_array.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	flagged := map[string]bool{}
	for _, e := range events {
		var props struct {
			Expression string `json:"expression"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Expression] = true
	}

	if flagged[`strcpy(log->id, "bad")`] {
		t.Errorf("expected strcpy(log->id, \"bad\") into char id[8] to be suppressed, got %v", flagged)
	}
	if !flagged[`strcpy(log->id, "way_too_long_string_for_this_field")`] {
		t.Errorf("expected overflowing strcpy into char id[8] to be flagged, got %v", flagged)
	}
}

// TestArrayOOB_ConstantValuedVariable pins the cross-assignment OOB detection: a
// variable assigned a single constant before a subscript (`int n = 12; buf[n]`)
// is OOB exactly when the constant is, even though the index is not a literal.
func TestArrayOOB_ConstantValuedVariable(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "const_oob.c")
	src := `int f(void) {
    int n = 12;
    int buf[10];
    buf[n] = 0;
    return 0;
}
`
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewBufferOverflowDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Array    string `json:"array"`
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Array == "buf" && props.Category == "array_oob_write" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected array_oob_write for buf[n] with n=12 >= 10, got no such event")
	}
}
