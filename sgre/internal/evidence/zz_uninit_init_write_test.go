package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// runUninitDetect indexes src in a temp file and runs only the uninit detector,
// returning the VALUE_USE events.
func runUninitDetect(t *testing.T, src string) []*db.SecurityEvent {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "init_write.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	if _, err := (NewUninitVariableDetector(store, p, logger)).Detect(ctx); err != nil {
		t.Fatalf("uninit detect: %v", err)
	}
	events, err := store.ListEventsByType(ctx, "VALUE_USE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	return events
}

// initWriteOf returns the init_write / init_write_line props of the VALUE_USE
// event for the named variable, and whether such an event exists.
func initWriteOf(events []*db.SecurityEvent, variable string) (string, int, bool) {
	for _, e := range events {
		var props struct {
			Variable      string `json:"variable"`
			InitWrite     string `json:"init_write"`
			InitWriteLine int    `json:"init_write_line"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == variable {
			return props.InitWrite, props.InitWriteLine, true
		}
	}
	return "", 0, false
}

// TestUninit_InitWriteFacts pins the Evidence Contract v2 F4 fact: the detector
// attaches the machine-proven write-path shape to the VALUE_USE event so the
// classifier settles maybe-uninit rows from the hint instead of tracing write
// paths in the source.
func TestUninit_InitWriteFacts(t *testing.T) {
	t.Run("no write site at all", func(t *testing.T) {
		events := runUninitDetect(t, `int f(void) {
    int x;
    return x;
}
`)
		kind, _, ok := initWriteOf(events, "x")
		if !ok {
			t.Fatal("no VALUE_USE for x")
		}
		if kind != "none" {
			t.Fatalf("bare scalar never written: init_write = %q, want none", kind)
		}
	})

	t.Run("heap never written", func(t *testing.T) {
		events := runUninitDetect(t, `int *f(void) {
    int *p = malloc(4);
    int v = *p;
    (void)v;
    return p;
}
`)
		kind, _, ok := initWriteOf(events, "p")
		if !ok {
			t.Fatal("no VALUE_USE for p (malloc'd block read uninitialized)")
		}
		if kind != "none" {
			t.Fatalf("malloc'd block never written: init_write = %q, want none", kind)
		}
	})

	t.Run("loop-only write is may-skip", func(t *testing.T) {
		events := runUninitDetect(t, `int f(int n) {
    int x;
    while (n > 0) { x = n; n--; }
    return x;
}
`)
		kind, line, ok := initWriteOf(events, "x")
		if !ok {
			t.Fatal("no VALUE_USE for x (loop-only write may be skipped)")
		}
		if kind != "loop" {
			t.Fatalf("loop-only write: init_write = %q, want loop", kind)
		}
		if line == 0 {
			t.Fatalf("loop-only write must carry the first write line, got 0")
		}
	})

	t.Run("single-line loop body counts as in-loop", func(t *testing.T) {
		events := runUninitDetect(t, `int f(int n) {
    int x;
    while (n > 0) { x = n; n--; }
    return x;
}
`)
		if _, _, ok := initWriteOf(events, "x"); !ok {
			t.Fatal("single-line while body: the write must still be reported as a candidate")
		}
	})

	t.Run("branch write carries no fact", func(t *testing.T) {
		events := runUninitDetect(t, `int f(int c) {
    int x;
    if (c) { x = 1; }
    return x;
}
`)
		kind, _, ok := initWriteOf(events, "x")
		if !ok {
			t.Fatal("no VALUE_USE for x (branch write may be skipped)")
		}
		if kind != "" {
			t.Fatalf("if-branch write is not loop-only: init_write = %q, want empty (AI traces)", kind)
		}
	})

	t.Run("mixed loop and branch write carries no fact", func(t *testing.T) {
		events := runUninitDetect(t, `int f(int n, int c) {
    int x;
    while (n > 0) { x = n; n--; }
    if (c) { x = 2; }
    return x;
}
`)
		kind, _, ok := initWriteOf(events, "x")
		if !ok {
			t.Fatal("no VALUE_USE for x")
		}
		if kind != "" {
			t.Fatalf("mixed loop+branch writes: init_write = %q, want empty", kind)
		}
	})
}

// TestUninit_AllSitesInLoops pins the pure helper: every site must fall inside
// a while/for span in the function; a site outside any loop breaks the
// loop-only classification.
func TestUninit_AllSitesInLoops(t *testing.T) {
	if allSitesInLoops([]int{4}, []parser.Node{}, []parser.Node{}, &db.Function{StartLine: 1, EndLine: 10}) {
		t.Error("empty loop lists must not classify anything as loop-only")
	}
	if allSitesInLoops(nil, []parser.Node{}, []parser.Node{}, &db.Function{}) {
		t.Error("no sites must not classify as loop-only")
	}
}
