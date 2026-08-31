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

// TestNewDetector_DivideByZero_VariableProperty pins the root-cause field: the
// DIVIDE_BY_ZERO event must carry `variable` = divisor (not the whole division
// expression), otherwise the planner seed falls back to `expression` text and
// the dedup key + report "Variable" column show "x / y" instead of "y".
func TestNewDetector_DivideByZero_VariableProperty(t *testing.T) {
	store := runOneDetector(t, "tc59_divide_by_zero.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "DIVIDE_BY_ZERO")
	if err != nil {
		t.Fatalf("list DIVIDE_BY_ZERO events: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected DIVIDE_BY_ZERO events, got none")
	}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Divisor  string `json:"divisor"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("unmarshal properties: %v", err)
		}
		if props.Variable == "" {
			t.Errorf("DIVIDE_BY_ZERO event missing `variable` property: %s", e.Properties)
		}
		if props.Variable != props.Divisor {
			t.Errorf("variable %q != divisor %q", props.Variable, props.Divisor)
		}
	}
}

func TestNewDetector_DivideByZero_ReassignmentGuard(t *testing.T) {
	store := runOneDetector(t, "tc71_divide_by_zero_guard.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	if got := eventCount(t, store, "DIVIDE_BY_ZERO"); got != 1 {
		t.Errorf("expected 1 DIVIDE_BY_ZERO event (clamp/negate/compound guards suppressed), got %d", got)
	}
}

// TestNewDetector_DivideByZero_ConstantSymbols pins the deterministic
// constant-symbol suppression: a divisor spelled as a non-zero macro / enumerator
// / top-level const is dropped at the detector (like a literal), while a complex
// macro body (`(1u << 3)`), a zero macro, and a plain variable still emit.
func TestNewDetector_DivideByZero_ConstantSymbols(t *testing.T) {
	store := runOneDetector(t, "tc80_divide_by_zero_const.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	if got := eventCount(t, store, "DIVIDE_BY_ZERO"); got != 3 {
		t.Errorf("expected 3 DIVIDE_BY_ZERO events (macro/enum/const constants suppressed; shift-expr/zero/var kept), got %d", got)
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
	if got := eventCount(t, store, "SIZEOF_MISUSE"); got != 4 {
		t.Errorf("expected 4 SIZEOF_MISUSE events (char **p, char *q, char *buf, cstr_t *s), got %d", got)
	}
	// The single-pointer `sizeof(q)` and `sizeof(buf)` are the provable CWE-467
	// defect; the pointer-to-pointer `sizeof(p)` and the pointer-typedef
	// `cstr_t *s` are only suspected.
	assertEventCategory(t, store, "SIZEOF_MISUSE", "sizeof_pointer", "tc62_sizeof_misuse")
	events, err := store.ListEventsByType(context.Background(), "SIZEOF_MISUSE")
	if err != nil {
		t.Fatalf("list SIZEOF_MISUSE events: %v", err)
	}
	confirmed := 0
	for _, e := range events {
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Category == "sizeof_pointer" {
			confirmed++
		}
	}
	if confirmed != 2 {
		t.Errorf("expected 2 confirmed sizeof_pointer events (char *q, char *buf), got %d", confirmed)
	}
}

func TestNewDetector_SignedCompare(t *testing.T) {
	store := runOneDetector(t, "tc63_signed_compare.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignedCompareDetector(s, p, l) })
	if got := eventCount(t, store, "SIGNED_COMPARE"); got != 5 {
		t.Errorf("expected 5 SIGNED_COMPARE events (size_t param, uint32_t param, size_t local, unsigned int init, my_uint typedef), got %d", got)
	}
}

func TestNewDetector_SignedCompare_CrossFileTypedef(t *testing.T) {
	// my_uint is declared in types.h, not main.c — the detector must resolve it
	// across files to flag the always-false comparison.
	store := runOneDetector(t, "tc73_cross_file_typedef",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignedCompareDetector(s, p, l) })
	if got := eventCount(t, store, "SIGNED_COMPARE"); got != 1 {
		t.Errorf("expected 1 SIGNED_COMPARE event (header my_uint param), got %d", got)
	}
}

func TestNewDetector_SignedCompare_UintTypes(t *testing.T) {
	// uint8_t/uint16_t/uint32_t (and size_t/unsigned int) all resolve to
	// unsigned, so the tautological comparisons (a<0, b>=0, c<=-1, 0>c, 0<=b)
	// are flagged — but `> 0` (non-zero) and `<= 0` (zero) checks are
	// legitimate and must NOT be flagged.
	store := runOneDetector(t, "tc77_signed_compare_uint.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignedCompareDetector(s, p, l) })
	if got := eventCount(t, store, "SIGNED_COMPARE"); got != 5 {
		t.Errorf("expected 5 SIGNED_COMPARE events (a<0, b>=0, c<=-1, 0>c, 0<=b), got %d", got)
	}
}

func TestNewDetector_SizeofMisuse_CrossFileTypedef(t *testing.T) {
	// cstr_t resolves to `char *` via types.h, so `cstr_t *s` is char** and
	// sizeof(s) is only suspected; my_uint *p is a plain pointer, hence confirmed.
	store := runOneDetector(t, "tc73_cross_file_typedef",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSizeofMisuseDetector(s, p, l) })
	if got := eventCount(t, store, "SIZEOF_MISUSE"); got != 2 {
		t.Errorf("expected 2 SIZEOF_MISUSE events (cstr_t *s ambig, my_uint *p confirmed), got %d", got)
	}
	events, err := store.ListEventsByType(context.Background(), "SIZEOF_MISUSE")
	if err != nil {
		t.Fatalf("list SIZEOF_MISUSE events: %v", err)
	}
	confirmed, ambig := 0, 0
	for _, e := range events {
		var props struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		switch props.Category {
		case "sizeof_pointer":
			confirmed++
		case "sizeof_pointer_ambig":
			ambig++
		}
	}
	if confirmed != 1 || ambig != 1 {
		t.Errorf("expected 1 confirmed + 1 ambig sizeof events, got %d confirmed + %d ambig", confirmed, ambig)
	}
}
