package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestArrayOOB_LoopBodyCompareNotOverflow(t *testing.T) {
	// The loop CONDITION constrains the index; a `<` comparison inside the
	// body (i < 100) must not be read as the loop bound and turn a safe
	// subscript (i < 4) into a false array-OOB.
	store := runIndexAndDetect(t, "tc72_loop_body_compare.c")
	events, _ := store.ListEventsByType(context.Background(), "BUFFER_ACCESS")

	flagged := map[string]bool{} // function -> reported
	for _, e := range events {
		fn, _ := store.GetFunctionByID(context.Background(), e.EntityID)
		if fn != nil {
			flagged[fn.Name] = true
		}
	}
	if flagged["fp_body_compare"] {
		t.Errorf("fp_body_compare (body i<100) must not be reported as OOB, got %v", flagged)
	}
	if !flagged["tp_loop_oob"] {
		t.Errorf("tp_loop_oob (i<=4) should still be reported as OOB, got %v", flagged)
	}
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

// TestArrayOOB_ReassignedIndexNotConstant pins the C1 fix: a variable assigned a
// constant and then REASSIGNED (to another literal, or to a non-literal call)
// before the subscript is no longer a single constant. The old code froze the
// FIRST constant, so `n = 12; n = 3; buf[10]; buf[n]` was reported as OOB
// (12 >= 10) even though n is actually 3 — a false positive. Both the second
// literal and the non-literal reassignment must now fail the constant proof.
func TestArrayOOB_ReassignedIndexNotConstant(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "reassigned_oob.c")
	src := `int f_literal(void) {
    int n = 12;
    int buf[10];
    n = 3;
    buf[n] = 0;
    return 0;
}
int f_nonliteral(void) {
    int m = 12;
    int buf2[10];
    m = get_index();
    buf2[m] = 0;
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
	for _, e := range events {
		var props struct {
			Array string `json:"array"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Array == "buf" || props.Array == "buf2" {
			t.Errorf("reassigned index %q must not be treated as its earlier constant; got OOB event", props.Array)
		}
	}
}

// TestBufferOverflow_GenericPathCarriesBufferProps pins the F1 props chain:
// every generic buffer_overflow event — and the bounded/secure-copy events —
// must carry the destination name (array) and its resolved capacity (size), so
// the planner hint renders buf@/cap@/idx@ and the classifier can judge from
// the index row without opening the source. The scanf family only names the
// vararg of a buffer-consuming conversion (a numeric conversion's argument is
// not a buffer).
func TestBufferOverflow_GenericPathCarriesBufferProps(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "generic_props.c")
	src := `struct entry { char id[8]; };

void gen_field(struct entry *log) {
    strcpy(log->id, "way_too_long_string_for_this_field");
}

void gen_scanf_buf(void) {
    char buf[64];
    scanf("%s", buf);
}

void gen_scanf_num(int *out) {
    scanf("%d", out);
}

void gen_read(int n) {
    char rbuf[32];
    read(0, rbuf, n);
}

void gen_memcpy_unknown(char *unk, char *src) {
    memcpy(unk, src, 16);
}

void gen_bounded(char *src) {
    char dst[8];
    memcpy(dst, src, 64);
}

void gen_secure(void) {
    char dst[16];
    strcpy_s(dst, 128, "hello");
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
	type want struct {
		category     string
		contains     string
		array        string
		size         string
		sizeArgument string
		copySize     string
		dstCapacity  string
		needSize     bool
		needCopySize bool
		needSizeArg  bool
		needDstCap   bool
	}
	wants := []want{
		{category: "buffer_overflow", contains: "log->id", array: "log->id", size: "8", needSize: true},
		{category: "buffer_overflow", contains: "scanf(\"%s\"", array: "buf", size: "64", needSize: true},
		{category: "buffer_overflow", contains: "read(0", array: "rbuf", size: "32", copySize: "n", needSize: true, needCopySize: true},
		{category: "buffer_overflow", contains: "memcpy(unk", array: "unk", copySize: "16", needCopySize: true},
		{category: "bounded_copy_overflow", contains: "memcpy(dst", array: "dst", size: "8", copySize: "64", dstCapacity: "8", needSize: true, needCopySize: true, needDstCap: true},
		{category: "secure_copy_overflow", contains: "strcpy_s", array: "dst", size: "16", sizeArgument: "128", dstCapacity: "16", needSize: true, needSizeArg: true, needDstCap: true},
	}
	matched := make([]bool, len(wants))
	sawScanfNum := false
	for _, e := range events {
		var props struct {
			Function     string `json:"function"`
			Category     string `json:"category"`
			Expression   string `json:"expression"`
			Array        string `json:"array"`
			Size         string `json:"size"`
			SizeArgument string `json:"size_argument"`
			CopySize     string `json:"copy_size"`
			DstCapacity  string `json:"dst_capacity"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Function == "scanf" && strings.Contains(props.Expression, "%d") {
			sawScanfNum = true
			if props.Array != "" {
				t.Errorf("scanf(\"%%d\") argument is not a buffer; array must stay empty, got %q", props.Array)
			}
			continue
		}
		for i, w := range wants {
			if matched[i] || props.Category != w.category || !strings.Contains(props.Expression, w.contains) {
				continue
			}
			matched[i] = true
			if props.Array != w.array {
				t.Errorf("%s: array = %q, want %q", w.contains, props.Array, w.array)
			}
			if w.needSize && props.Size != w.size {
				t.Errorf("%s: size = %q, want %q", w.contains, props.Size, w.size)
			}
			if !w.needSize && props.Size != "" {
				t.Errorf("%s: size = %q, want empty", w.contains, props.Size)
			}
			if w.needCopySize && props.CopySize != w.copySize {
				t.Errorf("%s: copy_size = %q, want %q", w.contains, props.CopySize, w.copySize)
			}
			if w.needSizeArg && props.SizeArgument != w.sizeArgument {
				t.Errorf("%s: size_argument = %q, want %q", w.contains, props.SizeArgument, w.sizeArgument)
			}
			if w.needDstCap && props.DstCapacity != w.dstCapacity {
				t.Errorf("%s: dst_capacity = %q, want %q", w.contains, props.DstCapacity, w.dstCapacity)
			}
		}
	}
	for i, w := range wants {
		if !matched[i] {
			t.Errorf("expected a %s event containing %q with the destination-buffer props; not found", w.category, w.contains)
		}
	}
	if !sawScanfNum {
		t.Logf("note: scanf(\"%%d\") produced no BUFFER_ACCESS event; the no-array guarantee held vacuously")
	}
}
