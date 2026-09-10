//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// setupDetector indexes one fixture and builds call graph + data flow, returning
// the store and parser a single detector needs. A gap test then asserts BOTH the
// "missed" pattern (no event) AND a positive control (event), so a broken
// detector cannot make the gap assertion pass vacuously.
func setupDetector(t *testing.T, fixture string) (db.Store, *parser.Parser) {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath(fixture)); err != nil {
		t.Fatalf("index %s: %v", fixture, err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	return store, p
}

func eventFuncs(t *testing.T, store db.Store, eventType string) map[string]bool {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("list %s: %v", eventType, err)
	}
	out := map[string]bool{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		out[fn.Name] = true
	}
	return out
}

func eventVars(t *testing.T, store db.Store, eventType string) map[string]bool {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("list %s: %v", eventType, err)
	}
	out := map[string]bool{}
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			if v := props["variable"]; v != "" {
				out[v] = true
			}
		}
	}
	return out
}

// TestIntegerOverflow_CallocVariants locks in the fixed calloc(n, sizeof(T)) and
// calloc(n, CONST) blind spots: the implicit product is now flagged with the same
// categories as the explicit malloc(n * sizeof(T)) / malloc(n * 2) forms, while
// constant * constant / constant * sizeof stay unflagged.
func TestIntegerOverflow_CallocVariants(t *testing.T) {
	store, p := setupDetector(t, "tc93_int_overflow_calloc_sizeof.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewIntegerOverflowDetector(store, p, logger).Detect(context.Background())

	flagged := eventFuncs(t, store, "INTEGER_OVERFLOW")
	for _, fn := range []string{
		"calloc_var_sizeof", "calloc_sizeof_var", "calloc_param_const",
		"calloc_const_param", "calloc_var_var", "malloc_var_sizeof",
		"malloc_nested_product", "malloc_assigned_product", "wrapper_alloc",
		"vos_malloc", "vos_malloc_f",
	} {
		if !flagged[fn] {
			t.Errorf("%s: expected INTEGER_OVERFLOW, got none", fn)
		}
	}
	for _, fn := range []string{"calloc_const_const", "calloc_const_sizeof", "calloc_var_sizeof_char", "calloc_var_const_one", "malloc_constant", "malloc_assigned_constant", "wrapper_alloc_constant", "vos_free"} {
		if flagged[fn] {
			t.Errorf("%s: expected NO INTEGER_OVERFLOW (safe product), got flagged", fn)
		}
	}
}

// TestSizeofMisuse_TypedefPointer locks in the typedef-pointer fix: `sizeof(s)`
// on a pointer typedef'd parameter is now flagged, while `sizeof(*s)` and a
// non-pointer typedef remain unflagged.
func TestSizeofMisuse_TypedefPointer(t *testing.T) {
	store, p := setupDetector(t, "tc94_sizeof_typedef_pointer.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewSizeofMisuseDetector(store, p, logger).Detect(context.Background())

	flagged := eventFuncs(t, store, "SIZEOF_MISUSE")
	if !flagged["typedef_pointer"] {
		t.Error("typedef'd pointer param sizeof(s) should be flagged")
	}
	if !flagged["explicit_pointer"] {
		t.Error("explicit char*q sizeof(q) should be flagged")
	}
	if !flagged["file_scope_pointer"] {
		t.Error("file-scope char* sizeof(g_buf) should be flagged")
	}
	if flagged["typedef_deref"] {
		t.Error("sizeof(*s) on a typedef'd pointer is sizeof(char) and must NOT be flagged")
	}
	if flagged["non_pointer_typedef"] {
		t.Error("sizeof(n) on a non-pointer typedef must NOT be flagged")
	}
}

// TestHardcodedSecret_EntropyAndStructured locks in the value-entropy fix: a
// high-entropy literal with a non-secret name is flagged, a name-matched
// password is flagged, while a structured URL and a whitespace sentence are not.
func TestHardcodedSecret_EntropyAndStructured(t *testing.T) {
	store, p := setupDetector(t, "tc95_hardcoded_secret_value_only.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewHardcodedSecretDetector(store, p, logger).Detect(context.Background())

	flagged := eventVars(t, store, "HARDCODED_SECRET")
	if !flagged["high_entropy"] {
		t.Error("high-entropy literal with non-secret name should be flagged (entropy analysis)")
	}
	if !flagged["password"] {
		t.Error("name-matched password should be flagged")
	}
	if !flagged["conn"] {
		t.Error("URL with embedded credentials should be flagged")
	}
	if !flagged["db_password"] {
		t.Error("designated initializer .db_password should be flagged")
	}
	if flagged["url"] {
		t.Error("URL without credentials must NOT be flagged")
	}
	if flagged["note"] {
		t.Error("whitespace sentence should NOT be flagged")
	}
}

// TestHardcodedSecret_ZeroFunctionFile locks in the data-only-file fix: a
// file-scope secret in a .c file with no function is now scanned and flagged.
func TestHardcodedSecret_ZeroFunctionFile(t *testing.T) {
	store, p := setupDetector(t, "tc96_hardcoded_secret_zero_func.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewHardcodedSecretDetector(store, p, logger).Detect(context.Background())

	flagged := eventVars(t, store, "HARDCODED_SECRET")
	if !flagged["password"] {
		t.Error("file-scope secret in a data-only file should now be flagged")
	}
}

// TestOutOfBounds_GlobalArray locks in the file-scope array-size fix: a
// constant OOB read of a global `int arr[10]` is now resolved (findArraySize
// accepts file-scope declarations), alongside the same-function local case.
func TestOutOfBounds_GlobalArray(t *testing.T) {
	store, p := setupDetector(t, "tc97_oob_global_array.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewBufferOverflowDetector(store, p, logger).Detect(context.Background())

	// out-of-bounds seeds BUFFER_ACCESS with category array_oob_read.
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list BUFFER_ACCESS: %v", err)
	}
	readOOBFuncs := map[string]bool{}
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		if props["category"] != "array_oob_read" {
			continue
		}
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err == nil && fn != nil {
			readOOBFuncs[fn.Name] = true
		}
	}
	if !readOOBFuncs["global_missed"] {
		t.Error("file-scope array constant OOB read should now be flagged")
	}
	if !readOOBFuncs["macro_missed"] {
		t.Error("macro-sized array constant OOB read should now be flagged")
	}
	if !readOOBFuncs["local_flagged"] {
		t.Error("same-function constant OOB read should be flagged")
	}
}

// TestRaceCondition_AddrTakenThread locks in the address-taken thread-fn fix:
// `pthread_create(..., &worker, ...)` is now recognized, so two such threads
// writing a shared global produce a shared_data_race event.
func TestRaceCondition_AddrTakenThread(t *testing.T) {
	store, p := setupDetector(t, "tc98_race_addr_taken_thread.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewRaceConditionDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}
	found := false
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props["category"] == "shared_data_race" {
			found = true
		}
	}
	if !found {
		t.Error("&worker thread fns writing a shared global should now produce a shared_data_race")
	}
}

// TestRaceCondition_RwlockProtected locks in the rwlock/spinlock/C11 recognition:
// two thread fns writing a shared global under the SAME rwlock must NOT be a
// race (the lock was previously invisible, producing a false positive).
func TestRaceCondition_RwlockProtected(t *testing.T) {
	store, p := setupDetector(t, "tc99_race_rwlock.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewRaceConditionDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props["category"] == "shared_data_race" {
			t.Error("rwlock-protected shared writes must NOT be a shared_data_race")
		}
	}
}

// TestRaceCondition_ExternGlobal locks in the cross-file extern fix: a global
// declared `extern` in a header and written by two thread fns is a race.
func TestRaceCondition_ExternGlobal(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("race_extern")); err != nil {
		t.Fatalf("index race_extern: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewRaceConditionDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}
	found := false
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) == nil &&
			props["category"] == "shared_data_race" && props["variable"] == "shared_counter" {
			found = true
		}
	}
	if !found {
		t.Error("extern-declared shared_counter written by two thread fns should be a shared_data_race")
	}
}

// TestDivideByZero_DefiniteZeroAutoConfirm locks in the definite-zero auto-confirm:
// a literal `x/0`, a zero-valued symbol `x/ZERO`, and a `d=0` assignment are all
// confirmed by the pipeline, while an unknown divisor `x/d` stays suspected for
// the AI agent.
func TestDivideByZero_DefiniteZeroAutoConfirm(t *testing.T) {
	store, p := setupDetector(t, "tc100_divide_by_zero_definite.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDivideByZeroDetector(store, p, logger).Detect(context.Background())

	// Detector-level: only the syntactic definite-zero cases carry the marker.
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, "DIVIDE_BY_ZERO")
	if err != nil {
		t.Fatalf("list DIVIDE_BY_ZERO: %v", err)
	}
	marked := map[string]bool{}
	for _, e := range events {
		var props map[string]string
		if json.Unmarshal([]byte(e.Properties), &props) == nil && props["definitely_zero"] == "true" {
			fn, _ := store.GetFunctionByID(ctx, e.EntityID)
			if fn != nil {
				marked[fn.Name] = true
			}
		}
	}
	if !marked["lit"] {
		t.Error("x/0 literal should be marked definitely_zero")
	}
	if !marked["sym"] {
		t.Error("x/ZERO symbol should be marked definitely_zero")
	}
	if marked["var_div"] {
		t.Error("unknown divisor x/d must NOT be marked definitely_zero")
	}

	// Planner-level: all three definite-zero shapes confirm, the unknown stays
	// suspected.
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan divide-by-zero: %v", err)
	}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}
	for _, fn := range []string{"lit", "sym", "assigned"} {
		if suspicion[fn] != "confirmed" {
			t.Errorf("%s: expected confirmed, got %q", fn, suspicion[fn])
		}
	}
	if suspicion["var_div"] != "suspected" {
		t.Errorf("var_div: expected suspected, got %q", suspicion["var_div"])
	}
}

// TestDivideByZero_ParamZeroPropagation locks in the parameter zero-propagation
// over the semantic graph: a divisor that is a function parameter is auto-confirmed
// when a caller passes literal 0, auto-dismissed when every caller passes a
// non-zero constant, and left suspected when a caller passes an unknown value.
func TestDivideByZero_ParamZeroPropagation(t *testing.T) {
	store, p := setupDetector(t, "tc101_divide_by_zero_param.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDivideByZeroDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan divide-by-zero: %v", err)
	}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}
	if suspicion["div_param"] != "confirmed" {
		t.Errorf("div_param (caller passes 0): expected confirmed, got %q", suspicion["div_param"])
	}
	if _, present := suspicion["div_param2"]; present {
		t.Errorf("div_param2 (caller passes non-zero): expected dismissed, got %q", suspicion["div_param2"])
	}
	if suspicion["div_param3"] != "suspected" {
		t.Errorf("div_param3 (caller passes variable): expected suspected, got %q", suspicion["div_param3"])
	}
}

// TestUninit_MacroLoopAndSetterMacro locks in two uninit false-positive fixes:
// (1) an assignment inside a single-macro loop body (`LCORE_FOREACH_SLAVE(x){ ret
// = ...; }`, misparsed as a nested function_definition) kills the uninit source;
// (2) a third-party parse macro that writes a by-value struct argument
// (`CAP_MSG_HEAD_PARSE(msg, head)`) is not a read of an uninitialized struct.
func TestUninit_MacroLoopAndSetterMacro(t *testing.T) {
	for _, fx := range []string{"tc102_uninit_macro_loop.c", "tc103_uninit_setter_macro.c"} {
		store, p := setupDetector(t, fx)
		logger := log.New(io.Discard, log.LevelWarn)
		NewUninitVariableDetector(store, p, logger).Detect(context.Background())

		ctx := context.Background()
		pl := planner.NewPlanner(store, p, logger)
		res, err := pl.Plan(ctx, "uninit")
		if err != nil {
			t.Fatalf("%s: plan uninit: %v", fx, err)
		}
		if len(res.Candidates) != 0 {
			t.Errorf("%s: expected 0 uninit candidates (false positive), got %d", fx, len(res.Candidates))
		}
	}
}

// TestDivideByZero_UnlikelyGuard locks in the branch-hint guard fix: an
// early-return guard wrapped in unlikely() (`if (unlikely(d == 0)) return;`)
// still establishes d != 0 on the fall-through, so the later `% d` is not a
// divide-by-zero — while an unguarded `100 / d` stays suspected.
func TestDivideByZero_UnlikelyGuard(t *testing.T) {
	store, p := setupDetector(t, "tc104_divide_by_zero_unlikely.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewDivideByZeroDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "divide-by-zero")
	if err != nil {
		t.Fatalf("plan divide-by-zero: %v", err)
	}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}
	if _, present := suspicion["f"]; present {
		t.Errorf("f (unlikely-guarded divisor) should NOT be flagged, got %q", suspicion["f"])
	}
	if suspicion["g"] != "suspected" {
		t.Errorf("g (unguarded divisor) should stay suspected, got %q", suspicion["g"])
	}
}

// TestUncheckedReturn_DerefCheck locks in the pointer-deref check fix: a malloc
// result stored through a pointer (`*retMsg = malloc(n)`) and then checked via
// the dereference (`if (*retMsg == NULL)`) is a checked return, while a plain
// `char *p = malloc(n); p[0] = ...` without any check stays flagged.
func TestUncheckedReturn_DerefCheck(t *testing.T) {
	store, p := setupDetector(t, "tc105_unchecked_return_ptr.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewUncheckedReturnDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "unchecked-return")
	if err != nil {
		t.Fatalf("plan unchecked-return: %v", err)
	}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}
	if _, present := suspicion["testcase"]; present {
		t.Errorf("testcase (*retMsg checked via deref) should NOT be flagged, got %q", suspicion["testcase"])
	}
	if suspicion["g"] != "confirmed" {
		t.Errorf("g (unchecked malloc use) should stay confirmed, got %q", suspicion["g"])
	}
}

// TestNullDeref_CastReassign locks in the MUST-dataflow fix: a pointer assigned
// NULL and then REASSIGNED from a cast-wrapped call (`v = (T *)f()`) is no longer
// "certain null" — the reassignment clears the NULL fact, so the later deref is
// at most suspected (the call result may still be null), never confirmed. A plain
// `v = NULL; v->f` without reassignment stays confirmed.
func TestNullDeref_CastReassign(t *testing.T) {
	store, p := setupDetector(t, "tc106_null_deref_cast_reassign.c")
	logger := log.New(io.Discard, log.LevelWarn)
	NewNullSourceDetector(store, p, logger).Detect(context.Background())
	NewDereferenceDetector(store, p, logger).Detect(context.Background())
	NewInterproceduralDetector(store, p, logger).Detect(context.Background())

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}
	suspicion := map[string]string{}
	for _, c := range res.Candidates {
		suspicion[c.Target.Function] = c.SuspicionLevel
	}
	if suspicion["fill_info"] == "confirmed" {
		t.Error("fill_info (NULL reassigned from a call) should NOT be certain-null/confirmed")
	}
	if suspicion["certain_null"] != "confirmed" {
		t.Errorf("certain_null (no reassignment) should stay confirmed, got %q", suspicion["certain_null"])
	}
}
