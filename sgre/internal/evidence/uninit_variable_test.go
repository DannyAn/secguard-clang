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

func TestUninit_RegcompOutputParam(t *testing.T) {
	store := runIndexAndDetect(t, "tc18_output_param_regcomp.c")
	assertNoEvent(t, store, "VALUE_USE", "RegcompOutputParam")
}

func TestUninit_NeverAssignedFlag(t *testing.T) {
	store := runIndexAndDetect(t, "tc21_uninit_flag.c")
	assertHasEvent(t, store, "VALUE_USE", "UninitFlag")
}

func TestUninit_OutputParamInitializersExpanded(t *testing.T) {
	expected := []string{"regcomp", "regexec", "OpenProcessToken", "GetTokenInformation",
		"RegCreateKeyExA", "RegOpenKeyExA", "GetTempPathA", "GetTempFileNameA",
		"stat", "fstat", "lstat", "gettimeofday", "clock_gettime",
		"strtol", "strtoul", "wcstombs"}
	for _, api := range expected {
		if !isOutputParamInitializer(api) {
			t.Errorf("%s should be in outputParamInitializers", api)
		}
	}
}

func TestUninit_HeapReassignNotHeapUninit(t *testing.T) {
	store := runIndexAndDetect(t, "tc42_heap_reassign.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")

	heapUninit := make(map[string]bool)
	for _, e := range events {
		var props struct {
			Origin   string `json:"origin"`
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin == "heap_uninit" {
			heapUninit[props.Variable] = true
		}
	}
	if heapUninit["q"] {
		t.Error("q should not be reported as heap_uninit after reassignment to &g_fallback")
	}
	if !heapUninit["r"] {
		t.Error("r should still be reported as heap_uninit (genuine uninitialized malloc read)")
	}
}

func TestUninit_FieldOutputParamNotUninit(t *testing.T) {
	// info is filled via &info.field output-params; neither the struct nor its
	// fields are uninitialized. Guards the &field output-param recognition.
	store := runIndexAndDetect(t, "tc43_field_output_param.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "info" {
			t.Errorf("info should not be reported as uninit when filled via &info.field output-params")
		}
	}
}

func TestUninit_AlwaysWriteParamNotUninit(t *testing.T) {
	// fill_point writes *p on every path, so &p initializes p. Guards the
	// ParamWrites interprocedural summary.
	store := runIndexAndDetect(t, "tc44_always_write_param.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "p" {
			t.Errorf("p should not be reported as uninit when fill_point(&p) always writes *p")
		}
	}
}

func TestUninit_ExistingInitializersPreserved(t *testing.T) {
	existing := []string{"pthread_create", "DES_set_key_unchecked", "DES_set_key_checked",
		"pthread_mutex_init", "pthread_cond_init", "pthread_rwlock_init", "sem_init"}
	for _, api := range existing {
		if !isOutputParamInitializer(api) {
			t.Errorf("%s should still be in outputParamInitializers (regression)", api)
		}
	}
}

func TestUninit_ChainedFieldAssignNotRead(t *testing.T) {
	// `info.tm.sec = info.tm.min = info.tm.hour = 0` writes every sub-field; the
	// base `info.tm` is addressed as a write target, not an uninitialized read.
	store := runIndexAndDetect(t, "tc56_chained_field.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")

	flagged := make(map[string]map[string]bool) // variable -> origins
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if flagged[props.Variable] == nil {
			flagged[props.Variable] = map[string]bool{}
		}
		flagged[props.Variable][props.Origin] = true
	}
	if len(flagged["info"]) > 0 {
		t.Errorf("fill_info's info (all sub-fields chained-assigned) must not be flagged, got %v", flagged)
	}
	if !flagged["other"]["struct_partial_uninit"] {
		t.Errorf("partial_init's other (dos never set) should be flagged as struct_partial_uninit, got %v", flagged)
	}
	if flagged["other"]["stack_uninit"] {
		t.Errorf("partial_init's other (a struct value) must not be flagged as stack_uninit, got %v", flagged)
	}
}

func TestUninit_PreprocBranch(t *testing.T) {
	// A variable assigned in BOTH #ifdef/#else branches is definitely
	// initialized (dropped by the planner's flow filter); one assigned in only
	// ONE branch is possibly uninitialized (kept).
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	ctx := context.Background()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc58_preproc_branch.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	NewUninitVariableDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	kept := map[string]bool{}
	for _, c := range res.Candidates {
		kept[c.Target.Function] = true
	}
	if kept["preproc_both_nested"] {
		t.Errorf("preproc_both_nested (x in both preproc branches + else) should be dropped, got %v", kept)
	}
	if !kept["preproc_one_nested"] {
		t.Errorf("preproc_one_nested (x in only one preproc branch) should be kept, got %v", kept)
	}
	if kept["preproc_cross_region"] {
		t.Errorf("preproc_cross_region (x assigned and used under the same #ifdef) should be dropped, got %v", kept)
	}
}

func TestUninit_ChainedAssignNotRead(t *testing.T) {
	// `code = first = index = 0` writes all three; first/index in the RHS are
	// assignment targets, not reads, and must not be reported as uninitialized.
	store := runIndexAndDetect(t, "tc48_chained_assign.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")

	flagged := make(map[string]bool)
	genuine := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
		if props.Variable == "a" {
			genuine = true
		}
	}
	if flagged["first"] || flagged["index"] || flagged["code"] {
		t.Errorf("chained assignment targets must not be reported as uninit, got %v", flagged)
	}
	if !genuine {
		t.Errorf("genuine_uninit's `a` should still be reported, got %v", flagged)
	}
}

func TestUninit_ForInitInitializesLoopVar(t *testing.T) {
	// `for (i=0; i<n; i++)` initializes i in the init clause before the
	// condition; i must not be reported, while a genuinely-uninit while-loop
	// variable must still be.
	store := runIndexAndDetect(t, "tc50_for_init.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")

	flagged := make(map[string]bool)
	genuine := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		flagged[props.Variable] = true
		if props.Variable == "j" {
			genuine = true
		}
	}
	if flagged["i"] {
		t.Errorf("for-init's `i` must not be reported as uninit, got %v", flagged)
	}
	if !genuine {
		t.Errorf("genuine_while_uninit's `j` should still be reported, got %v", flagged)
	}
}

func TestUninit_RwPoolMacroNotUninit(t *testing.T) {
	// RW_POOL_FOR(group_id, pool_id) is a multi-parameter macro whose SECOND
	// parameter is the loop variable it initializes in the for-init clause
	// (`for ((pool_id) = rw_pool_first_group(...); ...)`). Passing a
	// just-declared pool_id to it must NOT be reported as use-before-init even
	// though the call-site argument looks like a by-value read.
	store := runIndexAndDetect(t, "tc78_rw_pool_macro.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "pool_id" {
			t.Errorf("pool_id must not be reported as uninit (RW_POOL_FOR initializes it)")
		}
	}
}

func TestUninit_ThreeParamMacro(t *testing.T) {
	// A 3-parameter macro can write ANY parameter position — SET_THIRD writes its
	// 3rd parameter, SET_FIRST writes its 1st. The written argument must not be
	// reported as uninit, while the read arguments still must. The single-char
	// parameter names (`a`/`b`/`c`) also pin that the write detection uses
	// identifier boundaries — `c` must not be mistaken for a substring of the
	// callee `combine`.
	store := runIndexAndDetect(t, "tc79_three_param_macro.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")
	flagged := make(map[string]bool)
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin == "stack_uninit" {
			flagged[props.Variable] = true
		}
	}
	// writes_third: a1,b1 read → reported; c1 written → not reported.
	// writes_first: b2,c2 read → reported; a2 written → not reported.
	for _, v := range []string{"a1", "b1", "b2", "c2"} {
		if !flagged[v] {
			t.Errorf("%s (read argument) should be reported as uninit", v)
		}
	}
	for _, v := range []string{"c1", "a2"} {
		if flagged[v] {
			t.Errorf("%s (written argument) must not be reported as uninit", v)
		}
	}
}

func TestUninit_VaListVaStartNotUninit(t *testing.T) {
	// va_start/va_copy's first argument is the va_list they initialize (a write
	// target), not a read of its current value. The va_start line must not
	// report the just-declared va_list as stack_uninit, while a genuine
	// use-before-va_start still must.
	store := runIndexAndDetect(t, "tc71_va_list.c")
	events, _ := store.ListEventsByType(context.Background(), "VALUE_USE")

	// function -> variable -> true, for stack_uninit events only.
	stackUninit := map[string]map[string]bool{}
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin != "stack_uninit" {
			continue
		}
		fn, _ := store.GetFunctionByID(context.Background(), e.EntityID)
		if fn == nil {
			continue
		}
		if stackUninit[fn.Name] == nil {
			stackUninit[fn.Name] = map[string]bool{}
		}
		stackUninit[fn.Name][props.Variable] = true
	}

	if stackUninit["va_ok"]["args"] {
		t.Errorf("va_ok's args must not be reported as stack_uninit (va_start initializes it), got %v", stackUninit)
	}
	if stackUninit["va_copy_ok"]["copy"] {
		t.Errorf("va_copy_ok's copy must not be reported as stack_uninit (va_copy initializes it), got %v", stackUninit)
	}
	if !stackUninit["va_use_before_start"]["args"] {
		t.Errorf("va_use_before_start's args (used before va_start) should be reported as stack_uninit, got %v", stackUninit)
	}
}
