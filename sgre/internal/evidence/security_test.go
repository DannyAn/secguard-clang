package evidence

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func runFullPipeline(t *testing.T, fixture string) (*planner.PlanResult, db.Store) {
	t.Helper()
	ctx := context.Background()

	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath(fixture)); err != nil {
		t.Fatalf("index failed for %s: %v", fixture, err)
	}

	cgBuilder := graph.NewCallGraphBuilder(store, p, logger)
	if _, err := cgBuilder.Build(ctx); err != nil {
		t.Fatalf("call graph build failed: %v", err)
	}

	dfBuilder := graph.NewDataFlowBuilder(store, p, logger)
	if _, err := dfBuilder.Build(ctx); err != nil {
		t.Fatalf("data flow build failed: %v", err)
	}

	nsDetector := NewNullSourceDetector(store, p, logger)
	if _, err := nsDetector.Detect(ctx); err != nil {
		t.Fatalf("null source detect failed: %v", err)
	}

	derefDetector := NewDereferenceDetector(store, p, logger)
	if _, err := derefDetector.Detect(ctx); err != nil {
		t.Fatalf("dereference detect failed: %v", err)
	}

	guardDetector := NewNullGuardDetector(store, p, logger)
	if _, err := guardDetector.Detect(ctx); err != nil {
		t.Fatalf("null guard detect failed: %v", err)
	}

	interDetector := NewInterproceduralDetector(store, p, logger)
	if _, err := interDetector.Detect(ctx); err != nil {
		t.Fatalf("interprocedural detect failed: %v", err)
	}

	pl := planner.NewPlanner(store, nil, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan failed: %v", err)
	}

	return result, store
}

func runIndexAndDetect(t *testing.T, fixture string) db.Store {
	t.Helper()
	ctx := context.Background()

	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath(fixture)); err != nil {
		t.Fatalf("index failed for %s: %v", fixture, err)
	}

	nsDetector := NewNullSourceDetector(store, p, logger)
	nsDetector.Detect(ctx)

	derefDetector := NewDereferenceDetector(store, p, logger)
	derefDetector.Detect(ctx)

	guardDetector := NewNullGuardDetector(store, p, logger)
	guardDetector.Detect(ctx)

	memDetector := NewMemoryLeakDetector(store, p, logger)
	memDetector.Detect(ctx)

	boDetector := NewBufferOverflowDetector(store, p, logger)
	boDetector.Detect(ctx)

	injDetector := NewInjectionDetector(store, p, logger)
	injDetector.Detect(ctx)

	resDetector := NewResourceLeakDetector(store, p, logger)
	resDetector.Detect(ctx)

	uninitDetector := NewUninitVariableDetector(store, p, logger)
	uninitDetector.Detect(ctx)

	intOverflowDetector := NewIntegerOverflowDetector(store, p, logger)
	intOverflowDetector.Detect(ctx)

	raceDetector := NewRaceConditionDetector(store, p, logger)
	raceDetector.Detect(ctx)

	secretDetector := NewHardcodedSecretDetector(store, p, logger)
	secretDetector.Detect(ctx)

	deadlockDetector := NewDeadlockDetector(store, p, logger)
	deadlockDetector.Detect(ctx)

	cryptoDetector := NewCryptoMisuseDetector(store, p, logger)
	cryptoDetector.Detect(ctx)

	return store
}

func assertHasFinding(t *testing.T, result *planner.PlanResult, fixture string) {
	t.Helper()
	if result.CandidateCount() == 0 {
		t.Errorf("%s: expected at least 1 finding, got 0", fixture)
	}
}

func assertNoFinding(t *testing.T, result *planner.PlanResult, fixture string) {
	t.Helper()
	if result.CandidateCount() > 0 {
		t.Errorf("%s: expected 0 findings (safe pattern), got %d", fixture, result.CandidateCount())
	}
}

func assertHasEvent(t *testing.T, store db.Store, eventType, fixture string) {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("%s: failed to list events: %v", fixture, err)
	}
	if len(events) == 0 {
		t.Errorf("%s: expected at least 1 %s event, got 0", fixture, eventType)
	}
}

func assertNoEvent(t *testing.T, store db.Store, eventType, fixture string) {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("%s: failed to list events: %v", fixture, err)
	}
	if len(events) > 0 {
		t.Errorf("%s: expected 0 %s events (safe pattern), got %d", fixture, eventType, len(events))
	}
}

func assertEventCategory(t *testing.T, store db.Store, eventType, category, fixture string) {
	t.Helper()
	ctx := context.Background()
	events, err := store.ListEventsByType(ctx, eventType)
	if err != nil {
		t.Fatalf("%s: failed to list events: %v", fixture, err)
	}
	for _, e := range events {
		var props map[string]interface{}
		if json.Unmarshal([]byte(e.Properties), &props) != nil {
			continue
		}
		if props["category"] == category {
			return
		}
	}
	t.Errorf("%s: expected %s event with category %q, got %d events", fixture, eventType, category, len(events))
}

func TestSecurity_TC01_NullReturn(t *testing.T) {
	result, _ := runFullPipeline(t, "tc01_null_return.c")
	assertHasFinding(t, result, "TC01")
}

func TestSecurity_TC02_MallocFailure(t *testing.T) {
	result, _ := runFullPipeline(t, "tc02_malloc_failure.c")
	assertHasFinding(t, result, "TC02")
}

func TestSecurity_TC03_CheckedPointer(t *testing.T) {
	result, _ := runFullPipeline(t, "tc03_checked_pointer.c")
	assertNoFinding(t, result, "TC03")
}

func TestSecurity_TC04_Interprocedural(t *testing.T) {
	result, _ := runFullPipeline(t, "tc04_interprocedural.c")
	assertHasFinding(t, result, "TC04")
}

func TestSecurity_TC05_MemleakNoFree(t *testing.T) {
	store := runIndexAndDetect(t, "tc05_memleak_no_free.c")
	assertHasEvent(t, store, "MEMORY_ALLOC", "TC05")
	assertNoEvent(t, store, "MEMORY_RELEASE", "TC05")
}

func TestSecurity_TC06_MemleakErrorPath(t *testing.T) {
	store := runIndexAndDetect(t, "tc06_memleak_error_path.c")
	assertHasEvent(t, store, "MEMORY_ALLOC", "TC06")

}

func TestSecurity_TC07_ResleakFile(t *testing.T) {
	store := runIndexAndDetect(t, "tc07_resleak_file.c")
	assertHasEvent(t, store, "RESOURCE_ACQUIRE", "TC07")
	assertNoEvent(t, store, "RESOURCE_RELEASE", "TC07")
}

func TestSecurity_TC08_ResleakErrorPath(t *testing.T) {
	store := runIndexAndDetect(t, "tc08_resleak_error_path.c")
	assertHasEvent(t, store, "RESOURCE_ACQUIRE", "TC08")
	assertHasEvent(t, store, "RESOURCE_RELEASE", "TC08")
}

func TestSecurity_TC09_ResleakSocket(t *testing.T) {
	store := runIndexAndDetect(t, "tc09_resleak_socket.c")
	assertHasEvent(t, store, "RESOURCE_ACQUIRE", "TC09")
	assertNoEvent(t, store, "RESOURCE_RELEASE", "TC09")
}

func TestSecurity_TC10_ResleakLock(t *testing.T) {
	store := runIndexAndDetect(t, "tc10_resleak_lock.c")
	assertHasEvent(t, store, "RESOURCE_ACQUIRE", "TC10")
	assertNoEvent(t, store, "RESOURCE_RELEASE", "TC10")
}

func TestSecurity_TC11_UninitStack(t *testing.T) {
	store := runIndexAndDetect(t, "tc11_uninit_stack.c")
	assertHasEvent(t, store, "VALUE_USE", "TC11")
}

func TestSecurity_TC12_UninitHeap(t *testing.T) {
	store := runIndexAndDetect(t, "tc12_uninit_heap.c")
	assertHasEvent(t, store, "VALUE_USE", "TC12")
}

func TestSecurity_TC13_UninitCallocSafe(t *testing.T) {
	store := runIndexAndDetect(t, "tc13_uninit_calloc_safe.c")
	assertNoEvent(t, store, "VALUE_USE", "TC13")
}

func TestSecurity_TC14_UninitStaticSafe(t *testing.T) {
	store := runIndexAndDetect(t, "tc14_uninit_static_safe.c")
	assertNoEvent(t, store, "VALUE_USE", "TC14")
}

func TestSecurity_TC15_UninitConditional(t *testing.T) {
	store := runIndexAndDetect(t, "tc15_uninit_conditional.c")
	assertHasEvent(t, store, "VALUE_USE", "TC15")
}

func TestSecurity_TC16_UninitInterprocedural(t *testing.T) {
	store := runIndexAndDetect(t, "tc16_uninit_interprocedural.c")
	assertHasEvent(t, store, "VALUE_USE", "TC16")
}

func TestSecurity_TC17_UninitStructPartial(t *testing.T) {
	store := runIndexAndDetect(t, "tc17_uninit_struct_partial.c")
	assertHasEvent(t, store, "VALUE_USE", "TC17")
}
