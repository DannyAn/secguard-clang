//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_GlobalStoreHeuristicSuppressed pins the global-store
// false positive: a factory whose name matches the allocator heuristic (`_new`)
// stored into a file-scope global must not be an unchecked-return source. The
// "check" for a global is cross-function (invisible to the function-scoped
// detector) and the contract is only a name guess. A local store of the same
// factory is still a lead (contract@unknown), and a declared allocator stored
// into a global is still reported.
func TestUncheckedReturn_GlobalStoreHeuristicSuppressed(t *testing.T) {
	store := runOneDetector(t, "tc_unchecked_return_global_assign.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })

	byFunc := make(map[string]int)
	events, err := store.ListEventsByType(context.Background(), "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	if byFunc["id_init"] != 0 {
		t.Errorf("id_init (global store of a `_new` heuristic factory) must not be an unchecked-return source, got %d event(s)", byFunc["id_init"])
	}
	if byFunc["id_init_local"] != 1 {
		t.Errorf("id_init_local (local store of the same factory) should still be a lead (contract@unknown), expected 1 event, got %d", byFunc["id_init_local"])
	}
	if byFunc["id_init_malloc_global"] != 1 {
		t.Errorf("id_init_malloc_global (declared allocator to a global) must still be reported, expected 1 event, got %d", byFunc["id_init_malloc_global"])
	}
}

// TestUncheckedReturn_GlobalStoreHeuristicSuppressed_CrossFile pins the exact
// production shape: idm_id_init is defined in idm_db_id.c, references
// idm_new_idmgr declared in idm_idmgr.h and implemented in idm_idmgr.c
// (cross-file factory). Storing its result into a file-scope global must not be
// an unchecked-return source, even though the factory is DEFINED in the scan
// tree and genuinely returns NULL on allocation failure — the global's check
// lives at its use sites, not at the store.
func TestUncheckedReturn_GlobalStoreHeuristicSuppressed_CrossFile(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("unchecked_return_crossfile")); err != nil {
		t.Fatalf("index crossfile fixture: %v", err)
	}
	if _, err := NewUncheckedReturnDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	byFunc := make(map[string]int)
	events, err := store.ListEventsByType(context.Background(), "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	if byFunc["idm_id_init"] != 0 {
		t.Errorf("idm_id_init (global store of cross-file `_new` factory) must not be an unchecked-return source, got %d event(s)", byFunc["idm_id_init"])
	}
	// The factory's own malloc is null-checked, so it must not be flagged either.
	if byFunc["idm_new_idmgr"] != 0 {
		t.Errorf("idm_new_idmgr (checked malloc) must not be an unchecked-return source, got %d event(s)", byFunc["idm_new_idmgr"])
	}
}
