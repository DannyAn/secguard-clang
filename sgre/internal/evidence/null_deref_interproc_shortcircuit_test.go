//go:build !nosqlite

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

// Short-circuit protection on the guard line: a callee whose parameter
// dereference sits ON the null-guard condition line (`p == NULL || !p->field`,
// `p == NULL || p[0] == '\0'`) is guarded by the short-circuit evaluation —
// the right operand only evaluates when p is non-null. The interprocedural
// detector must NOT treat such a parameter as unguarded and must not
// synthesize a DEREFERENCE event at the caller. A callee that dereferences
// its parameter with no guard at all must still produce the event.
const interprocShortCircuitFixture = `#include <stdlib.h>

typedef struct {
    int is_used;
    unsigned int value;
} idm_record_t;

unsigned int idm_get_import_result(const idm_record_t *record)
{
    if (record == NULL || !record->is_used) {
        return 0xFFFFFFFFu;
    }
    return record->value;
}

int idm_custom_portal_delete_unused_image(const char *file_name)
{
    if (file_name == NULL || file_name[0] == '\0') {
        return 0;
    }
    return 1;
}

static int unguarded_get(const idm_record_t *record)
{
    return record->value;
}

int main(void)
{
    idm_record_t *rec = malloc(sizeof *rec);
    const char *name = (const char *)malloc(8);
    (void)idm_get_import_result(rec);
    (void)idm_custom_portal_delete_unused_image(name);
    (void)unguarded_get(rec);
    free(rec);
    free((void *)name);
    return 0;
}
`

func TestInterproceduralShortCircuitGuardedParam(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "shortcircuit.c")
	if err := os.WriteFile(path, []byte(interprocShortCircuitFixture), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}

	NewNullSourceDetector(store, p, logger).Detect(ctx)
	NewDereferenceDetector(store, p, logger).Detect(ctx)
	NewNullGuardDetector(store, p, logger).Detect(ctx)
	NewInterproceduralDetector(store, p, logger).Detect(ctx)

	events, err := store.ListEventsByType(ctx, "DEREFERENCE")
	if err != nil {
		t.Fatalf("list dereference events: %v", err)
	}
	interprocByCallee := map[string]int{}
	for _, e := range events {
		var props struct {
			Origin string `json:"origin"`
			Callee string `json:"callee"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if props.Origin == "interprocedural" {
			interprocByCallee[props.Callee]++
		}
	}

	for _, callee := range []string{"idm_get_import_result", "idm_custom_portal_delete_unused_image"} {
		if n := interprocByCallee[callee]; n != 0 {
			t.Errorf("callee %s: short-circuit-guarded parameter must not synthesize an interprocedural dereference, got %d", callee, n)
		}
	}
	if n := interprocByCallee["unguarded_get"]; n == 0 {
		t.Errorf("callee unguarded_get: an unguarded dereferenced parameter passed a nullable variable must keep the interprocedural dereference event (true-positive control)")
	}
}
