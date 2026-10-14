//go:build !nosqlite

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
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func indexDetect(t *testing.T, src, detector string) (db.Store, map[string][]string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "q.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	if _, err := indexer.NewIndexer(store, logger).Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	var d Detector
	switch detector {
	case "unchecked":
		d = NewUncheckedReturnDetector(store, p, logger)
	case "uaf":
		d = NewUseAfterFreeDetector(store, p, logger)
	case "dangerous":
		d = NewDangerousFunctionDetector(store, p, logger)
	default:
		t.Fatalf("unknown detector %s", detector)
	}
	if _, err := d.Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	types := map[string]string{"unchecked": "UNCHECKED_RETURN", "uaf": "USE_AFTER_FREE", "dangerous": "DANGEROUS_FUNCTION"}
	events, err := store.ListEventsByType(ctx, types[detector])
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	byFunc := map[string][]string{}
	for _, e := range events {
		fn, err := store.GetFunctionByID(ctx, e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		var props map[string]interface{}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		byFunc[fn.Name] = append(byFunc[fn.Name], e.Properties)
	}
	return store, byFunc
}

// TestUseAfterFree_FieldWriteThroughFreedBase pins the write-after-free shape:
// `free(p); p->n = 1;` stores into freed memory and must be reported, while the
// field-free idiom `free(s->msg); s->msg = NULL;` must not (only the field was
// freed, and assigning it does not read through the freed pointer).
func TestUseAfterFree_FieldWriteThroughFreedBase(t *testing.T) {
	_, byFunc := indexDetect(t, `#include <stdlib.h>
typedef struct node { int n; struct node *next; } node_t;
typedef struct state { char *msg; int mode; } state_t;

void write_after_whole_free(void) {
    node_t *p = malloc(sizeof(node_t));
    free(p);
    p->n = 1;
    p->next = 0;
}

void clear_msg_field(state_t *s) {
    free(s->msg);
    s->msg = NULL;
}

int read_other_field_after_field_free(state_t *s) {
    free(s->msg);
    return s->mode;
}
`, "uaf")

	if len(byFunc["write_after_whole_free"]) == 0 {
		t.Errorf("write_after_whole_free: `p->n = 1` after free(p) is a use-after-free write, expected events, got none")
	}
	if len(byFunc["clear_msg_field"]) != 0 {
		t.Errorf("clear_msg_field: `s->msg = NULL` after free(s->msg) must not be a use, got %v", byFunc["clear_msg_field"])
	}
	if len(byFunc["read_other_field_after_field_free"]) != 0 {
		t.Errorf("read_other_field_after_field_free: freeing s->msg does not dangle s->mode, got %v", byFunc["read_other_field_after_field_free"])
	}
}

// TestUncheckedReturn_HeuristicNameNotContractProof pins the source-kind split:
// a call to a built-in API / declared allocator carries a known failure
// contract (contract_known=true), while a callee that is only an allocator by
// NAME (`_dup`) does not — the planner must not auto-confirm the latter.
func TestUncheckedReturn_HeuristicNameNotContractProof(t *testing.T) {
	_, byFunc := indexDetect(t, `#include <stdlib.h>
#include <string.h>
typedef struct rec { char name[64]; } rec_t;
rec_t *idm_asset_record_dup(const rec_t *r, rec_t *out);

void known_api_unchecked(size_t n) {
    void *p = malloc(n);
    memset(p, 0, n);
}

void name_heuristic(const rec_t *rec) {
    char buf[256];
    idm_asset_record_dup(rec, (rec_t *)buf);
}
`, "unchecked")

	known := byFunc["known_api_unchecked"]
	if len(known) == 0 || !strings.Contains(known[0], `"contract_known":"true"`) {
		t.Errorf("known_api_unchecked: malloc has a known contract, expected contract_known=true, got %v", known)
	}
	heur := byFunc["name_heuristic"]
	if len(heur) == 0 {
		t.Fatalf("name_heuristic: the _dup call should still be reported (as a lead)")
	}
	if strings.Contains(heur[0], `"contract_known":"true"`) {
		t.Errorf("name_heuristic: an allocator-name-only match must not claim a known contract, got %v", heur)
	}
}

// TestDangerousFunction_InetAddrHonestTier pins the inet_addr category: its
// CWE-676 risk is conditional (runtime-controlled string + unchecked
// INADDR_NONE), so it is reported under obsolete_api_conditional for the AI,
// while a constant argument is still exempt and the unconditional obsolete APIs
// keep the plain category.
func TestDangerousFunction_InetAddrHonestTier(t *testing.T) {
	_, byFunc := indexDetect(t, `#include <arpa/inet.h>
#define NLOG_HOST_IP "192.168.0.1"
struct cfg { char server_ip[32]; };

int use_constant(void) { return (int)inet_addr(NLOG_HOST_IP); }
int use_param(const char *host) { return (int)inet_addr(host); }
int use_field(struct cfg *c) { return (int)inet_addr(c->server_ip); }
void use_obsolete(void) { (void)gethostbyname("x"); }
`, "dangerous")

	if len(byFunc["use_constant"]) != 0 {
		t.Errorf("use_constant: inet_addr(constant) is exempt, got %v", byFunc["use_constant"])
	}
	for _, fn := range []string{"use_param", "use_field"} {
		if len(byFunc[fn]) == 0 || !strings.Contains(byFunc[fn][0], `"category":"obsolete_api_conditional"`) {
			t.Errorf("%s: expected category obsolete_api_conditional, got %v", fn, byFunc[fn])
		}
	}
	if len(byFunc["use_obsolete"]) == 0 || !strings.Contains(byFunc["use_obsolete"][0], `"category":"obsolete_api"`) {
		t.Errorf("use_obsolete: gethostbyname stays unconditional (obsolete_api), got %v", byFunc["use_obsolete"])
	}
}
