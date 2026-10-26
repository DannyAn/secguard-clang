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

// The project security guideline's exception clauses for the banned memory
// functions (no externally controlled data, operation provably local). A call
// in one of those shapes is NOT a policy finding; anything else stays one.
func TestDangerousFunction_GuidelineExceptions(t *testing.T) {
	src := `#include <stdlib.h>
#include <string.h>

typedef struct { unsigned int a; char buf[8]; } ctx_t;

#define MSG_LITERAL "hello"

static void init_fixed(void)
{
    char buf[16];
    ctx_t ctx;
    memset(buf, 0, sizeof(buf));            /* 1: fixed array init */
    memset(&ctx, 0, sizeof(ctx));           /* 1: fixed struct init */
}

static void init_caller(void *p, unsigned int n)
{
    memset(p, 0, n);                        /* 2: pointer param + size param */
}

static void init_heap_size(void)
{
    char *q = malloc(32);
    memset(q, 0, 32);                       /* 3: right after allocation */
}

static void copy_source_sized(char *dst, const char *src)
{
    memcpy(dst, src, strlen(src));          /* 4: size from the source */
}

static void copy_literal(char *dst)
{
    strcpy(dst, "abc");                     /* 5: static string source */
    strcat(dst, MSG_LITERAL);               /* 5: static string macro */
    memcpy(dst, "abc", sizeof("abc"));      /* 5: literal + sizeof(source) */
}

/* ---- controls: still policy findings ---- */
static void init_wrong_size(void)
{
    char buf[16];
    memset(buf, 0, 64);                     /* literal size, not sizeof */
}

static void copy_param_size(char *dst, const char *src, unsigned int n)
{
    memcpy(dst, src, n);                    /* size not derived from source */
}

static void copy_param_source(char *dst, const char *src)
{
    strcpy(dst, src);                       /* source is not static data */
}

static void format_call(char *dst, const char *src)
{
    sprintf(dst, "%s", src);
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "guideline.c")
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
	if _, err := NewDangerousFunctionDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(ctx, "DANGEROUS_FUNCTION")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	byFunc := map[string]string{}
	for _, e := range events {
		fn, ferr := store.GetFunctionByID(ctx, e.EntityID)
		if ferr != nil || fn == nil {
			continue
		}
		var props struct {
			Variable string `json:"variable"`
		}
		if json.Unmarshal([]byte(e.Properties), &props) == nil {
			byFunc[fn.Name] = props.Variable
		}
	}

	for _, exempt := range []string{
		"init_fixed", "init_caller", "init_heap_size",
		"copy_source_sized", "copy_literal",
	} {
		if api, ok := byFunc[exempt]; ok {
			t.Errorf("%s: %s call matches a guideline exception clause and must NOT be flagged", exempt, api)
		}
	}
	for _, flagged := range []string{
		"init_wrong_size", "copy_param_size", "copy_param_source", "format_call",
	} {
		if _, ok := byFunc[flagged]; !ok {
			t.Errorf("%s: call is outside the exception clauses and must stay a finding", flagged)
		}
	}
}
