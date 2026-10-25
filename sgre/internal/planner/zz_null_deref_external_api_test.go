//go:build !nosqlite

package planner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// External-API null-deref matrix (docs §9.2): modeled library APIs whose
// returns are documented maybe-NULL (xmlDocGetRootElement, cJSON_GetObjectItem,
// ...) must surface an unguarded dereference through the nullable tier
// (auto-confirm, same standard as strchr); guarded and comparison-only uses
// must stay silent.

func TestNullDeref_ExternalAPIBorrowDeref(t *testing.T) {
	src := `typedef struct _xmlDoc { int dummy; } xmlDoc;
typedef struct _xmlNode { const char *name; } xmlNode;
extern xmlNode *xmlDocGetRootElement(xmlDoc *doc);
extern xmlNode *xmlFirstElementChild(xmlNode *node);
extern xmlNode *xmlNextElementSibling(xmlNode *node);
extern void use(const char *s);

void f(xmlDoc *doc) {
    use(xmlDocGetRootElement(doc)->name);
}
`
	res := planNullDerefSrc(t, src)
	if !hasNullDerefCandidate(res, "f") {
		t.Fatal("unguarded xmlDocGetRootElement(doc)->name must surface a null-deref candidate")
	}
	for _, c := range res.Candidates {
		if c.Target.Function == "f" && c.SuspicionLevel != "suspected" {
			t.Fatalf("documented maybe-NULL borrow deref should be suspected (may-null, AI-judged), got %q", c.SuspicionLevel)
		}
	}
}

func TestNullDeref_ExternalAPIBorrowDerefGuarded(t *testing.T) {
	src := `typedef struct _xmlDoc { int dummy; } xmlDoc;
typedef struct _xmlNode { const char *name; } xmlNode;
extern xmlNode *xmlDocGetRootElement(xmlDoc *doc);
extern void use(const char *s);

void guarded_return(xmlDoc *doc) {
    xmlNode *root = xmlDocGetRootElement(doc);
    if (root == NULL) return;
    use(root->name);
}

void guarded_positive_branch(xmlDoc *doc) {
    xmlNode *root = xmlDocGetRootElement(doc);
    if (root != NULL) {
        use(root->name);
    }
}

void comparison_only(xmlDoc *doc) {
    xmlNode *root = xmlDocGetRootElement(doc);
    if (root != NULL) { use("x"); }
}
`
	for _, fn := range []string{"guarded_return", "guarded_positive_branch", "comparison_only"} {
		if hasNullDerefCandidate(planNullDerefSrc(t, src), fn) {
			t.Errorf("%s: guarded/comparison-only use of a nullable borrow must not report", fn)
		}
	}
}

func TestNullDeref_ExternalAPICJSONLookups(t *testing.T) {
	src := `typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern cJSON *cJSON_GetArrayItem(const cJSON *array, int index);
extern void use_int(int v);

void f(const char *value, const char *key) {
    cJSON *obj = cJSON_Parse(value);
    if (obj == NULL) return;
    cJSON *item = cJSON_GetObjectItem(obj, key);
    use_int(item->valueint);
}

void g(const char *value) {
    cJSON *obj = cJSON_Parse(value);
    if (obj == NULL) return;
    cJSON *first = cJSON_GetArrayItem(obj, 0);
    use_int(first->valueint);
}

void h(const char *value) {
    cJSON *obj = cJSON_Parse(value);
    use_int(obj->valueint);
}
`
	res := planNullDerefSrc(t, src)
	for _, fn := range []string{"f", "g", "h"} {
		if !hasNullDerefCandidate(res, fn) {
			t.Errorf("%s: unguarded deref of a documented maybe-NULL cJSON API result must surface a candidate", fn)
		}
	}
}

func TestNullDeref_ExternalAPICJSONLookupsGuarded(t *testing.T) {
	src := `typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern void use_int(int v);

void f(const char *value, const char *key) {
    cJSON *obj = cJSON_Parse(value);
    if (obj == NULL) return;
    cJSON *item = cJSON_GetObjectItem(obj, key);
    if (item == NULL) return;
    use_int(item->valueint);
}
`
	if hasNullDerefCandidate(planNullDerefSrc(t, src), "f") {
		t.Error("fully guarded cJSON lookup chain must not report null-deref")
	}
}

func TestNullDeref_ExternalAPIAllocatorCallResult(t *testing.T) {
	// xmlDocGetRootElement's own call-result dereference (`f(...)->field`)
	// and an allocator's (`xmlXPathNewContext(...)`) unguarded call-result
	// deref both go through the confirmed tier.
	src := `typedef struct _xmlDoc { int dummy; } xmlDoc;
typedef struct _xmlXPathContext { int node; } xmlXPathContext;
extern xmlXPathContext *xmlXPathNewContext(xmlDoc *doc);
extern xmlDoc *xmlReadMemory(const char *buf, int size, const char *url, const char *enc, int opts);

void f(xmlDoc *doc) {
    xmlXPathNewContext(doc)->node = 1;
}

void g(const char *buf, int size) {
    xmlReadMemory(buf, size, 0, 0, 0)->dummy = 1;
}
`
	res := planNullDerefSrc(t, src)
	for _, fn := range []string{"f", "g"} {
		if !hasNullDerefCandidate(res, fn) {
			t.Errorf("%s: unguarded call-result deref of a maybe-NULL library API must surface a candidate", fn)
		}
	}
}

// TestMemoryLeak_FreeOnBorrowPipeline locks the user-provided cJSON misuse
// end-to-end through the planner: cJSON_Delete on cJSON_GetObjectItem's
// borrowed result surfaces as a suspected memory-leak candidate (never
// auto-confirmed — the classifier judges the CWE-415/416 consequence)
// carrying the free-on-borrow hint token, while the correctly-paired root
// produces nothing.
func TestMemoryLeak_FreeOnBorrowPipeline(t *testing.T) {
	src := `typedef struct cJSON { int valueint; struct cJSON *child; } cJSON;
extern cJSON *cJSON_Parse(const char *value);
extern cJSON *cJSON_GetObjectItem(const cJSON *obj, const char *key);
extern void cJSON_Delete(cJSON *item);

void f(const char *value) {
    cJSON *root = cJSON_Parse(value);
    if (root == NULL) return;
    cJSON *name = cJSON_GetObjectItem(root, "name");
    cJSON_Delete(name);
    cJSON_Delete(root);
}
`
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.Default()
	p := parser.NewParser()
	dir := t.TempDir()
	path := filepath.Join(dir, "borrow.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.RunAllDetectors(ctx, store, p, logger)
	res, err := NewPlanner(store, p, logger).Plan(ctx, "memory-leak")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var found bool
	for _, c := range res.Candidates {
		if c.Target.Function != "f" {
			continue
		}
		if c.Target.Variable == "root" {
			t.Errorf("the correctly-paired root must not surface a candidate, got %s", c.SuspicionLevel)
		}
		if c.Target.Variable == "name" {
			found = true
			if c.SuspicionLevel != "suspected" {
				t.Errorf("free-on-borrow must stay suspected for the AI (invalid-free/UAF consequence), got %q", c.SuspicionLevel)
			}
			hasToken := false
			for _, tok := range c.HintTokens {
				if tok == "free-on-borrow@cJSON_Delete" {
					hasToken = true
				}
			}
			if !hasToken {
				t.Errorf("candidate hint must carry free-on-borrow@cJSON_Delete, got %v", c.HintTokens)
			}
		}
	}
	if !found {
		t.Fatal("cJSON_Delete on cJSON_GetObjectItem's borrowed result must surface a free-on-borrow candidate")
	}
}
