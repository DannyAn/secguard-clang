//go:build !nosqlite

package allocdiscover

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestDiscover(t *testing.T) {
	s := db.NewTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	fileID, err := s.InsertFile(ctx, &db.File{Path: filepath.Join(dir, "app.c"), Language: "c", Checksum: "abc", LOC: 10})
	if err != nil {
		t.Fatal(err)
	}

	myMalloc := &db.Function{FileID: fileID, Name: "my_malloc", Signature: "my_malloc(size_t n)", ReturnType: "void*"}
	myFree := &db.Function{FileID: fileID, Name: "my_free", Signature: "my_free(void *p)", ReturnType: "void"}
	plain := &db.Function{FileID: fileID, Name: "plain_fn", Signature: "plain_fn(int x)", ReturnType: "int"}
	idMalloc, _ := s.InsertFunction(ctx, myMalloc)
	idFree, _ := s.InsertFunction(ctx, myFree)
	s.InsertFunction(ctx, plain)

	nMalloc, _ := s.GetOrCreateGraphNode(ctx, "function", idMalloc, "")
	nFree, _ := s.GetOrCreateGraphNode(ctx, "function", idFree, "")
	extMalloc, _ := s.GetOrCreateGraphNode(ctx, "external_function", 0, `{"name":"malloc","external":"true"}`)
	extFree, _ := s.GetOrCreateGraphNode(ctx, "external_function", 0, `{"name":"free","external":"true"}`)

	s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: nMalloc, DstID: extMalloc, EdgeType: "CALL"})
	s.InsertGraphEdge(ctx, &db.GraphEdge{SrcID: nFree, DstID: extFree, EdgeType: "CALL"})

	res, err := Discover(ctx, s)
	if err != nil {
		t.Fatal(err)
	}

	allocNames := map[string]bool{}
	for _, e := range res.Allocators {
		allocNames[e.Name] = true
	}
	deallocNames := map[string]bool{}
	for _, e := range res.Deallocators {
		deallocNames[e.Name] = true
	}
	if !allocNames["my_malloc"] {
		t.Errorf("my_malloc missing from allocators: %+v", res.Allocators)
	}
	if !deallocNames["my_free"] {
		t.Errorf("my_free missing from deallocators: %+v", res.Deallocators)
	}
	if allocNames["plain_fn"] || deallocNames["plain_fn"] {
		t.Errorf("plain_fn must not be suggested")
	}
	if allocNames["malloc"] || deallocNames["free"] {
		t.Errorf("built-in malloc/free must be skipped")
	}
}

func TestDiscoverSkipsDeclaredNames(t *testing.T) {
	s := db.NewTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	fileID, _ := s.InsertFile(ctx, &db.File{Path: filepath.Join(dir, "app.c"), Language: "c", Checksum: "def", LOC: 1})
	// A project already declared nat_malloc/nat_free in secguard.toml: those are
	// built-in VOS_*/HpeMem* or config-registered names and must not be
	// re-suggested. Use built-in names directly (always declared) to avoid
	// mutating apikb package state from this test.
	s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "malloc", Signature: "malloc(size_t n)", ReturnType: "void*"})
	s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "free", Signature: "free(void *p)", ReturnType: "void"})

	res, err := Discover(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Allocators {
		if e.Name == "malloc" {
			t.Errorf("malloc must be skipped as a declared allocator")
		}
	}
	for _, e := range res.Deallocators {
		if e.Name == "free" {
			t.Errorf("free must be skipped as a declared deallocator")
		}
	}
}

func TestDiscoverMacros(t *testing.T) {
	s := db.NewTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()

	cPath := filepath.Join(dir, "app.c")
	hPath := filepath.Join(dir, "mem.h")
	if err := os.WriteFile(cPath, []byte("#include \"mem.h\"\nvoid *wrap_alloc(size_t n) { return NAT_MALLOC(n); }\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hPath, []byte("#define NAT_MALLOC(n) malloc(n)\n#define NLOG_FREE(p) free(p)\n#define MAX_BUF 256\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertFile(ctx, &db.File{Path: cPath, Language: "c", Checksum: "ghi", LOC: 1}); err != nil {
		t.Fatal(err)
	}

	res, err := Discover(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	allocNames := map[string]bool{}
	for _, e := range res.Allocators {
		allocNames[e.Name] = true
	}
	deallocNames := map[string]bool{}
	for _, e := range res.Deallocators {
		deallocNames[e.Name] = true
	}
	if !allocNames["NAT_MALLOC"] {
		t.Errorf("NAT_MALLOC macro missing from allocators: %+v", res.Allocators)
	}
	if !deallocNames["NLOG_FREE"] {
		t.Errorf("NLOG_FREE macro missing from deallocators: %+v", res.Deallocators)
	}
	if allocNames["MAX_BUF"] || deallocNames["MAX_BUF"] {
		t.Errorf("MAX_BUF must not be suggested")
	}
}
