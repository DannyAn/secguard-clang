package graph

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestRepoIndexFunctionsFilesAndOrder(t *testing.T) {
	ri := NewRepoIndex(
		[]*db.Function{{ID: 2, Name: "b", FileID: 10}, {ID: 1, Name: "a", FileID: 20}},
		[]*db.File{{ID: 10, Path: "a.c"}, {ID: 20, Path: "b.c"}},
	)
	if got := ri.FuncByID(1); got == nil || got.Name != "a" {
		t.Fatalf("FuncByID(1) = %+v", got)
	}
	if got := ri.FuncsByName("b"); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("FuncsByName(b) = %+v", got)
	}
	if got := ri.FileByID(20); got == nil || got.Path != "b.c" {
		t.Fatalf("FileByID(20) = %+v", got)
	}
	if got := ri.FileOrder(); len(got) != 2 || got[0] != 10 || got[1] != 20 {
		t.Fatalf("FileOrder = %v", got)
	}
	if got := ri.FuncsByFile(10); len(got) != 1 || got[0].ID != 2 {
		t.Fatalf("FuncsByFile(10) = %+v", got)
	}
	if ri.HasFileScope() || ri.HasFuncPtrTargets() {
		t.Fatal("plain NewRepoIndex unexpectedly reports optional facts")
	}
}

func TestRepoIndexWithFacts(t *testing.T) {
	ri := NewRepoIndexWithFacts(nil, nil, RepoFacts{
		FileScope: []*db.FileScopeVariable{
			{FileID: 7, Name: "g", StorageClass: "static"},
			{FileID: 7, Name: "h", StorageClass: "extern"},
			{FileID: 8, Name: "x", StorageClass: "extern"},
		},
		FuncPtrWrites: []db.FuncPtrWrite{
			{SlotName: "ops->open", TargetName: "real_open"},
			{SlotName: "ops->open", TargetName: "safe_open"},
		},
		FileScopeOK:     true,
		FuncPtrWritesOK: true,
	})
	if !ri.HasFileScope() || !ri.HasFuncPtrTargets() {
		t.Fatal("facts not marked loaded")
	}
	if got := ri.FileScopeByFile()[7]["g"]; got != "static" {
		t.Fatalf("file scope g = %q", got)
	}
	if got := ri.FuncPtrTargets()["ops->open"]; len(got) != 2 || got[0] != "real_open" || got[1] != "safe_open" {
		t.Fatalf("slot targets = %v", got)
	}
}

func TestRepoIndexWithFactsEmptyButLoaded(t *testing.T) {
	ri := NewRepoIndexWithFacts(nil, nil, RepoFacts{FileScopeOK: true, FuncPtrWritesOK: true})
	if !ri.HasFileScope() || !ri.HasFuncPtrTargets() {
		t.Fatal("empty-but-loaded facts should report loaded")
	}
	if ri.FileScopeByFile() == nil || ri.FuncPtrTargets() == nil {
		t.Fatal("empty-but-loaded facts should return non-nil maps")
	}
}
