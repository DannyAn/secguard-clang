//go:build !nosqlite

package repofacts

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

func parseRoot(t *testing.T, src string) parser.Node {
	t.Helper()
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	t.Cleanup(tree.Release)
	return tree.RootNode()
}

func TestCollectStructDecls_SimpleStruct(t *testing.T) {
	src := `struct Foo { int a; char b; long c; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	if len(decls) != 1 {
		t.Fatalf("want 1 decl, got %d", len(decls))
	}
	if decls[0].name != "Foo" || decls[0].isUnion {
		t.Fatalf("want struct Foo, got %+v", decls[0])
	}
	wantFields := []string{"a", "b", "c"}
	if len(decls[0].fields) != len(wantFields) {
		t.Fatalf("want %d fields, got %d: %+v", len(wantFields), len(decls[0].fields), decls[0].fields)
	}
	for i, w := range wantFields {
		if decls[0].fields[i].Name != w {
			t.Errorf("field[%d]: want %q, got %q", i, w, decls[0].fields[i].Name)
		}
	}
}

func TestCollectStructDecls_Union(t *testing.T) {
	src := `union U { int x; long y; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	if len(decls) != 1 || !decls[0].isUnion {
		t.Fatalf("want union U, got %+v", decls)
	}
}

func TestCollectStructDecls_PointerAndArray(t *testing.T) {
	src := `struct S { char *p; int arr[4]; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	if len(decls) != 1 {
		t.Fatalf("want 1 decl, got %d", len(decls))
	}
	f := decls[0].fields
	if len(f) != 2 {
		t.Fatalf("want 2 fields, got %d: %+v", len(f), f)
	}
	if f[0].Name != "p" || !f[0].IsPointer {
		t.Errorf("field p: want pointer, got %+v", f[0])
	}
	if f[1].Name != "arr" || !f[1].IsArray || f[1].ArrayCount != 4 {
		t.Errorf("field arr: want array[4], got %+v", f[1])
	}
}

func TestBuildLayouts_PrimitiveStruct(t *testing.T) {
	src := `struct Foo { int a; char b; long c; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, ok := layouts[typeinfo.LayoutKey{Type: "Foo"}]
	if !ok {
		t.Fatal("Foo layout not found")
	}
	if tl.IsUnknown() {
		t.Fatalf("Foo should be resolvable, got unknown: %q", tl.Unknown)
	}
	if tl.Size != 16 {
		t.Errorf("size: want 16, got %d", tl.Size)
	}
	if tl.Align != 8 {
		t.Errorf("align: want 8, got %d", tl.Align)
	}
	wantOffsets := map[string]int{"a": 0, "b": 4, "c": 8}
	for name, wantOff := range wantOffsets {
		fl, found := tl.FieldByName(name)
		if !found {
			t.Errorf("field %q not found", name)
			continue
		}
		if fl.Offset != wantOff {
			t.Errorf("field %q offset: want %d, got %d", name, wantOff, fl.Offset)
		}
	}
	if tl.Provenance != typeinfo.ProvenanceAssumedDefaultABI {
		t.Errorf("provenance: want %q, got %q", typeinfo.ProvenanceAssumedDefaultABI, tl.Provenance)
	}
}

func TestBuildLayouts_PointerField(t *testing.T) {
	src := `struct S { char *p; int x; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	if tl.Size != 16 {
		t.Errorf("size: want 16, got %d", tl.Size)
	}
	fl, _ := tl.FieldByName("p")
	if fl.Size != 8 || !fl.IsPointer {
		t.Errorf("p: want 8-byte pointer, got %+v", fl)
	}
}

func TestBuildLayouts_ArrayField(t *testing.T) {
	src := `struct S { char buf[8]; int x; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	if tl.Size != 12 {
		t.Errorf("size: want 12, got %d", tl.Size)
	}
	fl, _ := tl.FieldByName("buf")
	if fl.Size != 8 || fl.ArrayCount != 8 {
		t.Errorf("buf: want 8-byte array[8], got %+v", fl)
	}
}

func TestBuildLayouts_NestedStruct(t *testing.T) {
	src := `
struct Inner { int x; char y; };
struct Outer { struct Inner a; long z; };
`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	inner, ok := layouts[typeinfo.LayoutKey{Type: "Inner"}]
	if !ok || inner.IsUnknown() {
		t.Fatalf("Inner should be resolvable: %+v", inner)
	}
	if inner.Size != 8 {
		t.Errorf("Inner size: want 8, got %d", inner.Size)
	}

	outer, ok := layouts[typeinfo.LayoutKey{Type: "Outer"}]
	if !ok || outer.IsUnknown() {
		t.Fatalf("Outer should be resolvable: %+v", outer)
	}
	if outer.Size != 16 {
		t.Errorf("Outer size: want 16, got %d", outer.Size)
	}
}

func TestBuildLayouts_Union(t *testing.T) {
	src := `union U { int x; long y; char buf[8]; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, _ := layouts[typeinfo.LayoutKey{Type: "U"}]
	if tl.Size != 8 {
		t.Errorf("union size: want 8, got %d", tl.Size)
	}
	if tl.Align != 8 {
		t.Errorf("union align: want 8, got %d", tl.Align)
	}
}

func TestBuildLayouts_UnknownType(t *testing.T) {
	src := `struct S { WeirdType x; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	if !tl.IsUnknown() {
		t.Errorf("S with unresolvable field should be unknown, got %+v", tl)
	}
}

func TestBuildLayouts_ProvenanceNoCompileCommands(t *testing.T) {
	src := `struct S { int x; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, layoutProvenance(false))

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	if tl.Provenance != typeinfo.ProvenanceAssumedDefaultABI {
		t.Errorf("want assumed_default_abi, got %q", tl.Provenance)
	}
	if tl.CanConfirm() {
		t.Errorf("assumed_default_abi must not allow confirmed")
	}
}

func TestBuildLayouts_ProvenanceWithCompileCommands(t *testing.T) {
	src := `struct S { int x; };`
	root := parseRoot(t, src)
	decls := collectStructDecls(root, nil)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, layoutProvenance(true))

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	// Phase 1 MVP: layoutProvenance 始终返回 assumed_default_abi，
	// 因为"有 compile_commands"不等于"配置完整"（P0-2）。
	// Phase 2 接线完整配置检查后才升级为 derived_from_complete_config。
	if tl.Provenance != typeinfo.ProvenanceAssumedDefaultABI {
		t.Errorf("want assumed_default_abi (MVP: config completeness not checked), got %q", tl.Provenance)
	}
	if tl.CanConfirm() {
		t.Errorf("assumed_default_abi must not allow confirmed")
	}
}

func TestBuildLayouts_MacroArrayCapacity(t *testing.T) {
	src := `#define BUF_SIZE 64
struct S { char buf[BUF_SIZE]; };`
	root := parseRoot(t, src)
	macros := map[string]int{"BUF_SIZE": 64}
	decls := collectStructDecls(root, macros)
	layouts := buildLayouts(decls, typeinfo.ABILP64, 0, typeinfo.ProvenanceAssumedDefaultABI)

	tl, _ := layouts[typeinfo.LayoutKey{Type: "S"}]
	if tl.IsUnknown() {
		t.Fatalf("S should be resolvable: %q", tl.Unknown)
	}
	fl, _ := tl.FieldByName("buf")
	if fl.Size != 64 || fl.ArrayCount != 64 {
		t.Errorf("buf: want 64-byte array[64], got %+v", fl)
	}
}

func TestFactsLayoutOf_ZeroValue(t *testing.T) {
	var f *Facts
	_, ok := f.LayoutOf(typeinfo.LayoutKey{Type: "S"})
	if ok {
		t.Error("nil Facts should return ok=false")
	}
}
