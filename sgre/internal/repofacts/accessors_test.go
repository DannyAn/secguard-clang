//go:build !nosqlite

package repofacts

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

func TestFactsAccessors(t *testing.T) {
	key := typeinfo.LayoutKey{Type: "node_s"}
	f := &Facts{
		Macros: map[string]int{"MAX_ITEMS": 8, "ZERO": 0},
		structs: map[string]map[string]FieldFact{
			"node_s": {"next": {Name: "next", Pointer: true}},
		},
		fields: map[string][]FieldFact{
			"unique":    {{Name: "unique", Type: "int"}},
			"ambiguous": {{Name: "ambiguous"}, {Name: "ambiguous"}},
		},
		globals: map[string][]GlobalArray{
			"g_buf":   {{Name: "g_buf", Count: 16}},
			"g_dup":   {{Name: "g_dup", Count: 1}, {Name: "g_dup", Count: 2}},
			"g_alone": {{Name: "g_alone", Count: 4}},
		},
		layouts: map[typeinfo.LayoutKey]typeinfo.TypeLayout{
			key: {Key: key, Name: "node_s", Size: 16},
		},
	}

	if v, ok := f.MacroValue(" MAX_ITEMS "); !ok || v != 8 {
		t.Errorf("MacroValue(MAX_ITEMS) = %d,%v; want 8,true", v, ok)
	}
	if _, ok := f.MacroValue("MISSING"); ok {
		t.Error("MacroValue(MISSING) unexpectedly found")
	}
	if ff, ok := f.FieldByTag(" node_s ", " next "); !ok || !ff.Pointer {
		t.Errorf("FieldByTag = %+v,%v; want pointer field", ff, ok)
	}
	if _, ok := f.FieldByTag("absent", "next"); ok {
		t.Error("FieldByTag(absent) unexpectedly found")
	}
	if _, ok := f.FieldByName("ambiguous"); ok {
		t.Error("FieldByName(ambiguous) must not answer an ambiguous name")
	}
	if ff, ok := f.FieldByName("unique"); !ok || ff.Type != "int" {
		t.Errorf("FieldByName(unique) = %+v,%v", ff, ok)
	}
	if ga, ok := f.GlobalArray("g_alone"); !ok || ga.Count != 4 {
		t.Errorf("GlobalArray(g_alone) = %+v,%v", ga, ok)
	}
	if _, ok := f.GlobalArray("g_dup"); ok {
		t.Error("GlobalArray(g_dup) must not answer an ambiguous name")
	}
	if got := f.Layouts(); len(got) != 1 || got[key].Size != 16 {
		t.Errorf("Layouts = %v, want the node_s layout", got)
	}

	var nilFacts *Facts
	if _, ok := nilFacts.MacroValue("X"); ok {
		t.Error("nil Facts MacroValue found a value")
	}
	if _, ok := nilFacts.FieldByTag("a", "b"); ok {
		t.Error("nil Facts FieldByTag found a field")
	}
	if _, ok := nilFacts.FieldByName("a"); ok {
		t.Error("nil Facts FieldByName found a field")
	}
	if _, ok := nilFacts.GlobalArray("a"); ok {
		t.Error("nil Facts GlobalArray found an array")
	}
	if nilFacts.Layouts() != nil {
		t.Error("nil Facts Layouts should be nil")
	}
}

func TestFactsContext(t *testing.T) {
	base := context.Background()
	if WithFacts(base, nil) != base {
		t.Error("WithFacts(ctx, nil) should return ctx unchanged")
	}
	if FactsFromCtx(context.Background()) != nil {
		t.Error("FactsFromCtx on a bare context should be nil")
	}
	var nilCtx context.Context
	if FactsFromCtx(nilCtx) != nil {
		t.Error("FactsFromCtx(nil) should be nil")
	}
	f := &Facts{Macros: map[string]int{}}
	if got := FactsFromCtx(WithFacts(base, f)); got != f {
		t.Error("FactsFromCtx did not return the attached Facts")
	}
}

func TestInsideFunctionAndBitfieldWidth(t *testing.T) {
	root := parseRoot(t, `
struct S { unsigned a : 3; unsigned b : 5; };
int f(void) { int x; return x; }
`)
	// A node inside the function body is detected; a struct field is not.
	body := root.FindAll("return_statement")
	if len(body) != 1 || !insideFunction(body[0]) {
		t.Fatalf("return_statement not recognised as inside a function: %v", body)
	}
	for _, fd := range root.FindAll("field_declaration") {
		if insideFunction(fd) {
			t.Errorf("field_declaration unexpectedly inside a function")
		}
	}

	clauses := root.FindAll("bitfield_clause")
	if len(clauses) != 2 {
		t.Fatalf("bitfield_clause count = %d, want 2", len(clauses))
	}
	if got := bitfieldWidth(clauses[0]); got != 3 {
		t.Errorf("bitfieldWidth(a) = %d, want 3", got)
	}
	if got := bitfieldWidth(clauses[1]); got != 5 {
		t.Errorf("bitfieldWidth(b) = %d, want 5", got)
	}
}

func TestHasPointerInArray(t *testing.T) {
	root := parseRoot(t, `struct S { int vals[4]; int (*pp)[4]; };`)
	arrays := root.FindAll("array_declarator")
	if len(arrays) != 2 {
		t.Fatalf("array_declarator count = %d, want 2", len(arrays))
	}
	if hasPointerInArray(arrays[0]) {
		t.Error("plain array wrongly reported as pointer array")
	}
	if !hasPointerInArray(arrays[1]) {
		t.Error("pointer array not recognised")
	}
}

func TestPointerFieldsNilFacts(t *testing.T) {
	var f *Facts
	if got, ok := f.PointerFields("node_s"); ok || got != nil {
		t.Errorf("nil PointerFields = %v,%v; want nil,false", got, ok)
	}
}

func TestLayoutOf(t *testing.T) {
	key := typeinfo.LayoutKey{Type: "node_s"}
	f := &Facts{layouts: map[typeinfo.LayoutKey]typeinfo.TypeLayout{
		key: {Key: key, Size: 8},
	}}
	if tl, ok := f.LayoutOf(key); !ok || tl.Size != 8 {
		t.Errorf("LayoutOf = %+v,%v", tl, ok)
	}
	if _, ok := f.LayoutOf(typeinfo.LayoutKey{Type: "missing"}); ok {
		t.Error("LayoutOf(missing) unexpectedly found")
	}
	var nilFacts *Facts
	if _, ok := nilFacts.LayoutOf(key); ok {
		t.Error("nil Facts LayoutOf unexpectedly found")
	}
}
