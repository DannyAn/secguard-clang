package typeinfo

import "testing"

func TestLayoutStruct_SimpleFields(t *testing.T) {
	key := LayoutKey{Type: "S"}
	fields := []FieldSpec{
		{Name: "a", TypeSpelling: "char"},
		{Name: "b", TypeSpelling: "int"},
		{Name: "c", TypeSpelling: "char"},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 12 {
		t.Errorf("Size = %d; want 12 (char+pad3+int+char+pad3)", tl.Size)
	}
	if tl.Align != 4 {
		t.Errorf("Align = %d; want 4", tl.Align)
	}
	fa, _ := tl.FieldByName("a")
	if fa.Offset != 0 || fa.Size != 1 {
		t.Errorf("field a: offset=%d size=%d; want 0,1", fa.Offset, fa.Size)
	}
	fb, _ := tl.FieldByName("b")
	if fb.Offset != 4 || fb.Size != 4 {
		t.Errorf("field b: offset=%d size=%d; want 4,4", fb.Offset, fb.Size)
	}
	fc, _ := tl.FieldByName("c")
	if fc.Offset != 8 || fc.Size != 1 {
		t.Errorf("field c: offset=%d size=%d; want 8,1", fc.Offset, fc.Size)
	}
}

func TestLayoutStruct_Pack1(t *testing.T) {
	key := LayoutKey{Type: "Packed"}
	fields := []FieldSpec{
		{Name: "a", TypeSpelling: "char"},
		{Name: "b", TypeSpelling: "int"},
		{Name: "c", TypeSpelling: "char"},
	}
	tl := LayoutStruct(ABILP64, key, fields, 1, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 6 {
		t.Errorf("packed Size = %d; want 6", tl.Size)
	}
	if tl.Align != 1 {
		t.Errorf("packed Align = %d; want 1", tl.Align)
	}
	fb, _ := tl.FieldByName("b")
	if fb.Offset != 1 {
		t.Errorf("packed field b offset = %d; want 1", fb.Offset)
	}
}

func TestLayoutStruct_PointerField(t *testing.T) {
	key := LayoutKey{Type: "WithPtr"}
	fields := []FieldSpec{
		{Name: "p", TypeSpelling: "char *"},
		{Name: "v", TypeSpelling: "int"},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 16 {
		t.Errorf("Size = %d; want 16 (ptr8+int4+pad4)", tl.Size)
	}
	fp, _ := tl.FieldByName("p")
	if fp.Size != 8 || fp.Offset != 0 {
		t.Errorf("ptr field: size=%d offset=%d; want 8,0", fp.Size, fp.Offset)
	}
}

func TestLayoutStruct_ArrayField(t *testing.T) {
	key := LayoutKey{Type: "WithArr"}
	fields := []FieldSpec{
		{Name: "buf", TypeSpelling: "char", IsArray: true, ArrayCount: 16},
		{Name: "len", TypeSpelling: "int"},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 20 {
		t.Errorf("Size = %d; want 20 (char[16]+int4)", tl.Size)
	}
	fb, _ := tl.FieldByName("buf")
	if fb.Size != 16 || fb.Offset != 0 {
		t.Errorf("array field: size=%d offset=%d; want 16,0", fb.Size, fb.Offset)
	}
}

func TestLayoutStruct_NestedStruct(t *testing.T) {
	inner := TypeLayout{Kind: "struct", Size: 8, Align: 4}
	resolve := func(spelling string) (TypeLayout, bool) {
		if spelling == "Inner" {
			return inner, true
		}
		return TypeLayout{}, false
	}
	key := LayoutKey{Type: "Outer"}
	fields := []FieldSpec{
		{Name: "tag", TypeSpelling: "int"},
		{Name: "inner", TypeSpelling: "Inner", IsStruct: true},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, resolve)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 12 {
		t.Errorf("Size = %d; want 12 (int4+Inner8)", tl.Size)
	}
	fi, _ := tl.FieldByName("inner")
	if fi.Offset != 4 || fi.Size != 8 {
		t.Errorf("nested field: offset=%d size=%d; want 4,8", fi.Offset, fi.Size)
	}
}

func TestLayoutStruct_NestedUnknown(t *testing.T) {
	resolve := func(spelling string) (TypeLayout, bool) {
		return TypeLayout{}, false
	}
	key := LayoutKey{Type: "Outer"}
	fields := []FieldSpec{
		{Name: "inner", TypeSpelling: "Unknown", IsStruct: true},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, resolve)
	if !tl.IsUnknown() {
		t.Error("expected unknown for unresolvable nested struct")
	}
}

func TestLayoutStruct_Bitfield_Unknown(t *testing.T) {
	key := LayoutKey{Type: "Bit"}
	fields := []FieldSpec{
		{Name: "a", TypeSpelling: "int", BitWidth: 4},
	}
	tl := LayoutStruct(ABILP64, key, fields, 0, nil)
	if !tl.IsUnknown() {
		t.Error("bitfield should produce unknown in MVP")
	}
}

func TestLayoutStruct_Empty(t *testing.T) {
	tl := LayoutStruct(ABILP64, LayoutKey{Type: "Empty"}, nil, 0, nil)
	if !tl.IsUnknown() {
		t.Error("empty struct should produce unknown")
	}
}

func TestLayoutUnion(t *testing.T) {
	key := LayoutKey{Type: "U"}
	fields := []FieldSpec{
		{Name: "a", TypeSpelling: "char"},
		{Name: "b", TypeSpelling: "int"},
		{Name: "c", TypeSpelling: "long"},
	}
	tl := LayoutUnion(ABILP64, key, fields, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 8 {
		t.Errorf("union Size = %d; want 8 (max long)", tl.Size)
	}
	if tl.Align != 8 {
		t.Errorf("union Align = %d; want 8", tl.Align)
	}
	for _, f := range tl.Fields {
		if f.Offset != 0 {
			t.Errorf("union field %s offset = %d; want 0", f.Name, f.Offset)
		}
	}
}

func TestLayoutUnion_TailPadding(t *testing.T) {
	// C sizeof(union) rounds the largest member up to the union alignment:
	// union { long long x; char buf[9]; } is 16, not 9.
	tl := LayoutUnion(ABILP64, LayoutKey{Type: "U"}, []FieldSpec{
		{Name: "x", TypeSpelling: "long long"},
		{Name: "buf", TypeSpelling: "char", IsArray: true, ArrayCount: 9},
	}, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 16 || tl.Align != 8 {
		t.Errorf("union size/align = %d/%d; want 16/8", tl.Size, tl.Align)
	}
}

func TestLayoutStruct_FlexibleArrayMember(t *testing.T) {
	// A flexible array member contributes 0 bytes to sizeof but keeps its
	// element alignment; `struct F { int n; char data[]; }` is 4 bytes.
	tl := LayoutStruct(ABILP64, LayoutKey{Type: "F"}, []FieldSpec{
		{Name: "n", TypeSpelling: "int"},
		{Name: "data", TypeSpelling: "char", IsArray: true, ArrayCount: 0},
	}, 0, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 4 {
		t.Errorf("struct size = %d; want 4 (FAM contributes no bytes)", tl.Size)
	}
	f, _ := tl.FieldByName("data")
	if f.Size != 0 || !f.IsArray || f.IsPointer {
		t.Errorf("data field = %+v; want a zero-size IsArray field", f)
	}
}

func TestLayoutPointer(t *testing.T) {
	tl := LayoutPointer(ABILP64, LayoutKey{Type: "void *"})
	if tl.Size != 8 || tl.Align != 8 {
		t.Errorf("LP64 pointer: size=%d align=%d; want 8,8", tl.Size, tl.Align)
	}
	tl32 := LayoutPointer(ABIILP32, LayoutKey{Type: "void *"})
	if tl32.Size != 4 || tl32.Align != 4 {
		t.Errorf("ILP32 pointer: size=%d align=%d; want 4,4", tl32.Size, tl32.Align)
	}
}

func TestLayoutArray(t *testing.T) {
	tl := LayoutArray(ABILP64, LayoutKey{Type: "arr"}, "int", 10, nil)
	if tl.IsUnknown() {
		t.Fatalf("unexpected unknown: %s", tl.Unknown)
	}
	if tl.Size != 40 {
		t.Errorf("int[10] Size = %d; want 40", tl.Size)
	}
	if tl.Align != 4 {
		t.Errorf("int[10] Align = %d; want 4", tl.Align)
	}
}

func TestLayoutArray_UnknownCount(t *testing.T) {
	tl := LayoutArray(ABILP64, LayoutKey{Type: "arr"}, "int", 0, nil)
	if !tl.IsUnknown() {
		t.Error("zero count should produce unknown")
	}
}

func TestTypeLayout_CanConfirm(t *testing.T) {
	good := TypeLayout{Size: 24, Provenance: ProvenanceDerivedFromFullConfig}
	if !good.CanConfirm() {
		t.Error("derived + size>0 should CanConfirm")
	}
	assumed := TypeLayout{Size: 24, Provenance: ProvenanceAssumedDefaultABI}
	if assumed.CanConfirm() {
		t.Error("assumed should NOT CanConfirm")
	}
	unknown := TypeLayout{Size: 24, Provenance: ProvenanceDerivedFromFullConfig, Unknown: "bad"}
	if unknown.CanConfirm() {
		t.Error("unknown layout should NOT CanConfirm")
	}
	zero := TypeLayout{Size: 0, Provenance: ProvenanceDerivedFromFullConfig}
	if zero.CanConfirm() {
		t.Error("zero size should NOT CanConfirm")
	}
}

func TestAlignUp(t *testing.T) {
	cases := []struct{ offset, align, want int }{
		{0, 4, 0}, {1, 4, 4}, {3, 4, 4}, {4, 4, 4}, {5, 4, 8},
		{0, 1, 0}, {7, 8, 8}, {8, 8, 8}, {0, 0, 0},
	}
	for _, c := range cases {
		if got := alignUp(c.offset, c.align); got != c.want {
			t.Errorf("alignUp(%d, %d) = %d; want %d", c.offset, c.align, got, c.want)
		}
	}
}
