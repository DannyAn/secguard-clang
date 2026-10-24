package graph

import "testing"

// TestTypeModel pins the Phase-11 skeleton contract: Type is a value type
// (safe to copy), the integer / float / pointer predicates classify
// correctly, and the SignedMax/SignedMin/UnsignedMax helpers compute the
// right bounds for the widths the pipeline cares about.
func TestTypeModel(t *testing.T) {
	i32 := Type{Kind: TypeInt, Width: 32, Signed: true, Name: "int"}
	if !i32.IsInteger() || i32.IsFloat() || i32.IsPointer() {
		t.Errorf("i32 predicates wrong: %+v", i32)
	}
	if got := i32.SignedMax(); got != 2147483647 {
		t.Errorf("i32.SignedMax() = %d, want 2147483647", got)
	}
	if got := i32.SignedMin(); got != -2147483648 {
		t.Errorf("i32.SignedMin() = %d, want -2147483648", got)
	}

	u64 := Type{Kind: TypeUint, Width: 64, Signed: false, Name: "uint64_t"}
	if got := u64.UnsignedMax(); got != 18446744073709551615 {
		t.Errorf("u64.UnsignedMax() = %d, want 2^64-1", got)
	}

	f64 := Type{Kind: TypeFloat, Width: 64, Name: "double"}
	if f64.IsInteger() || !f64.IsFloat() {
		t.Errorf("f64 predicates wrong: %+v", f64)
	}

	ptr := Type{Kind: TypePointer, Name: "int *"}
	if !ptr.IsPointer() || ptr.IsInteger() {
		t.Errorf("ptr predicates wrong: %+v", ptr)
	}
}

// TestTypeByName pins the LP64 width table and the default signedness.
func TestTypeByName(t *testing.T) {
	cases := []struct {
		name   string
		kind   TypeKind
		width  int
		signed bool
	}{
		{"int", TypeInt, 32, true},
		{"uint32_t", TypeUint, 32, false},
		{"int64_t", TypeInt, 64, true},
		{"size_t", TypeUint, 64, false},
		{"double", TypeFloat, 64, false},
		{"long long", TypeInt, 64, true},
	}
	for _, tc := range cases {
		ty, ok := TypeByName(tc.name)
		if !ok {
			t.Errorf("TypeByName(%q) not found", tc.name)
			continue
		}
		if ty.Kind != tc.kind {
			t.Errorf("TypeByName(%q).Kind = %v, want %v", tc.name, ty.Kind, tc.kind)
		}
		if ty.Width != tc.width {
			t.Errorf("TypeByName(%q).Width = %d, want %d", tc.name, ty.Width, tc.width)
		}
		if tc.kind != TypeFloat && ty.Signed != tc.signed {
			t.Errorf("TypeByName(%q).Signed = %v, want %v", tc.name, ty.Signed, tc.signed)
		}
	}

	if _, ok := TypeByName("struct foo"); ok {
		t.Error("TypeByName(struct foo) unexpectedly found — struct names need repofacts, not the width table")
	}
	if _, ok := TypeByName("int *"); ok {
		t.Error("TypeByName(int *) unexpectedly found — pointer types need declarator structure")
	}
}
