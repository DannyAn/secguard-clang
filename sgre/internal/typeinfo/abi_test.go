package typeinfo

import "testing"

func TestPrimitiveBits_LP64(t *testing.T) {
	cases := map[string]int{
		"char": 8, "signed char": 8, "unsigned char": 8, "_Bool": 8, "bool": 8,
		"short": 16, "unsigned short": 16, "short int": 16,
		"int": 32, "unsigned int": 32, "signed": 32, "unsigned": 32,
		"long": 64, "unsigned long": 64, "long int": 64, "unsigned long int": 64,
		"long long": 64, "unsigned long long": 64,
		"float": 32, "double": 64, "long double": 128,
		"int8_t": 8, "uint8_t": 8, "int16_t": 16, "uint16_t": 16,
		"int32_t": 32, "uint32_t": 32, "int64_t": 64, "uint64_t": 64,
	}
	for name, want := range cases {
		got, ok := PrimitiveBits(ABILP64, name)
		if !ok {
			t.Errorf("PrimitiveBits(LP64, %q) = not ok; want %d", name, want)
			continue
		}
		if got != want {
			t.Errorf("PrimitiveBits(LP64, %q) = %d; want %d", name, got, want)
		}
	}
}

func TestPrimitiveBits_ILP32(t *testing.T) {
	cases := map[string]int{
		"long": 32, "unsigned long": 32, "long int": 32,
		"int": 32, "short": 16, "char": 8, "long long": 64,
	}
	for name, want := range cases {
		got, ok := PrimitiveBits(ABIILP32, name)
		if !ok || got != want {
			t.Errorf("PrimitiveBits(ILP32, %q) = %d, ok=%v; want %d", name, got, ok, want)
		}
	}
}

func TestPrimitiveBits_LLP64(t *testing.T) {
	cases := map[string]int{
		"long": 32, "unsigned long": 32,
		"long long": 64, "int": 32, "short": 16,
	}
	for name, want := range cases {
		got, ok := PrimitiveBits(ABILLP64, name)
		if !ok || got != want {
			t.Errorf("PrimitiveBits(LLP64, %q) = %d, ok=%v; want %d", name, got, ok, want)
		}
	}
}

func TestPrimitiveBits_Unknown(t *testing.T) {
	if _, ok := PrimitiveBits(ABILP64, "struct Foo"); ok {
		t.Error("PrimitiveBits(LP64, \"struct Foo\") should be unknown")
	}
	if _, ok := PrimitiveBits(ABILP64, "my_typedef"); ok {
		t.Error("PrimitiveBits(LP64, \"my_typedef\") should be unknown")
	}
}

func TestPrimitiveAlign(t *testing.T) {
	cases := map[string]int{
		"char": 1, "short": 2, "int": 4, "long": 8,
		"long long": 8, "double": 8, "long double": 16,
		"int32_t": 4, "int64_t": 8,
	}
	for name, want := range cases {
		got, ok := PrimitiveAlign(ABILP64, name)
		if !ok || got != want {
			t.Errorf("PrimitiveAlign(LP64, %q) = %d, ok=%v; want %d", name, got, ok, want)
		}
	}
}

func TestPrimitiveSignedness(t *testing.T) {
	if s, ok := PrimitiveSignedness(ABILP64, "unsigned int"); !ok || s {
		t.Error("unsigned int should be unsigned")
	}
	if s, ok := PrimitiveSignedness(ABILP64, "int"); !ok || !s {
		t.Error("int should be signed")
	}
	if s, ok := PrimitiveSignedness(ABILP64, "uint64_t"); !ok || s {
		t.Error("uint64_t should be unsigned")
	}
}

func TestPointerBits(t *testing.T) {
	if got := PointerBits(ABILP64); got != 64 {
		t.Errorf("PointerBits(LP64) = %d; want 64", got)
	}
	if got := PointerBits(ABIILP32); got != 32 {
		t.Errorf("PointerBits(ILP32) = %d; want 32", got)
	}
	if got := PointerBits(ABILLP64); got != 64 {
		t.Errorf("PointerBits(LLP64) = %d; want 64", got)
	}
}

func TestIsFloat(t *testing.T) {
	for _, name := range []string{"float", "double", "long double"} {
		if !IsFloat(name) {
			t.Errorf("IsFloat(%q) = false; want true", name)
		}
	}
	for _, name := range []string{"int", "char", "long"} {
		if IsFloat(name) {
			t.Errorf("IsFloat(%q) = true; want false", name)
		}
	}
}

func TestIsPointerSpelling(t *testing.T) {
	cases := map[string]bool{
		"char *": true, "int *": true, "void *": true,
		"int": false, "struct Foo": false, "": false,
	}
	for spelling, want := range cases {
		if got := IsPointerSpelling(spelling); got != want {
			t.Errorf("IsPointerSpelling(%q) = %v; want %v", spelling, got, want)
		}
	}
}

func TestNormalizeABI(t *testing.T) {
	if got := NormalizeABI("lp64"); got != ABILP64 {
		t.Errorf("NormalizeABI(\"lp64\") = %v; want lp64", got)
	}
	if got := NormalizeABI("ilp32"); got != ABIILP32 {
		t.Errorf("NormalizeABI(\"ilp32\") = %v; want ilp32", got)
	}
	if got := NormalizeABI("garbage"); got != ABILP64 {
		t.Errorf("NormalizeABI(\"garbage\") = %v; want lp64 fallback", got)
	}
}

func TestProvenanceCanConfirm(t *testing.T) {
	if !ProvenanceCompilerProven.CanConfirm() {
		t.Error("compiler_proven should CanConfirm")
	}
	if !ProvenanceDerivedFromFullConfig.CanConfirm() {
		t.Error("derived_from_complete_config should CanConfirm")
	}
	if ProvenanceAssumedDefaultABI.CanConfirm() {
		t.Error("assumed_default_abi should NOT CanConfirm")
	}
	if ProvenanceUnknown.CanConfirm() {
		t.Error("unknown should NOT CanConfirm")
	}
}
