package graph

// LP64 type widths (macOS / Linux 64-bit). LLP64 (Windows 64-bit) differs
// only in `long` and pointer widths; the pipeline defaults to LP64 and
// exposes the table for per-platform override.
var lp64Widths = map[string]int{
	"char":      8,
	"short":     16,
	"int":       32,
	"long":      64,
	"long long": 64,

	"float":       32,
	"double":      64,
	"long double": 128,

	"size_t":    64,
	"ssize_t":   64,
	"ptrdiff_t": 64,

	"int8_t":   8,
	"int16_t":  16,
	"int32_t":  32,
	"int64_t":  64,
	"uint8_t":  8,
	"uint16_t": 16,
	"uint32_t": 32,
	"uint64_t": 64,
}

// signednessByName maps a type spelling to its default signedness.
var signednessByName = map[string]bool{
	"char":      true, // plain char is implementation-defined, but sgre treats it as signed
	"short":     true,
	"int":       true,
	"long":      true,
	"long long": true,

	"int8_t":  true,
	"int16_t": true,
	"int32_t": true,
	"int64_t": true,

	"uint8_t":   false,
	"uint16_t":  false,
	"uint32_t":  false,
	"uint64_t":  false,
	"size_t":    false,
	"ssize_t":   true,
	"ptrdiff_t": true,
}

// floatKinds are the type spellings that map to TypeFloat.
var floatKinds = map[string]bool{
	"float":       true,
	"double":      true,
	"long double": true,
}

// TypeByName resolves a C type spelling to a Type using the LP64 width and
// default signedness tables. The second return value is false when the
// spelling is not a recognized integer / float type (a typedef, a struct
// name, a pointer — those need the caller to look through repofacts /
// declarator structure).
func TypeByName(name string) (Type, bool) {
	if floatKinds[name] {
		return Type{Kind: TypeFloat, Width: lp64Widths[name], Name: name}, true
	}
	if w, ok := lp64Widths[name]; ok {
		signed, known := signednessByName[name]
		kind := TypeInt
		if known && !signed {
			kind = TypeUint
		}
		return Type{Kind: kind, Width: w, Signed: signed, Name: name}, true
	}
	return Type{}, false
}

// WidthOfName is a convenience for the common "integer width by name" query.
// The second return value is false when the name is not a recognized integer
// or float type.
func WidthOfName(name string) (int, bool) {
	w, ok := lp64Widths[name]
	return w, ok
}
