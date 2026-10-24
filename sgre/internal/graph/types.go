package graph

// TypeKind classifies a C type at the granularity the pipeline's detectors
// need (integer signedness + width, float vs pointer vs aggregate), not at
// the granularity a full C compiler would track (bit-fields, enum
// underlying types, etc).
type TypeKind int

const (
	TypeUnknown TypeKind = iota
	TypeInt              // any-width signed integer
	TypeUint             // any-width unsigned integer
	TypeFloat            // float / double / long double
	TypePointer          // T*
	TypeArray            // T[N]
	TypeStruct           // struct S
	TypeUnion
	TypeFunction
	TypeVoid
)

// Type is the pipeline's C-type model. It is deliberately small — enough
// for divide-by-zero's float exemption, integer-overflow's width-aware
// bounds, and argument-type's ABI-layout compatibility, without trying to
// be a full C type system.
type Type struct {
	Kind      TypeKind
	Width     int    // bits, only for Int/Uint/Float; 0 = unknown
	Signed    bool   // only for Int/Uint
	Pointee   *Type  // only for Pointer
	Elem      *Type  // only for Array
	ArrayLen  int64  // only for Array; -1 = unknown
	Name      string // original spelling (e.g. "uint32_t"), for display
	TypedefOf string // if a typedef, the underlying type name
}

// IsInteger reports whether t is any-width integer.
func (t Type) IsInteger() bool { return t.Kind == TypeInt || t.Kind == TypeUint }

// IsFloat reports whether t is any-width floating point.
func (t Type) IsFloat() bool { return t.Kind == TypeFloat }

// IsPointer reports whether t is a pointer type.
func (t Type) IsPointer() bool { return t.Kind == TypePointer }

// SignedMax returns the maximum value of a signed integer of t's width.
// Only meaningful when t.Kind == TypeInt and t.Width > 0.
func (t Type) SignedMax() int64 {
	if t.Width <= 0 || t.Width > 63 {
		return 0
	}
	return 1<<(t.Width-1) - 1
}

// SignedMin returns the minimum value of a signed integer of t's width.
func (t Type) SignedMin() int64 {
	if t.Width <= 0 || t.Width > 63 {
		return 0
	}
	return -1 << (t.Width - 1)
}

// UnsignedMax returns the maximum value of an unsigned integer of t's width.
// Only meaningful when t.Kind == TypeUint and t.Width > 0.
func (t Type) UnsignedMax() uint64 {
	if t.Width <= 0 || t.Width > 64 {
		return 0
	}
	if t.Width == 64 {
		return ^uint64(0)
	}
	return 1<<t.Width - 1
}
