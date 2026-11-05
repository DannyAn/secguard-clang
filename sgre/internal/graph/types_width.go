package graph

import "github.com/DannyAn/secguard-clang/internal/typeinfo"

// WidthOfName returns the LP64 bit width of a recognized integer or float type
// spelling, delegating to the shared typeinfo ABI table (GAP-1038 Phase 1a
// width-table convergence). The second return value is false when the name is
// not a recognized type.
func WidthOfName(name string) (int, bool) {
	return typeinfo.PrimitiveBits(typeinfo.ABILP64, name)
}

// TypeByName resolves a C type spelling to a Type using the LP64 width and
// default signedness tables (now sourced from typeinfo). The second return
// value is false when the spelling is not a recognized integer / float type.
//
// The `unsigned ` / `signed ` prefixes are handled by flipping the default
// signedness of the base spelling.
func TypeByName(name string) (Type, bool) {
	if rest, ok := stripPrefix(name, "unsigned "); ok {
		base, found := TypeByName(rest)
		if !found || base.Kind == TypeFloat {
			return Type{}, false
		}
		base.Kind = TypeUint
		base.Signed = false
		base.Name = name
		return base, true
	}
	if rest, ok := stripPrefix(name, "signed "); ok {
		base, found := TypeByName(rest)
		if !found || base.Kind == TypeFloat {
			return Type{}, false
		}
		base.Kind = TypeInt
		base.Signed = true
		base.Name = name
		return base, true
	}
	if typeinfo.IsFloat(name) {
		w, _ := typeinfo.PrimitiveBits(typeinfo.ABILP64, name)
		return Type{Kind: TypeFloat, Width: w, Name: name}, true
	}
	if w, ok := typeinfo.PrimitiveBits(typeinfo.ABILP64, name); ok {
		signed, known := typeinfo.PrimitiveSignedness(typeinfo.ABILP64, name)
		kind := TypeInt
		if known && !signed {
			kind = TypeUint
		}
		return Type{Kind: kind, Width: w, Signed: signed, Name: name}, true
	}
	return Type{}, false
}

// stripPrefix removes a leading prefix from s, returning the rest and true
// when the prefix matched.
func stripPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return s, false
}
