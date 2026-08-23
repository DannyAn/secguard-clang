package evidence

import (
	"context"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// typedefs is a lightweight typedef resolution table. tree-sitter gives us the
// *syntax* tree — `typedef` declarations are fully present as `type_definition`
// nodes — but not the *semantic* type resolution a compiler would do. This table
// closes that gap for the two properties the sizeof-misuse and signed-compare
// detectors need: whether a type is a pointer, and whether it is unsigned.
//
// It resolves typedef names transitively. The table is built per-file, but the
// detectors prime it with a *cross-file* pass over every indexed file (including
// headers) via buildGlobalTypedefs, then let the current file's own typedefs
// override the global view — mirroring C's rule that a translation unit's local
// typedef shadows an included header's.
type typedefs struct {
	// underlying maps a typedef name to its base type spelling (the specifier
	// text plus any `*` from a pointer_declarator), e.g. "my_uint" → "unsigned int",
	// "cstr_t" → "char *", "FooPtr" → "Foo *".
	underlying map[string]string
	// isPointer is the cached resolution of "does this type (transitively)
	// resolve to a pointer?".
	isPointer map[string]bool
	// isUnsigned is the cached resolution of "does this type (transitively)
	// resolve to an unsigned integer type?".
	isUnsigned map[string]bool
}

func emptyTypedefs() *typedefs {
	return &typedefs{
		underlying: make(map[string]string),
		isPointer:  make(map[string]bool),
		isUnsigned: make(map[string]bool),
	}
}

// buildGlobalTypedefs collects typedef declarations from every indexed file
// (including headers, which carry most real-world typedefs) into one table. It
// mirrors the cross-file pattern of InterproceduralDetector: read every file via
// the store, parse once (ParseCached), and aggregate into memory. Detectors then
// clone it and overlay the current file's own typedefs.
func buildGlobalTypedefs(ctx context.Context, store db.Store, p *parser.Parser) *typedefs {
	t := emptyTypedefs()
	files, err := store.ListFiles(ctx)
	if err != nil {
		return t
	}
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		t.addRoot(tree.RootNode())
	}
	return t
}

// addRoot merges every typedef declaration in a file's root node, overriding any
// earlier definition of the same name (so the current file wins over the global
// pass).
func (t *typedefs) addRoot(root parser.Node) {
	for _, td := range root.FindAll("type_definition") {
		name, base := typedefParts(td)
		if name == "" {
			continue
		}
		t.underlying[name] = base
	}
	// The underlying table changed, so any cached resolution is now stale.
	t.isPointer = make(map[string]bool)
	t.isUnsigned = make(map[string]bool)
}

// clone returns a shallow copy of the underlying table with a fresh resolution
// cache, so a detector can overlay the current file's typedefs without mutating
// the shared global table.
func (t *typedefs) clone() *typedefs {
	c := emptyTypedefs()
	for k, v := range t.underlying {
		c.underlying[k] = v
	}
	return c
}

// typedefParts returns the typedef's name and its base type spelling from a
// `type_definition` node. The base is the leading specifier (`unsigned int`,
// `char`, `struct {...}`, or another typedef's name) plus one `*` per pointer
// declarator level; the name is the last `type_identifier` (the declarator's
// identifier, which for `typedef Foo *FooPtr` is `FooPtr`, not `Foo`).
func typedefParts(td parser.Node) (name, base string) {
	var baseParts []string
	var declarator parser.Node
	haveDeclarator := false
	for _, child := range td.NamedChildren() {
		switch child.Kind() {
		case "type_identifier", "primitive_type", "sized_type_specifier", "struct_specifier", "union_specifier", "enum_specifier":
			baseParts = append(baseParts, strings.TrimSpace(child.Text()))
		case "pointer_declarator":
			declarator = child
			haveDeclarator = true
		}
	}
	if len(baseParts) == 0 {
		return "", ""
	}
	baseType := baseParts[0]
	if haveDeclarator {
		name = declaratorName(declarator)
		cur := declarator
		for cur.Kind() == "pointer_declarator" {
			baseType += "*"
			parent := cur.Parent()
			if parent == nil || parent.Kind() != "pointer_declarator" {
				break
			}
			cur = *parent
		}
	} else {
		// `typedef struct {...} Foo;` — the trailing type_identifier is the name,
		// the leading specifier is the base.
		name = baseParts[len(baseParts)-1]
	}
	return name, baseType
}

// declaratorName returns the identifier declared by a pointer/array/function
// declarator, matching the declarator's own kind (which is a `type_identifier`
// in a typedef, or an `identifier` elsewhere).
func declaratorName(declarator parser.Node) string {
	for _, child := range declarator.NamedChildren() {
		if child.Kind() == "type_identifier" || child.Kind() == "identifier" || child.Kind() == "field_identifier" {
			return child.Text()
		}
	}
	return ""
}

// resolvesToPointer reports whether type (a type spelling) is, transitively, a
// pointer type: either it spells a pointer (`char *`), or it is a typedef whose
// base resolves to a pointer.
func (t *typedefs) resolvesToPointer(typeSpelling string) bool {
	if typeSpelling == "" {
		return false
	}
	if strings.HasSuffix(typeSpelling, "*") {
		return true
	}
	name := typeSpelling
	if v, ok := t.isPointer[name]; ok {
		return v
	}
	base, ok := t.underlying[name]
	if !ok || base == name {
		return false
	}
	res := t.resolvesToPointer(base)
	t.isPointer[name] = res
	return res
}

// resolvesToUnsigned reports whether type (a type spelling) is, transitively, an
// unsigned integer type: an `unsigned` spelling, or a typedef whose base resolves
// to unsigned.
func (t *typedefs) resolvesToUnsigned(typeSpelling string) bool {
	if typeSpelling == "" {
		return false
	}
	if isUnsignedDecl(typeSpelling) {
		return true
	}
	name := typeSpelling
	if v, ok := t.isUnsigned[name]; ok {
		return v
	}
	base, ok := t.underlying[name]
	if !ok || base == name {
		return false
	}
	res := t.resolvesToUnsigned(base)
	t.isUnsigned[name] = res
	return res
}
