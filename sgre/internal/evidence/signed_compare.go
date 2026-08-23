package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SignedCompareDetector flags an `unsigned` variable compared with `0` via `<`
// (or with a negative literal via `<=`/`<`), which is always false because an
// unsigned value is never negative (CWE-681 / CWE-195). The comparison is
// provably dead logic — a classic sign-conversion defect (e.g. a loop guard
// `for (size_t i = n; i >= 0; i--)` never terminates, or a bounds check that
// silently passes).
type SignedCompareDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSignedCompareDetector(store db.Store, p *parser.Parser, logger *log.Logger) *SignedCompareDetector {
	return &SignedCompareDetector{store: store, parser: p, logger: logger}
}

func (d *SignedCompareDetector) Name() string { return "signed_compare" }

func (d *SignedCompareDetector) Domain() string { return "boundary" }

func (d *SignedCompareDetector) Capabilities() []string {
	return []string{"unsigned-negative", "sign-conversion"}
}

// unsignedTypeMarkers are type spellings that are unsigned by definition in C
// (the `unsigned` keyword plus the ubiquitous typedefs). The detector matches
// them textually because a lightweight detector has no typedef resolution.
var unsignedTypeMarkers = []string{
	"unsigned", "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
	"uintptr_t", "DWORD", "ULONG", "ULONGLONG",
}

func isUnsignedDecl(text string) bool {
	// ssize_t is the signed counterpart of size_t; the substring match on
	// "size_t" must not classify it as unsigned (ssize_t nwritten < 0 is a
	// legitimate signed check, not dead logic).
	if strings.Contains(text, "ssize_t") {
		return false
	}
	for _, m := range unsignedTypeMarkers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

func (d *SignedCompareDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Cross-file typedef table: `my_uint`/`size_t` are typically declared in a
	// header, so resolve against every indexed file, then overlay the current
	// file's own typedefs per function.
	global := buildGlobalTypedefs(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		decls := root.FindAll("declaration")
		params := root.FindAll("parameter_declaration")
		binaries := root.FindAll("binary_expression")
		typedefs := global.clone()
		typedefs.addRoot(root)

		for _, f := range funcs {
			unsignedVars := d.unsignedVars(append(decls, params...), f, typedefs)
			for _, b := range binaries {
				if !funcLineRange(f, b.StartLine()) {
					continue
				}
				if !d.unsignedVsNegative(b, unsignedVars) {
					continue
				}

				if emitEvent(ctx, d.store, d.logger, "SIGNED_COMPARE", f.ID, &db.Location{FileID: file.ID, Line: b.StartLine(), Column: b.StartColumn()}, map[string]string{
					"expression": b.Text(),
					"category":   "signed_compare",
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// unsignedVars returns the names declared with an `unsigned` type in f's line
// range. Unlike a whole-declaration identifier scan (which would also pick up
// names from an initializer expression), the declared name is taken from each
// declarator, so `unsigned int x = n;` yields only `x` and multi-declarators
// (`unsigned int y, z;`) yield both `y` and `z`. A typedef whose base resolves
// to unsigned (`typedef unsigned int my_uint; my_uint x;`) is detected via the
// typedefs table, not just a keyword substring match.
func (d *SignedCompareDetector) unsignedVars(decls []parser.Node, f *db.Function, typedefs *typedefs) map[string]bool {
	set := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		if !d.unsignedType(decl, typedefs) {
			continue
		}
		// Pick up the declarators (init_declarator, pointer_declarator, or a
		// bare identifier for `size_t i;`). extractVarName on the whole `decl`
		// would find the FIRST identifier only, so iterate each declarator so
		// multi-declarators are all registered.
		for _, child := range decl.NamedChildren() {
			switch child.Kind() {
			case "init_declarator", "pointer_declarator", "identifier":
				if name := extractVarName(child); name != "" && !parser.IsCTypeKeyword(name) {
					set[name] = true
				}
			}
		}
	}
	return set
}

// unsignedType reports whether a declaration's type specifier is unsigned,
// resolving typedef names through the typedefs table. It keys off the type
// specifier (`unsigned int`, `size_t`, `my_uint`), not the whole declaration
// text, so the initializer/declarator parts can never contribute a false match.
func (d *SignedCompareDetector) unsignedType(decl parser.Node, typedefs *typedefs) bool {
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "primitive_type", "sized_type_specifier", "type_identifier":
			return isUnsignedDecl(child.Text()) || typedefs.resolvesToUnsigned(child.Text())
		}
	}
	return false
}

// unsignedVsNegative reports whether b is `<`/`<=` with an unsigned variable on
// the left and `0` or a negative literal on the right (always false), or a
// mirrored form `0 > x`.
func (d *SignedCompareDetector) unsignedVsNegative(b parser.Node, unsignedVars map[string]bool) bool {
	op := ""
	for _, child := range b.Children() {
		switch child.Kind() {
		case "<", "<=", ">", ">=":
			op = child.Kind()
		}
	}
	if op == "" {
		return false
	}
	named := b.NamedChildren()
	if len(named) < 2 {
		return false
	}
	left, right := named[0], named[len(named)-1]

	// x < 0, x <= -1: always false for unsigned x.
	if unsignedVars[left.Text()] && isZeroOrNegative(right.Text()) {
		return true
	}
	// 0 > x, -1 >= x: same defect mirrored.
	if unsignedVars[right.Text()] && isZeroOrNegative(left.Text()) {
		return true
	}
	return false
}

func isZeroOrNegative(text string) bool {
	t := strings.TrimSpace(text)
	if t == "0" || t == "0U" || t == "0u" || t == "0UL" || t == "0ULL" {
		return true
	}
	return strings.HasPrefix(t, "-")
}
