package evidence

import (
	"context"
	"encoding/json"
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
	for _, m := range unsignedTypeMarkers {
		if strings.Contains(text, m) {
			return true
		}
	}
	return false
}

func (d *SignedCompareDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		decls := root.FindAll("declaration")
		params := root.FindAll("parameter_declaration")
		binaries := root.FindAll("binary_expression")

		for _, f := range funcs {
			unsignedVars := d.unsignedVars(append(decls, params...), f)
			for _, b := range binaries {
				if !funcLineRange(f, b.StartLine()) {
					continue
				}
				if !d.unsignedVsNegative(b, unsignedVars) {
					continue
				}

				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: b.StartLine(), Column: b.StartColumn()})
				props, _ := json.Marshal(map[string]string{
					"expression": b.Text(),
					"category":   "signed_compare",
				})
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "SIGNED_COMPARE",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				if err == nil {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// unsignedVars returns the names declared with an `unsigned` type in f's line
// range, for declarations without an initializer (so the identifier scan does
// not pick up names from the initializer expression).
func (d *SignedCompareDetector) unsignedVars(decls []parser.Node, f *db.Function) map[string]bool {
	set := make(map[string]bool)
	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		if !isUnsignedDecl(decl.Text()) {
			continue
		}
		hasInit := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "init_declarator" {
				hasInit = true
			}
		}
		if hasInit {
			continue
		}
		for _, id := range decl.FindAll("identifier") {
			if parser.IsCTypeKeyword(id.Text()) {
				continue
			}
			set[id.Text()] = true
		}
	}
	return set
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
