package evidence

import (
	"context"
	"encoding/json"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SizeofMisuseDetector flags `sizeof` applied to a pointer VARIABLE (not
// `sizeof(*p)` and not `sizeof(T)`) when that size is passed to a
// malloc-family / memset / memcpy-family call (CWE-467/468). `malloc(n *
// sizeof(p))` allocates n pointers' worth of bytes regardless of `*p`'s size,
// and `memset(p, 0, sizeof(p))` zeroes only a pointer's width — both are the
// classic incorrect-pointer-scaling defects.
type SizeofMisuseDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSizeofMisuseDetector(store db.Store, p *parser.Parser, logger *log.Logger) *SizeofMisuseDetector {
	return &SizeofMisuseDetector{store: store, parser: p, logger: logger}
}

func (d *SizeofMisuseDetector) Name() string { return "sizeof_misuse" }

func (d *SizeofMisuseDetector) Domain() string { return "boundary" }

func (d *SizeofMisuseDetector) Capabilities() []string {
	return []string{"sizeof-pointer", "pointer-scaling"}
}

func (d *SizeofMisuseDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		sizeExprs := root.FindAll("sizeof_expression")
		ptrDecls := root.FindAll("pointer_declarator")

		for _, f := range funcs {
			ptrVars := d.pointerVars(ptrDecls, f)
			for _, se := range sizeExprs {
				if !funcLineRange(f, se.StartLine()) {
					continue
				}
				operand := sizeofOperandName(se)
				if operand == "" || !ptrVars[operand] {
					continue
				}
				if !d.inSizeContext(se) {
					continue
				}

				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: se.StartLine(), Column: se.StartColumn()})
				props, _ := json.Marshal(map[string]string{
					"expression": se.Text(),
					"variable":   operand,
					"category":   "sizeof_pointer",
				})
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "SIZEOF_MISUSE",
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

// pointerVars returns the set of names declared with a pointer declarator
// (`T *p`) inside f's line range.
func (d *SizeofMisuseDetector) pointerVars(ptrDecls []parser.Node, f *db.Function) map[string]bool {
	set := make(map[string]bool)
	for _, pd := range ptrDecls {
		if !funcLineRange(f, pd.StartLine()) {
			continue
		}
		if name := extractVarName(pd); name != "" {
			set[name] = true
		}
	}
	return set
}

// sizeofOperandName returns the operand of a `sizeof` expression when it is a
// bare identifier (`sizeof(p)`), or "" for `sizeof(*p)`, `sizeof(T)`, and
// `sizeof arr` (array-to-pointer decay is a size-of-array, not a bug here).
// `sizeof(p)` parses the operand as a parenthesized_expression, so it is
// unwrapped first.
func sizeofOperandName(se parser.Node) string {
	children := se.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	op := children[0]
	for op.Kind() == "parenthesized_expression" {
		inner := op.NamedChildren()
		if len(inner) == 0 {
			return ""
		}
		op = inner[0]
	}
	if op.Kind() != "identifier" {
		return ""
	}
	return op.Text()
}

// inSizeContext reports whether the sizeof expression is consumed as the size
// argument of a malloc-family / memset / memcpy-family call.
func (d *SizeofMisuseDetector) inSizeContext(se parser.Node) bool {
	for p := se.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "call_expression":
			return sizeFunctions[extractCallName(*p)]
		case "expression_statement", "compound_statement", "return_statement", "declaration":
			return false
		}
	}
	return false
}
