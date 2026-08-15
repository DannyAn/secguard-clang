package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type NullSourceDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewNullSourceDetector(store db.Store, p *parser.Parser, logger *log.Logger) *NullSourceDetector {
	return &NullSourceDetector{store: store, parser: p, logger: logger}
}

func (d *NullSourceDetector) Name() string { return "null_source" }

func (d *NullSourceDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Pass 1: return-null and malloc sources. detectReturnNull populates the
	// function_summary return-nullability that detectExternalCall consults, so it
	// must complete for every function before the external-call pass builds its
	// nullable-function map.
	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		for _, f := range funcs {
			d.detectReturnNull(ctx, f, file, returns, &result)
			d.detectMallocResult(ctx, f, file, assigns, inits, &result)
			d.detectExplicitNull(ctx, f, file, assigns, inits, &result)
		}
	})
	if err != nil {
		return result, fmt.Errorf("null source: %w", err)
	}

	knownFuncs := d.getKnownFunctionNames(ctx)
	nullableFuncs := d.getNullableReturnFunctions(ctx)

	// Pass 2: external-call sources, now that nullableFuncs is complete.
	err = forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		for _, f := range funcs {
			d.detectExternalCall(ctx, f, file, assigns, inits, &result, knownFuncs, nullableFuncs)
		}
	})
	return result, err
}

func (d *NullSourceDetector) detectReturnNull(ctx context.Context, f *db.Function, file *db.File, returns []parser.Node, result *DetectResult) {
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		text := ret.Text()
		if strings.Contains(text, "NULL") || (strings.Contains(text, "return") && strings.Contains(text, " 0")) {
			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: ret.StartLine(), Column: ret.StartColumn()})
			props, _ := json.Marshal(map[string]string{"variable": "<return>", "origin": "return"})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "NULL_VALUE",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
				d.store.UpdateReturnNullable(ctx, f.ID, true)
			}
		}
	}
}

func (d *NullSourceDetector) detectMallocResult(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult) {
	allocators := []string{"malloc", "calloc", "realloc"}

	checkNode := func(node parser.Node) {
		text := node.Text()
		for _, a := range allocators {
			if strings.Contains(text, a) {
				children := node.NamedChildren()
				if len(children) < 2 {
					return
				}
				lhs := children[0]
				varName := assignedVariable(lhs)
				if varName != "" {
					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: node.StartLine()})
					props, _ := json.Marshal(map[string]string{"variable": varName, "origin": a})
					_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "NULL_VALUE",
						EntityID:   f.ID,
						LocationID: locID,
						Properties: string(props),
					})
					if err == nil {
						result.EventsCreated++
					}
				}
				return
			}
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

// detectExplicitNull records a DEFINITE null source: `p = NULL` / `p = nullptr`
// / `p = (void*)0`. Unlike malloc/fopen (which may or may not return NULL),
// an explicit null assignment means the pointer IS null, so a later dereference
// is a definite null-deref (the must-analysis tier the AI does not need to
// re-derive). It deliberately skips bare `0` (ambiguous with a zero int).
func (d *NullSourceDetector) detectExplicitNull(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult) {
	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		varName := assignedVariable(children[0])
		if varName == "" {
			return
		}
		if !isNullLiteral(children[1].Text()) {
			return
		}
		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: node.StartLine()})
		props, _ := json.Marshal(map[string]string{"variable": varName, "origin": "explicit_null", "definite": "true"})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "NULL_VALUE",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

// isNullLiteral reports whether an expression is an explicit null pointer
// constant (NULL, nullptr, or a (void*)0 cast). Bare 0 is excluded because it
// is ambiguous with a zero integer value.
func isNullLiteral(text string) bool {
	t := strings.TrimSpace(text)
	switch t {
	case "NULL", "nullptr", "(void*)0", "(void *)0", "((void*)0)", "((void *)0)":
		return true
	}
	return false
}

func (d *NullSourceDetector) detectExternalCall(ctx context.Context, f *db.Function, file *db.File, assigns, inits []parser.Node, result *DetectResult, knownFuncs map[string]bool, nullableFuncs map[string]bool) {
	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs := children[0]
		rhs := children[1]
		varName := assignedVariable(lhs)
		if varName == "" {
			return
		}
		callExpr := rhs
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					callExpr = child
					break
				}
			}
		}
		if callExpr.Kind() != "call_expression" {
			return
		}
		callName := extractCallName(callExpr)
		if callName == "" || isAllocator(callName) {
			return
		}
		if knownFuncs[callName] && !nullableFuncs[callName] {
			return
		}
		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: node.StartLine()})
		props, _ := json.Marshal(map[string]string{"variable": varName, "origin": "external_call", "function": callName})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "NULL_VALUE",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}
}

func (d *NullSourceDetector) getKnownFunctionNames(ctx context.Context) map[string]bool {
	funcs, _ := d.store.ListFunctions(ctx)
	m := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		m[f.Name] = true
	}
	return m
}

func (d *NullSourceDetector) getNullableReturnFunctions(ctx context.Context) map[string]bool {
	funcs, _ := d.store.ListFunctions(ctx)
	m := make(map[string]bool)
	for _, f := range funcs {
		sum, err := d.store.GetSummaryByFunction(ctx, f.ID)
		if err != nil || sum == nil {
			continue
		}
		if sum.ReturnNullable {
			m[f.Name] = true
		}
	}
	return m
}

func isAllocator(name string) bool {
	switch name {
	case "malloc", "calloc", "realloc", "free":
		return true
	}
	return false
}

func extractCallName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// assignedVariable returns the storage location a value is assigned into,
// matching the dereference detector's attribution so that a NULL_VALUE source
// and a later DEREFERENCE resolve to the same variable. A field access is
// attributed by its full path text ("p->data"), not its first identifier
// ("p"), so that `p->data = malloc()` marks `p->data` (and only `p->data`) as
// nullable rather than suppressing every deref of `p`.
func assignedVariable(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "field_expression", "subscript_expression":
		return lhs.Text()
	}
	// *p = ... and other shapes: attribute to the first identifier inside.
	for _, child := range lhs.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}
