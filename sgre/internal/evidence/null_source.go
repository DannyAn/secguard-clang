package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("null source: list functions: %w", err)
	}

	// Pass 1: return-null and malloc sources. detectReturnNull populates the
	// function_summary return-nullability that detectExternalCall consults, so it
	// must complete for every function before the external-call pass builds its
	// nullable-function map. The previous single-pass version called
	// getNullableReturnFunctions once per function (an O(F^2) run of DB reads)
	// and still read a half-populated map.
	for _, f := range funcs {
		file, root, ok := d.rootFor(ctx, f)
		if !ok {
			continue
		}
		d.detectReturnNull(ctx, f, file, root, &result)
		d.detectMallocResult(ctx, f, file, root, &result)
	}

	knownFuncs := d.getKnownFunctionNames(ctx)
	nullableFuncs := d.getNullableReturnFunctions(ctx)

	// Pass 2: external-call sources, now that nullableFuncs is complete.
	for _, f := range funcs {
		file, root, ok := d.rootFor(ctx, f)
		if !ok {
			continue
		}
		d.detectExternalCall(ctx, f, file, root, &result, knownFuncs, nullableFuncs)
	}

	return result, nil
}

// rootFor returns the parsed root node for a function, reusing the parser's
// per-file cache so each file is read and parsed at most once across the
// detector's two passes.
func (d *NullSourceDetector) rootFor(ctx context.Context, f *db.Function) (*db.File, parser.Node, bool) {
	file, _ := d.store.GetFileByID(ctx, f.FileID)
	if file == nil {
		return nil, parser.Node{}, false
	}
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return nil, parser.Node{}, false
	}
	tree, err := d.parser.ParseCached(source, file.Path)
	if err != nil {
		return nil, parser.Node{}, false
	}
	return file, tree.RootNode(), true
}

func (d *NullSourceDetector) detectReturnNull(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	returns := root.FindAll("return_statement")
	for _, ret := range returns {
		if ret.StartLine() < f.StartLine || ret.StartLine() > f.EndLine {
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

func (d *NullSourceDetector) detectMallocResult(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
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

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		checkNode(assign)
	}

	for _, init := range root.FindAll("init_declarator") {
		if init.StartLine() < f.StartLine || init.StartLine() > f.EndLine {
			continue
		}
		checkNode(init)
	}
}

func (d *NullSourceDetector) detectExternalCall(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult, knownFuncs map[string]bool, nullableFuncs map[string]bool) {
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

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		checkNode(assign)
	}

	for _, init := range root.FindAll("init_declarator") {
		if init.StartLine() < f.StartLine || init.StartLine() > f.EndLine {
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
