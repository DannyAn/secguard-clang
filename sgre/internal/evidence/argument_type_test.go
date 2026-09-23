package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestResolveScopedVar_NestedShadowScopeEnds locks in the cross-scope shadowing
// fix: a same-name declaration in a nested block must stop shadowing once that
// block closes. Before the fix, resolveScopedVar only picked the nearest
// declaration on-or-before the line, so a use after the inner block ended still
// resolved to the (out-of-scope) inner declaration.
func TestResolveScopedVar_NestedShadowScopeEnds(t *testing.T) {
	globals := map[string]string{}
	locals := []scopedVarDecl{
		{name: "p", typ: "int *", line: 5, end: 100}, // outer, function-scoped
		{name: "p", typ: "bool", line: 10, end: 20},  // inner block shadow
	}
	if got := resolveScopedVar("p", 15, globals, locals); got != "bool" {
		t.Errorf("line 15: got %q, want bool (inner shadow in scope)", got)
	}
	if got := resolveScopedVar("p", 25, globals, locals); got != "int *" {
		t.Errorf("line 25: got %q, want int * (outer after inner scope ended)", got)
	}
	// Before the first local declaration, fall back to the file-scope global.
	globals["p"] = "char *"
	if got := resolveScopedVar("p", 3, globals, locals); got != "char *" {
		t.Errorf("line 3: got %q, want char * (global fallback)", got)
	}
}

// TestDeclScopeEnd_NestedBlock verifies declScopeEnd returns the enclosing
// block's closing line for a shadowing declaration, not the whole function end.
func TestDeclScopeEnd_NestedBlock(t *testing.T) {
	p := parser.NewParser()
	src := []byte("void f(void) {\n  int x = 0;\n  {\n    int x = 1;\n  }\n  x = 2;\n}\n")
	tree, err := p.Parse(src, "t.c")
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()

	fn := &db.Function{StartLine: 1, EndLine: 7}
	var inner parser.Node
	found := false
	for _, d := range tree.RootNode().FindAll("declaration") {
		if d.StartLine() == 4 {
			inner = d
			found = true
			break
		}
	}
	if !found {
		t.Fatal("inner declaration (line 4) not found")
	}
	if got := declScopeEnd(inner, fn); got != 5 {
		t.Errorf("inner decl scope end = %d, want 5 (inner block close)", got)
	}
}

func TestArgumentTypeDetector(t *testing.T) {
	store := runOneDetector(t, "tc119_argument_type.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewArgumentTypeDetector(s, p, l) })
	if got := eventCount(t, store, "ARGUMENT_TYPE_MISMATCH"); got != 2 {
		t.Errorf("expected 2 ARGUMENT_TYPE_MISMATCH events (bool→uint, uint32→uint64), got %d", got)
	}
}

// TestArgumentTypeDetector_Properties pins the root-cause evidence fields: the
// event must carry the callee, source variable, expected parameter type, actual
// pre-cast pointer type, and the explicit cast target, so the AI agent sees the
// contract violation rather than a bare cast.
func TestArgumentTypeDetector_Properties(t *testing.T) {
	store := runOneDetector(t, "tc119_argument_type.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewArgumentTypeDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "ARGUMENT_TYPE_MISMATCH")
	if err != nil {
		t.Fatalf("list ARGUMENT_TYPE_MISMATCH events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 ARGUMENT_TYPE_MISMATCH events, got %d", len(events))
	}

	type props struct {
		Function string `json:"function"`
		Variable string `json:"variable"`
		Expected string `json:"expected"`
		Actual   string `json:"actual"`
		Cast     string `json:"cast"`
	}
	byVar := map[string]props{}
	for _, e := range events {
		var p props
		if err := json.Unmarshal([]byte(e.Properties), &p); err != nil {
			t.Fatalf("unmarshal event props: %v", err)
		}
		byVar[p.Variable] = p
	}

	flag, ok := byVar["flag"]
	if !ok {
		t.Fatalf("missing bool→uint event, got %+v", byVar)
	}
	if flag.Function != "sink_uint" || flag.Expected != "uint *" || flag.Actual != "bool *" || flag.Cast != "uint *" {
		t.Errorf("bool→uint props wrong: %+v", flag)
	}

	x, ok := byVar["x"]
	if !ok {
		t.Fatalf("missing uint32→uint64 event, got %+v", byVar)
	}
	if x.Function != "sink_u64" || x.Expected != "uint64_t *" || x.Actual != "uint32_t *" || x.Cast != "uint64_t *" {
		t.Errorf("uint32→uint64 props wrong: %+v", x)
	}
}
