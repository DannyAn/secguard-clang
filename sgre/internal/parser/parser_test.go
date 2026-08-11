package parser

import (
	"testing"
)

func TestNewParser(t *testing.T) {
	p := NewParser()
	if p == nil {
		t.Fatal("NewParser returned nil")
	}
}

func TestParseCSource(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 0; }`)
	tree, err := p.Parse(source, "test.c")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	defer tree.Close()

	root := tree.RootNode()
	if root.Kind() != "translation_unit" {
		t.Errorf("expected root kind 'translation_unit', got %q", root.Kind())
	}
}

func TestParse_HasErrorFlag(t *testing.T) {
	p := NewParser()
	source := []byte(`int broken( { return 0 }`)
	tree, _ := p.Parse(source, "broken.c")
	defer tree.Close()

	if !tree.HasError() {
		t.Error("expected HasError=true for syntax error file")
	}
}

func TestParse_FindAllFunctions(t *testing.T) {
	p := NewParser()
	source := []byte(`
int func_a(void) { return 1; }
static int func_b(int x) { return x; }
void func_c(void) { }
`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) != 3 {
		t.Errorf("expected 3 function_definition nodes, got %d", len(funcs))
	}
}

func TestNode_Text(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 42; }`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
	text := funcs[0].Text()
	if text == "" {
		t.Error("expected non-empty function text")
	}
}

func TestNode_StartLine(t *testing.T) {
	p := NewParser()
	source := []byte("\n\nint main(void) {\n  return 0;\n}\n")
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
	if funcs[0].StartLine() != 3 {
		t.Errorf("expected start line 3, got %d", funcs[0].StartLine())
	}
}

func TestNode_ChildByFieldName(t *testing.T) {
	p := NewParser()
	source := []byte(`int main(void) { return 0; }`)
	tree, _ := p.Parse(source, "test.c")
	defer tree.Close()

	root := tree.RootNode()
	funcs := root.FindAll("function_definition")
	if len(funcs) == 0 {
		t.Fatal("no function_definition found")
	}
}
