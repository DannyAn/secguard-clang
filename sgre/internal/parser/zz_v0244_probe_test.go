package parser

import "testing"

func TestV0244_B1_VarDeclPostAttribute(t *testing.T) {
	cases := []string{
		`int g __attribute__((aligned(16))) = 0;`,
		`int g __attribute__((packed)) = 0;`,
		`int g __attribute__((section(".data"))) = 0;`,
		`int g __attribute__((used)) = 0;`,
		`void free_fn(int *p){}  int f(void){ int g __attribute__((cleanup(free_fn))) = 0; return g; }`,
	}
	for i, src := range cases {
		p := NewParser()
		tree, err := p.Parse([]byte(src), "probe.c")
		if err != nil {
			t.Fatalf("B1 case %d parse error: %v", i, err)
		}
		if tree.HasError() {
			t.Errorf("B1 case %d HasError=true: %s", i, src)
		}
		tree.Close()
		p.CloseAll()
	}
}

func TestV0244_B2_TypedefAttribute(t *testing.T) {
	cases := []string{
		`typedef int __attribute__((vector_size(16))) v4si;`,
		`typedef int __attribute__((may_alias)) alias_int;`,
	}
	for i, src := range cases {
		p := NewParser()
		tree, err := p.Parse([]byte(src), "probe.c")
		if err != nil {
			t.Fatalf("B2 case %d parse error: %v", i, err)
		}
		if tree.HasError() {
			t.Errorf("B2 case %d HasError=true: %s", i, src)
		}
		tree.Close()
		p.CloseAll()
	}
}

func TestV0244_B3_EnumAttribute(t *testing.T) {
	src := `enum E __attribute__((packed)) { A, B, C };`
	p := NewParser()
	tree, err := p.Parse([]byte(src), "probe.c")
	if err != nil {
		t.Fatalf("B3 parse error: %v", err)
	}
	if tree.HasError() {
		t.Errorf("B3 HasError=true: %s", src)
	}
	tree.Close()
	p.CloseAll()
}

func TestV0244_B4_LabelAttribute(t *testing.T) {
	src := `int f(void){ goto L; L: __attribute__((cold)); return 0; }`
	p := NewParser()
	tree, err := p.Parse([]byte(src), "probe.c")
	if err != nil {
		t.Fatalf("B4 parse error: %v", err)
	}
	if tree.HasError() {
		t.Errorf("B4 HasError=true: %s", src)
	}
	tree.Close()
	p.CloseAll()
}

func TestV0244_B5_CaseRange(t *testing.T) {
	src := `int f(int x){ switch(x){ case 1 ... 5: return 1; default: return 0; } }`
	p := NewParser()
	tree, err := p.Parse([]byte(src), "probe.c")
	if err != nil {
		t.Fatalf("B5 parse error: %v", err)
	}
	if tree.HasError() {
		t.Errorf("B5 HasError=true: %s", src)
	}
	tree.Close()
	p.CloseAll()
}

func TestV0244_B6_ComputedGoto(t *testing.T) {
	cases := []string{
		`int f(void){ void *p = &&L; goto *p; L: return 0; }`,
		`int f(void){ L: void *p = &&L; goto *p; return 0; }`,
	}
	for i, src := range cases {
		p := NewParser()
		tree, err := p.Parse([]byte(src), "probe.c")
		if err != nil {
			t.Fatalf("B6 case %d parse error: %v", i, err)
		}
		if tree.HasError() {
			t.Errorf("B6 case %d HasError=true: %s", i, src)
		}
		tree.Close()
		p.CloseAll()
	}
}
