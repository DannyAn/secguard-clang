package parser

import "testing"

// pinArg returns the single call argument of the function's only call
// expression, parsed from a one-function snippet.
func pinArg(t *testing.T, src string) Node {
	t.Helper()
	p := NewParser()
	tree, err := p.Parse([]byte(src), "pin.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, call := range tree.RootNode().FindAll("call_expression") {
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			args := child.NamedChildren()
			if len(args) > 0 {
				return args[len(args)-1]
			}
		}
	}
	t.Fatalf("no call argument found in %q", src)
	return Node{}
}

// TestAddressTakenTarget_Unambiguous pins the spellings that need no scope
// knowledge: a real `&x`, a pointer cast `(T *)&x`, and `&(x)`.
func TestAddressTakenTarget_Unambiguous(t *testing.T) {
	cases := []struct {
		name   string
		arg    string
		want   string
		wantOK bool
	}{
		{"plain address-of", `f(&dst);`, "dst", true},
		{"parenthesized operand", `f(&(dst));`, "dst", true},
		{"pointer cast", `f((unsigned int *)&dst);`, "dst", true},
		{"void pointer cast", `f((void *)&(dst));`, "dst", true},
		{"by-value", `f(dst);`, "", false},
		{"dereference", `f(*dst);`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arg := pinArg(t, "extern void f(void *p);\nvoid g(void) { void *dst; "+tc.arg+" }\n")
			tgt, ok := arg.AddressTakenTarget()
			if ok != tc.wantOK || tgt.Text() != tc.want {
				t.Errorf("AddressTakenTarget() = (%q, %v), want (%q, %v)", tgt.Text(), ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestAddressTakenTarget_AmbiguousBitAnd pins the core defect the scope oracle
// exists for: tree-sitter-c parses `(flags) & mask` and `(shm_handle)&dst`
// IDENTICALLY, so the shape alone cannot tell a cast from a bit-and.
func TestAddressTakenTarget_AmbiguousBitAnd(t *testing.T) {
	bitAnd := pinArg(t, "extern void f(unsigned x);\nvoid g(int flags, int mask) { f((flags) & mask); }\n")
	cast := pinArg(t, "extern void f(void *p);\nvoid g(void) { int dst; f((shm_handle)&dst); }\n")
	if bitAnd.node.ToSexp() != cast.node.ToSexp() {
		t.Fatalf("expected identical parses, got\n bit-and: %s\n cast:    %s", bitAnd.node.ToSexp(), cast.node.ToSexp())
	}
}

// TestAddressTakenTargetScoped resolves the ambiguity with scope knowledge: a
// left operand that names a value is a bit-and, one that names a type is a cast.
func TestAddressTakenTargetScoped(t *testing.T) {
	bitAnd := pinArg(t, "extern void f(unsigned x);\nvoid g(int flags, int mask) { f((flags) & mask); }\n")
	cast := pinArg(t, "extern void f(void *p);\nvoid g(void) { int dst; f((shm_handle)&dst); }\n")

	// `flags` is bound to a value in scope ⇒ bit-and, not `&mask`.
	if tgt, ok := bitAnd.AddressTakenTargetScoped(func(n string) bool { return n == "flags" }); ok {
		t.Errorf("(flags) & mask with flags bound to a value must NOT be an address-of, got %q", tgt.Text())
	}

	// `shm_handle` is a type name (never bound to a value) ⇒ address-of dst.
	if tgt, ok := cast.AddressTakenTargetScoped(func(string) bool { return false }); !ok || tgt.Text() != "dst" {
		t.Errorf("(shm_handle)&dst must resolve to dst, got (%q, %v)", tgt.Text(), ok)
	}

	// The permissive form keeps the legacy behavior for oracle-free callers.
	if tgt, ok := bitAnd.AddressTakenTarget(); !ok || tgt.Text() != "mask" {
		t.Errorf("permissive AddressTakenTarget should still return mask, got (%q, %v)", tgt.Text(), ok)
	}
}

// TestAddressTakenTargetScoped_TypeNamedDeclaration guards the oracle against
// the dangerous direction. A typedef name in a declaration parses as
// type_identifier (and `typedef` as type_definition), so a bound-value oracle
// built from declarators can never classify a type name as a value — which
// would reject a real cast and resurrect the output-parameter false positive.
func TestAddressTakenTargetScoped_TypeNamedDeclaration(t *testing.T) {
	src := `typedef void *shm_handle;
struct S { int n; };
void g(void) {
    shm_handle out;
    struct S *sp;
    unsigned char *in;
    int a = 0, b;
    char buf[8];
}
`
	p := NewParser()
	tree, err := p.Parse([]byte(src), "pin.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	bound := map[string]bool{}
	// Mirrors evidence.boundValueNames: only declarators are collected, never
	// the type specifier that precedes them.
	var declaratorName func(Node) string
	declaratorName = func(n Node) string {
		if n.Kind() == "identifier" {
			return n.Text()
		}
		for _, c := range n.NamedChildren() {
			if name := declaratorName(c); name != "" {
				return name
			}
		}
		return ""
	}
	for _, decl := range tree.RootNode().FindAll("declaration") {
		for _, child := range decl.NamedChildren() {
			switch child.Kind() {
			case "identifier":
				bound[child.Text()] = true
			case "init_declarator", "pointer_declarator", "array_declarator",
				"function_declarator", "parenthesized_declarator":
				if name := declaratorName(child); name != "" {
					bound[name] = true
				}
			}
		}
	}
	for _, typeName := range []string{"shm_handle", "S"} {
		if bound[typeName] {
			t.Errorf("type name %q must never be collected as a bound value (would reject a real cast)", typeName)
		}
	}
	for _, varName := range []string{"out", "sp", "in", "a", "b", "buf"} {
		if !bound[varName] {
			t.Errorf("declarator %q should be collected as a bound value", varName)
		}
	}
}
