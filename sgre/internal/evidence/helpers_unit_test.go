package evidence

import (
	"context"
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func parseEvidenceSrc(t *testing.T, src string) parser.Node {
	t.Helper()
	tree, err := parser.NewParser().Parse([]byte(src), "helpers.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Cleanup(tree.Close)
	return tree.RootNode()
}

func TestMirrorRelationalOp(t *testing.T) {
	cases := map[string]string{
		"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "": "",
	}
	for in, want := range cases {
		if got := mirrorRelationalOp(in); got != want {
			t.Errorf("mirrorRelationalOp(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestReverseOp(t *testing.T) {
	cases := map[string]string{
		">=": "<=", "<=": ">=", ">": "<", "<": ">", "!=": "!=", "": "",
	}
	for in, want := range cases {
		if got := reverseOp(in); got != want {
			t.Errorf("reverseOp(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSizeofTypeNameAndOperand(t *testing.T) {
	typeCases := map[string]string{
		"sizeof(PacketHeader)": "PacketHeader",
		"sizeof( int )":        "",
		"sizeof(*p)":           "",
		"sizeof(dst.field)":    "",
		"other(dst)":           "",
	}
	for in, want := range typeCases {
		if got := sizeofTypeName(in); got != want {
			t.Errorf("sizeofTypeName(%q) = %q, want %q", in, got, want)
		}
	}

	if !sizeofOperandMatches("sizeof(dst)", "dst") {
		t.Error("sizeof(dst) should match dst")
	}
	if !sizeofOperandMatches("sizeof(*dst)", "dst") {
		t.Error("sizeof(*dst) should match dst")
	}
	if !sizeofOperandMatches("sizeof((dst))", "dst") {
		t.Error("sizeof((dst)) should match dst")
	}
	if sizeofOperandMatches("sizeof(src)", "dst") {
		t.Error("sizeof(src) must not match dst")
	}
	if sizeofOperandMatches("cap(dst)", "dst") {
		t.Error("non-sizeof expression must not match")
	}
}

func TestFieldAccessName(t *testing.T) {
	cases := map[string]string{
		"x->f":  "f",
		"x.f":   "f",
		"a.b.c": "c",
		"f":     "",
		"":      "",
	}
	for in, want := range cases {
		if got := fieldAccessName(in); got != want {
			t.Errorf("fieldAccessName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOverflowsInt32(t *testing.T) {
	cases := []struct {
		v    int64
		want bool
	}{
		{-(1 << 31), false},
		{-(1 << 31) - 1, true},
		{(1 << 31) - 1, false},
		{1 << 31, true},
		{0, false},
	}
	for _, tc := range cases {
		if got := overflowsInt32(tc.v); got != tc.want {
			t.Errorf("overflowsInt32(%d) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

func TestIsIntMinWidth32(t *testing.T) {
	var scope integerOverflowTypeScope
	cases := []struct {
		dividend string
		want     bool
	}{
		{"INT_MIN", true},
		{"INT32_MIN", true},
		{"-2147483648", true},
		{"2147483648L", false},
		{"2147483648LL", false},
		{"x", false},
	}
	for _, tc := range cases {
		if got := isIntMinWidth32(tc.dividend, 1, nil, scope, nil); got != tc.want {
			t.Errorf("isIntMinWidth32(%q) = %v, want %v", tc.dividend, got, tc.want)
		}
	}
}

func TestFloatSize(t *testing.T) {
	cases := map[string]int{"float": 4, "double": 8, "long double": 16, "int": 0, "": 0}
	for in, want := range cases {
		if got := floatSize(in); got != want {
			t.Errorf("floatSize(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestBalancedOuterParens(t *testing.T) {
	cases := map[string]bool{
		"(a)":       true,
		"((a))":     true,
		"(a)+(b)":   false,
		"(a":        false,
		"a)":        false,
		"":          false,
		"(a)(b)":    false,
		"(a+(b))":   true,
		"((a)+(b))": true,
	}
	for in, want := range cases {
		if got := balancedOuterParens(in); got != want {
			t.Errorf("balancedOuterParens(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestContainsAndSubtractLines(t *testing.T) {
	if !containsLine([]int{1, 2, 3}, 2) {
		t.Error("containsLine(2) should be true")
	}
	if containsLine([]int{1, 2, 3}, 4) {
		t.Error("containsLine(4) should be false")
	}
	if got, want := subtractLines([]int{1, 2, 3, 4}, []int{2, 4}), []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Errorf("subtractLines = %v, want %v", got, want)
	}
	if got := subtractLines(nil, []int{1}); len(got) != 0 {
		t.Errorf("subtractLines(nil) = %v, want empty", got)
	}
}

func TestMacroAssignsName(t *testing.T) {
	cases := []struct {
		text, name string
		want       bool
	}{
		{"x = 1", "x", true},
		{"x == 1", "x", false},
		{"x+= 1", "x", false},
		{"if (x)", "x", false},
		{"x==1; later x=2", "x", true},
		{"prefix_x = 1", "x", false},
		{"y = x", "x", false},
	}
	for _, tc := range cases {
		if got := macroAssignsName(tc.text, tc.name); got != tc.want {
			t.Errorf("macroAssignsName(%q, %q) = %v, want %v", tc.text, tc.name, got, tc.want)
		}
	}
}

func TestFirstIdentifierAndPointerFromArrowError(t *testing.T) {
	root := parseEvidenceSrc(t, `void f(void) { g(q->x); }`)
	fields := root.FindAll("field_expression")
	if len(fields) != 1 {
		t.Fatalf("field_expression count = %d, want 1", len(fields))
	}
	if got := firstIdentifier(fields[0]); got != "q" {
		t.Errorf("firstIdentifier = %q, want q", got)
	}
	if got := pointerFromArrowError(fields[0]); got != "q" {
		t.Errorf("pointerFromArrowError = %q, want q", got)
	}
	numbers := root.FindAll("number_literal")
	if len(numbers) != 0 {
		t.Fatalf("unexpected number_literal nodes")
	}
}

func TestAssertGuardedVarsAndBareVarName(t *testing.T) {
	root := parseEvidenceSrc(t, `int f(int *p, int *q) {
    if (p != NULL && q != NULL) { return 1; }
    if (p) { return 2; }
    return 0;
}`)
	conds := root.FindAll("binary_expression")
	if len(conds) == 0 {
		t.Fatal("no binary_expression in fixture")
	}
	if got, want := assertGuardedVars(conds[0]), []string{"p", "q"}; !reflect.DeepEqual(got, want) {
		t.Errorf("assertGuardedVars(&&) = %v, want %v", got, want)
	}
	ids := root.FindAll("identifier")
	if len(ids) == 0 {
		t.Fatal("no identifier in fixture")
	}
	if got := bareVarName(ids[0]); got != ids[0].Text() {
		t.Errorf("bareVarName(%q) = %q", ids[0].Text(), got)
	}
}

func TestUsedAfterLine(t *testing.T) {
	root := parseEvidenceSrc(t, `void f(void) {
    int x;
    x = 1;
}`)
	ids := root.FindAll("identifier")
	fn := &db.Function{StartLine: 1, EndLine: 4}
	if !usedAfterLine("x", 2, fn, ids) {
		t.Error("usedAfterLine(x, 2) should be true")
	}
	if usedAfterLine("x", 3, fn, ids) {
		t.Error("usedAfterLine(x, 3) should be false")
	}
	if usedAfterLine("absent", 1, fn, ids) {
		t.Error("usedAfterLine(absent) should be false")
	}
}

func TestWithCFGCacheContext(t *testing.T) {
	base := context.Background()
	if withCFGCache(base, nil) != base {
		t.Error("withCFGCache(ctx, nil) should return ctx unchanged")
	}
	if cfgCacheFromCtx(context.Background()) != nil {
		t.Error("cfgCacheFromCtx on a bare context should be nil")
	}
	var nilCtx context.Context
	if cfgCacheFromCtx(nilCtx) != nil {
		t.Error("cfgCacheFromCtx(nil) should be nil")
	}
	cache := &graph.CFGCache{}
	if got := cfgCacheFromCtx(withCFGCache(base, cache)); got != cache {
		t.Error("cfgCacheFromCtx did not return the attached cache")
	}
}
