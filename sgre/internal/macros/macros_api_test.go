package macros

import (
	"reflect"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// firstCall returns the first call_expression whose callee is name.
func firstCall(t *testing.T, root parser.Node, name string) parser.Node {
	t.Helper()
	for _, call := range root.FindAll("call_expression") {
		if callName(call) == name {
			return call
		}
	}
	t.Fatalf("no call to %s", name)
	return parser.Node{}
}

func callArgs(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

func TestWrittenArgsAndFieldArgs(t *testing.T) {
	root := parseTestRoot(t, `
#define SET_OUT(x, v) do { (x) = (v); } while (0)
#define SET_FIELD(s, v) do { (s).field = (v); } while (0)
void f(void) {
    int out;
    struct S s;
    SET_OUT(out, 1);
    SET_FIELD(s, 2);
}
`)
	summaries := WriteSummaries(root)

	got := WrittenArgs(firstCall(t, root, "SET_OUT"), summaries)
	want := map[string]bool{"out": true}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WrittenArgs = %v, want %v", got, want)
	}

	fields := WrittenFieldArgs(firstCall(t, root, "SET_FIELD"), summaries)
	wantFields := map[string]string{"s": ".field"}
	if !reflect.DeepEqual(fields, wantFields) {
		t.Errorf("WrittenFieldArgs = %v, want %v", fields, wantFields)
	}

	// An unknown macro yields an empty (non-nil) map, not a panic.
	if got := WrittenArgs(firstCall(t, root, "SET_OUT"), nil); len(got) != 0 {
		t.Errorf("WrittenArgs with no summaries = %v, want empty", got)
	}
	if got := WrittenFieldArgs(firstCall(t, root, "SET_FIELD"), nil); len(got) != 0 {
		t.Errorf("WrittenFieldArgs with no summaries = %v, want empty", got)
	}
}

func TestWrittenFreeAndByName(t *testing.T) {
	root := parseTestRoot(t, `
#define CMD_MSG_INIT(recv) do { execId = 0; paraNum = 0; } while (0)
void f(void) {
    int execId, paraNum;
    CMD_MSG_INIT(recv);
}
`)
	summaries := WriteSummaries(root)
	call := firstCall(t, root, "CMD_MSG_INIT")

	got := WrittenFree(call, summaries)
	if !got["execId"] || !got["paraNum"] {
		t.Fatalf("WrittenFree = %v, want execId and paraNum", got)
	}

	byName := WrittenFreeByName("CMD_MSG_INIT", summaries)
	if len(byName) != 2 {
		t.Errorf("WrittenFreeByName = %v, want two identifiers", byName)
	}
	if got := WrittenFreeByName("MISSING", summaries); got != nil {
		t.Errorf("WrittenFreeByName(MISSING) = %v, want nil", got)
	}
}

func TestWrittenArgsInError(t *testing.T) {
	summaries := map[string]WriteSummary{
		"OUT": {writesParam: map[int]bool{0: true}},
	}
	root := parseTestRoot(t, `void f(void) { OUT(a, b); }`)
	args := callArgs(firstCall(t, root, "OUT"))
	got := WrittenArgsInError("OUT", args, summaries)
	if !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("WrittenArgsInError = %v, want [a]", got)
	}
	if got := WrittenArgsInError("MISSING", args, summaries); got != nil {
		t.Errorf("WrittenArgsInError(MISSING) = %v, want nil", got)
	}
}

func TestObjectLikeWrites(t *testing.T) {
	root := parseTestRoot(t, `
#define MSG_INIT do { paraNum = 0; execId = 0; } while (0)
#define COMPARE(x) ((x) == 1)
#define FLAG 1
`)
	got := ObjectLikeWrites(root)
	want := map[string]map[string]bool{
		"MSG_INIT": {"paraNum": true, "execId": true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ObjectLikeWrites = %v, want %v", got, want)
	}
}

func TestMergeWriteSummaries(t *testing.T) {
	a := map[string]WriteSummary{
		"MACRO": {
			writesParam: map[int]bool{0: true},
			writesField: map[int]string{1: ".f"},
			writesFree:  map[string]bool{"lhs": true},
		},
	}
	b := map[string]WriteSummary{
		"MACRO": {
			writesParam: map[int]bool{1: true},
			writesFree:  map[string]bool{"rhs": true},
		},
		"OTHER": {},
	}
	merged := MergeWriteSummaries(a, b)

	m := merged["MACRO"]
	if !m.writesParam[0] || !m.writesParam[1] {
		t.Errorf("merged writesParam = %v, want 0 and 1", m.writesParam)
	}
	if m.writesField[1] != ".f" {
		t.Errorf("merged writesField = %v, want 1:.f", m.writesField)
	}
	if !m.writesFree["lhs"] || !m.writesFree["rhs"] {
		t.Errorf("merged writesFree = %v, want lhs and rhs", m.writesFree)
	}
	// The inputs must not alias the merged summary.
	a["MACRO"].writesParam[2] = true
	if merged["MACRO"].writesParam[2] {
		t.Error("MergeWriteSummaries aliased the input summary")
	}
}

func TestMergeWriteSummariesNilMaps(t *testing.T) {
	// A zero-value summary has nil maps; merging it with a populated one must
	// not panic and must keep the populated facts.
	merged := MergeWriteSummaries(
		map[string]WriteSummary{"M": {}},
		map[string]WriteSummary{"M": {writesParam: map[int]bool{0: true}}},
	)
	if !merged["M"].writesParam[0] {
		t.Errorf("merged writesParam = %v, want 0", merged["M"].writesParam)
	}
	if merged["M"].writesFree != nil {
		t.Errorf("merged writesFree = %v, want nil", merged["M"].writesFree)
	}
}

func TestGuardSummariesAndGuardedArgs(t *testing.T) {
	root := parseTestRoot(t, `
#define CHECK_RET(cond, ret) if ((cond)) { return ret; }
#define CHECK_PTR(p, ret) if (!(p)) { return ret; }
void f(void) {
    int c;
    int *p;
    CHECK_RET(c == 0, -1);
    CHECK_PTR(p, -1);
}
`)
	summaries := GuardSummaries(root)

	if got := GuardedArgs(firstCall(t, root, "CHECK_RET"), summaries); !reflect.DeepEqual(got, map[int]bool{0: false}) {
		t.Errorf("CHECK_RET GuardedArgs = %v, want {0:false}", got)
	}
	if got := GuardedArgs(firstCall(t, root, "CHECK_PTR"), summaries); !reflect.DeepEqual(got, map[int]bool{0: true}) {
		t.Errorf("CHECK_PTR GuardedArgs = %v, want {0:true}", got)
	}
	if got := GuardedArgs(firstCall(t, root, "CHECK_RET"), nil); got != nil {
		t.Errorf("GuardedArgs with no summaries = %v, want nil", got)
	}
}
