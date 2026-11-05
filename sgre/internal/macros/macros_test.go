package macros

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestGuardParamsInBody(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		params      []string
		wantPlain   map[int]bool
		wantNegated map[int]bool
	}{
		{
			name:        "non-negated condition",
			body:        "if ((cond)) { return ret; }",
			params:      []string{"cond", "ret"},
			wantPlain:   map[int]bool{0: true},
			wantNegated: map[int]bool{},
		},
		{
			name:        "negated variable",
			body:        "if (!(ptr)) { return ret; }",
			params:      []string{"ptr", "ret"},
			wantPlain:   map[int]bool{},
			wantNegated: map[int]bool{0: true},
		},
		{
			name:        "no return is not a guard",
			body:        "if ((cond)) { x = 1; }",
			params:      []string{"cond"},
			wantPlain:   map[int]bool{},
			wantNegated: map[int]bool{},
		},
		{
			name:        "multi-line layout",
			body:        "if ((cond)) {                              \\\n        return ret;                            \\\n    }",
			params:      []string{"cond", "ret"},
			wantPlain:   map[int]bool{0: true},
			wantNegated: map[int]bool{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain, negated := guardParamsInBody(tc.body, tc.params)
			if !equalBoolMap(plain, tc.wantPlain) {
				t.Errorf("plain = %v, want %v", plain, tc.wantPlain)
			}
			if !equalBoolMap(negated, tc.wantNegated) {
				t.Errorf("negated = %v, want %v", negated, tc.wantNegated)
			}
		})
	}
}

func equalBoolMap(a, b map[int]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func parseTestRoot(t *testing.T, src string) parser.Node {
	t.Helper()
	tree, err := parser.NewParser().Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	t.Cleanup(func() { tree.Close() })
	return tree.RootNode()
}

// A command-init macro assigns caller locals that never appear in its parameter
// list. WriteSummaries must record those free identifiers so the uninit detector
// and planner treat the call as initialization, while member/subscript/deref
// targets and parameters are not mistaken for whole caller-variable writes.
func TestWriteSummaries_InitMacroFreeWrites(t *testing.T) {
	src := `
#define CMD_MSG_INIT(recv) do { \
    execId = get_exec_id(recv); \
    paraNum = 0; \
    msg.field = 0; \
    arr[i] = 0; \
    *raw = 0; \
    (recv) = 1; \
} while (0)

uint32_t handler(uint32_t msgRcv)
{
    uint32_t execId;
    uint32_t paraNum;
    CMD_MSG_INIT(msgRcv);
    return execId + paraNum;
}
`
	root := parseTestRoot(t, src)
	summaries := WriteSummaries(root)
	summary, ok := summaries["CMD_MSG_INIT"]
	if !ok {
		t.Fatalf("CMD_MSG_INIT not summarized; got %v", summaries)
	}
	free := map[string]bool{}
	for name := range summary.writesFree {
		free[name] = true
	}
	for _, want := range []string{"execId", "paraNum"} {
		if !free[want] {
			t.Errorf("writesFree missing %q: %v", want, free)
		}
	}
	for _, unwanted := range []string{"recv", "field", "arr", "i", "raw"} {
		if free[unwanted] {
			t.Errorf("writesFree must not contain %q (parameter/member/subscript/deref target): %v", unwanted, free)
		}
	}

	// The call site resolves the free writes.
	var call parser.Node
	for _, c := range root.FindAll("call_expression") {
		if callName(c) == "CMD_MSG_INIT" {
			call = c
			break
		}
	}
	if call.Kind() == "" {
		t.Fatalf("CMD_MSG_INIT call not found")
	}
	written := WrittenFree(call, summaries)
	if !written["execId"] || !written["paraNum"] || written["field"] {
		t.Errorf("WrittenFree = %v, want execId+paraNum only", written)
	}
}

func TestIsInitializationMacro(t *testing.T) {
	for _, name := range []string{"CMD_MSG_INIT", "MSG_INIT", "INIT_CTX", "NAT_CMD_INIT"} {
		if !IsInitializationMacro(name) {
			t.Errorf("IsInitializationMacro(%q) = false, want true", name)
		}
	}
	for _, name := range []string{"conn_init", "cmd_cfg_init", "INIT_GET_STATE", "MSG_SEND", ""} {
		if IsInitializationMacro(name) {
			t.Errorf("IsInitializationMacro(%q) = true, want false", name)
		}
	}
	RegisterInitializationMacros([]string{"msg_ctx_fill"})
	if !IsInitializationMacro("msg_ctx_fill") {
		t.Errorf("configured lowercase init macro not recognized")
	}
	if !IsConfiguredInitializationMacro("msg_ctx_fill") {
		t.Errorf("configured init macro not reported as configured")
	}
}
