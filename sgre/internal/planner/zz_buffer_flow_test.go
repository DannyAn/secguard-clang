//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// The buffer-overflow / out-of-bounds diagnostic path renders as an ordered
// flow_step trace (definition → origin → missing guard → sink), so the reviewer
// sees the CSA-style path instead of a bare "there is an OOB".
func TestBufferFlow_FieldArrayPath(t *testing.T) {
	src := `struct S { int items[8]; int idx; };
int get(struct S *s) { return s->items[s->idx]; }
int main(void) { struct S s = {0}; return get(&s); }
`
	res := planType(t, src, "out-of-bounds")
	c, ok := res["get"]
	if !ok {
		t.Fatalf("expected an out-of-bounds candidate for get")
	}
	steps := flowStepText(c.Evidence)
	for _, want := range []string{"declared as a struct field at line 1", "capacity 8 elements", "the index is the struct field `idx`", "no bounds check dominates", "reads past the end"} {
		if !strings.Contains(steps, want) {
			t.Errorf("flow path missing %q; got:\n%s", want, steps)
		}
	}
}

// The concrete cross-function call chain replaces the boolean "reachable from
// entry": the candidate records main → caller → sink with per-hop call lines.
func TestCallChain_Concrete(t *testing.T) {
	src := `#include <string.h>
struct cfg { char name[8]; };
struct cfg g_cfg;
void apply_setting(struct cfg *c, const char *v) { strcpy(c->name, v); }
void load_config(const char *v) { apply_setting(&g_cfg, v); }
int main(int argc, char **argv) { if (argc > 1) load_config(argv[1]); return 0; }
`
	res := planType(t, src, "buffer-overflow")
	c, ok := res["apply_setting"]
	if !ok {
		t.Fatalf("expected a buffer-overflow candidate for apply_setting")
	}
	if len(c.CallChain) != 2 {
		t.Fatalf("CallChain = %+v, want 2 hops (main → load_config → apply_setting)", c.CallChain)
	}
	if c.CallChain[0].Caller != "main" || c.CallChain[0].Callee != "load_config" {
		t.Errorf("hop 0 = %+v, want main → load_config", c.CallChain[0])
	}
	if c.CallChain[1].Caller != "load_config" || c.CallChain[1].Callee != "apply_setting" {
		t.Errorf("hop 1 = %+v, want load_config → apply_setting", c.CallChain[1])
	}
	if c.CallChain[1].Line == 0 {
		t.Errorf("hop 1 must carry the call site line")
	}
	// The rendered call_path fragment must name the chain, not the old boolean.
	path := ""
	for _, f := range c.Evidence {
		if f.Type == "call_path" {
			path = f.Detail
		}
	}
	if !strings.Contains(path, "main → load_config") || !strings.Contains(path, "apply_setting") {
		t.Errorf("call_path detail = %q, want the concrete chain", path)
	}
}

func flowStepText(ev []EvidenceFragment) string {
	var b strings.Builder
	for _, f := range ev {
		if f.Type == "flow_step" {
			b.WriteString(f.Detail)
			b.WriteString("\n")
		}
	}
	return b.String()
}
