//go:build !nosqlite

package evidence

import (
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The address-taken census decides whether a STATIC function may be dismissed as
// dead code. C registers callbacks by decaying a bare function name to a pointer
// (`{"get", getCommand, ...}`, `.proc = handler`), which the old `&f`-only scan
// never saw — so every table-registered static handler with an opaque message
// pointer was treated as dead and silently produced no candidate.
//
// The fixture is a complete-program scan (main exists), so the in-tree-invariant
// policy stays in force: the parameter type is unknown here, which is exactly the
// class that must be fail-open.
func TestStaticCallbackRegisteredByBareNameIsOpen(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		"cb.c": `typedef void (*census_handler_t)(ExtMsg_t *);

static void census_registered(ExtMsg_t *cr_m)
{
    (void)cr_m->len;
}

static void census_dead(ExtMsg_t *cd_m)
{
    (void)cd_m->len;
}

static void census_address_of(ExtMsg_t *ca_m)
{
    (void)ca_m->len;
}

static void (*census_addr_slot)(ExtMsg_t *) = &census_address_of;

static census_handler_t census_table[] = { census_registered, 0 };

int main(void) { return census_table[0] != 0 || census_addr_slot != 0; }
`,
	})
	has := func(variable string) bool {
		for _, r := range records {
			if r.variable == variable && r.origin == "caller_null" {
				return true
			}
		}
		return false
	}
	// Bare-name registration in an initializer list.
	if !has("cr_m") {
		t.Errorf("a static callback registered by bare function name must not read as dead code; got %v", records)
	}
	// The explicit `&f` form keeps working.
	if !has("ca_m") {
		t.Errorf("a static callback registered with &f must stay open; got %v", records)
	}
	// Unregistered AND uncalled: genuinely dead, stays closed.
	if has("cd_m") {
		t.Errorf("an unregistered static helper must stay closed; got %v", records)
	}
}

// A registration table can live in a quoted #include fragment that the indexer
// never walks (redis emits commands.def and pulls it in from commands.c). The
// address-taken fact depends on the text, not the file's extension, so the
// census follows quoted includes one level.
func TestStaticCallbackRegisteredInIncludedFragmentIsOpen(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		// The include sits at file scope, exactly as redis pulls in
		// commands.def from commands.c: the fragment DEFINES the table.
		"frag.c": `typedef struct {
    const char *name;
    void (*fn)(ExtMsg_t *);
} census_entry_t;

static void census_frag_registered(ExtMsg_t *cf_m)
{
    (void)cf_m->len;
}

#include "census_table.def"

int main(void) { return census_frag_table[0].fn != 0; }
`,
		// Not a .c/.h file: the indexer ignores it, the include census reads it.
		"census_table.def": `static census_entry_t census_frag_table[] = {
    { "frag", census_frag_registered },
};
`,
	})
	found := false
	for _, r := range records {
		if r.variable == "cf_m" && r.origin == "caller_null" {
			found = true
		}
	}
	if !found {
		t.Errorf("a static callback registered in an included fragment must not read as dead code; got %v", records)
	}
}

// The include census must not resurrect arbitrary dead static helpers: only a
// registration that names the function counts.
func TestIncludedFragmentWithoutRegistrationStaysClosed(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		"frag2.c": `static void census_frag_dead(ExtMsg_t *fd_m)
{
    (void)fd_m->len;
}

#include "census_names.def"

int main(void) { return census_names[0] != 0; }
`,
		"census_names.def": `static const char *census_names[] = {
    "alpha",
    "beta",
};
`,
	})
	for _, r := range records {
		if r.variable == "fd_m" && r.origin == "caller_null" {
			t.Errorf("a dead static helper must stay closed even when an included fragment is parsed; got %v", records)
		}
	}
}

func TestEnclosingNullCondition(t *testing.T) {
	p := parser.NewParser()
	src := []byte(`void f(int type) {
    switch (type) {
    case ASM_EVENT_DONE:
        process(NULL);
    case ASM_EVENT_IMPORT_START:
        if (type > 0) process2(NULL);
    }
}
`)
	tree, err := p.Parse(src, "t.c")
	if err != nil {
		t.Fatal(err)
	}
	var gotSwitch, gotIf string
	for _, c := range tree.RootNode().FindAll("call_expression") {
		switch extractCallName(c) {
		case "process":
			gotSwitch = enclosingNullCondition(c)
		case "process2":
			gotIf = enclosingNullCondition(c)
		}
	}
	if !strings.Contains(gotSwitch, "switch(") || !strings.Contains(gotSwitch, "ASM_EVENT_DONE") {
		t.Errorf("switch-case condition = %q, want switch(...) case ASM_EVENT_DONE", gotSwitch)
	}
	// process2 sits inside if(type>0) inside case ASM_EVENT_IMPORT_START: the
	// switch-case is the decisive branch, so it wins over the nested if.
	if !strings.Contains(gotIf, "ASM_EVENT_IMPORT_START") {
		t.Errorf("nested-if-in-case condition = %q, want the enclosing case ASM_EVENT_IMPORT_START", gotIf)
	}
}

func TestEnclosingNullCondition_PureIf(t *testing.T) {
	p := parser.NewParser()
	src := []byte(`void f(int type) {
    if (type > 0) process(NULL);
}
`)
	tree, err := p.Parse(src, "t.c")
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, c := range tree.RootNode().FindAll("call_expression") {
		if extractCallName(c) == "process" {
			got = enclosingNullCondition(c)
		}
	}
	if !strings.Contains(got, "if") || !strings.Contains(got, "type > 0") {
		t.Errorf("pure-if condition = %q, want if (type > 0)", got)
	}
}
