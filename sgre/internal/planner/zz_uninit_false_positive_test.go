//go:build !nosqlite

package planner

import (
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// Issue #29 regression: the uninit pipeline reported false positives for five
// initialization patterns. Each is reduced to its essential shape below (the
// vendor-specific macros/functions that surfaced them are intentionally not
// reproduced — only the feature they exercise).

const uninitFPPreamble = `#include <stdint.h>
#include <stddef.h>

// A function-like macro that writes its LAST parameter (a hash output).
#define HASH_OUT(pro, srcip, dstip, ulHashIndex) \
    do {                                         \
        uint32_t a = srcip;                      \
        uint32_t b = dstip;                      \
        uint32_t c = (srcip) | (dstip);          \
        c += (pro);                              \
        ulHashIndex = c;                         \
    } while (0)

// A function-like macro that writes its LAST parameter (a division remainder).
#define MOD_OUT(num, den, rem) do { (rem) = (num) % (den); } while (0)

int fetch_value(const char *name, uint32_t *out, uint32_t *len);
void log_value(const char *fmt, ...);
`

const uninitFPBody = `
// Case 1: an assignment inside a while condition initializes the variable.
uint32_t hash_str(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Case 2: &out passed to an output-parameter writer initializes it.
uint32_t query_max(void) {
    uint32_t val;
    uint32_t len = sizeof(uint32_t);
    if (fetch_value("max", &val, &len) == 0) {
        log_value("value(%u)", val);
        return val;
    }
    return 0;
}

// Case 3: a macro output argument initializes the variable in both branches.
uint32_t pick_hash(int use_ipv6, uint32_t src, uint32_t dst) {
    uint32_t hash_index;
    if (!use_ipv6) {
        HASH_OUT(1, src, dst, hash_index);
    } else {
        HASH_OUT(2, src, dst, hash_index);
    }
    return hash_index & 0x7fff;
}

// Case 4: a macro output argument initializes the variable before a later use.
void refresh_day(void) {
    uint32_t mod;
    uint32_t total = 10;
    MOD_OUT(total, 3, mod);
    log_value("mod:0x%x", mod);
}

// Case 5: every switch branch (including default) assigns the variable.
uint32_t match_value(int type) {
    uint32_t v;
    switch (type) {
        case 1:
            v = 1;
            break;
        case 2:
            v = 2;
            break;
        default:
            v = 0;
            break;
    }
    if (v == 0) {
        return 0;
    }
    return 1;
}
`

// genuineUninitBody pins that the false-positive fixes do not over-suppress:
// each function below is a REAL uninitialized read that must still be reported.
const genuineUninitBody = `

int genuine_while_uninit(void) {
    int j;
    while (j) {
        break;
    }
    return 0;
}

int genuine_switch_no_default(int mode) {
    int k;
    switch (mode) {
        case 1:
            k = 1;
            break;
    }
    return k;
}

int genuine_switch_default_skips(int mode) {
    int m;
    switch (mode) {
        case 1:
            m = 1;
            break;
        default:
            break;
    }
    return m;
}
`

func TestUninit_FalsePositiveRepro(t *testing.T) {
	result := planUninitMacro(t, uninitFPPreamble+uninitFPBody+genuineUninitBody)

	falsePositive := map[string]bool{
		"c":          false,
		"val":        false,
		"hash_index": false,
		"mod":        false,
		"v":          false,
	}
	flagged := map[string]string{} // variable -> function
	for _, c := range result.Candidates {
		flagged[c.Target.Variable] = c.Target.Function
		if _, tracked := falsePositive[c.Target.Variable]; tracked {
			falsePositive[c.Target.Variable] = true
		}
		t.Logf("candidate: func=%s var=%s line=%d level=%s", c.Target.Function, c.Target.Variable, c.Target.Line, c.SuspicionLevel)
	}
	for v, isFP := range falsePositive {
		if isFP {
			t.Errorf("false positive: %s must NOT be reported as uninit", v)
		}
	}

	// Genuine uninitialized reads must survive the fixes.
	for _, v := range []string{"j", "k", "m"} {
		if flagged[v] == "" {
			t.Errorf("false negative: %s should still be reported as uninit, got candidates: %v", v, candidateNames(result))
		}
	}
}

// TestBuildDefiniteInitFlow_HeaderAndMacroKills pins the planner-side defence in
// depth directly against buildDefiniteInitFlow: the flow engine itself must
// recognize a control-flow-header condition assignment and a macro output
// argument as kills, independently of the detector's suppression. Each function
// below has its variable definitely initialized before the use, so the
// uninitialized declaration's source must NOT reach the use line.
func TestBuildDefiniteInitFlow_HeaderAndMacroKills(t *testing.T) {
	src := `#include <stdint.h>

#define HASH_OUT(pro, srcip, dstip, ulHashIndex) \
    do { uint32_t a = srcip; uint32_t c = (srcip) | (dstip); c += (pro); ulHashIndex = c; } while (0)

uint32_t while_cond(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

uint32_t if_cond(const char *str) {
    int x;
    if ((x = *str) == -1) {
        return 0;
    }
    return x;
}

uint32_t for_cond(const char *str) {
    uint32_t hash = 5381;
    int c;
    for (; (c = *str++); ) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

uint32_t macro_out(void) {
    uint32_t hash_index;
    HASH_OUT(1, 2, 3, hash_index);
    return hash_index;
}
`
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "t.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	root := tree.RootNode()
	macroWrites := macros.WriteSummaries(root)

	// bodies/endLines keyed by function name.
	type fnInfo struct {
		body    parser.Node
		endLine int
	}
	infos := map[string]fnInfo{}
	for _, def := range root.FindAll("function_definition") {
		name := ""
		for _, ch := range def.NamedChildren() {
			if ch.Kind() != "function_declarator" {
				continue
			}
			for _, d := range ch.NamedChildren() {
				if d.Kind() == "identifier" {
					name = d.Text()
					break
				}
			}
			break
		}
		if name == "" {
			continue
		}
		if body := def.FindFirst("compound_statement"); body != nil {
			infos[name] = fnInfo{body: *body, endLine: def.EndLine()}
		}
	}

	cases := []struct {
		fn      string
		variable string
		useKind  string
		useSub   string
	}{
		{"while_cond", "c", "assignment_expression", "+ c"},
		{"if_cond", "x", "return_statement", "x"},
		{"for_cond", "c", "assignment_expression", "+ c"},
		{"macro_out", "hash_index", "return_statement", "hash_index"},
	}
	for _, tc := range cases {
		info, ok := infos[tc.fn]
		if !ok {
			t.Fatalf("function %s not found", tc.fn)
		}
		useLine := -1
		for _, n := range info.body.FindAll(tc.useKind) {
			if strings.Contains(n.Text(), tc.useSub) {
				useLine = n.StartLine()
				break
			}
		}
		if useLine < 0 {
			t.Fatalf("%s: use not found (%s in %s)", tc.fn, tc.useSub, tc.useKind)
		}
		flow := buildDefiniteInitFlow(&db.Function{Name: tc.fn, EndLine: info.endLine}, info.body, macroWrites)
		if flow.reaching(tc.variable, useLine) {
			t.Errorf("%s: %s should be killed before line %d, but its uninit source still reaches it", tc.fn, tc.variable, useLine)
		}
	}
}
