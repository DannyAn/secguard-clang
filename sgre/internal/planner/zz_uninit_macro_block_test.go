//go:build !nosqlite

package planner

import "testing"

// NAT sc_2026-10-26_094012_1b2a50 的 uninit auto-confirm 误报（20/21，95%）里的
// 最大一类：循环宏的 for-init 给迭代变量赋值，但宏展开成 `for (...)` 且带大括号体，
// tree-sitter 把它解析成 **function_definition**（返回类型 = 宏名，declarator =
// parenthesized_declarator），既不是 call_expression 也不是 ERROR。uninit 的
// 宏写入 kill 只扫 call_expression，于是变量被判成 `init@none`（从未赋值）并被
// auto-confirm 成 CWE-457。

const uninitMacroBlockHeader = `extern unsigned short pool_first_group(void);
extern unsigned short pool_next_group(unsigned short g);

#define POOL_ID_INVALID 0xFFFFu
#define POOL_FOR_ALL(pool_id) \
    for ((pool_id) = pool_first_group(); POOL_ID_INVALID != (pool_id); \
         (pool_id) = pool_next_group(pool_id))
`

// A macro whose block body is a loop body: the iterator is written in the
// macro's for-init, so a read inside the body is initialized.
func TestUninit_MacroBlockForInitSameFile(t *testing.T) {
	src := uninitMacroBlockHeader + `
unsigned int pool_cmd_show(void)
{
    unsigned short pool_id;
    unsigned int total = 0;
    POOL_FOR_ALL(pool_id) {
        total += pool_id;
    }
    return total;
}

unsigned int real_uninit_bug(void)
{
    unsigned short pool_id;
    return pool_id;
}
`
	result := planUninitMacroFiles(t, map[string]string{"pool_cmd.c": src})
	if c := candidateForFunc(t, result, "pool_cmd_show"); c != nil {
		t.Errorf("pool_cmd_show must NOT be flagged (pool_id is written by the macro's for-init), got var=%s level=%s line=%d",
			c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	// Control: a variable with no init at all stays a (confirmed) uninit read.
	c := candidateForFunc(t, result, "real_uninit_bug")
	if c == nil {
		t.Fatalf("real_uninit_bug must stay flagged, got %s", candidateNames(result))
	}
	if c.SuspicionLevel != "confirmed" {
		t.Errorf("real_uninit_bug: suspicion = %q, want confirmed (control)", c.SuspicionLevel)
	}
}

// The same macro defined in a .h header (the real NAT layout): the write
// summary must be merged across the whole tree, not just the calling file.
func TestUninit_MacroBlockForInitCrossFile(t *testing.T) {
	src := `#include "pool_loop.h"

unsigned int pool_cmd_show(void)
{
    unsigned short pool_id;
    unsigned int total = 0;
    POOL_FOR_ALL(pool_id) {
        total += pool_id;
    }
    return total;
}
`
	result := planUninitMacroFiles(t, map[string]string{
		"pool_loop.h": uninitMacroBlockHeader,
		"pool_cmd.c":  src,
	})
	if c := candidateForFunc(t, result, "pool_cmd_show"); c != nil {
		t.Errorf("cross-file macro: pool_cmd_show must NOT be flagged, got var=%s level=%s line=%d",
			c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}

// Defense in depth: even when the macro's write cannot be modeled, a
// `confirmed` (machine-proved) candidate whose variable is NAMED by a macro in
// the same statement region must not keep claiming certainty — the CFG does not
// expand macros, so the "never assigned" premise is unverified. `result.sarif`
// is meant to be filed as-is, so an unverifiable machine verdict is presented
// as suspected for the AI instead.
func TestUninit_MacroNamedVariableDemotedFromConfirmed(t *testing.T) {
	src := `extern void trace_value(long v);

#define TRACE_VAL(v) trace_value((long)(v))

int macro_named(void)
{
    int v;
    TRACE_VAL(v);
    return v;
}

int plain_uninit(void)
{
    int v;
    return v;
}
`
	result := planUninitMacroFiles(t, map[string]string{"demote.c": src})

	named := candidateForFunc(t, result, "macro_named")
	if named == nil {
		t.Fatalf("macro_named must stay a candidate (demoted, not dropped), got %s", candidateNames(result))
	}
	if named.SuspicionLevel != "suspected" {
		t.Errorf("macro_named: suspicion = %q, want suspected (a macro names v; CFG cannot expand it)", named.SuspicionLevel)
	}
	if !named.MacroContext {
		t.Errorf("macro_named: MacroContext = false, want true")
	}

	plain := candidateForFunc(t, result, "plain_uninit")
	if plain == nil {
		t.Fatalf("plain_uninit must stay a candidate, got %s", candidateNames(result))
	}
	if plain.SuspicionLevel != "confirmed" {
		t.Errorf("plain_uninit: suspicion = %q, want confirmed (no macro in scope)", plain.SuspicionLevel)
	}
}

// A block-scope `extern` declaration names a global defined elsewhere; it is not
// a definition with indeterminate storage, so it can never be an uninitialized
// local. Production reported `extern` globals as certain stack-uninit
// (`init@none`, auto-confirmed CWE-457) — 2 of the 21 uninit false positives.
func TestUninit_BlockScopeExternIsNotUninit(t *testing.T) {
	src := `unsigned int g_total;

unsigned int pat_get_portseg(unsigned int idx)
{
    extern unsigned int g_pp_var[];
    return g_pp_var[idx];
}

unsigned int portseg_get_hrp_flag(void)
{
    extern unsigned int g_ps_var;
    if (g_ps_var == 0) { return 0; }
    return g_ps_var + 1;
}

unsigned int real_uninit_bug(void)
{
    unsigned int local;
    return local;
}
`
	result := planUninitMacroFiles(t, map[string]string{"extern.c": src})
	for _, fn := range []string{"pat_get_portseg", "portseg_get_hrp_flag"} {
		if c := candidateForFunc(t, result, fn); c != nil {
			t.Errorf("%s: an `extern` declaration is a reference to global storage, not an uninitialized local; got var=%s level=%s",
				fn, c.Target.Variable, c.SuspicionLevel)
		}
	}
	if c := candidateForFunc(t, result, "real_uninit_bug"); c == nil {
		t.Fatalf("real_uninit_bug must stay flagged (control), got %s", candidateNames(result))
	}
}
