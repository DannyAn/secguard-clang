//go:build !nosqlite

package planner

import "testing"

// Regression tests for the two boundaries left after the first out-parameter
// fix: the null-deref side of the `(A) & x` scope oracle, and the struct path's
// caller-guard recognition.

// ---- Boundary 1: the struct path must recognize a consumed-result guard ----

const structGuardSrc = `#include <stdlib.h>
#include <stdint.h>

struct VMData { uint32_t a; uint32_t b; };

static uint32_t load_s(unsigned char *in, uint32_t len, struct VMData *out)
{
    if (len < 1) {
        return 0; /* failure: neither field is written */
    }
    out->a = in[0];
    out->b = in[0];
    return 1;
}

uint32_t struct_guarded(unsigned char *in, uint32_t len)
{
    uint32_t pos = 0;
    struct VMData d;
    pos += load_s(in, len, &d);
    if (pos == 0) {
        return 0; /* error guard on the variable the result was consumed into */
    }
    return d.a + d.b; /* success continuation: both fields were written */
}

uint32_t struct_unguarded(unsigned char *in, uint32_t len)
{
    struct VMData d;
    load_s(in, len, &d);
    return d.a + d.b; /* failure path leaves both fields unwritten */
}
`

// TestUninit_StructWriteBackGuardRecognized pins the struct-path false positive:
// the caller guards the conditional writer through the variable it stored the
// result in (`pos += load(&d); if (pos == 0) return;`), which the scalar path
// already recognizes via outputParamGuardLine but the struct path did not.
func TestUninit_StructWriteBackGuardRecognized(t *testing.T) {
	res := planUninitOutputParam(t, structGuardSrc)
	if c := candidateForFunc(t, res, "struct_guarded"); c != nil {
		t.Errorf("struct_guarded must NOT be flagged (the error guard excludes the path where the fields are unwritten), got var=%s line=%d", c.Target.Variable, c.Target.Line)
	}
}

// TestUninit_StructUnguardedStillReported is the counterpart guard: an UNGUARDED
// conditional struct writer leaves its fields unwritten on the failure path, so
// struct_partial_uninit must keep reporting it (cf. tc88's bad_msg). This
// documents that the struct path was deliberately NOT given the scalar path's
// unguarded write-back relaxation.
func TestUninit_StructUnguardedStillReported(t *testing.T) {
	res := planUninitOutputParam(t, structGuardSrc)
	c := candidateForFunc(t, res, "struct_unguarded")
	if c == nil {
		t.Fatalf("struct_unguarded must stay reported (fields are uninitialized on the callee's failure path), got: %s", candidateNames(res))
	}
}

// ---- Boundary 2: the null-deref side must use the same scope oracle --------

const nullBitAndSrc = `#include <stdlib.h>

extern void sink(unsigned x);

int bitand_null(int flags)
{
    int *p = NULL;
    sink((flags) & p); /* a genuine bit-and, NOT an address-of p */
    return *p;         /* genuine null-deref */
}
`

// TestNullDeref_BitAndArgIsNotAddressOf: `(flags) & p` must not be read as
// `&p`, which would kill p's null state and hide the dereference.
func TestNullDeref_BitAndArgIsNotAddressOf(t *testing.T) {
	res := planNullDeref(t, nullBitAndSrc)
	if c := candidateForFunc(t, res, "bitand_null"); c == nil {
		t.Errorf("bitand_null must be flagged: (flags) & p is a bit-and, so p is still NULL at the dereference")
	}
}

const nullCastOutParamSrc = `#include <stdlib.h>

struct L { int n; };

static int cfg_parse(const char *cfg, handle_t *out)
{
    struct L *l = (struct L *)malloc(sizeof(*l));
    if (!l) {
        return -1;
    }
    *out = (handle_t)l;
    return 0;
}

int use_it(const char *cfg)
{
    struct L *l = NULL;
    if (cfg_parse(cfg, (handle_t)&l) != 0) {
        return -1;
    }
    return l->n; /* l was written through the cast-typed &l */
}
`

// TestNullDeref_CastAddressKillStillWorks guards the oracle's dangerous
// direction: the cast-typed address argument is still recognized (so the kill
// still fires) even though the round now consults a scope oracle. `handle_t` is
// a type name, never a bound value, so the cast reading must win.
func TestNullDeref_CastAddressKillStillWorks(t *testing.T) {
	res := planNullDeref(t, nullCastOutParamSrc)
	if c := candidateForFunc(t, res, "use_it"); c != nil {
		t.Errorf("use_it must NOT be flagged: (handle_t)&l is an address-of, so l is rewritten by cfg_parse, got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}
