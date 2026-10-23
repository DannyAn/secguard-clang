//go:build !nosqlite

package planner

import "testing"

// TestND3_VoidPointerContract pins the "opaque void* parameter dereferenced by
// contract" convergence (ND-3): an IPC / callback handler that receives a void*
// framework buffer, immediately casts it (or extracts it through an accessor)
// and dereferences it without any NULL check must NOT surface as a null-deref,
// while a genuine possible-null value (an explicit NULL call, getenv) still does.
func TestND3_VoidPointerContract(t *testing.T) {
	cases := []struct {
		name      string
		src       string
		wantDeref bool // true: must surface as a null-deref candidate
	}{
		{
			name: "accessor cast (sub-pattern A) — surfaces as suspected (accessor may return NULL)",
			src: `
typedef struct { int f; } T;
extern void *get_buf(void *mbuf);
void proc(void *mbuf) {
    void *raw = get_buf(mbuf);
    T *t = (T *)raw;
    t->f = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: true,
		},
		{
			name: "inline accessor cast — surfaces as suspected (accessor may return NULL)",
			src: `
typedef struct { int f; } T;
extern void *get_buf(void *mbuf);
void proc(void *mbuf) {
    T *t = (T *)get_buf(mbuf);
    t->f = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: true,
		},
		{
			name: "direct cast of void* param (sub-pattern B)",
			src: `
typedef struct { int f; } T;
void proc(void *msg) {
    T *t = (T *)msg;
    t->f = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: false,
		},
		{
			name: "const void* param",
			src: `
typedef struct { int f; } T;
void proc(const void *msg) {
    const T *t = (const T *)msg;
    int v = t->f;
    (void)v;
}
void call(const void *x) { proc(x); }
`,
			wantDeref: false,
		},
		{
			name: "pointer arithmetic on void* param (sub-pattern C)",
			src: `
typedef struct { int f; } T;
typedef struct { int b; } U;
void proc(void *buf) {
    T *head = (T *)buf;
    U *body = (U *)(head + 1);
    body->b = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: false,
		},
		{
			name: "real defect: caller passes literal zero",
			src: `
typedef struct { int f; } T;
void proc(void *msg) {
    T *t = (T *)msg;
    t->f = 1;
}
void call(void) { proc(0); }
`,
			wantDeref: true,
		},
		{
			name: "real defect: unguarded getenv result is not contract",
			src: `
extern char *getenv(const char *name);
int proc(const char *name) {
    char *v = getenv(name);
    return v[0];
}
`,
			wantDeref: true,
		},
		{
			name: "null-checked void* param negates the contract",
			src: `
typedef struct { int f; } T;
extern void note(void);
extern void *get_val(void *p);
void proc(void *p) {
    if (p == NULL) { note(); }
    T *t = (T *)get_val(p);
    t->f = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: true,
		},
		{
			name: "NP-04: deref-read through a cast void* param is NOT contract-derived",
			src: `
typedef struct { int f; } T;
void proc(void *msg) {
    T *r = *(T **)msg;
    r->f = 1;
}
void call(void *x) { proc(x); }
`,
			wantDeref: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			has := setOf(planNullDerefFull(t, tc.src))
			got := has["proc"]
			if got != tc.wantDeref {
				t.Errorf("proc surfaced=%v, want %v (candidates=%v)", got, tc.wantDeref, has)
			}
		})
	}
}

// TestND3_DerivedParameterAlias_TypeAgnostic pins the class-level fix: a
// variable that merely ALIASES a parameter (a copy or cast of it) must be
// converged by the same "no proven nullable caller argument" rule as a direct
// dereference of that parameter, for ordinary pointer parameters too — not only
// void*. Previously `t = p; t->f` surfaced while `p->f` did not.
func TestND3_DerivedParameterAlias_TypeAgnostic(t *testing.T) {
	// call has zero in-tree callers, but its parameter type Ctx is tree-
	// defined AND this fixture defines main (a complete-program scan), so the
	// in-tree-invariant precision policy keeps the entry closed and none of the
	// three surfaces. Boundary scans (no main) drop that assumption, and the
	// incomplete-type form surfaces in both — pinned by TestBoundaryScanExportedAPI
	// and the opaque_null tests.
	src := `
typedef struct { int f; } Ctx;

void direct(Ctx *ctx) { ctx->f = 1; }
void alias(Ctx *src) {
    Ctx *t = src;
    t->f = 1;
}
void cast(Ctx *src) {
    Ctx *t = (Ctx *)src;
    t->f = 1;
}

void call(Ctx *x) { direct(x); alias(x); cast(x); }

int main(void) { return 0; }
`
	has := setOf(planNullDerefFull(t, src))
	for _, fn := range []string{"direct", "alias", "cast"} {
		if has[fn] {
			t.Errorf("%s must NOT surface for a tree-defined type entry (candidates=%v)", fn, has)
		}
	}
}
