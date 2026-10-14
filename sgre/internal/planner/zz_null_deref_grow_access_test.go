//go:build !nosqlite

package planner

import "testing"

// TestNullDeref_CheckedGrowThenAccess pins the "checked grow then access"
// convergence: after a container has been grown to a strictly larger size under
// a failure guard, an accessor fetch at a lower index is in range, so its result
// is a valid interior pointer rather than a possible NULL. Without the rule the
// unknown external accessor seeds a fail-open external_call source and every
// such dereference is handed to the AI as a suspected false positive.
//
// The negative cases pin the boundary: the rule must NOT converge a fetch made
// BEFORE the grow, an unguarded or non-grow call, an index that is not provably
// in range, an allocator result, or a fetch on a different container.
func TestNullDeref_CheckedGrowThenAccess(t *testing.T) {
	const preamble = `
typedef struct { int x; } T;
typedef struct { T *buf; int len; int cap; } Deq;
Deq g;
Deq h;
extern void *deque_at_safe(Deq *d, unsigned idx);
extern void *deque_at(Deq *d, unsigned idx);
extern int   deque_resize(Deq *d, unsigned n);
extern int   deque_grow(Deq *d, unsigned n);
extern int   validate(Deq *d, unsigned n);
extern void *lookup(Deq *d, unsigned idx);
extern void *malloc(unsigned long n);
`

	cases := []struct {
		name      string
		src       string
		wantDeref bool
	}{
		{
			name: "vendor shape: checked resize(uid+1) then at(uid)",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&g, uid + 1) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: false,
		},
		{
			name: "vendor shape, pointer write form",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&g, uid + 1) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        *data = (T){0};
    }
}
`,
			wantDeref: false,
		},
		{
			name: "grow-named helper (deque_grow) is recognised",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_grow(&g, uid + 1) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: false,
		},
		{
			name: "size n with fetched index n-1 is in range",
			src: preamble + `
void add(unsigned n) {
    T *data = (T *)deque_at_safe(&g, n - 1);
    if (data == NULL) {
        if (deque_resize(&g, n) != 0) {
            return;
        }
        data = (T *)deque_at(&g, n - 1);
        data->x = 1;
    }
}
`,
			wantDeref: false,
		},
		{
			name: "negative: fetch happens BEFORE the grow",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at(&g, uid);
    if (deque_resize(&g, uid + 1) != 0) {
        return;
    }
    data->x = 1;
}
`,
			wantDeref: true,
		},
		{
			name: "negative: guarded call is not a grow",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (validate(&g, uid + 1) != 0) {
            return;
        }
        data = (T *)lookup(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
		{
			name: "negative: index equals size (not strictly in range)",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&g, uid) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
		{
			name: "negative: allocator result is never converged",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&g, uid + 1) != 0) {
            return;
        }
        data = (T *)malloc(16);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
		{
			name: "negative: grow on a different container",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&h, uid + 1) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
		{
			name: "negative: size unrelated to the fetched index",
			src: preamble + `
void add(unsigned uid, unsigned cap) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        if (deque_resize(&g, cap) != 0) {
            return;
        }
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
		{
			name: "negative: grow result is not failure-checked",
			src: preamble + `
void add(unsigned uid) {
    T *data = (T *)deque_at_safe(&g, uid);
    if (data == NULL) {
        deque_resize(&g, uid + 1);
        data = (T *)deque_at(&g, uid);
        data->x = 1;
    }
}
`,
			wantDeref: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			has := setOf(planNullDerefFull(t, tc.src))
			if got := has["add"]; got != tc.wantDeref {
				t.Errorf("add surfaced=%v, want %v (candidates=%v)", got, tc.wantDeref, has)
			}
		})
	}
}
