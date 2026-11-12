//go:build !nosqlite

package planner

import (
	"strings"
	"testing"
)

// planIssue263Uninit mirrors planUninitOutputParam for the issue #263
// auto-confirm blind-spot fixtures.
func planIssue263Uninit(t *testing.T, src string) *PlanResult {
	t.Helper()
	return planUninitOutputParam(t, src)
}

// TestUninit_Issue263_AsmNoAutoConfirm pins the planner side of the issue
// #263 P0-3 fix: an inline-asm output operand is a write, so a read of the
// operand symbol must never reach the auto-confirm (confirmed) tier.
func TestUninit_Issue263_AsmNoAutoConfirm(t *testing.T) {
	t.Run("unconditional asm read stays unconfirmed", func(t *testing.T) {
		result := planIssue263Uninit(t, `unsigned long long f(void) {
    unsigned long lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | (hi << 32);
}
`)
		if c := candidateForFunc(t, result, "f"); c != nil {
			t.Fatalf("asm outputs are written: want no candidate, got %s/%s at line %d",
				c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		}
	})

	t.Run("conditional asm read is suspected, never confirmed", func(t *testing.T) {
		result := planIssue263Uninit(t, `int f(int flag) {
    unsigned long v;
    if (flag) {
        __asm__ __volatile__("mov %%rsp, %0" : "=r"(v));
    }
    return (int)v;
}
`)
		c := candidateForFunc(t, result, "f")
		if c == nil {
			t.Fatal("conditional asm leaves a bypass path: the use must stay a candidate")
		}
		if c.SuspicionLevel == "confirmed" {
			t.Fatalf("bypass path exists: suspicion = confirmed, want suspected (auto-confirm is the issue #263 defect)")
		}
	})

	t.Run("bare scalar keeps auto-confirm", func(t *testing.T) {
		result := planIssue263Uninit(t, `int f(void) {
    int x;
    return x;
}
`)
		c := candidateForFunc(t, result, "f")
		if c == nil {
			t.Fatal("control: bare scalar read must stay a candidate")
		}
		if c.SuspicionLevel != "confirmed" {
			t.Fatalf("control: bare scalar must stay machine-confirmed, got %q", c.SuspicionLevel)
		}
	})
}

// TestUninit_Issue263_BacktraceArrayNoAutoConfirm pins the planner side of
// the issue #263 original skeleton: `void *buf[16]; backtrace(buf, 16)` —
// the pointer-array decay was tracked as a scalar pointer read and
// auto-confirmed; the array is not a scalar and must produce no candidate.
func TestUninit_Issue263_BacktraceArrayNoAutoConfirm(t *testing.T) {
	result := planIssue263Uninit(t, `int backtrace(void **, int);
int f(void) {
    void *buf[16];
    int n = backtrace(buf, 16);
    return n > 0 && buf[0] != 0;
}
`)
	for _, c := range result.Candidates {
		if strings.HasPrefix(c.Target.Function, "f") {
			t.Fatalf("array decay through backtrace must not be a candidate, got %s/%s at line %d",
				c.Target.Variable, c.SuspicionLevel, c.Target.Line)
		}
	}
}

// TestUninit_Issue263_StructBacktraceNoAutoConfirm pins the planner side:
// a struct member filled through backtrace's field-decay argument must not
// reach the confirmed tier (struct partial-init CAN auto-confirm).
func TestUninit_Issue263_StructBacktraceNoAutoConfirm(t *testing.T) {
	result := planIssue263Uninit(t, `struct fr {
    void *syms[16];
    int n;
};
int backtrace(void **, int);
int f(void) {
    struct fr fr;
    fr.n = backtrace(fr.syms, 16);
    return fr.n > 0 && fr.syms[0] != 0;
}
`)
	if c := candidateForFunc(t, result, "f"); c != nil {
		t.Fatalf("backtrace fills fr.syms: want no candidate, got %s/%s at line %d",
			c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
}
