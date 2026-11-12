package evidence

import (
	"testing"
)

// TestUninit_Issue263_AsmOutputOperands pins the issue #263 P0-3 fix: a GNU
// inline-asm OUTPUT operand (`"=a"(lo)`) writes its symbol variable, so a
// later read is not an init@none candidate the planner would auto-confirm.
func TestUninit_Issue263_AsmOutputOperands(t *testing.T) {
	t.Run("rdtsc outputs are initialized", func(t *testing.T) {
		events := runUninitDetect(t, `unsigned long long f(void) {
    unsigned long lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return lo | (hi << 32);
}
`)
		if len(events) != 0 {
			t.Fatalf("asm output operands write lo/hi: want 0 VALUE_USE events, got %d", len(events))
		}
	})

	t.Run("conditional asm keeps a bypass-path candidate", func(t *testing.T) {
		events := runUninitDetect(t, `int f(int flag) {
    unsigned long v;
    if (flag) {
        __asm__ __volatile__("mov %%rsp, %0" : "=r"(v));
    }
    return (int)v;
}
`)
		if len(events) == 0 {
			t.Fatal("asm inside an if leaves an unassigned bypass path: the use must stay a candidate")
		}
		kind, _, ok := initWriteOf(events, "v")
		if !ok {
			t.Fatal("no VALUE_USE for v")
		}
		if kind == "none" {
			t.Fatal("conditional asm write exists: init_write must not claim never-written (that fact auto-confirms)")
		}
	})

	t.Run("bare scalar detection still works", func(t *testing.T) {
		events := runUninitDetect(t, `int f(void) {
    int x;
    return x;
}
`)
		kind, _, ok := initWriteOf(events, "x")
		if !ok || kind != "none" {
			t.Fatalf("control: bare scalar must stay init@none, got kind=%q ok=%v", kind, ok)
		}
	})
}

// TestUninit_Issue263_DestWriterArgs pins the issue #263 P0-3 fix: I/O
// functions whose buffer sits at a non-first argument (backtrace arg0 via
// field decay, read/recv arg1) write that argument, so a struct member or
// heap block filled through them is not reported uninitialized.
func TestUninit_Issue263_DestWriterArgs(t *testing.T) {
	t.Run("backtrace fills a struct member", func(t *testing.T) {
		events := runUninitDetect(t, `struct fr {
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
		if len(events) != 0 {
			t.Fatalf("backtrace(fr.syms, 16) writes the member: want 0 VALUE_USE events, got %d", len(events))
		}
	})

	t.Run("backtrace fills a local array (issue skeleton)", func(t *testing.T) {
		events := runUninitDetect(t, `int backtrace(void **, int);
int f(void) {
    void *buf[16];
    int n = backtrace(buf, 16);
    return n > 0 && buf[0] != 0;
}
`)
		if len(events) != 0 {
			t.Fatalf("issue skeleton: backtrace(buf, 16) fills the array: want 0 VALUE_USE events, got %d", len(events))
		}
	})

	t.Run("read fills a heap block", func(t *testing.T) {
		events := runUninitDetect(t, `int read(int, void *, unsigned long);
int f(void) {
    char *buf = malloc(64);
    if (buf == 0) return -1;
    read(0, buf, 64);
    return buf[0];
}
`)
		if len(events) != 0 {
			t.Fatalf("read(0, buf, 64) writes the block: want 0 VALUE_USE events, got %d", len(events))
		}
	})

	t.Run("unfilled struct member stays reported", func(t *testing.T) {
		events := runUninitDetect(t, `struct fr {
    void *syms[16];
    int n;
};
int f(void) {
    struct fr fr;
    fr.n = 1;
    return fr.syms[0] != 0;
}
`)
		if len(events) == 0 {
			t.Fatal("control: a member never filled must keep producing a partial-init candidate")
		}
	})

	t.Run("bare uninit pointer passed to read stays reported", func(t *testing.T) {
		events := runUninitDetect(t, `int read(int, void *, unsigned long);
int f(void) {
    char *p;
    read(0, p, 64);
    return 0;
}
`)
		if len(events) == 0 {
			t.Fatal("control: passing an indeterminate pointer by value is a read of the pointer — must stay reported")
		}
	})
}

// TestUninit_Issue263_SecureCopyFallback pins the issue #263 P0-3 shape: a
// secure copy (strcpy_s) writes its destination on the success path AND the
// explicit fallback write covers the failure branch, so a later read is not
// uninitialized on any path. The heap-pointer shape is pinned at the planner
// layer (weak-tier dismissal), this evidence-level case pins the issue's
// original array shape.
func TestUninit_Issue263_SecureCopyFallback(t *testing.T) {
	t.Run("strcpy_s success and fallback both write", func(t *testing.T) {
		events := runUninitDetect(t, `int strcpy_s(char *, unsigned long, const char *);
int f(const char *src) {
    char dst[32];
    if (strcpy_s(dst, sizeof(dst), src) != 0) {
        dst[0] = '\0';
    }
    return dst[0];
}
`)
		if len(events) != 0 {
			t.Fatalf("both branches write dst: want 0 VALUE_USE events, got %d", len(events))
		}
	})
}

// TestUninit_Issue263_UnionSharedStorage re-pins the issue #253 P2-1a rule
// with the issue #263 shape (atomic_load whole-word write): a union member
// write initializes the shared storage, so reading another member is not a
// partial-init defect.
func TestUninit_Issue263_UnionSharedStorage(t *testing.T) {
	events := runUninitDetect(t, `union u {
    unsigned long atomic;
    unsigned char data[8];
};
unsigned long atomic_load(const unsigned long *);
int f(const unsigned long *p) {
    union u v;
    v.atomic = atomic_load(p);
    return v.data[0];
}
`)
	if len(events) != 0 {
		t.Fatalf("union member write covers all bits: want 0 VALUE_USE events, got %d", len(events))
	}
}
