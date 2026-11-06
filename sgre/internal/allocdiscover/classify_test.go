package allocdiscover

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		sym        symbol
		wantKind   string
		wantConf   string
		wantReason []string
		notReason  []string
	}{
		{
			name:     "strong allocator name with malloc call",
			sym:      symbol{name: "myapp_malloc", returnType: "void*", signature: "myapp_malloc(size_t n)", callsAlloc: []string{"malloc"}},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *_malloc", "calls malloc"},
		},
		{
			name:     "strong allocator name without call",
			sym:      symbol{name: "platform_alloc", returnType: "void*", signature: "platform_alloc(size_t sz, int flags)"},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *_alloc"},
		},
		{
			name:     "uppercase allocator variant",
			sym:      symbol{name: "VOS_MALLOC", returnType: "void*", signature: "VOS_MALLOC(size_t n)"},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *_malloc"},
		},
		{
			name:     "wrapper prefix form xmalloc",
			sym:      symbol{name: "xmalloc", returnType: "void*", signature: "xmalloc(size_t n)"},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *malloc"},
		},
		{
			name:     "weak allocator name no call",
			sym:      symbol{name: "make_item_new", returnType: "void*", signature: "make_item_new(size_t n)"},
			wantKind: "allocator", wantConf: ConfMedium,
			wantReason: []string{"name pattern *_new"},
		},
		{
			name:     "signature-only allocator",
			sym:      symbol{name: "buffer_create", returnType: "void*", signature: "buffer_create(size_t n)"},
			wantKind: "allocator", wantConf: ConfLow,
			wantReason: []string{"pointer return, size_t parameter"},
		},
		{
			name:     "signature allocator with malloc call",
			sym:      symbol{name: "buffer_create", returnType: "void*", signature: "buffer_create(size_t n)", callsAlloc: []string{"malloc"}},
			wantKind: "allocator", wantConf: ConfMedium,
			wantReason: []string{"calls malloc"},
		},
		{
			name:     "strong deallocator name with free call",
			sym:      symbol{name: "myapp_free", returnType: "void", signature: "myapp_free(void *p)", callsDealloc: []string{"free"}},
			wantKind: "deallocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *_free", "calls free"},
		},
		{
			name:     "weak deallocator name no call",
			sym:      symbol{name: "pool_destroy", returnType: "void", signature: "pool_destroy(void *p)"},
			wantKind: "deallocator", wantConf: ConfMedium,
			wantReason: []string{"name pattern *_destroy"},
		},
		{
			name:     "dealloc wins over alloc substring",
			sym:      symbol{name: "my_dealloc", returnType: "void", signature: "my_dealloc(void *p)"},
			wantKind: "deallocator", wantConf: ConfMedium,
			wantReason: []string{"name pattern *_dealloc"},
		},
		{
			name:     "signature-only deallocator",
			sym:      symbol{name: "cleanup_buffer", returnType: "void", signature: "cleanup_buffer(void *p)"},
			wantKind: "deallocator", wantConf: ConfLow,
			wantReason: []string{"void return, pointer parameter"},
		},
		{
			name:     "call evidence allocator without a name/signature match",
			sym:      symbol{name: "get_thing", returnType: "void*", signature: "get_thing(void)", callsAlloc: []string{"malloc"}},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"calls malloc"},
		},
		{
			name:     "call evidence deallocator without a name match",
			sym:      symbol{name: "release_all", returnType: "void", signature: "release_all(int flags)", callsDealloc: []string{"free"}},
			wantKind: "deallocator", wantConf: ConfHigh,
			wantReason: []string{"calls free"},
		},
		{
			name:     "non-void return is not a release by call evidence alone",
			sym:      symbol{name: "drop_status", returnType: "int", signature: "drop_status(obj_t *o)", callsDealloc: []string{"free"}},
			wantKind: "",
		},
		{
			name:     "_F allocator variant",
			sym:      symbol{name: "VOS_MALLOC_F", returnType: "void*", signature: "VOS_MALLOC_F(size_t n, int f)"},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"name pattern *_malloc_f"},
		},
		{
			name:     "not a candidate",
			sym:      symbol{name: "compute_sum", returnType: "int", signature: "compute_sum(int a, int b)"},
			wantKind: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, kind, ok := classify(c.sym)
			if c.wantKind == "" {
				if ok {
					t.Fatalf("classify(%s) = %q (unexpected candidate %+v)", c.sym.name, kind, e)
				}
				return
			}
			if !ok {
				t.Fatalf("classify(%s) not a candidate, want %s", c.sym.name, c.wantKind)
			}
			if kind != c.wantKind {
				t.Errorf("kind = %q, want %q", kind, c.wantKind)
			}
			if e.Confidence != c.wantConf {
				t.Errorf("confidence = %q, want %q (reasons=%v)", e.Confidence, c.wantConf, e.Reasons)
			}
			joined := strings.Join(e.Reasons, "; ")
			for _, want := range c.wantReason {
				if !strings.Contains(joined, want) {
					t.Errorf("reasons %v missing %q", e.Reasons, want)
				}
			}
			for _, not := range c.notReason {
				if strings.Contains(joined, not) {
					t.Errorf("reasons %v should not contain %q", e.Reasons, not)
				}
			}
		})
	}
}

func TestSplitParams(t *testing.T) {
	cases := []struct {
		sig  string
		want []string
	}{
		{"my_malloc(size_t n)", []string{"size_t n"}},
		{"my_malloc(void)", nil},
		{"f(int a, char *b)", []string{"int a", "char *b"}},
		{"f(int (*cb)(int x, int y), size_t n)", []string{"int (*cb)(int x, int y)", "size_t n"}},
		{"f()", nil},
	}
	for _, c := range cases {
		got := splitParams(c.sig)
		if len(got) != len(c.want) {
			t.Errorf("splitParams(%q) = %v, want %v", c.sig, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitParams(%q)[%d] = %q, want %q", c.sig, i, got[i], c.want[i])
			}
		}
	}
}

func TestClassifyMacro(t *testing.T) {
	cases := []struct {
		name       string
		m          macroEntry
		wantKind   string
		wantConf   string
		wantReason []string
	}{
		{
			name:     "function-like allocator macro expanding to malloc",
			m:        macroEntry{name: "NAT_MALLOC", bodies: []string{"malloc(n)"}, functionLike: true},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"macro name pattern *_malloc", "expands to malloc"},
		},
		{
			name:     "object-like allocator macro aliasing malloc",
			m:        macroEntry{name: "NLOG_MALLOC", bodies: []string{"malloc"}, functionLike: true},
			wantKind: "allocator", wantConf: ConfHigh,
			wantReason: []string{"macro name pattern *_malloc", "expands to malloc"},
		},
		{
			name:     "deallocator macro expanding to free",
			m:        macroEntry{name: "NLOG_FREE", bodies: []string{"free(p)"}, functionLike: true},
			wantKind: "deallocator", wantConf: ConfHigh,
			wantReason: []string{"macro name pattern *_free", "expands to free"},
		},
		{
			name:     "weak deallocator macro without free in body",
			m:        macroEntry{name: "POOL_DESTROY", bodies: []string{"pool_release(p)"}, functionLike: true},
			wantKind: "deallocator", wantConf: ConfMedium,
			wantReason: []string{"macro name pattern *_destroy"},
		},
		{
			name:     "non-allocator macro",
			m:        macroEntry{name: "MAX_BUF", bodies: []string{"256"}},
			wantKind: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, kind, ok := classifyMacro(c.m)
			if c.wantKind == "" {
				if ok {
					t.Fatalf("classifyMacro(%s) = %q (unexpected candidate %+v)", c.m.name, kind, e)
				}
				return
			}
			if !ok {
				t.Fatalf("classifyMacro(%s) not a candidate, want %s", c.m.name, c.wantKind)
			}
			if kind != c.wantKind {
				t.Errorf("kind = %q, want %q", kind, c.wantKind)
			}
			if e.Confidence != c.wantConf {
				t.Errorf("confidence = %q, want %q (reasons=%v)", e.Confidence, c.wantConf, e.Reasons)
			}
			joined := strings.Join(e.Reasons, "; ")
			for _, want := range c.wantReason {
				if !strings.Contains(joined, want) {
					t.Errorf("reasons %v missing %q", e.Reasons, want)
				}
			}
		})
	}
}

func TestRender(t *testing.T) {
	r := &Result{
		Allocators: []Entry{
			{Name: "myapp_malloc", Confidence: ConfHigh, Reasons: []string{"name pattern *_malloc", "calls malloc"}},
			{Name: "buffer_create", Confidence: ConfLow, Reasons: []string{"pointer return, size_t parameter"}},
		},
		Deallocators: []Entry{
			{Name: "myapp_free", Confidence: ConfHigh, Reasons: []string{"name pattern *_free", "calls free"}},
		},
	}
	out := r.Render()
	for _, want := range []string{
		"[allocators]",
		"[deallocators]",
		"\"myapp_malloc\"",
		"# high: name pattern *_malloc; calls malloc",
		"# needs review: pointer return, size_t parameter",
		"# high: name pattern *_free; calls free",
		"# \"buffer_create\",",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}

func TestRenderEmpty(t *testing.T) {
	out := (&Result{}).Render()
	if !strings.Contains(out, "[allocators]") || !strings.Contains(out, "[deallocators]") {
		t.Errorf("empty render must still emit both sections:\n%s", out)
	}
	if !strings.Contains(out, "names = []") {
		t.Errorf("empty sections should emit empty names lists:\n%s", out)
	}
}

func TestClassifyMacro_BodyEvidenceAndObjectLike(t *testing.T) {
	cases := []struct {
		name       string
		m          macroEntry
		wantKind   string
		wantConf   string
		wantAbsent bool
	}{
		{
			name:     "body expands to free",
			m:        macroEntry{name: "PUT_MEM", bodies: []string{"free(p)"}, functionLike: true},
			wantKind: "deallocator", wantConf: ConfHigh,
		},
		{
			name:     "body expands to malloc",
			m:        macroEntry{name: "GET_MEM", bodies: []string{"malloc(n)"}, functionLike: true},
			wantKind: "allocator", wantConf: ConfHigh,
		},
		{
			name:     "object-like name-only is needs-review",
			m:        macroEntry{name: "FREE", bodies: []string{"0"}},
			wantKind: "deallocator", wantConf: ConfLow,
		},
		{
			name:     "function-like predicate is not a release",
			m:        macroEntry{name: "IS_FREE", bodies: []string{"((s)==FREE)"}, functionLike: true},
			wantKind: "deallocator", wantConf: ConfLow,
		},
		{
			name:       "unrelated macro",
			m:          macroEntry{name: "MAX_BUF", bodies: []string{"256"}},
			wantAbsent: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, kind, ok := classifyMacro(c.m)
			if c.wantAbsent {
				if ok {
					t.Fatalf("unexpected candidate %+v", e)
				}
				return
			}
			if !ok || kind != c.wantKind || e.Confidence != c.wantConf {
				t.Fatalf("classifyMacro = (%+v, %q, %v), want kind=%q conf=%q", e, kind, ok, c.wantKind, c.wantConf)
			}
		})
	}
}
func TestClassifyOwnershipTransfer(t *testing.T) {
	cases := []struct {
		name     string
		sym      symbol
		wantOK   bool
		wantConf string
	}{
		{
			name:   "push with pointer param",
			sym:    symbol{name: "list_push_back", signature: "list_push_back(list_t *l, void *item)"},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "insert with pointer param",
			sym:    symbol{name: "dict_insert", signature: "dict_insert(dict_t *d, void *key, void *val)"},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "CamelCase Add with pointer param",
			sym:    symbol{name: "raxInsert", signature: "raxInsert(rax *r, void *data)"},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "push without pointer param",
			sym:    symbol{name: "queue_push_int", signature: "queue_push_int(queue_t *q, int val)"},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "non-transfer name",
			sym:    symbol{name: "compute_value", signature: "compute_value(int x)"},
			wantOK: false,
		},
		{
			name:   "transfer name but calls free — downgraded",
			sym:    symbol{name: "list_push_and_free", signature: "list_push_and_free(list_t *l, void *item)", callsDealloc: []string{"free"}},
			wantOK: true, wantConf: ConfLow,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, ok := classifyOwnershipTransfer(c.sym)
			if c.wantOK != ok {
				t.Fatalf("classifyOwnershipTransfer(%s) ok=%v, want %v", c.sym.name, ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if e.Confidence != c.wantConf {
				t.Errorf("confidence = %q, want %q (reasons=%v)", e.Confidence, c.wantConf, e.Reasons)
			}
		})
	}
}

func TestClassifyIteratorMacro(t *testing.T) {
	cases := []struct {
		name     string
		m        macroEntry
		wantOK   bool
		wantConf string
	}{
		{
			name:   "for_each with loop body",
			m:      macroEntry{name: "list_for_each", bodies: []string{"for (pos = (head)->next; pos != (head); pos = pos->next)"}, functionLike: true},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "scan with NULL guard",
			m:      macroEntry{name: "DLL_Scan", bodies: []string{"(ptr) && (ptr)->next != NULL"}, functionLike: true},
			wantOK: true, wantConf: ConfHigh,
		},
		{
			name:   "walk name only",
			m:      macroEntry{name: "tree_walk", bodies: []string{"traverse(node)"}, functionLike: true},
			wantOK: true, wantConf: ConfMedium,
		},
		{
			name:   "object-like macro — not iterator",
			m:      macroEntry{name: "MAX_SCAN", bodies: []string{"256"}, functionLike: false},
			wantOK: false,
		},
		{
			name:   "non-iterator name",
			m:      macroEntry{name: "COMPUTE", bodies: []string{"for (;;)"}, functionLike: true},
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, ok := classifyIteratorMacro(c.m)
			if c.wantOK != ok {
				t.Fatalf("classifyIteratorMacro(%s) ok=%v, want %v", c.m.name, ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if e.Confidence != c.wantConf {
				t.Errorf("confidence = %q, want %q (reasons=%v)", e.Confidence, c.wantConf, e.Reasons)
			}
		})
	}
}

func TestRenderOwnershipAndIterator(t *testing.T) {
	r := &Result{
		OwnershipTransfers: []Entry{
			{Name: "list_push_back", Confidence: ConfHigh, Reasons: []string{"name pattern *_push", "pointer parameter"}},
		},
		IteratorMacros: []Entry{
			{Name: "DLL_Scan", Confidence: ConfHigh, Reasons: []string{"macro name pattern *_scan", "body contains NULL/next guard"}},
		},
	}
	out := r.Render()
	for _, want := range []string{
		"[ownership_transfer_calls]",
		"\"list_push_back\"",
		"[iterator_macros.macros]",
		"# DLL_Scan = [0]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}
