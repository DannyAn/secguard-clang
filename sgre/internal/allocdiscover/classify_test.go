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
