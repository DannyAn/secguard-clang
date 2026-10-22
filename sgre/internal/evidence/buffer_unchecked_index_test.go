package evidence

import (
	"io"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The production shape: a fixed-size array member indexed by a struct field
// that arrives from configuration, with no bounds check at the access site.
// The unchecked-index channel must seed it (suspected, handed to the AI) and
// carry the chain evidence: the source field, the pointer member read out of
// the element, and the callee that receives the element address and
// dereferences that member.
const uncheckedIndexReportFixture = `#define MAF_RBL_SVR_CFG_COUNT 4

typedef struct {
    const char *domain;
    unsigned int code;
} maf_rbl_svr_cfg_t;

typedef struct maf_rbl_profile {
    unsigned int actived_index;
    maf_rbl_svr_cfg_t svr[MAF_RBL_SVR_CFG_COUNT];
} maf_rbl_profile_t;

int maf_show_config(const maf_rbl_svr_cfg_t *svr)
{
    if (svr->domain == 0) {
        return -1;
    }
    return (int)svr->code;
}

int show_active(maf_rbl_profile_t *p)
{
    unsigned int idx = p->actived_index;
    const char *q = p->svr[idx].domain;
    int rc = maf_show_config(&p->svr[idx]);
    return q ? rc : -1;
}
`

// The fixed form: the entry validates the field against the same capacity
// symbol the array is declared with, so the channel must stay silent.
const uncheckedIndexGuardedFixture = `#define MAF_RBL_SVR_CFG_COUNT 4

typedef struct {
    const char *domain;
    unsigned int code;
} maf_rbl_svr_cfg_t;

typedef struct maf_rbl_profile {
    unsigned int actived_index;
    maf_rbl_svr_cfg_t svr[MAF_RBL_SVR_CFG_COUNT];
} maf_rbl_profile_t;

int show_active(struct maf_rbl_profile *p)
{
    if (p->actived_index >= MAF_RBL_SVR_CFG_COUNT) {
        return 1;
    }
    return (int)p->svr[p->actived_index].code;
}
`

// Negative controls: every index below is NOT field-derived, and a plain
// parameter / loop variable index is exactly the ordinary shape the channel
// must not flood on. The constant index is covered by the proved channel.
const uncheckedIndexControlFixture = `typedef struct {
    int counters[8];
} Ctl_t;

void write_ctl(Ctl_t *c, unsigned int n)
{
    c->counters[n] = 1;
}

void loop_ctl(Ctl_t *c, int limit)
{
    for (int i = 0; i < limit; i++) {
        c->counters[i] = i;
    }
}

void const_ctl(Ctl_t *c)
{
    c->counters[0] = 7;
}

int read_guard_branch(Ctl_t *c, unsigned int n)
{
    if (n < 8) {
        return c->counters[n];
    }
    return -1;
}
`

// The write flavor of the production shape must seed the buffer-overflow
// category instead of the read one.
const uncheckedIndexWriteFixture = `typedef struct {
    unsigned int slot;
    int counters[4];
} Wr_t;

void store_slot(Wr_t *w)
{
    w->counters[w->slot] = 9;
}
`

type uncheckedIndexEvent struct {
	Category       string
	Array          string
	Index          string
	IndexSource    string
	CapacitySymbol string
	Size           int
	ElemField      string
	Escape         string
	EscapeDeref    string
	Function       string
	Line           int
}

func runUncheckedIndexDetect(t *testing.T, fixtures map[string]string) []uncheckedIndexEvent {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	var paths []string
	for name, src := range fixtures {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatalf("write fixture %s: %v", name, err)
		}
		paths = append(paths, path)
	}
	idx := indexer.NewIndexer(store, logger)
	for _, path := range paths {
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", path, err)
		}
	}
	if _, err := NewBufferOverflowDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("buffer overflow detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	fnByID := map[int64]*db.Function{}
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		t.Fatalf("list functions: %v", err)
	}
	for _, fn := range funcs {
		fnByID[fn.ID] = fn
	}
	locByID := map[int64]*db.Location{}
	files, err := store.ListFiles(ctx)
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	for _, fl := range files {
		locs, err := store.ListLocationsByFile(ctx, fl.ID)
		if err != nil {
			t.Fatalf("list locations: %v", err)
		}
		for _, loc := range locs {
			locByID[loc.ID] = loc
		}
	}

	var out []uncheckedIndexEvent
	for _, e := range events {
		var props struct {
			Category       string `json:"category"`
			Array          string `json:"array"`
			Index          string `json:"index"`
			IndexSource    string `json:"index_source"`
			CapacitySymbol string `json:"capacity_symbol"`
			Size           string `json:"size"`
			ElemField      string `json:"elem_field"`
			Escape         string `json:"escape"`
			EscapeDeref    string `json:"escape_deref"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("unmarshal props %q: %v", e.Properties, err)
		}
		if props.Category != "array_oob_read_unchecked" && props.Category != "array_oob_write_unchecked" {
			continue
		}
		size, _ := strconv.Atoi(props.Size)
		ev := uncheckedIndexEvent{
			Category:       props.Category,
			Array:          props.Array,
			Index:          props.Index,
			IndexSource:    props.IndexSource,
			CapacitySymbol: props.CapacitySymbol,
			Size:           size,
			ElemField:      props.ElemField,
			Escape:         props.Escape,
			EscapeDeref:    props.EscapeDeref,
		}
		if fn := fnByID[e.EntityID]; fn != nil {
			ev.Function = fn.Name
		}
		if loc := locByID[e.LocationID]; loc != nil {
			ev.Line = loc.Line
		}
		out = append(out, ev)
	}
	return out
}

func TestUncheckedIndexReadReportForm(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{"rbl.c": uncheckedIndexReportFixture})
	if len(events) != 1 {
		t.Fatalf("want exactly 1 unchecked-index event for the production shape, got %d: %+v", len(events), events)
	}
	e := events[0]
	if e.Category != "array_oob_read_unchecked" {
		t.Errorf("category = %s, want array_oob_read_unchecked", e.Category)
	}
	if e.Function != "show_active" {
		t.Errorf("function = %s, want show_active", e.Function)
	}
	if e.Array != "p->svr" {
		t.Errorf("array = %s, want p->svr", e.Array)
	}
	if e.IndexSource != "actived_index" {
		t.Errorf("index_source = %s, want actived_index (one level of local copy must be followed)", e.IndexSource)
	}
	if e.Size != 4 {
		t.Errorf("size = %d, want 4 (macro-sized member array)", e.Size)
	}
	if e.CapacitySymbol != "MAF_RBL_SVR_CFG_COUNT" {
		t.Errorf("capacity_symbol = %s, want MAF_RBL_SVR_CFG_COUNT", e.CapacitySymbol)
	}
	if e.ElemField != "domain" {
		t.Errorf("elem_field = %s, want domain (pointer member read from the element)", e.ElemField)
	}
	if e.Escape != "maf_show_config" {
		t.Errorf("escape = %s, want maf_show_config", e.Escape)
	}
	if !strings.HasPrefix(e.EscapeDeref, "domain@") {
		t.Errorf("escape_deref = %s, want the callee's pointer-member read (domain@<line>)", e.EscapeDeref)
	}
}

func TestUncheckedIndexGuardedControl(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{"rbl_fix.c": uncheckedIndexGuardedFixture})
	if len(events) != 0 {
		t.Fatalf("the fixed form (bounds check against the capacity symbol) must seed nothing, got %+v", events)
	}
}

// The guard idioms must all suppress, and a check against a bound LARGER than
// the capacity must not: it still admits out-of-range indices.
const uncheckedIndexGuardShapesFixture = `typedef struct {
    unsigned int idx;
    int v[4];
} G_t;

int guard_ge(G_t *g)
{
    if (g->idx >= 4) {
        return -1;
    }
    return g->v[g->idx];
}

int guard_gt(G_t *g)
{
    if (g->idx > 3) {
        return -1;
    }
    return g->v[g->idx];
}

int guard_lt_positive(G_t *g)
{
    if (g->idx < 4) {
        return g->v[g->idx];
    }
    return -1;
}

int guard_le_positive(G_t *g)
{
    if (g->idx <= 3) {
        return g->v[g->idx];
    }
    return -1;
}

int pseudo_guard(G_t *g)
{
    if (g->idx >= 8) {
        return -1;
    }
    return g->v[g->idx];
}
`

func TestUncheckedIndexGuardShapes(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{"guard.c": uncheckedIndexGuardShapesFixture})
	if len(events) != 1 {
		t.Fatalf("only the too-large-bound pseudo guard may seed, got %d: %+v", len(events), events)
	}
	if events[0].Function != "pseudo_guard" {
		t.Errorf("seeded function = %s, want pseudo_guard (the other four are real guards)", events[0].Function)
	}
}

func TestUncheckedIndexParameterIndexControl(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{"ctl.c": uncheckedIndexControlFixture})
	if len(events) != 0 {
		t.Fatalf("parameter/loop/constant indices are not field-derived and must not seed this channel, got %+v", events)
	}
}

func TestUncheckedIndexWriteCategory(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{"wr.c": uncheckedIndexWriteFixture})
	if len(events) != 1 {
		t.Fatalf("want 1 unchecked-index event, got %d: %+v", len(events), events)
	}
	if events[0].Category != "array_oob_write_unchecked" {
		t.Errorf("category = %s, want array_oob_write_unchecked for the write flavor", events[0].Category)
	}
	if events[0].IndexSource != "slot" {
		t.Errorf("index_source = %s, want slot (direct field index)", events[0].IndexSource)
	}
}

// The exact production report form, with the struct split into a header — the
// normal C layout. Before the tree-wide census, `bc.fields` and `bc.macros` were
// scoped to the file being analyzed, so the member array's capacity was
// unresolvable and the function produced ZERO candidates (the production
// regression: "out-of-bounds 0 candidates").
func TestUncheckedIndexHeaderDeclaredStruct(t *testing.T) {
	events := runUncheckedIndexDetect(t, map[string]string{
		"maf.h": `#define MAF_RBL_SVR_CFG_COUNT 8
#define SHOW_CONTINUE 0

struct maf_rbl_svr_cfg {
    char *domain;
    unsigned int action;
    unsigned int reply_code_any;
};

struct maf_rbl_profile {
    unsigned int actived_index;
    char actived_svr_name[64];
    struct maf_rbl_svr_cfg svr[MAF_RBL_SVR_CFG_COUNT];
};

extern int maf_write_to_buffer(char *outbuf, int buflen, int *pos, const char *fmt, ...);
extern int maf_show_dataplane_config_all_reply_code(const struct maf_rbl_svr_cfg *svr, char *outbuf, int buflen, int *pos);
`,
		"show.c": `#include "maf.h"

int show_dataplane_config_active_rbl_server(struct maf_rbl_profile *rbl_profile, char *outbuf, int buflen, int *pos)
{
    int ret = maf_write_to_buffer(outbuf, buflen, pos, "%s",
        rbl_profile->svr[rbl_profile->actived_index].domain);
    if (ret != SHOW_CONTINUE) {
        return ret;
    }
    return maf_show_dataplane_config_all_reply_code(&rbl_profile->svr[rbl_profile->actived_index], outbuf, buflen, pos);
}
`,
	})
	if len(events) != 1 {
		t.Fatalf("want exactly 1 unchecked-index event for the header-split production shape, got %d: %+v", len(events), events)
	}
	e := events[0]
	if e.Category != "array_oob_read_unchecked" {
		t.Errorf("category = %s, want array_oob_read_unchecked", e.Category)
	}
	if e.Function != "show_dataplane_config_active_rbl_server" {
		t.Errorf("function = %s", e.Function)
	}
	if e.Array != "rbl_profile->svr" {
		t.Errorf("array = %s, want rbl_profile->svr", e.Array)
	}
	if e.IndexSource != "actived_index" {
		t.Errorf("index_source = %s, want actived_index", e.IndexSource)
	}
	if e.Size != 8 {
		t.Errorf("size = %d, want 8 (capacity macro from the header)", e.Size)
	}
	if e.CapacitySymbol != "MAF_RBL_SVR_CFG_COUNT" {
		t.Errorf("capacity_symbol = %s, want MAF_RBL_SVR_CFG_COUNT", e.CapacitySymbol)
	}
	if e.ElemField != "domain" {
		t.Errorf("elem_field = %s, want domain (pointer member of the element)", e.ElemField)
	}
	if e.Escape != "maf_show_dataplane_config_all_reply_code" {
		t.Errorf("escape = %s, want the sink that receives &svr[idx]", e.Escape)
	}
}

// Same blind spot, the bare-array half: a file-scope array declared in a header
// (`extern char g_buf[256];`) used with a constant index in another file. The
// per-file declaration scan cannot see it, so before the tree-wide census the
// capacity was unknown and the proved OOB channel stayed silent.
func TestArrayCapacityDeclaredInHeader(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	fixtures := map[string]string{
		"glob.h": "#define G_TBL_LEN 4\nextern int g_tbl[G_TBL_LEN];\n",
		"use.c":  "#include \"glob.h\"\n\nint read_tbl(void)\n{\n    return g_tbl[7];\n}\n",
	}
	idx := indexer.NewIndexer(store, logger)
	for name, src := range fixtures {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(src), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := idx.Index(ctx, path); err != nil {
			t.Fatalf("index %s: %v", name, err)
		}
	}
	if _, err := NewBufferOverflowDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatal(err)
	}

	events, err := store.ListEventsByType(ctx, "BUFFER_ACCESS")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Array          string `json:"array"`
			Category       string `json:"category"`
			Size           string `json:"size"`
			CapacitySymbol string `json:"capacity_symbol"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			t.Fatalf("unmarshal props: %v", err)
		}
		if props.Array != "g_tbl" {
			continue
		}
		found = true
		if props.Category != "array_oob_read" {
			t.Errorf("category = %s, want array_oob_read", props.Category)
		}
		if props.Size != "4" {
			t.Errorf("size = %s, want 4 (capacity macro from the header)", props.Size)
		}
	}
	if !found {
		t.Fatalf("want an out-of-bounds event for g_tbl[7] (capacity from the header), got %d events", len(events))
	}
}
