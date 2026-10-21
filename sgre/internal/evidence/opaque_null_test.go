//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// The production scenario the OpaqueNullDetector closes: a function whose
// parameters use third-party typedefs that are not defined anywhere in the
// scan tree (exact report form — no typedef, no struct definition, external
// callees unresolved). The syntax layer recovers everything; the detector must
// seed the fail-open null sources for the invisible contracts.
const opaqueNullReportFixture = `int import_dn_group_tree_refresh(
    Nac_LdapSearchAckMsg_t *resp,
    import_para_ext_t *para)
{
    ldap_usrgroup_node_t *tree =
        (ldap_usrgroup_node_t *)(resp->group_data);

    if ((para->search_index != INVALID_SEARCHDN_IDX) &&
        (import_get_dn_level_diff(
            para->orig->base_dn,
            para->search_dn) > 1)) {
        return -1;
    }
    strcpy_s((char *)tree[0].group_name,
             sizeof(tree[0].group_name),
             path);
    return 0;
}
`

// Positive and negative control shapes for both seeding channels. Parameter
// names are unique per function so per-function assertions stay unambiguous.
const opaqueNullControlFixture = `typedef struct KnownRec KnownRec_t;

int guarded_handler(ExtMsg_t *gh_msg)
{
    if (gh_msg == NULL) {
        return -1;
    }
    return gh_msg->len;
}

int guarded_chain(ExtMsg_t *gc_m)
{
    if (gc_m->sub == NULL) {
        return -1;
    }
    return gc_m->sub->val;
}

int multi_level_chain(ExtMsg_t *ml_m)
{
    return ml_m->a->b->c;
}

int subscript_source(ExtMsg_t *ss_m)
{
    Node_t *n = ss_m->items[0];
    return n->flag;
}

static int dead_static_helper(ExtMsg_t *dsh_m)
{
    return dsh_m->len;
}

int known_user(KnownRec_t *ku_k)
{
    return ku_k->len;
}

int known_caller(void)
{
    KnownRec_t kk;
    kk.len = 1;
    return known_user(&kk);
}

int main(int argc, char **argv)
{
    (void)argc;
    return argv[0] != 0;
}
`

type opaqueSourceRecord struct {
	variable string
	origin   string
	line     int
}

func runOpaqueNullDetect(t *testing.T, fixtures map[string]string) []opaqueSourceRecord {
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
	if _, err := NewOpaqueNullDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect: %v", err)
	}

	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("list null value events: %v", err)
	}
	locIDs := make([]int64, 0, len(events))
	for _, e := range events {
		locIDs = append(locIDs, e.LocationID)
	}
	locs, err := store.ListLocationsByIDs(ctx, locIDs)
	if err != nil {
		t.Fatalf("list locations: %v", err)
	}
	var out []opaqueSourceRecord
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if props.Origin != "opaque_param" && props.Origin != "opaque_field_read" {
			continue
		}
		line := 0
		if loc := locs[e.LocationID]; loc != nil {
			line = loc.Line
		}
		out = append(out, opaqueSourceRecord{variable: props.Variable, origin: props.Origin, line: line})
	}
	return out
}

func TestOpaqueNullDetectorReportForm(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{"report.c": opaqueNullReportFixture})
	byVar := map[string]opaqueSourceRecord{}
	for _, r := range records {
		byVar[r.variable] = r
	}

	// The three report-mandated positions: resp->group_data (parameter),
	// tree[0].group_name (assigned field read), plus the shared para contract
	// and the chained intermediate para->orig.
	for _, want := range []struct{ variable, origin string }{
		{"resp", "opaque_param"},
		{"para", "opaque_param"},
		{"tree", "opaque_field_read"},
		{"para->orig", "opaque_field_read"},
	} {
		got, ok := byVar[want.variable]
		if !ok {
			t.Errorf("missing %s source (want origin %s); got %v", want.variable, want.origin, records)
			continue
		}
		if got.origin != want.origin {
			t.Errorf("variable %s: origin = %s, want %s", want.variable, got.origin, want.origin)
		}
	}
	// tree's source must be line-keyed at the assignment (the init_declarator
	// starts on line 5), and the chained intermediate's must sit at the
	// function header (birth form the planner seeds at the entry).
	if got, ok := byVar["tree"]; !ok || got.line != 5 {
		t.Errorf("tree source must be line-keyed at the assignment (init starts line 5), got %+v", got)
	}
	if got, ok := byVar["para->orig"]; !ok || got.line != 1 {
		t.Errorf("para->orig source must anchor at the function header line 1 (birth form), got %+v", got)
	}
}

func TestOpaqueNullDetectorControls(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{"controls.c": opaqueNullControlFixture})
	has := func(variable, origin string) bool {
		for _, r := range records {
			if r.variable == variable && r.origin == origin {
				return true
			}
		}
		return false
	}

	// A guarded parameter still seeds at the evidence layer (the planner's
	// path-sensitive guard model is what kills it), so the channel itself must
	// not grow a guard check that would duplicate that logic.
	if !has("gh_msg", "opaque_param") {
		t.Errorf("guarded_handler's gh_msg must still seed (guard is the planner's job); got %v", records)
	}
	// Chained intermediate + subscript field-read sources.
	if !has("gc_m->sub", "opaque_field_read") {
		t.Errorf("guarded_chain's gc_m->sub intermediate must seed a field-read source; got %v", records)
	}
	if !has("ml_m->a", "opaque_field_read") || !has("ml_m->a->b", "opaque_field_read") {
		t.Errorf("multi_level_chain must seed BOTH intermediate levels ml_m->a and ml_m->a->b; got %v", records)
	}
	if !has("n", "opaque_field_read") {
		t.Errorf("subscript_source's n (ss_m->items[0]) must seed a field-read source; got %v", records)
	}

	// Zero-caller exemptions: a static dead helper must not seed opaque_param.
	if has("dsh_m", "opaque_param") {
		t.Errorf("dead_static_helper is static with zero callers: dsh_m must not seed; got %v", records)
	}
	if has("ku_k", "opaque_param") {
		t.Errorf("known_user has an in-tree caller: ku_k must not seed opaque_param; got %v", records)
	}
	if has("argv", "opaque_param") {
		t.Errorf("main's argv must be exempt; got %v", records)
	}
	// A tree-defined typedef (KnownRec_t) is not opaque: known_user must not
	// get an opaque_field_read source even though it reads a field.
	if has("ku_k", "opaque_field_read") {
		t.Errorf("KnownRec_t is defined in-tree: no opaque_field_read for ku_k; got %v", records)
	}
}
