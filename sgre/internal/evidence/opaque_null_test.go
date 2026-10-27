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

// NE-05: `typedef struct Foo Foo_t;` (forward-declaration typedef) followed by
// a BODIED `struct Foo { ... };` elsewhere defines the alias too — the typedef
// node's own specifier has no body, but the tag it names does. Previously the
// alias stayed opaque and every `Foo_t *` parameter grew a phantom
// fail-open seed.
func TestCollectDefinedTypesSplitTypedef(t *testing.T) {
	src := `typedef struct Foo Foo_t;
struct Foo { int x; };
typedef struct Bar Bar_t;
`
	p := parser.NewParser()
	tree, err := p.Parse([]byte(src), "fixture.c")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	defined := map[string]bool{}
	collectDefinedTypes(tree.RootNode(), defined)
	if !defined["Foo"] || !defined["Foo_t"] {
		t.Errorf("split typedef: Foo and Foo_t must both be defined (the tag has a body), got %v", defined)
	}
	if defined["Bar"] || defined["Bar_t"] {
		t.Errorf("forward-only typedef: Bar/Bar_t must stay opaque (no body anywhere), got %v", defined)
	}
}

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
const opaqueNullControlFixture = `typedef struct KnownRec {
    unsigned int len;
} KnownRec_t;

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

int opaque_fwd_target(ExtMsg_t *oft_m)
{
    return oft_m->len;
}

int opaque_fwd_caller(ExtMsg_t *oft_p)
{
    return opaque_fwd_target(oft_p);
}

int tree_typed_target(KnownRec_t *ttt_k)
{
    return ttt_k->len;
}

int tree_typed_caller(KnownRec_t *ttt_p)
{
    return tree_typed_target(ttt_p);
}

int main(int argc, char **argv)
{
    (void)argc;
    return argv[0] != 0;
}
`

type opaqueSourceRecord struct {
	variable   string
	origin     string
	line       int
	countField string
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
	// Both detectors are order-independent now (caller_null's open-chain
	// fixpoint is self-contained; opaque_null reads no detector output), but
	// run both so the record set reflects the production event stream.
	if _, err := NewCallerNullDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("caller null detect: %v", err)
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
			Variable   string `json:"variable"`
			Origin     string `json:"origin"`
			CountField string `json:"count_field"`
		}
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if props.Origin != "caller_null" && props.Origin != "opaque_field_read" {
			continue
		}
		line := 0
		if loc := locs[e.LocationID]; loc != nil {
			line = loc.Line
		}
		out = append(out, opaqueSourceRecord{variable: props.Variable, origin: props.Origin, line: line, countField: props.CountField})
	}
	return out
}

// NE-07: a chained dereference through a SUBSCRIPT (`a->b[0]->c`) reads the
// same open-world intermediate value as `a->b->c` does — the chained-deref
// seed only matched a field_expression base, so the subscript form's
// intermediate value never seeded and the chain's nullability was lost.
func TestOpaqueNullDetectorChainedSubscriptDeref(t *testing.T) {
	src := `typedef struct ExtMsg ExtMsg_t;

void chain_subscript(ExtMsg_t *a) {
    int x = a->b[0]->c;
    (void)x;
}
`
	records := runOpaqueNullDetect(t, map[string]string{"chain.c": src})
	for _, r := range records {
		if r.variable == "a->b[0]" && r.origin == "opaque_field_read" {
			return
		}
	}
	t.Errorf("`a->b[0]->c`: the intermediate subscript value must seed an opaque_field_read source, got %v", records)
}

func TestOpaqueNullDetectorReportForm(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{"report.c": opaqueNullReportFixture})
	byVar := map[string]opaqueSourceRecord{}
	for _, r := range records {
		byVar[r.variable] = r
	}

	// The three report-mandated positions: resp->group_data (parameter),
	// tree[0].group_name (assigned field read), plus the shared para contract
	// and the chained intermediate para->orig. The isolated report form has
	// zero in-tree callers, so the parameters' openness comes from the
	// caller_null open-entry base (origin caller_null, chain open).
	for _, want := range []struct{ variable, origin string }{
		{"resp", "caller_null"},
		{"para", "caller_null"},
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
	// not grow a guard check that would duplicate that logic. Zero in-tree
	// callers => the caller_null open-entry base seeds every pointer parameter.
	if !has("gh_msg", "caller_null") {
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

	// Zero-caller exemptions: a static dead helper must not seed.
	if has("dsh_m", "caller_null") {
		t.Errorf("dead_static_helper is static with zero callers: dsh_m must not seed; got %v", records)
	}
	if has("ku_k", "caller_null") {
		t.Errorf("known_user's caller passes &kk (provably non-null): ku_k must not seed; got %v", records)
	}
	if has("argv", "caller_null") {
		t.Errorf("main's argv must be exempt; got %v", records)
	}
	// A tree-defined typedef (KnownRec_t) is not opaque: known_user must not
	// get an opaque_field_read source even though it reads a field.
	if has("ku_k", "opaque_field_read") {
		t.Errorf("KnownRec_t is defined in-tree: no opaque_field_read for ku_k; got %v", records)
	}

	// The open-chain volume contract (the soul-searching answer): an unproven
	// FORWARDING caller only keeps the callee parameter open when the chain is
	// itself open at the root. opaque_fwd_caller has zero in-tree callers and
	// its parameter type is invisible, so its forwarding edge propagates the
	// open entry to opaque_fwd_target.
	if !has("oft_m", "caller_null") {
		t.Errorf("opaque_fwd_target's oft_m (forwarded from a zero-caller open entry) must seed; got %v", records)
	}
	// The type gate: tree_typed_caller has zero in-tree callers too, but
	// KnownRec_t is defined in-tree — the v0.9.4 contract keeps that entry
	// closed, so ttt_k does not seed.
	if has("ttt_k", "caller_null") {
		t.Errorf("tree_typed_target's ttt_k (tree-defined type entry) must not seed; got %v", records)
	}
}

// The in-tree-caller channel against the report's exact production shape: the
// target function HAS an in-tree caller forwarding its own unproven opaque
// parameters. The fail-open opaque_param seed must land for resp/para (without
// it the planner's onlyUnprovenCallerNullSources dismissal drops the parameter
// candidates as an "analyzer limitation"), while a guarded caller and a
// tree-defined type stay dark.
func TestOpaqueNullDetectorInTreeCallerReportForm(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		"target.c": `int import_dn_group_tree_refresh(
    Nac_LdapSearchAckMsg_t *resp,
    import_para_ext_t *para)
{
    ldap_usrgroup_node_t *tree =
        (ldap_usrgroup_node_t *)(resp->group_data);
    if ((para->search_index != INVALID_SEARCHDN_IDX) &&
        (import_get_dn_level_diff(para->orig->base_dn, para->search_dn) > 1)) {
        return -1;
    }
    strcpy_s((char *)tree[0].group_name,
             sizeof(tree[0].group_name),
             path);
    return 0;
}
`,
		"caller.c": `int import_dn_group_tree(Nac_LdapSearchAckMsg_t *ack, import_para_ext_t *p)
{
    return import_dn_group_tree_refresh(ack, p);
}
`,
	})
	has := func(variable, origin string) bool {
		for _, r := range records {
			if r.variable == variable && r.origin == origin {
				return true
			}
		}
		return false
	}
	if !has("resp", "caller_null") {
		t.Errorf("resp (forwarded from the zero-caller open entry import_dn_group_tree) must seed; got %v", records)
	}
	if !has("para", "caller_null") {
		t.Errorf("para (forwarded from the zero-caller open entry import_dn_group_tree) must seed; got %v", records)
	}
	if !has("tree", "opaque_field_read") {
		t.Errorf("tree = (T *)(resp->group_data) must still seed opaque_field_read; got %v", records)
	}
}

// The type census must see types defined in FUNCTION-LESS headers. A normal C
// project keeps every struct/typedef in a header that defines no function, so a
// census built over "files that contain an indexed function" marks those
// layouts invisible and seeds fail-open field-read sources for a contract the
// scan tree can see completely — the in-tree-type false-positive class the
// opaque channel must never introduce.
func TestOpaqueNullDetectorHeaderDefinedTypeIsNotOpaque(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		"ext.h": `typedef struct ExtAck_s {
    unsigned int len;
    void *group_data;
} ExtAck_t;

typedef struct ExtNode_s {
    char name[32];
} ExtNode_t;
`,
		"known.c": `#include "ext.h"

int ext_known_refresh(ExtAck_t *ek_resp)
{
    ExtNode_t *ek_tree = (ExtNode_t *)(ek_resp->group_data);
    return ek_tree[0].name[0];
}
`,
		"opaque.c": `int ext_opaque_refresh(UnknownAck_t *uo_resp)
{
    UnknownNode_t *uo_tree = (UnknownNode_t *)(uo_resp->group_data);
    return uo_tree[0].name[0];
}

int main(void) { return 0; }
`,
	})
	has := func(variable, origin string) bool {
		for _, r := range records {
			if r.variable == variable && r.origin == origin {
				return true
			}
		}
		return false
	}

	// ExtAck_t / ExtNode_t are layout-visible in ext.h: the assignment's base
	// parameter type is NOT opaque, so no fail-open field-read source.
	if has("ek_tree", "opaque_field_read") {
		t.Errorf("ext.h defines ExtAck_t/ExtNode_t: ek_tree must not get an opaque_field_read source; got %v", records)
	}
	// The type gate closes the zero-caller entry for a visible type too.
	if has("ek_resp", "caller_null") {
		t.Errorf("ext_known_refresh's parameter type is defined in ext.h: ek_resp must not be an open entry; got %v", records)
	}
	// The undefined-type counterpart must keep the fail-open channel alive, so
	// the fix cannot blind the detector wholesale.
	if !has("uo_tree", "opaque_field_read") {
		t.Errorf("UnknownAck_t is not defined anywhere: uo_tree must still seed opaque_field_read; got %v", records)
	}
}

// A BOUNDARY scan (no program entry point: a library, or a partial subtree) has
// no in-tree convention to assume — its edge IS an external ABI. So an exported
// function's pointer parameter, and a field value read off it, are fail-open
// even when the type layout is fully visible. The app-mode counterpart (same
// layout, `main` present) stays closed: TestOpaqueNullDetectorHeaderDefinedTypeIsNotOpaque.
func TestBoundaryScanExportedAPIIsFailOpen(t *testing.T) {
	records := runOpaqueNullDetect(t, map[string]string{
		"api.h": `typedef struct ApiCtx_s {
    unsigned int len;
    void *group_data;
} ApiCtx_t;

typedef struct ApiNode_s {
    char name[32];
} ApiNode_t;
`,
		"api.c": `#include "api.h"

int api_len(ApiCtx_t *ac_ctx)
{
    return ac_ctx->len;
}

int api_tree(ApiCtx_t *at_ctx)
{
    ApiNode_t *at_tree = (ApiNode_t *)(at_ctx->group_data);
    return at_tree[0].name[0];
}
`,
	})
	has := func(variable, origin string) bool {
		for _, r := range records {
			if r.variable == variable && r.origin == origin {
				return true
			}
		}
		return false
	}
	if !has("ac_ctx", "caller_null") {
		t.Errorf("boundary scan: the exported API parameter must be an open entry; got %v", records)
	}
	if !has("at_tree", "opaque_field_read") {
		t.Errorf("boundary scan: the field value read off an exported API parameter must seed; got %v", records)
	}
}

// A count-gated array buffer: `tree = (T *)(resp->group_data)` where a same-file
// sibling reads `resp->group_num` (the count/length field the buffer's validity
// depends on). The detector must label the source with the paired count field so
// the null-deref filter can emit the array-buffer@<count-field> tier instead of
// the flat opaque-origin tier — the reported real null-deref's exact shape.
func TestOpaqueNullDetectorArrayBufferCountField(t *testing.T) {
	paired := runOpaqueNullDetect(t, map[string]string{"paired.c": `int import_dn_group_tree_refresh(
    Nac_LdapSearchAckMsg_t *resp, import_para_ext_t *para)
{
    ldap_usrgroup_node_t *tree =
        (ldap_usrgroup_node_t *)(resp->group_data);
    return tree[0].group_name[0];
}

int import_usrgroup_proc(Nac_LdapSearchAckMsg_t *resp, import_para_ext_t *para)
{
    if (resp->group_num == 0) {
        return 0;
    }
    return import_dn_group_tree_refresh(resp, para);
}
`})
	found := false
	for _, r := range paired {
		if r.variable != "tree" {
			continue
		}
		found = true
		if r.countField != "resp->group_num" {
			t.Errorf("tree source count_field = %q, want resp->group_num; records %+v", r.countField, paired)
		}
	}
	if !found {
		t.Errorf("tree = (T *)(resp->group_data) must seed an opaque_field_read source; got %+v", paired)
	}

	// Negative control: the same pointer field with NO count field in scope must
	// carry no count_field (the name pairing must not fire on a bare data field).
	unpaired := runOpaqueNullDetect(t, map[string]string{"unpaired.c": `int solo_refresh(Nac_LdapSearchAckMsg_t *resp)
{
    ldap_usrgroup_node_t *tree =
        (ldap_usrgroup_node_t *)(resp->group_data);
    return tree[0].group_name[0];
}
`})
	for _, r := range unpaired {
		if r.variable == "tree" && r.countField != "" {
			t.Errorf("no count field in scope: tree count_field must be empty, got %q", r.countField)
		}
	}
}
