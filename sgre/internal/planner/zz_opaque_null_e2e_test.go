//go:build !nosqlite

package planner

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"

	"context"
	"os"
	"path/filepath"
)

// Opaque-type null-source end-to-end: a function whose parameter typedefs are
// not defined in the scan tree must get null-deref candidates for its three
// report-mandated positions (the parameter dereference, the assigned
// field-read pointer, the chained intermediate), all suspected with the
// opaque-origin tier. Guarded and non-null-reassigned shapes must stay
// dismissed (the guard model and the non-null kills apply to the fail-open
// sources exactly as to any other source).
const opaqueE2EReportFixture = `int import_dn_group_tree_refresh(
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

const opaqueE2EControlFixture = `int guarded_handler(ExtMsg_t *gh_msg)
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

void reassign_safe(ExtMsg_t *rs_m)
{
    Other_t o;
    Other_t *p = rs_m->hdr;
    p = &o;
    p->len = 1;
}
`

func runOpaqueNullPlan(t *testing.T, files map[string]string) *PlanResult {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(os.NewFile(0, os.DevNull), log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	var paths []string
	for name, src := range files {
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
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewCallerNullDetector(store, p, logger).Detect(ctx)
	evidence.NewOpaqueNullDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	return result
}

func TestOpaqueNullEndToEndReportForm(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{"report.c": opaqueE2EReportFixture})
	byVar := map[string]EvidenceItem{}
	for _, c := range r.Candidates {
		byVar[c.Target.Variable] = c
	}
	for _, variable := range []string{"resp", "para", "para->orig", "tree"} {
		c, ok := byVar[variable]
		if !ok {
			t.Fatalf("missing null-deref candidate for %s; got %d candidates", variable, len(r.Candidates))
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("variable %s: suspicion = %s, want suspected (a fail-open source must never auto-confirm)", variable, c.SuspicionLevel)
		}
	}
	// The isolated form has zero in-tree callers: resp/para come from the
	// caller_null open-entry base (caller-arg tier), the field-read positions
	// keep the opaque-origin tier.
	for _, variable := range []string{"resp", "para"} {
		if c := byVar[variable]; c.NullOriginTier != "caller-arg" {
			t.Errorf("variable %s: tier = %s, want caller-arg (open-entry base)", variable, c.NullOriginTier)
		}
	}
	for _, variable := range []string{"para->orig", "tree"} {
		if c := byVar[variable]; c.NullOriginTier != "opaque-origin" {
			t.Errorf("variable %s: tier = %s, want opaque-origin", variable, c.NullOriginTier)
		}
	}
}

func TestOpaqueNullEndToEndControls(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{"controls.c": opaqueE2EControlFixture})
	has := func(variable string) bool {
		for _, c := range r.Candidates {
			if c.Target.Variable == variable {
				return true
			}
		}
		return false
	}
	// An early-return null guard kills the fail-open parameter source.
	if has("gh_msg") {
		t.Errorf("guarded_handler: a guarded parameter must not surface a candidate")
	}
	// A null check on the intermediate field value kills the chained source.
	if has("gc_m->sub") {
		t.Errorf("guarded_chain: gc_m->sub is null-checked before the dereference; must not surface")
	}
	// The parameter itself is still unguarded (gc_m->sub READS gc_m), so the
	// parameter-level candidate must surface.
	if !has("gc_m") {
		t.Errorf("guarded_chain: gc_m itself is unguarded; the parameter candidate must surface")
	}
	// A non-null reassignment (&o) kills the assigned field-read source.
	if has("p") {
		t.Errorf("reassign_safe: p is reassigned &o before the dereference; must not surface")
	}
	if !has("rs_m") {
		t.Errorf("reassign_safe: rs_m itself is unguarded; the parameter candidate must surface")
	}
}

// The production shape this round closed: the report form's function HAS an
// in-tree caller forwarding its own unproven opaque parameters. Before the
// in-tree-caller channel, the parameters' only source was a non-definite
// caller_null, which the planner's onlyUnprovenCallerNullSources dismissal
// dropped as an "analyzer limitation" — the parameter positions went dark
// exactly when the function had callers. The added opaque_param seed must
// keep them as suspected candidates (caller-arg tier: the unproven caller is
// now a concrete, named fact), while a guarded caller and a tree-defined
// forwarded type stay dismissed (the volume guard).
func TestOpaqueNullEndToEndInTreeCaller(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{
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
		"controls.c": `typedef struct KnownRec {
    unsigned int len;
} KnownRec_t;

int opaque_unguarded(ExtMsg_t *m2)
{
    return m2->len;
}

int guarded_caller(ExtMsg_t *g2)
{
    if (g2 == NULL) {
        return -1;
    }
    return opaque_unguarded(g2);
}

int tree_typed_target(KnownRec_t *k2)
{
    return k2->len;
}

int tree_typed_caller(KnownRec_t *k2f)
{
    return tree_typed_target(k2f);
}
`,
	})
	byVar := map[string]EvidenceItem{}
	for _, c := range r.Candidates {
		byVar[c.Target.Variable] = c
	}
	for _, variable := range []string{"resp", "para", "para->orig", "tree"} {
		c, ok := byVar[variable]
		if !ok {
			t.Fatalf("missing null-deref candidate for %s (in-tree caller form); got %d candidates: %v", variable, len(r.Candidates), byVar)
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("variable %s: suspicion = %s, want suspected", variable, c.SuspicionLevel)
		}
	}
	// resp/para resolve through the caller-arg tier (the open entry
	// import_dn_group_tree forwards them); the field-read positions keep the
	// opaque-origin tier.
	for _, variable := range []string{"resp", "para"} {
		if c := byVar[variable]; c.NullOriginTier != "caller-arg" {
			t.Errorf("variable %s: tier = %s, want caller-arg", variable, c.NullOriginTier)
		}
	}
	for _, variable := range []string{"para->orig", "tree"} {
		if c := byVar[variable]; c.NullOriginTier != "opaque-origin" {
			t.Errorf("variable %s: tier = %s, want opaque-origin", variable, c.NullOriginTier)
		}
	}

	// Volume guards — the soul-searching answer: a guarded caller proves the
	// argument non-null, closing its edge; the tree-defined forward shape
	// (tree_typed_caller has zero in-tree callers, but KnownRec_t is defined
	// in-tree) also stays closed — the type gate keeps the v0.9.4 contract
	// while the opaque-typed open entry surfaces.
	for _, variable := range []string{"m2", "k2"} {
		if _, ok := byVar[variable]; ok {
			t.Errorf("variable %s must not surface (guarded caller / tree-defined type entry)", variable)
		}
	}
}

// The production soul-searching case: EVERY call site of a function guards
// its argument (the guard may sit at ANY link of the forwarding chain — the C
// convention "guard once at the outer entry, inner functions assume non-null
// by contract"). The open-chain fixpoint must keep such parameters closed —
// no candidate at all — while an identically-shaped UNguarded chain surfaces.
// This is the candidate-volume contract whose violation flooded a production
// scan with 1264 null-deref candidates (every forwarded "unproven" argument
// had been seeded fail-open).
func TestOpaqueNullEndToEndAllCallersGuarded(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{"soul.c": `typedef struct KnownRec {
    unsigned int len;
} KnownRec_t;

int inner_guarded_user(KnownRec_t *k)
{
    return k->len;
}

int middle_forwarder(KnownRec_t *mk)
{
    return inner_guarded_user(mk);
}

int outer_entry(KnownRec_t *ok)
{
    if (ok == NULL) {
        return -1;
    }
    return middle_forwarder(ok);
}

int opaque_inner(ExtMsg_t *m)
{
    return m->len;
}

int opaque_middle(ExtMsg_t *om)
{
    return opaque_inner(om);
}

int opaque_entry(ExtMsg_t *oe)
{
    if (oe == NULL) {
        return -1;
    }
    return opaque_middle(oe);
}

int open_entry(ExtMsg_t *pe)
{
    return opaque_inner(pe);
}
`})
	byVar := map[string]EvidenceItem{}
	for _, c := range r.Candidates {
		byVar[c.Target.Variable] = c
	}
	// The guarded chains (outer_entry → middle_forwarder → inner_guarded_user
	// and opaque_entry → opaque_middle) must stay completely dark: the guard
	// at the chain's root closes every forwarded parameter below it.
	for _, variable := range []string{"k", "mk", "ok", "om", "oe"} {
		if _, ok := byVar[variable]; ok {
			t.Errorf("variable %s must not surface (its whole forwarding chain is guarded at the entry)", variable)
		}
	}
	// The unguarded chain (open_entry → opaque_inner) is the true-positive
	// direction: an unguarded entry's value reaches a dereference.
	c, ok := byVar["m"]
	if !ok {
		t.Fatalf("variable m must surface through the unguarded open_entry chain; got %v", byVar)
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("variable m: suspicion = %s, want suspected (open chain, no witness)", c.SuspicionLevel)
	}
	if c.NullOriginTier != "caller-arg" {
		t.Errorf("variable m: tier = %s, want caller-arg", c.NullOriginTier)
	}
	// The pure forwarder's own parameter (pe) has no dereference sink in
	// open_entry, so it must not surface either.
	if _, ok := byVar["pe"]; ok {
		t.Errorf("variable pe must not surface (no sink in open_entry)")
	}
}

// A type whose layout is defined in a FUNCTION-LESS header is fully visible to
// the scan tree — and that is where a real C project keeps its type layouts.
// The opaque fail-open channels must stay silent for it (a header type is not
// an "unknown external contract"), while the identical shape over a typedef
// absent from the tree still surfaces. Before the census visited every indexed
// file, the header was skipped (no function in it), the type read as opaque,
// and the in-tree-type false-positive class opened for every project struct.
func TestOpaqueNullEndToEndHeaderDefinedType(t *testing.T) {
	r := runOpaqueNullPlan(t, map[string]string{
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
`,
	})
	byVar := map[string]EvidenceItem{}
	for _, c := range r.Candidates {
		byVar[c.Target.Variable] = c
	}
	for _, variable := range []string{"ek_tree", "ek_resp"} {
		if _, ok := byVar[variable]; ok {
			t.Errorf("variable %s: ext.h defines its type, so no opaque candidate may surface; got %+v", variable, byVar[variable])
		}
	}
	c, ok := byVar["uo_tree"]
	if !ok {
		t.Fatalf("the undefined-type counterpart must still surface uo_tree; got %v", byVar)
	}
	if c.NullOriginTier != "opaque-origin" {
		t.Errorf("uo_tree: tier = %s, want opaque-origin", c.NullOriginTier)
	}
	if c.SuspicionLevel != "suspected" {
		t.Errorf("uo_tree: suspicion = %s, want suspected (fail-open never auto-confirms)", c.SuspicionLevel)
	}
}
