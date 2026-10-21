//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// planNullDerefFieldCast runs the null-deref pipeline for a fixture whose key
// shape is `p = (T*)(param->field); p[0]` — a pointer derived from a field read
// of a pointer parameter. It includes the CallerNullDetector so the caller-
// null source is seeded. It returns the surviving candidate variable names for
// the given function.
func planNullDerefFieldCast(t *testing.T, src, fn string) []string {
	t.Helper()
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	dir := t.TempDir()
	path := filepath.Join(dir, "fieldcast.c")
	if err := os.WriteFile(path, []byte(src), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, path); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	evidence.NewNullSourceDetector(store, p, logger).Detect(ctx)
	evidence.NewDereferenceDetector(store, p, logger).Detect(ctx)
	evidence.NewNullGuardDetector(store, p, logger).Detect(ctx)
	evidence.NewCallerNullDetector(store, p, logger).Detect(ctx)

	pl := NewPlanner(store, p, logger)
	result, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var vars []string
	for _, c := range result.Candidates {
		if c.Target.Function == fn {
			vars = append(vars, c.Target.Variable)
		}
	}
	return vars
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// TestNullDeref_FieldCastDerivedPointer pins the production false negative: a
// pointer derived by casting a pointer-parameter's field
// (`tree = (T*)(resp->group_data)`) and then dereferenced (`tree[0]`) has no
// null source today, so the `tree[0]` dereference is silently dropped. The
// field value is independently nullable (the builder may leave it NULL), so the
// dereference of the derived pointer `tree` must surface for the AI to judge.
func TestNullDeref_FieldCastDerivedPointer(t *testing.T) {
	// The issue's exact form: the ACK typedef is a FORWARD DECLARATION (the
	// third-party layout never appears in the scan tree), so the entry is an
	// open one and the field value is an opaque read.
	src := `typedef struct Nac_LdapSearchAckMsg_struct Nac_LdapSearchAckMsg_t;

typedef struct {
    char group_name[64];
} idm_ldap_usrgroup_node_t;

int idm_import_dn_group_tree_refresh(Nac_LdapSearchAckMsg_t *resp) {
    idm_ldap_usrgroup_node_t *tree = (idm_ldap_usrgroup_node_t *)(resp->group_data);
    return tree[0].group_name[0];
}

void idm_import_usrgroup_proc(Nac_LdapSearchAckMsg_t *resp) {
    idm_import_dn_group_tree_refresh(resp);
}
`
	vars := planNullDerefFieldCast(t, src, "idm_import_dn_group_tree_refresh")
	if !containsStr(vars, "tree") {
		t.Errorf("derived pointer `tree` dereference (tree[0]) was missed; candidates=%v", vars)
	}
}

// TestNullDeref_FieldCastDerivedPointer_DefiniteNull pins the definite-null
// flavour: the caller passes a literal NULL, so the derived pointer dereference
// must surface even though the direct `resp->group_data` read also surfaces.
func TestNullDeref_FieldCastDerivedPointer_DefiniteNull(t *testing.T) {
	src := `typedef struct {
    unsigned char *group_data;
} Nac_LdapSearchAckMsg_t;

typedef struct {
    char group_name[64];
} idm_ldap_usrgroup_node_t;

int idm_import_dn_group_tree_refresh(Nac_LdapSearchAckMsg_t *resp) {
    idm_ldap_usrgroup_node_t *tree = (idm_ldap_usrgroup_node_t *)(resp->group_data);
    return tree[0].group_name[0];
}

void idm_import_usrgroup_proc(void) {
    idm_import_dn_group_tree_refresh(NULL);
}
`
	vars := planNullDerefFieldCast(t, src, "idm_import_dn_group_tree_refresh")
	if !containsStr(vars, "tree") {
		t.Errorf("derived pointer `tree` dereference (tree[0]) from a NULL param was missed; candidates=%v", vars)
	}
}

// TestNullDeref_FieldCastDerivedPointer_OpaqueStruct pins the external/opaque
// struct flavour: the field's struct type is forward-declared (unindexed), so
// only the cast-to-pointer and the base's nullability are visible — the derived
// pointer dereference must still surface.
func TestNullDeref_FieldCastDerivedPointer_OpaqueStruct(t *testing.T) {
	src := `typedef struct Nac_LdapSearchAckMsg Nac_LdapSearchAckMsg_t;

typedef struct {
    char group_name[64];
} idm_ldap_usrgroup_node_t;

int idm_import_dn_group_tree_refresh(Nac_LdapSearchAckMsg_t *resp) {
    idm_ldap_usrgroup_node_t *tree = (idm_ldap_usrgroup_node_t *)(resp->group_data);
    return tree[0].group_name[0];
}

void idm_import_usrgroup_proc(Nac_LdapSearchAckMsg_t *resp) {
    idm_import_dn_group_tree_refresh(resp);
}
`
	vars := planNullDerefFieldCast(t, src, "idm_import_dn_group_tree_refresh")
	if !containsStr(vars, "tree") {
		t.Errorf("derived pointer `tree` dereference (tree[0]) from an opaque struct field was missed; candidates=%v", vars)
	}
}

// TestNullDeref_FieldCastDerivedPointer_Guarded pins the precision side: a null
// guard on the derived pointer before the dereference must suppress it.
func TestNullDeref_FieldCastDerivedPointer_Guarded(t *testing.T) {
	src := `typedef struct {
    unsigned char *group_data;
} Nac_LdapSearchAckMsg_t;

typedef struct {
    char group_name[64];
} idm_ldap_usrgroup_node_t;

int idm_import_dn_group_tree_refresh(Nac_LdapSearchAckMsg_t *resp) {
    idm_ldap_usrgroup_node_t *tree = (idm_ldap_usrgroup_node_t *)(resp->group_data);
    if (tree == NULL) return -1;
    return tree[0].group_name[0];
}

void idm_import_usrgroup_proc(Nac_LdapSearchAckMsg_t *resp) {
    idm_import_dn_group_tree_refresh(resp);
}
`
	vars := planNullDerefFieldCast(t, src, "idm_import_dn_group_tree_refresh")
	if containsStr(vars, "tree") {
		t.Errorf("guarded derived pointer `tree` must NOT surface; candidates=%v", vars)
	}
}
