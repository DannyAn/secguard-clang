//go:build !nosqlite

package planner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// The single_linkedlist.h / SINGLE_LINKEDLIST_Scan pattern: a function-like
// macro whose THIRD argument is a TYPE cast (`SINGLE_LINKEDLIST_Scan(list, iter,
// type *)`). A type is not a valid expression, so tree-sitter recovers the whole
// call + its loop body as an ERROR node instead of a call_expression — which is
// why the iterator-macro kill historically never fired for it (config-declared
// or in-tree). The fix models the ERROR node as a loop and recovers the macro
// name + args from it.

const sllIterHeader = `#ifndef __SINGLE_LINKEDLIST_H__
#define __SINGLE_LINKEDLIST_H__

typedef unsigned int UINT32;
typedef unsigned long UINTPTR;

typedef struct SINGLE_LINKEDLIST_NODE {
    struct SINGLE_LINKEDLIST_NODE *pNext;
    UINTPTR uiHandle;
} SINGLE_LINKEDLIST_NODE_S;

typedef struct SLL {
    SINGLE_LINKEDLIST_NODE_S Head;
    SINGLE_LINKEDLIST_NODE_S *Tail;
    UINT32 uiCount;
} SINGLE_LINKEDLIST_S;

#define SINGLE_LINKEDLIST_Count(pList) ((pList)->uiCount)
#define SINGLE_LINKEDLIST_First(pList) ((0 == SINGLE_LINKEDLIST_Count((pList))) ? NULL : (pList)->Head.pNext)
#define SINGLE_LINKEDLIST_Next(pList, pNode) \
    ((NULL == (pNode)) ? SINGLE_LINKEDLIST_First(pList) : (((pNode)->pNext == &(pList)->Head) ? NULL : (pNode)->pNext))

#define SINGLE_LINKEDLIST_Scan(pList, pNode, TypeCast)                        \
    for ((pNode) = (TypeCast)(SINGLE_LINKEDLIST_First((pList))); (pNode) != NULL; \
         pNode = (TypeCast)SINGLE_LINKEDLIST_Next((pList), ((SINGLE_LINKEDLIST_NODE_S *)(pNode))))

#endif
`

const sllIterUsageSrc = `#include "single_linkedlist.h"

typedef struct {
    UINT32 ulHandle;
} dslite_car_t;

typedef struct {
    dslite_car_t dslite_car;
} dslite_car_policy_t;

#define NAT_OK 0

int dslite_add_node(SINGLE_LINKEDLIST_S *sll, UINT32 acl_group_id, UINT32 car_data)
{
    dslite_car_policy_t *car_policy = NULL;
    SINGLE_LINKEDLIST_Scan(sll, car_policy, dslite_car_policy_t *) {
        if (acl_group_id == car_policy->dslite_car.ulHandle) {
            return NAT_OK;
        }
    }
    return 0;
}

int real_bug(SINGLE_LINKEDLIST_S *sll)
{
    dslite_car_policy_t *car_policy = NULL;
    if (car_policy->dslite_car.ulHandle) {
        return 1;
    }
    return 0;
}
`

// TestNullDeref_IterMacroTypeCastInTree: SINGLE_LINKEDLIST_Scan is DEFINED in the
// scan tree (header). The cross-file merged macro write-summary must recognize
// it writes arg 1 and kill car_policy's null source at the call site, even
// though the call parses as an ERROR node.
func TestNullDeref_IterMacroTypeCastInTree(t *testing.T) {
	result := planNullDerefMacroFiles(t, map[string]string{
		"single_linkedlist.h": sllIterHeader,
		"sll_usage.c":         sllIterUsageSrc,
	})
	if c := candidateForFunc(t, result, "dslite_add_node"); c != nil {
		t.Errorf("dslite_add_node should NOT be flagged (in-tree SINGLE_LINKEDLIST_Scan writes arg 1), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_bug"); c == nil {
		t.Errorf("real_bug must still be flagged (control)")
	}
}

// TestNullDeref_IterMacroTypeCastConfigDeclared: SINGLE_LINKEDLIST_Scan is NOT
// defined in the scan tree (SDK header), so the user declares it in
// secguard.toml [iterator_macros.macros] with iterator arg index 1. The
// config-declared kill must suppress the false positive for the ERROR-node call.
func TestNullDeref_IterMacroTypeCastConfigDeclared(t *testing.T) {
	dir := t.TempDir()
	tomlPath := filepath.Join(dir, "secguard.toml")
	tomlContent := `[iterator_macros.macros]
SINGLE_LINKEDLIST_Scan = [1]
`
	if err := os.WriteFile(tomlPath, []byte(tomlContent), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath(tomlPath)
	t.Cleanup(func() { config.SetExplicitPath("") })

	src := `typedef unsigned int UINT32;
typedef unsigned long UINTPTR;

typedef struct SINGLE_LINKEDLIST_NODE {
    struct SINGLE_LINKEDLIST_NODE *pNext;
    UINTPTR uiHandle;
} SINGLE_LINKEDLIST_NODE_S;

typedef struct SLL {
    SINGLE_LINKEDLIST_NODE_S Head;
    SINGLE_LINKEDLIST_NODE_S *Tail;
    UINT32 uiCount;
} SINGLE_LINKEDLIST_S;

typedef struct { UINT32 ulHandle; } dslite_car_t;
typedef struct { dslite_car_t dslite_car; } dslite_car_policy_t;

#define NAT_OK 0

int dslite_add_node(SINGLE_LINKEDLIST_S *sll, UINT32 acl_group_id, UINT32 car_data)
{
    dslite_car_policy_t *car_policy = NULL;
    SINGLE_LINKEDLIST_Scan(sll, car_policy, dslite_car_policy_t *) {
        if (acl_group_id == car_policy->dslite_car.ulHandle) {
            return NAT_OK;
        }
    }
    return 0;
}

int real_bug(SINGLE_LINKEDLIST_S *sll)
{
    dslite_car_policy_t *car_policy = NULL;
    if (car_policy->dslite_car.ulHandle) {
        return 1;
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "dslite_add_node"); c != nil {
		t.Errorf("dslite_add_node should NOT be flagged (config declares SINGLE_LINKEDLIST_Scan iterator arg 1), got var=%s level=%s line=%d", c.Target.Variable, c.SuspicionLevel, c.Target.Line)
	}
	if c := candidateForFunc(t, result, "real_bug"); c == nil {
		t.Errorf("real_bug must still be flagged (control)")
	}
}

// TestNullDeref_IterMacroTypeCastUnconfigured: without the iterator-macro
// declaration, the dereference inside the unknown macro body is reported — the
// macro is opaque to the pipeline, so a NULL assigned before it is a genuine
// (if conservative) finding. This pins that the loop-body dereference is now
// actually modelled (it was previously invisible because the ERROR node was
// skipped by the CFG).
func TestNullDeref_IterMacroTypeCastUnconfigured(t *testing.T) {
	src := `typedef unsigned int UINT32;
typedef struct SLL { int Head; } SLL_S;
typedef struct { UINT32 ulHandle; } dslite_car_t;
typedef struct { dslite_car_t dslite_car; } dslite_car_policy_t;

int dslite_add_node(SLL_S *sll, UINT32 acl_group_id)
{
    dslite_car_policy_t *car_policy = NULL;
    SINGLE_LINKEDLIST_Scan(sll, car_policy, dslite_car_policy_t *) {
        if (acl_group_id == car_policy->dslite_car.ulHandle) {
            return 1;
        }
    }
    return 0;
}
`
	result := planNullDerefMacro(t, src)
	if c := candidateForFunc(t, result, "dslite_add_node"); c == nil {
		t.Errorf("dslite_add_node should be flagged when the macro is unconfigured (deref is modelled), got: %s", candidateNames(result))
	}
}
