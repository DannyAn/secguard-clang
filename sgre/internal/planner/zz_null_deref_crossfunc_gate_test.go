//go:build !nosqlite

package planner

import "testing"

// Production (NAT #6/#7/#9) reported null-deref false positives where the NULL
// guard sits in a CHECK callee and the caller gates on that callee's status.
// The helper-guard contract ("a null parameter implies a non-zero return") only
// matched the literal `!= 0` spelling of a DIRECT call, so real code missed it
// in three ways: the success code is a SYMBOL (`NAT_OK`, `STMP_OK`), the status
// is first stored in a variable, and the callee's null test is OR-embedded in
// a larger condition. All three are modelled now.
//
// Every sub-case pairs a "proof" shape with a control that must STAY reported,
// so the extension cannot degenerate into "a check happened somewhere".
const crossFuncGatePreamble = `typedef struct { unsigned int id; unsigned int vsys_id; } capture_t;
extern capture_t *pool_read_capture(unsigned int idx);

#define NAT_OK 0
#define NAT_ERR 1
#define STMP_OK 0
#define STMP_CFG_INFO_CFG_NOT_EXIST 7
`

func TestNullDeref_CrossFunctionGate(t *testing.T) {
	src := crossFuncGatePreamble + `
/* check callee: NULL implies the error return */
int prepare_allocate(capture_t *group, unsigned int pool_id)
{
    if (!group) {
        return NAT_ERR;
    }
    (void)pool_id;
    return NAT_OK;
}

/* the #6/#7 shape: direct call gated on the SUCCESS symbol */
unsigned int nopat_proc(unsigned int idx)
{
    capture_t *group = pool_read_capture(idx);
    if (prepare_allocate(group, idx) != NAT_OK) {
        return 0;
    }
    return group->id;
}

/* check callee with an OR-embedded null test (the #9 shape) */
int del_pool_check(unsigned int vsys_id, capture_t *pool)
{
    if (pool == NULL || pool->vsys_id != vsys_id) {
        return STMP_CFG_INFO_CFG_NOT_EXIST;
    }
    return STMP_OK;
}

/* the #9 shape: status stored first, then gated on the SUCCESS symbol */
unsigned int del_pool(unsigned int vsys_id, unsigned int idx)
{
    capture_t *pool = pool_read_capture(idx);
    int ret = del_pool_check(vsys_id, pool);
    if (ret != STMP_OK) {
        return 0;
    }
    return pool->id;
}

/* CONTROL: the result is ignored, so nothing is proven */
unsigned int ignore_result(unsigned int idx)
{
    capture_t *group = pool_read_capture(idx);
    (void)prepare_allocate(group, idx);
    return group->id;
}

/* CONTROL: gating on a NON-success constant proves nothing */
unsigned int wrong_gate(unsigned int idx)
{
    capture_t *group = pool_read_capture(idx);
    if (prepare_allocate(group, idx) != NAT_ERR) {
        return 0;
    }
    return group->id;
}

/* CONTROL: the callee does not check its parameter */
int prepare_unchecked(capture_t *group)
{
    return (int)group->id;
}

unsigned int unchecked_callee(unsigned int idx)
{
    capture_t *group = pool_read_capture(idx);
    if (prepare_unchecked(group) != NAT_OK) {
        return 0;
    }
    return group->id;
}
`
	res := planNullDerefFullSrc(t, src)
	byFunc := map[string]string{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c.Target.Variable
	}
	for _, exempt := range []string{"nopat_proc", "del_pool"} {
		if v, ok := byFunc[exempt]; ok {
			t.Errorf("%s: the check callee proves %s non-null on the surviving path; must not be a candidate", exempt, v)
		}
	}
	for _, flagged := range []string{"ignore_result", "wrong_gate", "unchecked_callee"} {
		if _, ok := byFunc[flagged]; !ok {
			t.Errorf("%s: the gate does not prove the pointer non-null; must stay a candidate (got %v)", flagged, byFunc)
		}
	}
}

// Evidence embedding for the "branch premise excludes the callee's NULL
// condition" class (NAT #8): the candidate must carry the callee's NULL-return
// condition as a retnull-cond@ fact, so the AI compares it against the
// enclosing branch instead of re-deriving the state machine.
func TestNullDeref_CalleeNullConditionEmbedded(t *testing.T) {
	src := `#define POOL_SECT_NODE_INVALID 0xFFFFu

typedef struct { unsigned int head_next; } pool_sect_t;
typedef struct { unsigned int sect_head; } pool_group_t;

extern pool_sect_t *pool_sect_by_id(unsigned int id);
extern pool_sect_t *find_insert_sect(pool_group_t *group, unsigned int insertid);

static pool_sect_t *pool_last_sect(const pool_group_t *group)
{
    if (group->sect_head == POOL_SECT_NODE_INVALID) {
        return NULL;
    }
    return pool_sect_by_id(group->sect_head);
}

void insert_sect(pool_group_t *group, unsigned int node_id)
{
    if (group->sect_head == POOL_SECT_NODE_INVALID) {
        group->sect_head = node_id;
    } else {
        pool_sect_t *node = find_insert_sect(group, node_id);
        if (node == NULL) {
            node = pool_last_sect(group);
            group->sect_head = node_id;
        }
        pool_sect_by_id(node->head_next)->head_next = node_id;
    }
}
`
	res := planNullDerefFullSrc(t, src)
	found := false
	for _, c := range res.Candidates {
		if c.Target.Variable == "node" {
			found = true
			if c.CalleeNullCondition != "group->sect_head==POOL_SECT_NODE_INVALID" {
				t.Errorf("node: CalleeNullCondition = %q, want group->sect_head==POOL_SECT_NODE_INVALID", c.CalleeNullCondition)
			}
		}
	}
	if !found {
		t.Fatalf("expected a candidate for `node` (pool_last_sect result), got %v", candidateNames(res))
	}
}
