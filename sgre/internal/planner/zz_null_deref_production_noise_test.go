//go:build !nosqlite

package planner

import "testing"

// 第三轮 NAT 生产复核（sc_2026-10-26_094012_1b2a50）的三类 null-deref 噪声根因：
//
//	§2.3-3 / 特征 G  成员链的 `.` 步被当成指针解引用（同一根指针一条语句出 3 条候选，
//	                 其中 2 条的"变量"是 struct 值成员，fix 建议 `if (p->fc == NULL)`
//	                 根本无法编译）
//	特征 D            `node = node->next` 自指更新产生的新 null 源被算作"到达"同一条
//	                 语句里的解引用 —— 赋值右侧读的是旧值，新源只能向后流
//	§7               cfg-proof 与 macro-context 并存：CFG 不展开函数宏，
//	                 `SLL_Scan(sll, car_policy, ...)` 会在循环头给迭代变量赋值，
//	                 "p = NULL 后无重新赋值"在该场景下是伪证明
//
// 每条都配真实缺陷控制函数，防止过度压制。

// A `.` step selects a struct VALUE member — it never dereferences a pointer, so
// it can never be NULL. Only the `->` steps of the chain (each dereferencing a
// distinct pointer) are candidates.
func TestNullDeref_ValueMemberChainIsNotADeref(t *testing.T) {
	src := `typedef struct { unsigned int is_fullcone; } fc_flag_t;
typedef struct { fc_flag_t fullcone_flag; unsigned int vsys; } fc_info_t;
typedef struct { fc_info_t fc; unsigned int user_id; } portrng_userdata_t;

int portrng_set_fullcone(portrng_userdata_t *user_data)
{
    user_data->fc.fullcone_flag.is_fullcone = 1;
    user_data->fc.vsys = 2;
    user_data->user_id = 3;
    return 0;
}

typedef struct { int v; } b_t;
typedef struct { b_t *b; } a_t;
typedef struct { a_t *a; } p_t;

int walk_pointer_chain(p_t *p)
{
    return p->a->b->v;
}
`
	res := planNullDerefFullSrc(t, src)
	vars := map[string]bool{}
	for _, c := range res.Candidates {
		vars[c.Target.Variable] = true
	}
	// One candidate per POINTER dereference of the value-member chain: only the
	// root `user_data` (the sole `->`).
	for _, bad := range []string{"user_data->fc", "user_data->fc.fullcone_flag", "user_data->fc.vsys", "user_data->user_id"} {
		if vars[bad] {
			t.Errorf("%q selects a struct value member and must not be a candidate (got %v)", bad, vars)
		}
	}
	if !vars["user_data"] {
		t.Errorf("the root pointer deref (user_data) must still be a boundary candidate (got %v)", vars)
	}
	// Control: a genuine pointer chain keeps one candidate per `->` hop.
	for _, want := range []string{"p", "p->a", "p->a->b"} {
		if !vars[want] {
			t.Errorf("pointer chain p->a->b->v: missing candidate for %q (got %v)", want, vars)
		}
	}
}

// A self-referential field-read update (`node = node->next`) reads the OLD value
// on its right-hand side and only then overwrites it, so the new source cannot
// reach the dereference inside that same statement — the loop condition already
// guarantees `node` is non-null there.
func TestNullDeref_IteratorSelfUpdateIsNotItsOwnSink(t *testing.T) {
	src := `typedef struct node { int v; struct node *next; } node_t;

void walk(node_t *head)
{
    node_t *node = head;
    while (node) {
        node->v = 1;
        node = node->next;
    }
}

void walk_for(node_t *head)
{
    node_t *it = head;
    for (; it != NULL; it = it->next) {
        it->v = 2;
    }
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		if c.Target.Variable == "node" || c.Target.Variable == "it" {
			t.Errorf("%s: the guard-protected iterator update must not surface as a null-deref (var=%s line=%d hint=%v)",
				c.Target.Function, c.Target.Variable, c.Target.Line, c.Hint)
		}
	}
}

// The same source MUST still fire on a use AFTER the advance: that dereference
// happens in a later statement, where the loop condition no longer protects it.
func TestNullDeref_PostAdvanceUseStillFlagged(t *testing.T) {
	src := `typedef struct node { int v; struct node *next; } node_t;

void after_advance(node_t *head)
{
    node_t *node = head;
    while (node) {
        node = node->next;
        node->v = 1;
    }
}
`
	res := planNullDerefFullSrc(t, src)
	found := false
	for _, c := range res.Candidates {
		if c.Target.Variable == "node" {
			found = true
		}
	}
	if !found {
		t.Fatalf("post-advance dereference of the iterator is a real null-deref and must stay flagged, got %v", candidateNames(res))
	}
}

// A CFG proof assumes no macro rewrites the variable, but the CFG does not
// expand function-like macros. When a macro in the same statement region NAMES
// the variable, the proof is unverifiable and the candidate must not be
// presented as machine-proved.
func TestNullDeref_CfgProofMacroContextDemoted(t *testing.T) {
	src := `#define LOG_PTR(x) do { (void)(x); } while (0)

typedef struct node { int v; } node_t;

int plain_cfg_proof(void)
{
    node_t *q = NULL;
    q->v = 2;
    return 0;
}

int macro_cfg_proof(void)
{
    node_t *p = NULL;
    LOG_PTR(p);
    p->v = 1;
    return 0;
}
`
	res := planNullDerefFullSrc(t, src)
	byFunc := map[string]EvidenceItem{}
	for _, c := range res.Candidates {
		byFunc[c.Target.Function] = c
	}
	plain, ok := byFunc["plain_cfg_proof"]
	if !ok {
		t.Fatalf("plain_cfg_proof (no macro) must stay a candidate, got %v", candidateNames(res))
	}
	if plain.SuspicionLevel != "confirmed" {
		t.Errorf("plain_cfg_proof: suspicion = %q, want confirmed (its CFG proof is unaffected)", plain.SuspicionLevel)
	}
	macro, ok := byFunc["macro_cfg_proof"]
	if !ok {
		t.Fatalf("macro_cfg_proof must stay a candidate (demoted, not dropped), got %v", candidateNames(res))
	}
	if macro.SuspicionLevel != "suspected" {
		t.Errorf("macro_cfg_proof: suspicion = %q, want suspected (LOG_PTR names p; the CFG proof cannot expand it)", macro.SuspicionLevel)
	}
	if !macro.MacroContext {
		t.Errorf("macro_cfg_proof: MacroContext = false, want true so the classifier verifies the macro contract")
	}
}

// The macro-context window must not leak across a function boundary: a macro
// call in a NEIGHBOURING function never touches this function's variable, so a
// valid CFG proof there is not demoted (and the "no concrete source line"
// dismissal is not fed an unrelated macro).
func TestNullDeref_MacroContextDoesNotLeakAcrossFunctions(t *testing.T) {
	src := `#define LOG_PTR(x) do { (void)(x); } while (0)

typedef struct node { int v; } node_t;

int neighbor(void)
{
    node_t *n = NULL;
    LOG_PTR(n);
    return 0;
}

int subject(void)
{
    node_t *p = NULL;
    p->v = 1;
    return 0;
}
`
	res := planNullDerefFullSrc(t, src)
	var subject *EvidenceItem
	for i := range res.Candidates {
		if res.Candidates[i].Target.Function == "subject" {
			subject = &res.Candidates[i]
		}
	}
	if subject == nil {
		t.Fatalf("subject must stay a candidate, got %v", candidateNames(res))
	}
	if subject.MacroContext {
		t.Errorf("subject: MacroContext = true, want false — the only macro call is inside neighbor()")
	}
	if subject.SuspicionLevel != "confirmed" {
		t.Errorf("subject: suspicion = %q, want confirmed (no macro in its own body)", subject.SuspicionLevel)
	}
}

// A `for (init; cond; update)` header puts THREE statements on ONE line. The
// CFG gives each its own node, but a line-only sink lookup returned the
// initializer for every one of them — so `node = NULL;` followed by
// `for (node = pool->first; node != NULL; node = node->next)` resolved the
// update's `node->next` dereference to the initializer node, whose INCOMING
// definite-null fact is "node is NULL", and auto-confirmed a null-deref that
// does not exist (the commonest C linked-list walk). The column now breaks the
// tie: the dereference belongs to the update node, after the initializer killed
// the fact.
func TestNullDeref_ForHeaderSameLineAttribution(t *testing.T) {
	src := `typedef struct node { int id; struct node *next; } node_t;
typedef struct { node_t *first; } pool_t;

void walk(pool_t *pool)
{
    node_t *node = NULL;
    for (node = pool->first; node != NULL; node = node->next) {
        node->id = 0;
    }
}

void walk_address_init(pool_t *pool)
{
    node_t *node = NULL;
    node_t local = {0, 0};
    for (node = &local; node != NULL; node = node->next) {
        node->id = 0;
    }
}

void real_definite_null(void)
{
    node_t *node = NULL;
    node->id = 1;
}
`
	res := planNullDerefFullSrc(t, src)
	for _, c := range res.Candidates {
		switch c.Target.Function {
		case "walk", "walk_address_init":
			if c.Target.Variable == "node" {
				t.Errorf("%s: `node` is reassigned by the for-initializer and guarded by the loop condition; it must not be a null-deref candidate (line=%d suspicion=%s hint=%v)",
					c.Target.Function, c.Target.Line, c.SuspicionLevel, c.Hint)
			}
		}
	}
	// Control: a genuine definite-null dereference still reaches the confirmed tier.
	found := false
	for _, c := range res.Candidates {
		if c.Target.Function == "real_definite_null" && c.Target.Variable == "node" {
			found = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("real_definite_null: suspicion = %q, want confirmed (control)", c.SuspicionLevel)
			}
		}
	}
	if !found {
		t.Errorf("real_definite_null must stay a confirmed null-deref (control), got %v", candidateNames(res))
	}
}
