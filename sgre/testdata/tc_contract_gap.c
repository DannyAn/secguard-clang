typedef struct node {
    int value;
} node_t;

typedef struct resp {
    node_t   *group_data;
    unsigned  group_num;
    int       flag;
} resp_t;

node_t *g_alloc(void);
void consume(node_t *p);

/* POSITIVE: partial guard — tree null-checked on one path, dereferenced on the
 * count-gated path with no guard. Detector emits CONTRACT_GAP (ptr_guard). */
int partial_guard(resp_t *resp) {
    node_t *tree = resp->group_data;
    if (resp->flag != 0) {
        if (tree == NULL) {
            return -1;
        }
        return tree->value;
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0;
    }
    return 0;
}

/* POSITIVE: direct field subscript gated by the count, partial guard. */
int direct_counted(resp_t *resp) {
    if (resp->flag != 0) {
        if (resp->group_data == NULL) {
            return -1;
        }
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        resp->group_data[i].value = 0;
    }
    return 0;
}

/* NEGATIVE: guarded — the null guard dominates the deref. Detector emits
 * (checked somewhere) but the planner filter drops it (every path guarded). */
int fully_guarded(resp_t *resp) {
    node_t *tree = resp->group_data;
    if (tree == NULL) {
        return -1;
    }
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0;
    }
    return 0;
}

/* NEGATIVE: never null-checked — no E-b evidence, treated non-null by convention. */
int never_checked(resp_t *resp) {
    node_t *tree = resp->group_data;
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0;
    }
    return 0;
}

/* NEGATIVE: field written in-scope — function-controlled, null-deref owns it. */
int written_in_scope(resp_t *resp) {
    resp->group_data = g_alloc();
    for (unsigned i = 0; i < resp->group_num; i++) {
        resp->group_data[i].value = 0;
    }
    return 0;
}

/* NEGATIVE: field read but never dereferenced (only passed to a helper). */
int not_deref(resp_t *resp) {
    node_t *tree = resp->group_data;
    if (tree == NULL) {
        return -1;
    }
    consume(tree);
    return 0;
}

/* POSITIVE: pointer-null caught WITHOUT any count gating — field null-checked on
 * one path, dereferenced on the other path with no guard. */
int ptr_only_partial(resp_t *resp) {
    node_t *tree = resp->group_data;
    if (resp->flag != 0) {
        if (tree == NULL) {
            return -1;
        }
        return tree->value;
    }
    return tree->value;
}

/* POSITIVE: compound-condition partial guard with no count field — the guard
 * only covers `flag != 0`, so the flag==0 path dereferences a possibly-null tree. */
int ptr_only_compound(resp_t *resp) {
    node_t *tree = resp->group_data;
    if (resp->flag != 0 && tree == NULL) {
        return -1;
    }
    return tree->value;
}

/* NEGATIVE (issue #216): same-block guard — the deref sits inside the
 * `if (resp->group_data != NULL)` body, so entering the branch proves the field
 * non-null. The filter used to model only early-exit guards. */
int block_guarded(resp_t *resp) {
    if (resp->group_data != NULL) {
        return resp->group_data->value;
    }
    return 0;
}

/* NEGATIVE (issue #216): same-block guard on a local derived (cast) from the
 * field — the guard tests `tree`, the deref sits in its true branch. */
int block_guarded_local(resp_t *resp) {
    node_t *tree = (node_t *)resp->group_data;
    if (tree != NULL) {
        return tree->value;
    }
    return 0;
}

/* NEGATIVE (issue #216): the FALSE branch of the null test — the `else` of
 * `if (resp->group_data == NULL)` proves the field non-null. The consequence
 * does NOT exit, so only the else-branch model can drop this. */
int block_guarded_else(resp_t *resp) {
    int empty = 0;
    if (resp->group_data == NULL) {
        empty = 1;
    } else {
        return resp->group_data->value;
    }
    return empty;
}

/* NEGATIVE (issue #216): short-circuit `&&` — the deref is the right operand of
 * a condition whose left operand proves the field non-null. */
int short_circuit_guarded(resp_t *resp) {
    if (resp->group_data != NULL && resp->group_data->value > 0) {
        return 1;
    }
    return 0;
}

/* POSITIVE: the guard DOES NOT dominate — the deref runs after the guard block,
 * so it must stay a candidate (the same-block model must not over-drop). */
int guard_then_deref(resp_t *resp) {
    if (resp->group_data != NULL) {
        consume(resp->group_data);
    }
    return resp->group_data->value;
}

/* A struct with ONLY a pointer field (no count/length at all) — the pure
 * pointer-null shape with zero count interference. */
typedef struct payload {
    node_t *items;
    int     ready;
} payload_t;

/* POSITIVE: pure pointer field, no count anywhere, partial guard. */
int payload_partial(payload_t *p) {
    node_t *it = p->items;
    if (p->ready != 0) {
        if (it == NULL) {
            return -1;
        }
        return it->value;
    }
    return it->value;
}

/* NEGATIVE: the payload_t sibling that makes payload_t.items a nullable
 * contract for payload_partial; its own deref is guarded (early exit). */
int payload_sibling(payload_t *p) {
    if (p->items == NULL) {
        return -1;
    }
    return p->items->value;
}

/* ---- E-c: caller-side validation ---- */

/* The callee has a partial guard (E-b fires); its ONLY caller validates the
 * field before the call, so the unguarded path is safe → suppressed. */
int callee_validated(resp_t *resp) {
    if (resp->flag != 0) {
        if (resp->group_data == NULL) {
            return -1;
        }
        return resp->group_data->value;
    }
    return resp->group_data->value;
}

int caller_validates(resp_t *resp) {
    if (resp->group_data == NULL) {
        return -1;
    }
    return callee_validated(resp);
}

/* Same partial-guard callee, but its only caller does NOT validate → the field
 * can be null at the call → kept (suspected). */
int callee_unvalidated(resp_t *resp) {
    if (resp->flag != 0) {
        if (resp->group_data == NULL) {
            return -1;
        }
        return resp->group_data->value;
    }
    return resp->group_data->value;
}

int caller_no_validate(resp_t *resp) {
    return callee_unvalidated(resp);
}

/* A struct whose pointer field is checked by NOBODY — the true "no evidence"
 * negative (no self-check, no sibling checks, no caller checks). */
typedef struct opaque {
    node_t *ptr;
} opaque_t;

int opaque_no_evidence(opaque_t *o) {
    return o->ptr->value;
}
