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
