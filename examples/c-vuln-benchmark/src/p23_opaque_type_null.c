/*
 * Phase 23 — null-deref (CWE-476) opaque-type null-source regression.
 *
 * Production feedback: a function whose parameters use third-party typedefs
 * (not defined anywhere in the scan tree, the project does not compile)
 * produced ZERO null-deref candidates. Layer findings:
 *
 *   - Syntax layer: tree-sitter fully recovers the function (unknown typedefs
 *     do not break parsing) — sinks were emitted all along.
 *   - Source layer (the gap): parameter nullability only came from the
 *     caller_null detector, which needs an IN-TREE call site; a function
 *     called from outside the scan tree had no nullability model at all, and
 *     a locally assigned field read of such a parameter
 *     (`tree = (T *)(resp->group_data)`) had no seeding path.
 *
 * Two fail-open channels close it (both suspected, never auto-confirmed):
 *   - opaque_param: a non-static function with zero in-tree callers, a
 *     pointer parameter the body dereferences.
 *   - opaque_field_read: a field read whose base parameter type is not
 *     defined in the scan tree (assigned pointer or chained intermediate).
 *
 * Cases (exact report form first):
 *   P23-01 expect=finding     report form: resp dereferenced (in-tree caller
 *                             forwarding unproven + opaque type)
 *   P23-02 expect=finding     report form: tree = (T*)(resp->group_data),
 *                             tree[0].group_name dereferenced
 *   P23-03 expect=finding     chained intermediate para->orig dereferenced
 *   P23-04 expect=no_finding  guarded variant: entry null check kills the
 *                             fail-open source (planner guard model)
 *   P23-05 expect=no_finding  in-tree typedef + in-tree caller passing a
 *                             non-null value: no opaque source at all
 *   P23-06 expect=finding     same in-tree-caller form for para (caller-arg
 *                             tier; the opaque_param seed blocks the
 *                             onlyUnprovenCallerNullSources dismissal)
 *   P23-07 expect=no_finding  volume guard: the same unproven forward shape
 *                             over a tree-defined type stays dismissed
 *   P23-08 expect=no_finding  volume guard: a guarded caller proves the
 *                             argument non-null, no source at all
 */
typedef struct KnownRec {
    unsigned int len;
} KnownRec_t;

int import_dn_group_tree_refresh(
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

int opaque_guarded_handler(ExtMsg_t *msg)
{
    if (msg == NULL) {
        return -1;
    }
    return msg->len;
}

int known_user(KnownRec_t *k)
{
    return k->len;
}

int known_caller(void)
{
    KnownRec_t kk;
    kk.len = 1;
    return known_user(&kk);
}
/*
 * In-tree-caller shapes (the production report form actually has a caller):
 * an unproven forward caller of opaque-typed parameters keeps the parameter
 * candidates (P23-06), while the same forward shape over a tree-defined type
 * (P23-07) and a guarded caller (P23-08) stay dismissed.
 */
int import_dn_group_tree(Nac_LdapSearchAckMsg_t *ack, import_para_ext_t *p)
{
    return import_dn_group_tree_refresh(ack, p);
}

int tree_typed_target(KnownRec_t *tt_k)
{
    return tt_k->len;
}

int tree_typed_caller(KnownRec_t *tt_p)
{
    return tree_typed_target(tt_p);
}

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
/*
 * Header-defined layouts (the production shape): P23HdrRec_t / P23HdrNode_t
 * live in p23_header_type.h, which defines no function. The census must see
 * them so neither the parameter nor the assigned field-read pointer is opaque
 * (P23-09 / P23-10). Before the census fix both seeded and both surfaced.
 */
int header_typed_reader(P23HdrRec_t *ht_resp)
{
    return ht_resp->len;
}

int header_typed_tree(P23HdrRec_t *hh_resp)
{
    P23HdrNode_t *hh_tree = (P23HdrNode_t *)(hh_resp->group_data);
    return hh_tree[0].len;
}
