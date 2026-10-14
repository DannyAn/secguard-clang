typedef struct nac_ldap_search_ack_msg {
    void     *group_data;
    unsigned  group_num;
} Nac_LdapSearchAckMsg_t;

typedef struct ldap_usrgroup_node {
    int value;
} ldap_usrgroup_node_t;

void import_consume(ldap_usrgroup_node_t *p);

/* Sibling handler (same struct type) establishes the contract: group_data can
 * be NULL and group_num can be 0. This is the E-a evidence source. Its own
 * deref is guarded, so it is NOT a finding. */
int sibling_import_handler(Nac_LdapSearchAckMsg_t *resp) {
    if (resp->group_data == NULL || resp->group_num == 0) {
        return 0;
    }
    ldap_usrgroup_node_t *tree = (ldap_usrgroup_node_t *)(resp->group_data);
    return tree->value;
}

/* PRODUCTION CASE (import_dn_group_tree_refresh): no self null-check; derives
 * `tree` by casting the field; dereferences it in a count-gated loop. The fix
 * added `if (tree == NULL || resp->group_num == 0) return 0;` — missing here.
 * Caught via E-a (sibling checks group_data). */
int import_dn_group_tree_refresh(Nac_LdapSearchAckMsg_t *resp) {
    ldap_usrgroup_node_t *tree = (ldap_usrgroup_node_t *)(resp->group_data);
    for (unsigned i = 0; i < resp->group_num; i++) {
        tree[i].value = 0;
    }
    return 0;
}

/* VARIANT: null-check only in one branch (E-b partial guard). */
int import_partial_branch(Nac_LdapSearchAckMsg_t *resp) {
    ldap_usrgroup_node_t *tree = (ldap_usrgroup_node_t *)(resp->group_data);
    if (resp->group_num > 1) {
        if (tree == NULL) {
            return -1;
        }
        return tree->value;
    }
    return tree->value;
}

/* VARIANT: count==0 is handled (legal empty), but group_data NULL with a
 * positive count is NOT handled → the deref is still a null risk. E-a evidence. */
int import_empty_unhandled(Nac_LdapSearchAckMsg_t *resp) {
    if (resp->group_num == 0) {
        return 0;
    }
    ldap_usrgroup_node_t *tree = (ldap_usrgroup_node_t *)(resp->group_data);
    return tree->value;
}

/* VARIANT: field read but never dereferenced (only passed to a helper) → not caught. */
int import_no_deref(Nac_LdapSearchAckMsg_t *resp) {
    ldap_usrgroup_node_t *tree = (ldap_usrgroup_node_t *)(resp->group_data);
    if (tree == NULL) {
        return -1;
    }
    import_consume(tree);
    return 0;
}

/* VARIANT: the callee has a partial guard; its only caller validates the field
 * before the call, so the unguarded path is safe → E-c suppressed. */
int import_callee(Nac_LdapSearchAckMsg_t *resp) {
    if (resp->group_num > 1) {
        if (resp->group_data == NULL) {
            return -1;
        }
        return ((ldap_usrgroup_node_t *)(resp->group_data))->value;
    }
    return ((ldap_usrgroup_node_t *)(resp->group_data))->value;
}

int import_caller_validates(Nac_LdapSearchAckMsg_t *resp) {
    if (resp->group_data == NULL) {
        return -1;
    }
    return import_callee(resp);
}
