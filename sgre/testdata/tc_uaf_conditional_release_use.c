/*
 * UAF conditional-release (user-provided cbwl_tbl.c form, PATTERN-02
 * free-then-indirect-access + PATTERN-07 macro-wrapped use):
 * - release: cbwl_tbl_destory(add_node) — a defensive wrapper whose body
 *   frees the parameter only under `if (node != NULL)` (a MAY-free)
 * - use: cbwl_nodeinfo(add_node), a macro expanding to cbwl_dfx_node_info,
 *   which dereferences node->key / node->attr (an indirect use through the
 *   macro wrapper)
 * - order: free -> use -> return inside one error branch
 * A may-free use-after-free candidate must surface (suspected, never
 * auto-confirmed).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct {
    char key[32];
    int attr;
} cbwl_node_t;

#define cbwl_nodeinfo(node) cbwl_dfx_node_info(node)

static char cbwl_info_buf[128];

const char *cbwl_dfx_node_info(cbwl_node_t *node)
{
    if (node == NULL) {
        return "NULL";
    }
    snprintf(cbwl_info_buf, sizeof(cbwl_info_buf), "key=%s,attr=%d", node->key, node->attr);
    return cbwl_info_buf;
}

void cbwl_tbl_destory(cbwl_node_t *node)
{
    if (node != NULL) {
        free(node);
    }
}

int cbwl_tbl_insert(cbwl_node_t *node)
{
    (void)node;
    return -1;
}

#define CBWL_ERROR 1

static void cbwl_log(int level, const char *fmt, ...)
{
    (void)level;
    (void)fmt;
}

uint32_t cbwl_tbl_ha_add_node(cbwl_node_t *add_node)
{
    uint32_t ret = cbwl_tbl_insert(add_node);
    if (ret != 0) {
        cbwl_tbl_destory(add_node);                     /* release (may) */
        cbwl_log(CBWL_ERROR, "cbwl_tbl_ha_add_node err. node : %s.",
                 cbwl_nodeinfo(add_node));              /* use (macro-wrapped) */
        return ret;
    }
    return 0;
}

/* The must variant: an unconditional free in the wrapper body makes the
 * freed state certain — the candidate auto-confirms. */
void cbwl_tbl_destory_unconditional(cbwl_node_t *node)
{
    free(node);
}

uint32_t cbwl_must_variant(cbwl_node_t *add_node)
{
    uint32_t ret = cbwl_tbl_insert(add_node);
    if (ret != 0) {
        cbwl_tbl_destory_unconditional(add_node);
        cbwl_log(CBWL_ERROR, "err. node : %s.", cbwl_nodeinfo(add_node));
        return ret;
    }
    return 0;
}

/* The fixed form (user remediation): log FIRST, release LAST — no use
 * after the release, no candidate. */
uint32_t cbwl_fixed_form(cbwl_node_t *add_node)
{
    uint32_t ret = cbwl_tbl_insert(add_node);
    if (ret != 0) {
        cbwl_log(CBWL_ERROR, "cbwl_tbl_ha_add_node err. node : %s.",
                 cbwl_nodeinfo(add_node));              /* use BEFORE release */
        cbwl_tbl_destory(add_node);                     /* release LAST */
        return ret;
    }
    return 0;
}