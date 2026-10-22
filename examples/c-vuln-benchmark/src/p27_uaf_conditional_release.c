/*
 * Phase 27 — use-after-free conditional release (user-provided cbwl_tbl.c
 * form): a defensive release wrapper (`if (node != NULL) free(node)`), a
 * macro-wrapped use site (cbwl_nodeinfo -> cbwl_dfx_node_info dereferencing
 * node->key), and the fixed form (log before release).
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

/* P27-01 (finding): unconditional release in the wrapper, then the
 * macro-wrapped use — a machine-proved use-after-free. */
void cbwl_tbl_destory(cbwl_node_t *node)
{
    free(node);
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
        cbwl_tbl_destory(add_node);
        cbwl_log(CBWL_ERROR, "cbwl_tbl_ha_add_node err. node : %s.",
                 cbwl_nodeinfo(add_node));
        return ret;
    }
    return 0;
}

/* P27-02 (no_finding): the user remediation — log FIRST (the macro-wrapped
 * use precedes the release), release LAST. No use after the release. */
uint32_t cbwl_tbl_ha_add_node_fixed(cbwl_node_t *add_node)
{
    uint32_t ret = cbwl_tbl_insert(add_node);
    if (ret != 0) {
        cbwl_log(CBWL_ERROR, "cbwl_tbl_ha_add_node err. node : %s.",
                 cbwl_nodeinfo(add_node));
        cbwl_tbl_destory(add_node);
        return ret;
    }
    return 0;
}
