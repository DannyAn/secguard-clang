#include <stdint.h>
#include <stdlib.h>

typedef struct pktdrp_drop_key {
    uint8_t slot_id;
    uint8_t cpu_id;
} pktdrp_drop_key_t;

typedef struct pktdrp_tbl {
    pktdrp_drop_key_t drop_key;
    void *res;
    struct pktdrp_tbl *next;
} pktdrp_tbl_t;

static pktdrp_tbl_t *g_pktdrp_tbl;

static void pktdrp_free_tbl_res(pktdrp_tbl_t *item)
{
    if (item != NULL) {
        free(item->res);
        free(item);
    }
}

void pktdrp_del_tbl_by_slot(uint8_t slot_id, uint8_t cpu_id)
{
    pktdrp_tbl_t *item = g_pktdrp_tbl;
    pktdrp_tbl_t *pre_item = item;
    while (item != NULL) {
        if (item->drop_key.slot_id == slot_id && item->drop_key.cpu_id == cpu_id) {
            if (g_pktdrp_tbl == item) {
                g_pktdrp_tbl = item->next;
                pre_item = g_pktdrp_tbl;
                pktdrp_free_tbl_res(item);
                item = pre_item;
            } else {
                pre_item->next = item->next;
                pktdrp_free_tbl_res(item);
                item = pre_item->next;
            }
            continue;
        }
        pre_item = item;
        item = item->next;
    }
}