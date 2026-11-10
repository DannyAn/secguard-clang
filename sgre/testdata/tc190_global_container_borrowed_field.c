typedef struct item_s {
    char *name;
} item_t;

static const char *g_name = "builtin";

static item_t **g_items = 0;

static void item_new_at(int slot)
{
    item_t *it = (item_t *)malloc(sizeof(*it));
    if (it == 0) {
        return;
    }
    it->name = (char *)g_name;
    g_items[slot] = it;
}

void item_remove(int slot)
{
    item_t *it = g_items[slot];
    if (it == 0) {
        return;
    }
    free(it);
    g_items[slot] = 0;
}
