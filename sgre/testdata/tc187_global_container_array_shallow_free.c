typedef struct {
    char *name;
} item_t;

static item_t *g_items[8];

static void make_item(int slot)
{
    item_t *it = (item_t *)malloc(sizeof(*it));
    if (it == 0) {
        return;
    }
    it->name = (char *)malloc(16);
    g_items[slot] = it;
}

void drop_item(int slot)
{
    if (g_items[slot] == 0) {
        return;
    }
    free(g_items[slot]);
    g_items[slot] = 0;
}
