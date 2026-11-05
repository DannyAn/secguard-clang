static int g_state;
static int *g_node;

int check_global_state(void)
{
    if (g_state == 0) {
        return 0;
    }

    if (g_node == 0) {
        return -1;
    }

    return 1;
}
