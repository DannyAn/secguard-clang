typedef struct cfg_s {
    unsigned short id;
} cfg_t;

typedef struct policy_s {
    cfg_t *cfg;
} policy_t;

static policy_t **g_policy_table = 0;
static unsigned int g_table_size = 0;

void policy_table_init(unsigned int size)
{
    g_table_size = size;
    g_policy_table = (policy_t **)malloc(sizeof(policy_t *) * size);
    if (g_policy_table == 0) {
        return;
    }
    (void)memset(g_policy_table, 0, sizeof(policy_t *) * size);
}

policy_t *policy_new(void *cfg)
{
    policy_t *policy = (policy_t *)malloc(sizeof(*policy));
    if (policy == 0) {
        return 0;
    }
    policy->cfg = cfg;
    return policy;
}

void policy_create(unsigned short idx)
{
    cfg_t *cfg = (cfg_t *)malloc(sizeof(*cfg));
    if (cfg == 0) {
        return;
    }
    *cfg = (cfg_t){0};
    cfg->id = idx;

    policy_t *policy = policy_new(cfg);
    g_policy_table[idx] = policy;
}

void policy_free(policy_t *policy)
{
    free(policy);
}

void policy_delete(unsigned short idx)
{
    policy_t *policy = g_policy_table[idx];
    if (policy == 0) {
        return;
    }

    policy_free(policy);
    g_policy_table[idx] = 0;
}
