typedef struct cfg_s {
    unsigned short id;
} cfg_t;

typedef struct policy_s {
    cfg_t *cfg;
} policy_t;

static policy_t **g_policy_table = 0;

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
    g_policy_table[idx] = policy_new(cfg);
}

static void policy_destroy(policy_t *policy)
{
    free(policy->cfg);
    free(policy);
}

void policy_delete(unsigned short idx)
{
    policy_t *policy = g_policy_table[idx];
    if (policy == 0) {
        return;
    }
    policy_destroy(policy);
    g_policy_table[idx] = 0;
}
