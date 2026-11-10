typedef struct cfg_s {
    unsigned short id;
} cfg_t;

typedef struct policy_s {
    cfg_t *cfg;
} policy_t;

static policy_t *g_policy[4];

static void policy_init(policy_t *policy, cfg_t *cfg)
{
    policy->cfg = cfg;
}

void policy_create(unsigned short idx)
{
    cfg_t *cfg = (cfg_t *)malloc(sizeof(*cfg));
    policy_t *policy = (policy_t *)malloc(sizeof(*policy));
    if (cfg == 0 || policy == 0) {
        return;
    }
    cfg->id = idx;
    policy_init(policy, cfg);
    g_policy[idx] = policy;
}

void policy_remove(unsigned short idx)
{
    policy_t *policy = g_policy[idx];
    if (policy == 0) {
        return;
    }
    free(policy);
    g_policy[idx] = 0;
}
