typedef struct cfg_s {
    unsigned short id;
} cfg_t;

typedef struct policy_s {
    cfg_t *cfg;
} policy_t;

policy_t *policy_new(void *cfg)
{
    policy_t *policy = (policy_t *)malloc(sizeof(*policy));
    if (policy == 0) {
        return 0;
    }
    policy->cfg = cfg;
    return policy;
}

policy_t *policy_make(unsigned short idx)
{
    cfg_t *cfg = (cfg_t *)malloc(sizeof(*cfg));
    if (cfg == 0) {
        return 0;
    }
    cfg->id = idx;
    return policy_new(cfg);
}

void policy_drop(void)
{
    policy_t *policy = policy_make(1);
    if (policy == 0) {
        return;
    }
    free(policy);
}
