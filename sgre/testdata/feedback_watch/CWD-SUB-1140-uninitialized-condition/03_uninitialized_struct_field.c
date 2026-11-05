struct Config {
    int enabled;
    int mode;
};

int check_config(void)
{
    struct Config config;

    config.mode = 1;

    if (config.enabled && config.mode == 1) {
        return 1;
    }

    return 0;
}
