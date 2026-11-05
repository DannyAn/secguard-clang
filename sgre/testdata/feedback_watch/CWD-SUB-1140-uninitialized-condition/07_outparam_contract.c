static int load_value(int *out, int success)
{
    if (success) {
        *out = 42;
        return 0;
    }

    return -1;
}

int use_loaded_value(int success)
{
    int value;

    (void)load_value(&value, success);

    if (value > 0) {
        return 1;
    }

    return 0;
}
