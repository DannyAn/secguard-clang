int sink(int);

void guarded_continue(int idx)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        if (idx >= 16) { continue; }
        arr[idx] = 1;
    }
}

void guarded_return_loop(int idx)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        if (idx >= 16) { return; }
        arr[idx] = 2;
    }
}

void guarded_body(int idx)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        if (idx < 16) { arr[idx] = 3; }
    }
}

void guarded_wrong_bound(int idx)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        if (idx >= 64) { continue; }
        arr[idx] = 4;
    }
}

void guarded_other_var(int idx, int other)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        if (other >= 16) { continue; }
        arr[idx] = 5;
    }
}

void unguarded(int idx)
{
    int arr[16];
    for (idx = 0; idx < 32; idx++) {
        arr[idx] = 6;
    }
}
