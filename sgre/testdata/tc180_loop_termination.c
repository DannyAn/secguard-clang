/* Loop termination & progress analysis fixtures (CWE-835).
 * Positive cases (lt01..lt06) must emit a LOOP_TERMINATION event.
 * Negative cases (lt20..lt28) must not. */

int parse(int off) { return off; }
int next(void) { return 0; }
void g(int *p) { *p = 1; }

int g_count;

void work(void) {}

/* POSITIVE */

int lt01_no_progress_while(int n) {
    int i = 0, sum = 0;
    while (i < n) {
        sum += i;
    }
    return sum;
}

int lt02_no_progress_for(int n) {
    int i = 0, sum = 0;
    for (i = 0; i < n; ) {
        sum += i;
    }
    return sum;
}

int lt03_zero_step(int n) {
    int i = 0;
    while (i < n) {
        i = i;
    }
    return i;
}

int lt04_continue_bypass(int n) {
    int i = 0;
    while (i < n) {
        if (i % 2) continue;
        i++;
    }
    return i;
}

int lt05_protocol_offset(int len) {
    int off = 0;
    while (off < len) {
        parse(off);
    }
    return off;
}

int lt06_do_while_no_progress(int n) {
    int i = 0, sum = 0;
    do {
        sum += i;
    } while (i < n);
    return sum;
}

/* NEGATIVE */

int lt20_normal_inc(int n) {
    int i = 0;
    for (i = 0; i < n; i++) {
    }
    return i;
}

int lt21_normal_dec(int n) {
    while (n > 0) {
        n--;
    }
    return n;
}

void lt22_while_true(void) {
    while (1) {
        work();
    }
}

void lt23_for_infinite(void) {
    for (;;) {
        work();
    }
}

int lt24_break_exit(int n, int done) {
    int i = 0;
    while (i < n) {
        if (done) break;
    }
    return i;
}

int lt25_return_exit(int n, int done) {
    int i = 0;
    while (i < n) {
        if (done) return i;
    }
    return i;
}

int lt26_external_update(int n) {
    int i = 0;
    while (i < n) {
        i = next();
    }
    return i;
}

void lt27_global_cond(void) {
    while (g_count < 10) {
    }
}

int lt28_valid_parse(int len) {
    int off = 0;
    while (off < len) {
        off += 2;
    }
    return off;
}

int lt29_addr_taken(int n) {
    int i = 0;
    while (i < n) {
        g(&i);
    }
    return i;
}
