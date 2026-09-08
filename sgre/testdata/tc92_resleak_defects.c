/*
 * TC92 - Resource Leak: three design-defect regressions.
 *
 *   rl_err_return  — defect 1: `if (fd < 0) return fd;` is an error exit, not an
 *                    ownership transfer; the real leak is the later `return 0`
 *                    that never closes fd.
 *   rl_dup         — defect 2: dup() is an fd factory missing from the acquirer
 *                    whitelist.
 *   rl_sqlite_open — defect 3: sqlite3_open(path, &db) writes the handle through
 *                    an out-parameter, not the return value.
 *
 * Expected: each produces RESOURCE_ACQUIRE and NO RESOURCE_RELEASE (leak).
 */

static int open(const char *p, int f) { return 3; }
static int write(int fd, const void *b, unsigned long n) { return 0; }
static int dup(int fd) { return 4; }
static int sqlite3_open(const char *p, void **db) { return 0; }

int rl_err_return(void) {
    int fd = open("x", 0);
    if (fd < 0) {
        return fd;
    }
    write(fd, "a", 1);
    return 0;
}

int rl_dup(int fd) {
    int fd2 = dup(fd);
    if (fd2 < 0) {
        return -1;
    }
    return 0;
}

int rl_sqlite_open(const char *path) {
    void *db = 0;
    int rc = sqlite3_open(path, &db);
    if (rc != 0) {
        return rc;
    }
    return 0;
}
