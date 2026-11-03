/*
 * TC133 - Integer overflow: a `len - offset` subtraction where `offset` is
 * accumulated from a MANUAL min-clamp wrapper (a project `fmt` that clamps
 * snprintf's return to its capacity argument and returns 0 on error) cannot
 * underflow — the clamp proves the wrapper returns <= its size argument, so
 * offset never exceeds len (Issue #207 B.3 repro). A genuine unsigned underflow
 * (the control) must still be flagged.
 */

int snprintf(char *buf, unsigned int size, const char *fmt, ...);

/* Project wrapper: guarantees offset <= len, truncating the overflow. */
static unsigned int fmt(char *buf, unsigned int len, const char *f, unsigned int v) {
    int n = snprintf(buf, len, f, v);
    if (n < 0) {
        return 0;
    }
    return ((unsigned int)n < len) ? (unsigned int)n : len;
}

/* A max-clamp is NOT a truncating wrapper: its result can exceed the capacity
 * argument, so an accumulator built from it must still be flagged. */
static unsigned int fmt_max(char *buf, unsigned int len, const char *f, unsigned int v) {
    int n = snprintf(buf, len, f, v);
    if (n < 0) {
        return 0;
    }
    return ((unsigned int)n > len) ? (unsigned int)n : len;
}

void consume(unsigned int value);

unsigned int build(char *buf, unsigned int len, unsigned int a, unsigned int b) {
    unsigned int offset = 0;
    offset += fmt(buf + offset, len - offset, "a=%u\n", a);
    offset += fmt(buf + offset, len - offset, "b=%u\n", b);
    return offset;
}

/* Control: an accumulator built from a max-clamp wrapper can exceed len, so
 * `len - offset` is a genuine unsigned subtraction that must be flagged. */
unsigned int build_max(char *buf, unsigned int len, unsigned int a, unsigned int b) {
    unsigned int offset = 0;
    offset += fmt_max(buf + offset, len - offset, "a=%u\n", a);
    offset += fmt_max(buf + offset, len - offset, "b=%u\n", b);
    return offset;
}

/* Control: a plain unsigned subtraction passed to a function is still flagged. */
void bad_sub(unsigned int size, unsigned int *cnt) {
    consume(size - (*cnt));
}
