/*
 * TC129 - Integer overflow: a `size - count` subtraction where `count` is
 * accumulated from CUSTOM truncating wrappers (add_pri / add_hostname) that
 * forward to snprintf_truncated_s cannot underflow. The bounded-return summary
 * proves the wrappers return <= their size argument, so `count` stays <= `size`
 * across the mixed accumulation and the subtraction is a false positive. A
 * genuine unsigned underflow in the same file must still be flagged (control).
 */

int snprintf_truncated_s(char *buf, unsigned int size, const char *fmt, ...);

static unsigned int add_pri(char *buf, unsigned int size) {
    return snprintf_truncated_s(buf, size, "<%d>", 1);
}

static unsigned int add_hostname(char *buf, unsigned int size) {
    return snprintf_truncated_s(buf, size, "%s", "host");
}

void consume(unsigned int value);

int fmt_buf(char *buf, unsigned int size) {
    unsigned int count = 0;
    count += add_pri(buf, size);
    count += add_hostname(buf + count, size - count);
    return (int)count;
}

/* Assignment-init accumulator: `len = 0;` as a statement, not a declaration. */
int fmt_buf2(char *buf, unsigned int size) {
    unsigned int len;
    len = 0;
    len += snprintf_truncated_s(buf + len, size - len, "%d", 1);
    return (int)len;
}

/* Plain-assignment first write: `len = snprintf_truncated_s(...)` then `+=`. */
int fmt_buf3(char *buf, unsigned int size) {
    unsigned int len;
    len = snprintf_truncated_s(buf, size, "%d", 1);
    len += snprintf_truncated_s(buf + len, size - len, "%d", 2);
    return (int)len;
}

/* Control: a plain unsigned subtraction passed to a function is still flagged. */
void bad_sub(unsigned int size, unsigned int *cnt) {
    consume(size - (*cnt));
}
