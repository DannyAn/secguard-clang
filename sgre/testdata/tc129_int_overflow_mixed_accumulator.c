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

/* Control: a plain unsigned subtraction passed to a function is still flagged. */
void bad_sub(unsigned int size, unsigned int *cnt) {
    consume(size - (*cnt));
}
