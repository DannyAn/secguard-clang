/*
 * TC128 - Integer overflow: a `size - count` subtraction where `count` is a
 * truncating-snprintf accumulator (`count += snprintf_truncated_s(...)`) cannot
 * underflow — the truncating wrapper returns <= the remaining size, so count
 * never exceeds size (the P1-2 false-positive pattern). A genuine unsigned
 * underflow in the same file must still be flagged (the control).
 */

int snprintf_truncated_s(char *buf, unsigned int size, const char *fmt, ...);

void consume(unsigned int value);

int fmt_buf(char *buf, unsigned int size) {
    unsigned int count = 0;
    count += snprintf_truncated_s(buf + count, size - count, "%d", 1);
    count += snprintf_truncated_s(buf + count, size - count, "%d", 2);
    return (int)count;
}

/* Control: a plain unsigned subtraction passed to a function is still flagged. */
void bad_sub(unsigned int size, unsigned int *cnt) {
    consume(size - (*cnt));
}
