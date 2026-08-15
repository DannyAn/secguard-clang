#include <stdlib.h>
#include <string.h>

typedef struct { char *path; char *msg; } Path;

/* genuine: a + 16 can wrap, the relational guard can be fooled, and a feeds
 * malloc/memcpy. This is the "wraparound inside a bounds check" pattern the
 * detector is meant to catch. */
int real_wraparound(unsigned int a, unsigned int limit) {
    if (a + 16 > limit) {
        return -1;
    }
    void *buf = malloc(a);
    memcpy(buf, "x", a);
    free(buf);
    return 0;
}

/* noise: pointer arithmetic inside an strcmp equality is not an integer
 * overflow guard. The operand n later feeds malloc, but the arithmetic itself
 * is compared with ==, not a relational bound. */
int not_overflow_strcmp(char *p, unsigned int n) {
    if (strcmp(p + n - 3, ".gz") == 0) {
        return 1;
    }
    char *buf = (char *)malloc(n);
    free(buf);
    return 0;
}

/* noise: a size calculation checked against NULL is not an overflow guard,
 * even though an operand contains `->` (a text scan for `>` must not be
 * fooled by member access). */
int not_overflow_malloc_null(Path *s) {
    char *msg = (char *)malloc(strlen(s->path) + strlen(s->msg) + 3);
    if (msg == NULL) {
        return -1;
    }
    memcpy(msg, s->path, strlen(s->path));
    free(msg);
    return 0;
}
