#include <stddef.h>
#include <stdint.h>

// 真死逻辑（always false / always true）——应检出 SIGNED_COMPARE。
void uint_dead_compares(uint8_t a, uint16_t b, uint32_t c) {
    if (a < 0) {   /* uint8_t  < 0   always false */
        return;
    }
    if (b >= 0) {  /* uint16_t >= 0  always true */
        return;
    }
    if (c <= -1) { /* uint32_t <= -1 always false */
        return;
    }
    if (0 > c) {   /* mirrored: c < 0 always false */
        return;
    }
    if (0 <= b) {  /* mirrored: b >= 0 always true */
        return;
    }
}

// 合法检查（u != 0 / u == 0）——不得误报。
void uint_legit_compares(uint8_t a, uint16_t b, uint32_t c, unsigned int u, size_t n) {
    if (a > 0) {   /* a != 0 */
        return;
    }
    if (b > 0) {   /* b != 0 */
        return;
    }
    if (c > 0) {   /* c != 0 */
        return;
    }
    if (u > 0) {   /* u != 0 */
        return;
    }
    if (n > 0) {   /* n != 0 */
        return;
    }
    if (a <= 0) {  /* a == 0 */
        return;
    }
    if (c <= 0) {  /* c == 0 */
        return;
    }
    if (0 < c) {   /* mirrored: c > 0 */
        return;
    }
    if (0 >= a) {  /* mirrored: a <= 0 */
        return;
    }
}
