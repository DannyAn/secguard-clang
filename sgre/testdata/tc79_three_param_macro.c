#include <stdint.h>

uint16_t combine(uint16_t x, uint16_t y);

/* 3-param macro: only the THIRD parameter is written (output); a,b are read. */
#define SET_THIRD(a, b, c) do { (c) = combine(a, b); } while (0)

/* 3-param macro: only the FIRST parameter is written (output); b,c are read. */
#define SET_FIRST(a, b, c) do { (a) = combine(b, c); } while (0)

void writes_third(void) {
    uint16_t a1, b1, c1;
    SET_THIRD(a1, b1, c1); /* c1 written (not uninit); a1,b1 read (uninit) */
}

void writes_first(void) {
    uint16_t a2, b2, c2;
    SET_FIRST(a2, b2, c2); /* a2 written (not uninit); b2,c2 read (uninit) */
}
