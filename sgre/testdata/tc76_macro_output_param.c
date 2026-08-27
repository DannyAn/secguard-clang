#include <stdint.h>

#define TEST_MACRO_X(x) do { (x) = get_pool(); } while (0)

uint16_t get_pool(void);
void test_method_x(uint16_t x);

/* A macro that ASSIGNS its argument is an output macro: the call initializes
 * mpool, so it is NOT a use-before-init. */
void macro_output(void) {
    uint16_t mpool;
    TEST_MACRO_X(mpool);
}

/* A by-value function call READS the argument, so an uninitialized bpool here
 * IS a genuine use-before-init and must stay reported. */
void by_value_read(void) {
    uint16_t bpool;
    test_method_x(bpool);
}
