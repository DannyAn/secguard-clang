#include <stdint.h>

/* 误报：循环体里的 < 比较（i < 100）不是循环边界，diffs[i]（i<4）安全，
   必须不报 array OOB。 */
void fp_body_compare(void) {
    int diffs[4] = {0};
    for (int i = 0; i < 4; i++) {
        if (i < 100) {
            diffs[i] = i;
        }
    }
}

/* 真 OOB：i<=4，i=4 越界，必须报。 */
void tp_loop_oob(void) {
    int diffs[4] = {0};
    for (int i = 0; i <= 4; i++) {
        diffs[i] = i;
    }
}
