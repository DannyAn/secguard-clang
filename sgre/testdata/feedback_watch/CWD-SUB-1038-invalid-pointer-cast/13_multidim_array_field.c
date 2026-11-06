#include <stdint.h>
#include <stdlib.h>

struct MatrixRecord {
    uint32_t a;
    uint32_t grid[2][3];
    uint32_t z;
};

int read_matrix(void)
{
    struct MatrixRecord *p = (struct MatrixRecord *)malloc(28);
    if (p == NULL) {
        return -1;
    }

    p->z = 7;

    free(p);
    return 0;
}
