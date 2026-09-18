#include <stdlib.h>

/* traverse_free_id_result directly frees its argument (param 0). Two calls on
 * MUTUALLY-EXCLUSIVE error paths (each returns) must NOT be a double-free. */
void traverse_free_id_result(int **result)
{
    free(result);
}

int **new_id_result(void)
{
    return (int **)malloc(sizeof(int *));
}

int traverse_recursive_traverse(int **array)
{
    (void)array;
    int **merged = NULL;
    for (int i = 0; i < 3; i++) {
        int **p = new_id_result();
        if (!p) {
            traverse_free_id_result(merged);
            return 0;
        }
        int n = i;
        if (n == 0) {
            traverse_free_id_result(p);
            traverse_free_id_result(merged);
            return 0;
        }
    }
    return 0;
}
