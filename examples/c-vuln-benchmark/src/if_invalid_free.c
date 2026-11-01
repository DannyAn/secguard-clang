// if_invalid_free.c — invalid-free (CWE-761) benchmark cases.
#include <stdlib.h>

int g_arr[4];

void if01_stack_array(void) {
    int a[8];
    free(a);
}

void if02_addr_local(void) {
    int local = 0;
    free(&local);
}

void if03_mid_array(void) {
    int arr[8];
    free(&arr[5]);
}

void if04_global_array(void) {
    free(g_arr);
}

void if05_heap_offset(void) {
    int *p = malloc(16);
    free(p + 4);
}

void if10_free_ptr_var(void) {
    int *p = malloc(16);
    free(p);
}

void if11_free_null(void) {
    free(NULL);
}

void if12_free_unknown_offset(void) {
    int *p = get_ptr();
    free(p + 4);
}
