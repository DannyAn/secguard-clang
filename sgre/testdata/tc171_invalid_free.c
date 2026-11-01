#include <stdlib.h>

int g_arr[4];

void f1_stack_array(void) {
    int a[8];
    free(a);
}

void f1b_addr_local(void) {
    int local = 0;
    free(&local);
}

void f2_mid_array(void) {
    int arr[8];
    free(&arr[5]);
}

void f3_global_array(void) {
    free(g_arr);
}

void f4_heap_offset(void) {
    int *p = malloc(16);
    free(p + 4);
}

void f5_realloc_stack(void) {
    int a[8];
    realloc(a, 16);
}

void fp1_free_ptr_var(void) {
    int *p = malloc(16);
    free(p);
}

void fp2_free_null(void) {
    free(NULL);
}

void fp3_free_unknown_offset(void) {
    int *p = get_ptr();   /* pointee unknown — not a proven non-heap interior */
    free(p + 4);
}

int main(void) {
    f1_stack_array();
    f1b_addr_local();
    f2_mid_array();
    f3_global_array();
    f4_heap_offset();
    f5_realloc_stack();
    fp1_free_ptr_var();
    fp2_free_null();
    fp3_free_unknown_offset();
    return 0;
}
