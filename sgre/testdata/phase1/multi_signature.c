/* multi_signature.c - functions with varied signatures */
#include <stdlib.h>

void no_params_no_return(void) {
}

int one_param(int x) {
    return x;
}

int two_params(int a, int b) {
    return a + b;
}

int *pointer_param(int *p) {
    return p;
}

void multi_params(int a, char *b, double c, void *d) {
}

int array_param(int arr[]) {
    return arr[0];
}