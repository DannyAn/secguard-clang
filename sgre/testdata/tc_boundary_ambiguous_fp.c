#include <stdio.h>

void test_boundary_ambiguous_fp(char *user_input, FILE *fp) {
    fprintf(fp, "%s\n", user_input);
}