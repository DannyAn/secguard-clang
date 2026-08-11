#include <stdlib.h>
#include <regex.h>

void test_regcomp_output_param() {
    regex_t r;
    regcomp(&r, "pattern", 0);
    regfree(&r);
}