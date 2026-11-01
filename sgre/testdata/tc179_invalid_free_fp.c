#include <regex.h>
#include <stdlib.h>

struct para { char *user_filter; char *dst_name; };

void ur_para_free(struct para *p) {
    free(p->user_filter);
    free(p->dst_name);
}

void fp01_field_free_helper(void) {
    struct para p;
    p.user_filter = strdup("a");
    p.dst_name = strdup("b");
    ur_para_free(&p);
}

void fp02_regfree(void) {
    regex_t regex;
    regcomp(&regex, "pat", 0);
    regfree(&regex);
}

int main(void) {
    fp01_field_free_helper();
    fp02_regfree();
    return 0;
}
