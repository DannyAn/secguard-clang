#include <stdio.h>

void test_crlf_injection_fputs_tp(char *user_input, FILE *sock) {
    fputs(user_input, sock);
}
