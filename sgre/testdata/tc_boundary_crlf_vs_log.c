#include <stdio.h>
#include <syslog.h>

void test_boundary_crlf(char *user_input, FILE *sock) {
    fprintf(sock, "X-Header: %s\r\n", user_input);
}

void test_boundary_log(char *user_input) {
    syslog(6, "%s", user_input);
}