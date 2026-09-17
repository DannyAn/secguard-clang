#include <stdio.h>
#include <unistd.h>

void test_crlf_injection_tp_fprintf(char *user_input, FILE *sock) {
    fprintf(sock, "X-Custom-Header: %s\r\n", user_input);
}

void test_crlf_injection_tp_send(char *user_input, int fd) {
    char buf[256];
    snprintf(buf, sizeof(buf), "Set-Cookie: %s\r\n", user_input);
    send(fd, buf, 256, 0);
}