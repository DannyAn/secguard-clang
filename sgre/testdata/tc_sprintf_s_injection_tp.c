#include <stdio.h>
#include <stdlib.h>

void test_crlf_injection_sprintf_s_tp(char *user_input, int fd) {
    char buf[256];
    sprintf_s(buf, sizeof(buf), "Set-Cookie: %s\r\n", user_input);
    send(fd, buf, 256, 0);
}

void test_cmd_injection_sprintf_s_tp(char *user_input) {
    char cmd[256];
    sprintf_s(cmd, sizeof(cmd), "ls %s", user_input);
    system(cmd);
}