#include <stdlib.h>
#include <unistd.h>

void test_arg_injection_tp(char *user_input) {
    char *argv[3];
    argv[0] = "ls";
    argv[1] = user_input;
    argv[2] = NULL;
    execve("/bin/ls", argv, NULL);
}

void test_arg_injection_tp_execlp(char *user_input) {
    execlp("grep", "grep", user_input, NULL);
}