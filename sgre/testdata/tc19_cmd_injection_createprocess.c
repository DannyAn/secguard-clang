#include <stdlib.h>

void test_create_process_injection(char *user_input) {
    char cmd[256];
    extern int wsprintfA(char *, const char *, ...);
    extern int CreateProcessA(void *, char *, void *, void *, int, int, void *, void *, void *, void *);
    wsprintfA(cmd, "cmd.exe /c %s", user_input);
    CreateProcessA(0, cmd, 0, 0, 0, 0, 0, 0, 0, 0);
}