#include <stdlib.h>
#include <unistd.h>

void test_arg_injection_fp_const_literal(void) {
    execve("/bin/ls", (char *[]){"ls", "-l", NULL}, NULL);
}

void test_arg_injection_fp_execlp_const(void) {
    execlp("grep", "grep", "pattern", NULL);
}

void test_arg_injection_fp_execv_const(void) {
    execv("/bin/cat", (char *[]){"cat", NULL});
}
