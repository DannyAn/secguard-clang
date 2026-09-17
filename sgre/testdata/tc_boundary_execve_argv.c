#include <unistd.h>

void test_boundary_execve_argv_tainted(char **argv) {
    execve("/bin/ls", argv, NULL);
}
