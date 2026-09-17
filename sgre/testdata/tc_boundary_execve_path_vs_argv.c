#include <unistd.h>

void test_boundary_execve_path_tainted(char *user_input_path) {
    char *argv[] = {"ls", "-l", NULL};
    execve(user_input_path, argv, NULL);
}