#include <stdio.h>

void test_log_injection_fputs_tp(char *user_input, FILE *logfile) {
    fputs(user_input, logfile);
}

void test_log_injection_fwrite_tp(char *user_input, FILE *logfile) {
    fwrite(user_input, 1, 256, logfile);
}
