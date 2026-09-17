#include <syslog.h>

void test_log_injection_fp_const_syslog(void) {
    syslog(6, "user logged in successfully");
}

void test_log_injection_fp_structured(char *user_input) {
    log_structured("event", user_input);
}

void test_log_injection_fp_const_msg(FILE *logfile) {
    fprintf(logfile, "Static message\n");
}