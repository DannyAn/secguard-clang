#include <syslog.h>

void test_log_injection_tp_syslog(char *user_input) {
    syslog(6, "%s", user_input);
}

void test_log_injection_tp_fprintf(char *user_input, FILE *logfile) {
    fprintf(logfile, "%s\n", user_input);
}