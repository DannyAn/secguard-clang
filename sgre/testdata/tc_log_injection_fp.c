#include <syslog.h>

void test_log_injection_fp_const_syslog(void) {
    syslog(6, "user logged in successfully");
}

void test_log_injection_fp_structured(char *user_input) {
    log_structured("event", user_input);
}

void test_log_injection_fp_protocol_header(char *user_input, FILE *sock) {
    fprintf(sock, "Header: %s\r\n", user_input);
}