#include <stdio.h>

void test_crlf_injection_fp_const_header(FILE *sock) {
    fprintf(sock, "Content-Type: text/html\r\n");
}

void test_crlf_injection_fp_log_context(char *user_input, FILE *logfile) {
    fprintf(logfile, "%s\n", user_input);
}

void test_crlf_injection_fp_ambiguous(char *user_input, FILE *fp) {
    fprintf(fp, "%s\n", user_input);
}