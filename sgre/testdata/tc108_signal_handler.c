/*
 * TC108 - CWE-479: signal handler calls a non-async-signal-safe function.
 * Vulnerability: signal(SIGALRM, watchdog_handler) registers a handler whose
 *                body calls malloc/printf — not async-signal-safe.
 * Expected: SIGNAL_HANDLER event for watchdog_handler (unsafe call).
 * Negative: safe_handler calls only write() (async-signal-safe) — no event.
 */

#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

static volatile sig_atomic_t g_flag;

static void watchdog_handler(int sig) {
    (void)sig;
    char *buf = malloc(64);          /* NOT async-signal-safe */
    (void)buf;
}

static void safe_handler(int sig) {
    (void)sig;
    g_flag = 1;                      /* only a volatile flag write */
}

static void logger_handler(int sig) {
    (void)sig;
    printf("caught signal\n");       /* NOT async-signal-safe */
}

int tc108_signal_handler(void) {
    signal(SIGALRM, watchdog_handler);
    signal(SIGUSR1, safe_handler);
    signal(SIGTERM, logger_handler);
    return 0;
}
