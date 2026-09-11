/*
 * TC109 - CWE-676: calls to banned/obsolete libc functions.
 * Vulnerability: gets (no bounds), mktemp (insecure temp), gethostbyname
 *                (obsolete), bcopy (obsolete BSD).
 * Expected: DANGEROUS_FUNCTION events for gets/mktemp/gethostbyname/bcopy.
 * Negative: memcpy is NOT in the banned list.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

int tc109_dangerous_function(char *dst, const char *src) {
    char buf[256];
    gets(buf);                       /* CWE-242 — banned */
    char tpl[] = "/tmp/xxxxxx";
    mktemp(tpl);                     /* CWE-377 — banned */
    gethostbyname("localhost");      /* CWE-477 — banned */
    bcopy(src, dst, 16);             /* CWE-477 — banned */
    memcpy(dst, src, 16);            /* not banned */
    return 0;
}
