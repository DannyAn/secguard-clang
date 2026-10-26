/*
 * TC109 - CWE-676: calls to banned libc/runtime functions.
 * Vulnerability: gets (no bounds), mktemp (insecure temp), gethostbyname
 *                (obsolete), plus the non-_s policy families:
 *                memmove / memcpy / strcpy / sprintf / atoi.
 * Expected: DANGEROUS_FUNCTION events for each banned call.
 * Negative: the _s variants and the recommended replacements are NOT banned,
 *           and neither is the deprecated BSD trio (bzero/bcopy/bcmp): it has no
 *           _s counterpart and a project's own banned-function guideline
 *           routinely omits it, so the default policy must not assert it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>

int tc109_dangerous_function(char *dst, const char *src) {
    char buf[256];
    char tpl[] = "/tmp/xxxxxx";
    int n;

    gets(buf);                       /* unsafe_scan - banned */
    mktemp(tpl);                     /* insecure_temp - banned */
    gethostbyname("localhost");      /* obsolete_api - banned */
    memmove(dst, src, 16);           /* unsafe_memory - banned */

    memcpy(dst, src, 16);            /* unsafe_memory - banned */
    strcpy(dst, src);                /* unsafe_string - banned */
    sprintf(dst, "%s", src);         /* unsafe_format - banned */
    n = atoi(src);                   /* unchecked_conversion - banned */

    memcpy_s(dst, 16, src, 16);      /* safe _s variant - NOT banned */
    strcpy_s(dst, 16, src);          /* safe _s variant - NOT banned */
    sprintf_s(dst, 16, "%s", src);   /* safe _s variant - NOT banned */
    n = (int)strtol(src, NULL, 10);  /* recommended replacement - NOT banned */

    /* Deprecated BSD trio: NOT in the default ban table. */
    bzero(buf, sizeof(buf));
    bcopy(src, dst, 16);
    n += bcmp(src, dst, 16);

    return n;
}
