/*
 * TC132 - format-string: the Annex K `_s` printf variants must use their real
 * format-argument index. fprintf_s(FILE*, fmt, ...) / vfprintf_s(FILE*, fmt, ap)
 * put the format at args[1]; the detector treated args[0] (the FILE*) as the
 * format, so a LITERAL format was reported as a non-literal sink (false
 * positive) and a variable format carried the wrong evidence.
 */

#include <stdio.h>
#include <stdarg.h>

/* Literal format: must NOT be reported (args[1] is the string literal). */
void literal_fprintf_s(FILE *fp) {
    fprintf_s(fp, "%d\n", 1);
}

/* Variable format at args[1]: must be reported. */
void var_fprintf_s(FILE *fp, const char *fmt) {
    fprintf_s(fp, fmt, 1);
}

/* Variable format at args[1] for the v-variant: must be reported. */
void var_vfprintf_s(FILE *fp, const char *fmt, va_list ap) {
    vfprintf_s(fp, fmt, ap);
}

/* Literal v-variant: must NOT be reported. */
void literal_vfprintf_s(FILE *fp, va_list ap) {
    vfprintf_s(fp, "%s", ap);
}
