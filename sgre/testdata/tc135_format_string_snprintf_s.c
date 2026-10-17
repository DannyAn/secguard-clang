/*
 * TC135 - format-string: snprintf_s / vsnprintf_s must read the format from
 * the correct argument slot. The MSVC signature is (buf, size, count, fmt,
 * ...) so the format is args[3] — args[2] is the count (sizeof(buf) or
 * _TRUNCATE). The C11 Annex K layout (s, n, fmt, ...) puts the format at
 * args[2]; the detector probes which slot holds the string literal so both
 * layouts are covered. Reading args[2] unconditionally turned the MSVC count
 * argument into a phantom non-literal format (false positive).
 */

#include <stdio.h>
#include <stdarg.h>

/* MSVC layout, literal format at args[3]: must NOT be reported. */
void literal_snprintf_s_msvc(char *buf, size_t n, const char *src) {
    snprintf_s(buf, n, n, "%s", src);
}

/* MSVC layout, variable format at args[3]: must be reported. */
void var_snprintf_s_msvc(char *buf, size_t n, const char *fmt, const char *src) {
    snprintf_s(buf, n, n, fmt, src);
}

/* MSVC layout with _TRUNCATE count, literal format: must NOT be reported. */
void literal_truncate_snprintf_s_msvc(char *buf, size_t n, const char *src) {
    snprintf_s(buf, n, _TRUNCATE, "%s", src);
}

/* C11 Annex K layout (s, n, fmt), literal format at args[2]: must NOT be
 * reported. */
void literal_snprintf_s_annexk(char *buf, size_t n) {
    snprintf_s(buf, n, "%d", 1);
}

/* C11 Annex K layout, variable format at args[2]: must be reported. */
void var_snprintf_s_annexk(char *buf, size_t n, const char *fmt) {
    snprintf_s(buf, n, fmt);
}

/* MSVC v-variant: vsnprintf_s(buf, size, count, fmt, ap) — literal at
 * args[3]: must NOT be reported. */
void literal_vsnprintf_s_msvc(char *buf, size_t n, va_list ap) {
    vsnprintf_s(buf, n, n, "%s", ap);
}

/* MSVC v-variant, variable format at args[3]: must be reported. */
void var_vsnprintf_s_msvc(char *buf, size_t n, const char *fmt, va_list ap) {
    vsnprintf_s(buf, n, n, fmt, ap);
}