//go:build !nosqlite

package planner

import "testing"

// A call-site argument spelled with an object-like macro that expands to a
// string literal is a COMPILE-TIME CONSTANT. The format-string / path-traversal
// call-site census counted it as a variable (`2:2-var`), so the all-literal gate
// never fired and a wrapper whose every caller passes a constant format stayed
// in front of the classifier — production then confirmed it (CWE-134
// false positive). The census now resolves those macros; a genuinely variable
// caller still makes the wrapper a candidate.
func TestFormatString_MacroConstantCallerCountsAsLiteral(t *testing.T) {
	t.Run("all callers pass macro constants", func(t *testing.T) {
		src := `#include <stdio.h>

#define MSG_FMT "%d"
#define LOG_HELLO "hello %s"

void log_macro(const char *fmt)
{
    printf(fmt);
}

void callers(void)
{
    log_macro(MSG_FMT);
    log_macro(LOG_HELLO);
}
`
		result := planType(t, src, "format-string")
		if c, ok := result["log_macro"]; ok {
			t.Errorf("log_macro: every caller passes a constant string macro, must not be a candidate (hint=%v)", c.Hint)
		}
	})

	t.Run("a variable caller keeps it", func(t *testing.T) {
		src := `#include <stdio.h>

#define MSG_FMT "%d"

void log_mixed(const char *fmt)
{
    printf(fmt);
}

void literal_caller(void)
{
    log_macro_placeholder();
}

void variable_caller(const char *msg)
{
    log_mixed(msg);
}

void log_macro_placeholder(void) { }
`
		result := planType(t, src, "format-string")
		if _, ok := result["log_mixed"]; !ok {
			t.Errorf("log_mixed: a caller passes a variable format, the wrapper must stay a candidate")
		}
	})
}
