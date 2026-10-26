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

void variable_caller(const char *msg)
{
    log_mixed(msg);
}
`
		result := planType(t, src, "format-string")
		if _, ok := result["log_mixed"]; !ok {
			t.Errorf("log_mixed: a caller passes a variable format, the wrapper must stay a candidate")
		}
	})
}

// The census classified call-site arguments by SYNTAX only, so a caller that
// binds the format to a local (or a struct field) holding a compile-time string
// was counted as `var`. Those are constants: the wrapper's in-tree callers all
// pass literal templates, which makes the format parameter non-attacker-
// controlled and the finding a false positive (production reported exactly this
// for a vprintf wrapper whose callers pass local/field templates).
func TestFormatString_LocalAndFieldConstantsCountAsLiteral(t *testing.T) {
	src := `#include <stdio.h>

#define POOL_INFO_DEF "%s %u"

void log_msg(const char *fmt)
{
    printf(fmt);
}

typedef struct { const char *fmt_ipv4; } ui_t;

void caller_local(void)
{
    const char *fmt = "hello %s";
    log_msg(fmt);
}

void caller_local_macro(void)
{
    const char *fmt = POOL_INFO_DEF;
    log_msg(fmt);
}

void caller_field(ui_t *ui)
{
    ui->fmt_ipv4 = "ip %s";
    log_msg(ui->fmt_ipv4);
}
`
	result := planType(t, src, "format-string")
	if c, ok := result["log_msg"]; ok {
		t.Fatalf("log_msg: all three callers bind a compile-time string (local, macro, field); must not be a candidate (hint=%v)", c.Hint)
	}
}

// Precision control: a local reassigned to a non-constant (or left possibly
// mutated by an intervening call) must NOT be promoted to literal.
func TestFormatString_LocalNotConstantStaysVariable(t *testing.T) {
	src := `#include <stdio.h>

extern void refresh(void);

void log_msg2(const char *fmt)
{
    printf(fmt);
}

void caller_reassigned(const char *user_fmt)
{
    const char *fmt = "template";
    fmt = user_fmt;
    log_msg2(fmt);
}

void caller_intervening_call(void)
{
    const char *fmt = "template";
    refresh();
    log_msg2(fmt);
}
`
	result := planType(t, src, "format-string")
	c, ok := result["log_msg2"]
	if !ok {
		t.Fatalf("log_msg2: call sites are not provable constants, the wrapper must stay a candidate")
	}
	if c.SuspicionLevel != "suspected" && c.SuspicionLevel != "confirmed" {
		t.Errorf("unexpected suspicion level %q", c.SuspicionLevel)
	}
}

// The census summary is a count; the evidence needs the WHICH. CallsiteSites
// carries the bounded per-site breakdown (file:line + class) so the classifier
// can see the non-constant callers without a grep round.
func TestFormatString_CallsiteSitesEmbedded(t *testing.T) {
	src := `#include <stdio.h>

void log_msg(const char *fmt)
{
    printf(fmt);
}

void caller_literal(void)
{
    log_msg("hello %s");
}

void caller_buf(void)
{
    char buf[64];
    buf[0] = 'x';
    buf[1] = 0;
    log_msg(buf);
}
`
	// planType returns one EvidenceItem per function; log_msg is the sink.
	res := planType(t, src, "format-string")
	c, ok := res["log_msg"]
	if !ok {
		t.Fatalf("log_msg must stay a suspected candidate (mixed literal/var callers)")
	}
	if len(c.CallsiteSites) != 2 {
		t.Fatalf("CallsiteSites = %+v, want the 2 concrete call sites", c.CallsiteSites)
	}
	classes := map[string]bool{}
	for _, s := range c.CallsiteSites {
		classes[s.Class] = true
		if s.Line <= 0 || s.File == "" {
			t.Errorf("site %+v must carry a file and a line", s)
		}
	}
	if !classes["literal"] || !classes["variable"] {
		t.Errorf("expected one literal and one variable site, got %+v", c.CallsiteSites)
	}
}
