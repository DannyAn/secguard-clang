//go:build !nosqlite

package planner

import "testing"

// RL-01: string_join is a string concatenation, not a resource release, so an
// fd left unclosed by it must still be a leak.
func TestResourceLeakReview_SubstringNotReleaser(t *testing.T) {
	src := `#include <fcntl.h>
#include <unistd.h>
int rl_string_join(int x) {
    int fd = open("/x", 0);
    string_join("a", "b");
    return 0;
}
`
	got := planType(t, src, "resource-leak")
	if got["rl_string_join"].Target.Function == "" {
		t.Errorf("rl_string_join: fd leaks (string_join is not a release), got %v", keysOf(got))
	}
}

// RL-02: fd2 = fd; close(fd2) releases fd's handle — no leak.
func TestResourceLeakReview_AliasRelease(t *testing.T) {
	src := `#include <fcntl.h>
#include <unistd.h>
int rl_alias(int x) {
    int fd = open("/x", 0);
    int fd2 = fd;
    close(fd2);
    return 0;
}
`
	got := planType(t, src, "resource-leak")
	if got["rl_alias"].Target.Function != "" {
		t.Errorf("rl_alias: close(fd2) with fd2=fd releases fd, got %q", got["rl_alias"].Target.Function)
	}
}

// FS-01: err(eval, fmt, ...) puts the format at args[1]; err(eval, "literal")
// is NOT a format-string, err(eval, buf) is.
func TestFormatStringReview_ErrErrxIndex(t *testing.T) {
	src := `#include <err.h>
int fs_err_literal(int eval) { err(eval, "literal"); return 0; }
int fs_err_taint(int eval, char *buf) { err(eval, buf); return 0; }
`
	got := planType(t, src, "format-string")
	if got["fs_err_literal"].Target.Function != "" {
		t.Errorf("fs_err_literal: err(eval, \"literal\") has a constant format, got %q", got["fs_err_literal"].Target.Function)
	}
	if got["fs_err_taint"].Target.Function == "" {
		t.Errorf("fs_err_taint: err(eval, buf) has a non-literal format, got %v", keysOf(got))
	}
}

// FS-03: a u8/u/U-prefixed string literal is still a compile-time literal, not a
// tainted format.
func TestFormatStringReview_UTF8Literal(t *testing.T) {
	src := `#include <stdio.h>
int fs_u8(void) { printf(u8"literal"); return 0; }
int fs_plain(void) { printf("literal"); return 0; }
`
	got := planType(t, src, "format-string")
	if got["fs_u8"].Target.Function != "" {
		t.Errorf("fs_u8: u8\"literal\" is a constant literal, got %q", got["fs_u8"].Target.Function)
	}
	if got["fs_plain"].Target.Function != "" {
		t.Errorf("fs_plain: \"literal\" is a constant literal, got %q", got["fs_plain"].Target.Function)
	}
}

// INJ-01: CreateProcessA("app", cmd, ...) carries the tainted command line in
// args[1], not the constant args[0].
func TestInjectionReview_CreateProcessCmdLine(t *testing.T) {
	src := `#include <stdio.h>
int inj_cp(char *cmd) {
    char buf[64];
    snprintf(buf, 64, "%s", cmd);
    CreateProcessA("app.exe", buf, 0, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}
`
	got := planType(t, src, "injection")
	if got["inj_cp"].Target.Function == "" {
		t.Errorf("inj_cp: CreateProcessA's lpCommandLine (args[1]) is tainted, got %v", keysOf(got))
	}
}
