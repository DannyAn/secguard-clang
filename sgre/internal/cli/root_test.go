package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestExecute_SubcommandHelpLongFlag(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		cmd    string
		marker string
	}{
		{"index", "Index a C codebase"},
		{"scan", "Full pipeline"},
		{"status", "Show index status"},
		{"query", "Run a skill query"},
		{"types", "List all registered vulnerability types"},
		{"plan", "convergence pipeline"},
		{"report", "Output, persist, or audit findings"},
		{"db", "Execute a SQL query"},
		{"schema", "Show the DB schema"},
	}
	for _, c := range cases {
		stdout, _, code := captureOutput(func() int {
			return Execute(ctx, []string{c.cmd, "--help"})
		})
		if code != 0 {
			t.Errorf("%s --help: expected exit 0, got %d", c.cmd, code)
		}
		if !strings.Contains(stdout, c.marker) {
			t.Errorf("%s --help: stdout missing marker %q, got: %s", c.cmd, c.marker, stdout)
		}
		if !strings.Contains(stdout, "--help, -h") {
			t.Errorf("%s --help: usage should document --help, -h flag", c.cmd)
		}
	}
}

func TestExecute_SubcommandHelpShortFlag(t *testing.T) {
	ctx := context.Background()
	for _, cmd := range []string{"scan", "report", "status", "types"} {
		stdout, _, code := captureOutput(func() int {
			return Execute(ctx, []string{cmd, "-h"})
		})
		if code != 0 {
			t.Errorf("%s -h: expected exit 0, got %d", cmd, code)
		}
		if stdout == "" {
			t.Errorf("%s -h: expected non-empty usage", cmd)
		}
	}
}

func TestExecute_TopLevelHelpUnchanged(t *testing.T) {
	ctx := context.Background()
	for _, flag := range []string{"--help", "-h", "help"} {
		stdout, _, code := captureOutput(func() int {
			return Execute(ctx, []string{flag})
		})
		if code != 0 {
			t.Errorf("top-level %s: expected exit 0, got %d", flag, code)
		}
		if !strings.Contains(stdout, "AI-Augmented Program Security Analysis Platform") {
			t.Errorf("top-level %s: missing platform banner", flag)
		}
		if !strings.Contains(stdout, "Usage:") {
			t.Errorf("top-level %s: missing Usage section", flag)
		}
	}
}

func TestExecute_NoHelpFallsThrough(t *testing.T) {
	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		return Execute(ctx, []string{"types"})
	})
	if code != 0 {
		t.Fatalf("types (no help): expected exit 0, got %d", code)
	}
	if strings.Contains(stdout, "Show this usage") {
		t.Error("types (no help): should not print usage, should run the command")
	}
	if !strings.Contains(stdout, "\"count\"") {
		t.Errorf("types (no help): should output types JSON, got: %s", stdout)
	}
}

func TestExecute_UnknownSubcommandHelp(t *testing.T) {
	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		return Execute(ctx, []string{"bogus", "--help"})
	})
	if code == 0 && bytes.Contains([]byte(stdout), []byte("--help, -h")) {
		t.Error("unknown subcommand --help: should not print subcommand usage")
	}
}

func TestHasHelpFlag(t *testing.T) {
	cases := []struct {
		args []string
		want bool
	}{
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"--db", "x", "--help"}, true},
		{[]string{"--db", "x", "-h"}, true},
		{[]string{"--db", "x"}, false},
		{[]string{}, false},
		{[]string{"--helpme"}, false},
	}
	for _, c := range cases {
		if got := hasHelpFlag(c.args); got != c.want {
			t.Errorf("hasHelpFlag(%v) = %v, want %v", c.args, got, c.want)
		}
	}
}
