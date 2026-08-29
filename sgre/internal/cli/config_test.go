package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

func TestConfigCmd_HelpSelfDescribes(t *testing.T) {
	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		return Execute(ctx, []string{"config", "--help"})
	})
	if code != 0 {
		t.Fatalf("config --help: exit %d", code)
	}
	for _, marker := range []string{"trusted_macros", "trusted-macro", ".codeagent/secguard.toml", "secguard config --example"} {
		if !strings.Contains(stdout, marker) {
			t.Errorf("config --help: missing marker %q, got:\n%s", marker, stdout)
		}
	}
}

func TestConfigCmd_ExampleIsCopyPaste(t *testing.T) {
	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		return Execute(ctx, []string{"config", "--example"})
	})
	if code != 0 {
		t.Fatalf("config --example: exit %d", code)
	}
	if !strings.Contains(stdout, "[trusted_macros]") {
		t.Errorf("config --example: missing [trusted_macros], got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "names") {
		t.Errorf("config --example: missing names, got:\n%s", stdout)
	}
}

func TestConfigCmd_ReportsEffective(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(path, []byte("[trusted_macros]\nnames = [\"MACRO_A\"]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config.SetExplicitPath("")
	t.Cleanup(func() { config.SetExplicitPath("") })

	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		// --config is a global flag parsed by Execute, so pass it on the
		// command line rather than relying on the process-global setter.
		return Execute(ctx, []string{"config", "--config", path})
	})
	if code != 0 {
		t.Fatalf("config: exit %d", code)
	}
	for _, marker := range []string{`"path"`, `"loaded"`, `"trusted_macros"`, "MACRO_A"} {
		if !strings.Contains(stdout, marker) {
			t.Errorf("config: missing marker %q, got:\n%s", marker, stdout)
		}
	}
}
