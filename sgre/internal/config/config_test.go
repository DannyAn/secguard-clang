package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[trusted_macros]
names = ["MACRO_A", "MACRO_B"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	SetExplicitPath(path)
	cfg := Load()
	names := cfg.TrustedMacroNames()
	if len(names) != 2 || names[0] != "MACRO_A" || names[1] != "MACRO_B" {
		t.Errorf("expected [MACRO_A MACRO_B], got %v", names)
	}
}

func TestLoad_EnvVar(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "env.toml")
	content := `[trusted_macros]
names = ["ENV_MACRO"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECGUARD_CONFIG", path)
	SetExplicitPath("") // clear any explicit path set by a prior test

	cfg := Load()
	if got := cfg.TrustedMacroNames(); len(got) != 1 || got[0] != "ENV_MACRO" {
		t.Errorf("expected [ENV_MACRO], got %v", got)
	}
}

func TestLoad_MissingFileIsEmpty(t *testing.T) {
	SetExplicitPath(filepath.Join(t.TempDir(), "does-not-exist.toml"))
	cfg := Load()
	if cfg == nil {
		t.Fatal("Load must return a non-nil Config for a missing file")
	}
	if got := cfg.TrustedMacroNames(); len(got) != 0 {
		t.Errorf("expected no trusted macros, got %v", got)
	}
}

func TestLoad_IteratorMacros(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[iterator_macros.macros]
SAMPLE_Scan = [1]
POOL_FOR = [1]
LIST_FOR_EACH_SAFE = [0, 1]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	args := cfg.IteratorMacroArgs()
	if len(args) != 3 {
		t.Fatalf("expected 3 iterator macros, got %d: %v", len(args), args)
	}
	if got := args["SAMPLE_Scan"]; len(got) != 1 || got[0] != 1 {
		t.Errorf("SAMPLE_Scan = %v, want [1]", got)
	}
	if got := args["POOL_FOR"]; len(got) != 1 || got[0] != 1 {
		t.Errorf("POOL_FOR = %v, want [1]", got)
	}
	if got := args["LIST_FOR_EACH_SAFE"]; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("LIST_FOR_EACH_SAFE = %v, want [0 1]", got)
	}
}
