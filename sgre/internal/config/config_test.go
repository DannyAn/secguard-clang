package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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

func TestLoad_ExcludePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[exclude]
paths = ["./svc/src/bak/", "src/generated"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	got := cfg.ExcludePaths()
	if len(got) != 2 || got[0] != "./svc/src/bak/" || got[1] != "src/generated" {
		t.Errorf("expected [./svc/src/bak/ src/generated], got %v", got)
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

func TestLoad_DisabledTypes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[disabled_types]
types = ["path-traversal", " divide-by-zero ", "path-traversal"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()

	names := cfg.DisabledTypeNames()
	// Trimmed and deduped.
	if len(names) != 2 || names[0] != "path-traversal" || names[1] != "divide-by-zero" {
		t.Fatalf("DisabledTypeNames = %v, want [path-traversal divide-by-zero]", names)
	}

	set := cfg.DisabledTypeSet()
	if len(set) != 2 || !set["path-traversal"] || !set["divide-by-zero"] {
		t.Fatalf("DisabledTypeSet = %v", set)
	}
}

// TestFileExists_RejectsDirectory guards the probe-path fix: a directory named
// secguard.toml must not pass the existence probe and then fail the subsequent
// ReadFile (EISDIR); it should be treated as "no config here".
func TestFileExists_RejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if fileExists(dir) {
		t.Errorf("fileExists(%q) = true for a directory, want false", dir)
	}
	file := filepath.Join(dir, "real.toml")
	if err := os.WriteFile(file, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	if !fileExists(file) {
		t.Errorf("fileExists(%q) = false for a regular file, want true", file)
	}
}

func TestDisabledTypeSet_Empty(t *testing.T) {
	var c *Config
	if c.DisabledTypeSet() != nil {
		t.Errorf("nil Config must yield a nil disabled set, got %v", c.DisabledTypeSet())
	}
	if c.DisabledTypeNames() != nil {
		t.Errorf("nil Config must yield nil disabled names, got %v", c.DisabledTypeNames())
	}
	if (&Config{}).DisabledTypeSet() != nil {
		t.Errorf("zero Config must yield a nil disabled set")
	}
}

func TestLoad_AllocatorsDeallocators(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[allocators]
names = ["VOS_MALLOC", "VOS_MALLOC_F"]

[deallocators]
names = ["VOS_FREE", "VOS_FREE_F"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	if got := cfg.AllocatorNames(); len(got) != 2 || got[0] != "VOS_MALLOC" || got[1] != "VOS_MALLOC_F" {
		t.Errorf("allocators = %v, want [VOS_MALLOC VOS_MALLOC_F]", got)
	}
	if got := cfg.DeallocatorNames(); len(got) != 2 || got[0] != "VOS_FREE" || got[1] != "VOS_FREE_F" {
		t.Errorf("deallocators = %v, want [VOS_FREE VOS_FREE_F]", got)
	}
}
func TestLoad_OwnershipTransferCalls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[ownership_transfer_calls]
names = ["list_push_back", "dict_set", "buffer_append"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	got := cfg.OwnershipTransferCallNames()
	want := []string{"list_push_back", "dict_set", "buffer_append"}
	if len(got) != len(want) {
		t.Fatalf("ownership_transfer_calls = %v, want %v", got, want)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("ownership_transfer_calls[%d] = %q, want %q", i, got[i], w)
		}
	}
}

func TestLoad_IntegerOverflowTruncatingWrappers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[integer_overflow.truncating_wrappers]
nlog_syslog_add_pri = 1
nlog_syslog_add_hostname = 1
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	got := cfg.IntegerOverflowTruncatingWrappers()
	if len(got) != 2 || got["nlog_syslog_add_pri"] != 1 || got["nlog_syslog_add_hostname"] != 1 {
		t.Errorf("integer_overflow.truncating_wrappers = %v, want two wrappers with cap arg 1", got)
	}
}
func TestLoad_SanitizeFunctions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[sanitize_functions]
names = ["my_basename", "sanitize_path_segment"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	if got := cfg.SanitizeFunctionNames(); len(got) != 2 || got[0] != "my_basename" || got[1] != "sanitize_path_segment" {
		t.Errorf("sanitize_functions = %v, want [my_basename sanitize_path_segment]", got)
	}
}

// TestLoad_LogsOnUnreadableConfig pins the v0.10 warning contract: a config
// file that resolves but cannot be read (or parses invalid TOML) must produce
// a stderr warning, not silent zero-config degradation. This was the root
// cause of the v0.7.0 disabled_types/exclude "silently off" incident.
func TestLoad_LogsOnUnreadableConfig(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "secguard.toml")
	if err := os.WriteFile(bad, []byte("[not toml"), 0644); err != nil {
		t.Fatal(err)
	}

	old := explicitPath
	t.Cleanup(func() { explicitPath = old })
	explicitPath = bad

	// Capture stderr.
	oldStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = oldStderr })

	cfg := Load()

	w.Close()
	os.Stderr = oldStderr
	out, _ := io.ReadAll(r)
	r.Close()

	if cfg == nil {
		t.Fatal("Load returned nil config on parse failure")
	}
	if !strings.Contains(string(out), "config load warning") {
		t.Fatalf("expected stderr warning about config load failure, got: %q", string(out))
	}
}

// [nullability.non_null_params] is the no-code-change lever for a BOUNDARY
// scan's largest null-deref bucket (framework-supplied pointer parameters).
func TestLoad_NonNullParams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nnp.toml")
	content := `[nullability.non_null_params]
names = ["user_data", "reply_msg", "out_msg"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	got := cfg.NonNullParamNames()
	want := []string{"user_data", "reply_msg", "out_msg"}
	if len(got) != len(want) {
		t.Fatalf("NonNullParamNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("NonNullParamNames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if n := len(cfg.NonNullReturnNames()); n != 0 {
		t.Errorf("non_null_params must not leak into non_null_returns, got %d names", n)
	}
}
