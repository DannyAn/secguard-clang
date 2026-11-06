package config

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
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

// TestResolvePath_SuggestedConfigLocation pins the rename-in-place adoption flow:
// the index stage writes .codeagent/secguard-clang/secguard.toml.suggested, and
// dropping the suffix lands a config the loader probes.
func TestResolvePath_SuggestedConfigLocation(t *testing.T) {
	dir := t.TempDir()
	sug := filepath.Join(dir, ".codeagent", "secguard-clang", "secguard.toml")
	if err := os.MkdirAll(filepath.Dir(sug), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sug, []byte(`[allocators]
names = ["my_malloc"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	if got := ResolvedPath(); got != sug {
		t.Errorf("ResolvedPath = %q, want adopted-suggestion %q", got, sug)
	}
	cfg := Load()
	if got := cfg.AllocatorNames(); len(got) != 1 || got[0] != "my_malloc" {
		t.Errorf("AllocatorNames = %v, want [my_malloc] (rename-in-place must be adoptable)", got)
	}
}

func TestResolvePath_DocumentedProjectWinsOverSuggestion(t *testing.T) {
	dir := t.TempDir()
	doc := filepath.Join(dir, ".codeagent", "secguard.toml")
	sug := filepath.Join(dir, ".codeagent", "secguard-clang", "secguard.toml")
	for _, p := range []string{doc, sug} {
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(""), 0644); err != nil {
			t.Fatal(err)
		}
	}
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)
	if got := ResolvedPath(); got != doc {
		t.Errorf("ResolvedPath = %q, want documented project-level %q", got, doc)
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

// [banned_functions] exclude trims the DEFAULT policy: a project's own security
// guideline is the authority on which functions are banned, so a built-in it
// does not list must be removable without editing the tool.
func TestLoad_BannedFunctionExclude(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "banned.toml")
	content := `[banned_functions]
names   = ["my_legacy_alloc"]
exclude = ["bzero", "realloc"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	if got := cfg.BannedFunctionNames(); len(got) != 1 || got[0] != "my_legacy_alloc" {
		t.Errorf("BannedFunctionNames() = %v, want [my_legacy_alloc]", got)
	}
	got := cfg.BannedFunctionExcludeNames()
	want := []string{"bzero", "realloc"}
	if len(got) != len(want) {
		t.Fatalf("BannedFunctionExcludeNames() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("BannedFunctionExcludeNames()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLoad_SwitchAndGraphSections(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `
[switch]
fallthrough_markers = ["FALLTHRU", "intentional"]
noreturn_functions = ["my_abort"]

[graph]
indirect_call_resolution = false
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECGUARD_CONFIG", path)
	SetExplicitPath("") // clear any explicit path set by a prior test
	cfg := Load()
	markers := cfg.MergedFallthroughMarkers()
	joined := strings.Join(markers, "|")
	for _, want := range []string{"fallthrough", "FALLTHRU", "intentional"} {
		if !strings.Contains(joined, want) {
			t.Errorf("MergedFallthroughMarkers missing %q: %s", want, joined)
		}
	}
	noreturn := cfg.MergedNoreturnFunctions()
	if !noreturn["my_abort"] || !noreturn["longjmp"] {
		t.Errorf("MergedNoreturnFunctions should include my_abort + built-in longjmp, got %v", noreturn)
	}
	if cfg.IndirectCallResolutionEnabled() {
		t.Errorf("IndirectCallResolutionEnabled should be false when configured false")
	}
}

func TestLoad_SkipDetectors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[scan]
skip_detectors = ["unchecked_return", " memory_leak ", "unchecked_return"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	SetSkipDetectorsOverride("")
	cfg := Load()

	names := cfg.SkipDetectorNames()
	if len(names) != 2 || names[0] != "unchecked_return" || names[1] != "memory_leak" {
		t.Fatalf("SkipDetectorNames = %v, want [unchecked_return memory_leak]", names)
	}
	set := cfg.SkipDetectorSet()
	if len(set) != 2 || !set["unchecked_return"] || !set["memory_leak"] {
		t.Fatalf("SkipDetectorSet = %v", set)
	}

	// The CLI override REPLACES the configured list (a flag names exactly what
	// this run should skip), and an empty override restores the file.
	SetSkipDetectorsOverride("signed_compare, ,uninit")
	if got := cfg.SkipDetectorNames(); len(got) != 2 || got[0] != "signed_compare" || got[1] != "uninit" {
		t.Fatalf("SkipDetectorNames with override = %v, want [signed_compare uninit]", got)
	}
	SetSkipDetectorsOverride("")
	if got := cfg.SkipDetectorNames(); len(got) != 2 || got[0] != "unchecked_return" {
		t.Fatalf("SkipDetectorNames after clearing override = %v", got)
	}
}

func TestLoad_UninitInitializationMacros(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secguard.toml")
	content := `[uninit]
initialization_macros = ["CMD_MSG_INIT", "msg_ctx_fill"]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath(path)
	cfg := Load()
	got := cfg.UninitInitializationMacros()
	if len(got) != 2 || got[0] != "CMD_MSG_INIT" || got[1] != "msg_ctx_fill" {
		t.Errorf("[uninit] initialization_macros = %v, want [CMD_MSG_INIT msg_ctx_fill]", got)
	}
}

func TestTypeFilterOverride(t *testing.T) {
	SetTypeFilterOverride("")
	if got := (&Config{}).TypeFilterSet(); got != nil {
		t.Fatalf("empty override must yield a nil set, got %v", got)
	}

	SetTypeFilterOverride("format-string, ,injection,format-string")
	set := (&Config{}).TypeFilterSet()
	if len(set) != 2 || !set["format-string"] || !set["injection"] {
		t.Fatalf("TypeFilterSet = %v, want {format-string, injection}", set)
	}

	// "all" is the documented "no filter" sentinel.
	SetTypeFilterOverride("all")
	if got := (&Config{}).TypeFilterSet(); got != nil {
		t.Fatalf("override \"all\" must yield a nil set, got %v", got)
	}

	SetTypeFilterOverride("")
	if got := (&Config{}).TypeFilterSet(); got != nil {
		t.Fatalf("cleared override must yield a nil set, got %v", got)
	}
}

func TestCgroupMemoryLimitPaths(t *testing.T) {
	v2, v1 := cgroupMemoryLimitPaths("12:memory:/docker/abc\n0::/docker/abc\n1:name=systemd:/user.slice\n")
	wantV2 := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/docker/abc/memory.max",
		"/sys/fs/cgroup/docker/memory.max",
		"/sys/fs/cgroup/memory.max",
	}
	for _, w := range wantV2 {
		found := false
		for _, p := range v2 {
			if p == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("v2 candidates %v missing %q", v2, w)
		}
	}
	wantV1 := "/sys/fs/cgroup/memory/docker/abc/memory.limit_in_bytes"
	foundV1 := false
	for _, p := range v1 {
		if p == wantV1 {
			foundV1 = true
		}
	}
	if !foundV1 {
		t.Errorf("v1 candidates %v missing %q", v1, wantV1)
	}
}

func TestMinCgroupLimit(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := write("a", "100\n")
	b := write("b", "50\n")
	c := write("c", "max\n")
	missing := filepath.Join(dir, "missing")
	if got := minCgroupLimit([]string{a, b, c, missing}); got != 50 {
		t.Errorf("minCgroupLimit = %d, want 50 (smallest finite ancestor limit)", got)
	}
	if got := minCgroupLimit([]string{c, missing}); got != 0 {
		t.Errorf("minCgroupLimit with no finite limit = %d, want 0", got)
	}
}

func TestReadCgroupLimit(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	finite := write("finite", "34359738368\n")
	if v, ok := readCgroupLimit(finite); !ok || v != 34359738368 {
		t.Errorf("finite limit = (%d, %v), want (34359738368, true)", v, ok)
	}

	if v, ok := readCgroupLimit(write("max", "max\n")); ok || v != 0 {
		t.Errorf("max sentinel = (%d, %v), want (0, false)", v, ok)
	}

	if v, ok := readCgroupLimit(write("unlimited", strconv.FormatInt(cgroupV1UnlimitedSentinel, 10)+"\n")); ok || v != 0 {
		t.Errorf("v1 unlimited sentinel = (%d, %v), want (0, false)", v, ok)
	}

	if v, ok := readCgroupLimit(filepath.Join(dir, "missing")); ok || v != 0 {
		t.Errorf("missing file = (%d, %v), want (0, false)", v, ok)
	}
}
func TestConfigChecksum_NoConfigReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	if got := ConfigChecksum(); got != "default" {
		t.Errorf("ConfigChecksum with no config = %q, want %q", got, "default")
	}
}

func TestConfigChecksum_ReflectsConfigContent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".codeagent", "secguard.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`[allocators]
names = ["my_malloc"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	cs1 := ConfigChecksum()
	if cs1 == "default" {
		t.Fatal("ConfigChecksum should not be default when config exists")
	}

	cs2 := ConfigChecksum()
	if cs1 != cs2 {
		t.Fatalf("ConfigChecksum not stable: %q vs %q", cs1, cs2)
	}

	if err := os.WriteFile(cfgPath, []byte(`[allocators]
names = ["my_other_malloc"]
`), 0644); err != nil {
		t.Fatal(err)
	}
	cs3 := ConfigChecksum()
	if cs3 == cs1 {
		t.Fatal("ConfigChecksum should change when config content changes")
	}
}
func TestLoadE_ParseFailureReturnsDefaultsWithDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".codeagent", "secguard.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`this is not valid TOML = = =`), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	cfg, err := LoadE()
	if err == nil {
		t.Fatal("LoadE should return error on parse failure")
	}
	if cfg == nil {
		t.Fatal("LoadE should return non-nil cfg on parse failure")
	}
	if cfg.Scan.MaxCachedTrees != 4000 {
		t.Fatalf("parse failure should return cfg with applyScanDefaults, MaxCachedTrees=%d want 4000", cfg.Scan.MaxCachedTrees)
	}
	if cfg.Scan.CFGCacheMaxEntries != 4000 {
		t.Fatalf("parse failure should return cfg with applyScanDefaults, CFGCacheMaxEntries=%d want 4000", cfg.Scan.CFGCacheMaxEntries)
	}
	if cfg.Scan.EventBatchSize != 2000 {
		t.Fatalf("parse failure should return cfg with applyScanDefaults, EventBatchSize=%d want 2000", cfg.Scan.EventBatchSize)
	}
}

func TestConfigChecksum_ParseFailureReturnsDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, ".codeagent", "secguard.toml")
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, []byte(`this is not valid TOML = = =`), 0644); err != nil {
		t.Fatal(err)
	}
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	if got := ConfigChecksum(); got != "default" {
		t.Fatalf("ConfigChecksum on parse failure = %q, want %q (must match LoadE's effective zero-defaults config)", got, "default")
	}
}

func TestConfigChecksum_SuggestedMissingScanStillWorks(t *testing.T) {
	dir := t.TempDir()
	SetExplicitPath("")
	t.Setenv("SECGUARD_CONFIG", "")
	t.Chdir(dir)

	cfg := Load()
	if cfg == nil {
		t.Fatal("Load should return non-nil cfg even with no config")
	}
	if cfg.Scan.MaxCachedTrees != 4000 {
		t.Fatalf("no-config Load MaxCachedTrees=%d want 4000", cfg.Scan.MaxCachedTrees)
	}
	if got := ConfigChecksum(); got != "default" {
		t.Fatalf("no-config ConfigChecksum = %q, want %q", got, "default")
	}
}
