package build

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCompileCommands(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compile_commands.json")
	content := `[
  {"directory": "/src", "arguments": ["cc", "-DMAX_LEN=4096", "-I", "inc", "-DFOO=0", "main.c"]},
  {"directory": "/src", "command": "cc -DBAR=1 -I../lib -DX_NONNUMERIC=abc main2.c"}
]`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cc, err := LoadCompileCommands(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cc.Defines["MAX_LEN"] != 4096 {
		t.Errorf("MAX_LEN = %d, want 4096", cc.Defines["MAX_LEN"])
	}
	if cc.Defines["FOO"] != 0 {
		t.Errorf("FOO = %d, want 0", cc.Defines["FOO"])
	}
	if cc.Defines["BAR"] != 1 {
		t.Errorf("BAR = %d, want 1", cc.Defines["BAR"])
	}
	if _, ok := cc.Defines["X_NONNUMERIC"]; ok {
		t.Errorf("X_NONNUMERIC (non-numeric) must be dropped")
	}
	if len(cc.IncludeDirs) != 2 {
		t.Errorf("IncludeDirs = %v, want [inc ../lib]", cc.IncludeDirs)
	}
}
