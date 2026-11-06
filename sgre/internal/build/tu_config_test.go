package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

func TestParseTUConfig_Basic(t *testing.T) {
	args := []string{"clang", "-c", "-DFOO=1", "-DBAR=42", "-Iinclude", "src/foo.c"}
	tc := parseTUConfig("src/foo.c", "/proj", args)
	if tc.File != "src/foo.c" {
		t.Errorf("File = %q; want src/foo.c", tc.File)
	}
	if tc.Directory != "/proj" {
		t.Errorf("Directory = %q; want /proj", tc.Directory)
	}
	if tc.ABI != typeinfo.ABILP64 {
		t.Errorf("ABI = %v; want lp64 (default)", tc.ABI)
	}
	if tc.Defines["FOO"] != 1 || tc.Defines["BAR"] != 42 {
		t.Errorf("Defines = %v; want FOO=1 BAR=42", tc.Defines)
	}
	if len(tc.IncludeDirs) != 1 || tc.IncludeDirs[0] != "include" {
		t.Errorf("IncludeDirs = %v; want [include]", tc.IncludeDirs)
	}
}

func TestParseTUConfig_m32(t *testing.T) {
	tc := parseTUConfig("x.c", "", []string{"clang", "-m32", "-c", "x.c"})
	if tc.ABI != typeinfo.ABIILP32 {
		t.Errorf("ABI = %v; want ilp32", tc.ABI)
	}
}

func TestParseTUConfig_TargetWindows(t *testing.T) {
	tc := parseTUConfig("x.c", "", []string{"clang", "--target=x86_64-windows-msvc", "x.c"})
	if tc.ABI != typeinfo.ABILLP64 {
		t.Errorf("ABI = %v; want llp64", tc.ABI)
	}
	if tc.Target != "x86_64-windows-msvc" {
		t.Errorf("Target = %q", tc.Target)
	}
}

func TestParseTUConfig_PackStruct(t *testing.T) {
	tc := parseTUConfig("x.c", "", []string{"clang", "-fpack-struct=4", "x.c"})
	if tc.PackStruct != 4 {
		t.Errorf("PackStruct = %d; want 4", tc.PackStruct)
	}
	tc2 := parseTUConfig("x.c", "", []string{"clang", "-fpack-struct", "x.c"})
	if tc2.PackStruct != 1 {
		t.Errorf("PackStruct = %d; want 1", tc2.PackStruct)
	}
}

func TestParseTUConfig_ShortEnums(t *testing.T) {
	tc := parseTUConfig("x.c", "", []string{"clang", "-fshort-enums", "x.c"})
	if !tc.ShortEnums {
		t.Error("ShortEnums should be true")
	}
}

func TestParseTUConfig_ConfigKey(t *testing.T) {
	tc := parseTUConfig("x.c", "", []string{"clang", "-m64", "-fpack-struct=8", "-DFOO=1", "x.c"})
	if tc.ConfigKey == "" {
		t.Error("ConfigKey should not be empty")
	}
	if tc.ConfigKey != "lp64:pack=8:D=FOO=1" {
		t.Errorf("ConfigKey = %q; want lp64:pack=8:D=FOO=1", tc.ConfigKey)
	}
}

func TestLoadCompileCommands_PerTU(t *testing.T) {
	dir := t.TempDir()
	ccPath := filepath.Join(dir, "compile_commands.json")
	entries := []map[string]interface{}{
		{"file": "a.c", "directory": dir, "arguments": []string{"clang", "-m32", "-c", "a.c"}},
		{"file": "b.c", "directory": dir, "arguments": []string{"clang", "-fpack-struct=2", "-c", "b.c"}},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(ccPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	cc, err := LoadCompileCommands(ccPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cc.TUs) != 2 {
		t.Fatalf("TUs len = %d; want 2", len(cc.TUs))
	}
	tuA := cc.TUForFile("a.c")
	if tuA == nil {
		t.Fatal("TUForFile(a.c) = nil")
	}
	if tuA.ABI != typeinfo.ABIILP32 {
		t.Errorf("a.c ABI = %v; want ilp32", tuA.ABI)
	}
	tuB := cc.TUForFile("b.c")
	if tuB == nil {
		t.Fatal("TUForFile(b.c) = nil")
	}
	if tuB.PackStruct != 2 {
		t.Errorf("b.c PackStruct = %d; want 2", tuB.PackStruct)
	}
	if cc.TUForFile("nonexistent.c") != nil {
		t.Error("TUForFile(nonexistent) should be nil")
	}
}

func TestAbiFromTriple(t *testing.T) {
	cases := []struct {
		triple string
		want   typeinfo.ABI
	}{
		{"x86_64-linux-gnu", typeinfo.ABILP64},
		{"aarch64-linux-musl", typeinfo.ABILP64},
		{"i686-linux-gnu", typeinfo.ABIILP32},
		{"armv7-linux-gnueabihf", typeinfo.ABIILP32},
		{"wasm32-unknown-unknown", typeinfo.ABIILP32},
		{"riscv64-linux-gnu", typeinfo.ABILP64},
		{"mips-linux-gnu", typeinfo.ABIILP32},
		{"x86_64-pc-windows-msvc", typeinfo.ABILLP64},
		{"x86_64-w64-mingw32", typeinfo.ABILLP64},
		{"i686-w64-mingw32", typeinfo.ABIILP32},
	}
	for _, c := range cases {
		if got := abiFromTriple(c.triple); got != c.want {
			t.Errorf("abiFromTriple(%q) = %s, want %s", c.triple, got, c.want)
		}
	}
}

func TestTUForFile_RelativeToDirectory(t *testing.T) {
	dir := t.TempDir()
	ccPath := filepath.Join(dir, "compile_commands.json")
	entries := []map[string]interface{}{
		{"file": "src/a.c", "directory": dir, "arguments": []string{"clang", "-m32", "-c", "src/a.c"}},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(ccPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	cc, err := LoadCompileCommands(ccPath)
	if err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "src", "a.c")
	if tu := cc.TUForFile(abs); tu == nil || tu.ABI != typeinfo.ABIILP32 {
		t.Errorf("TUForFile(%q) = %+v, want the directory-relative entry", abs, tu)
	}
	if tu := cc.TUForFile("src/a.c"); tu == nil {
		t.Errorf("TUForFile(relative) = nil, want match")
	}
}

func TestLoadCompileCommands_GlobalUnionPreserved(t *testing.T) {
	dir := t.TempDir()
	ccPath := filepath.Join(dir, "compile_commands.json")
	entries := []map[string]interface{}{
		{"file": "a.c", "directory": dir, "arguments": []string{"clang", "-DFOO=1", "-Iinc1", "a.c"}},
		{"file": "b.c", "directory": dir, "arguments": []string{"clang", "-DBAR=2", "-Iinc2", "b.c"}},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(ccPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	cc, err := LoadCompileCommands(ccPath)
	if err != nil {
		t.Fatal(err)
	}
	if cc.Defines["FOO"] != 1 || cc.Defines["BAR"] != 2 {
		t.Errorf("global Defines = %v; want FOO=1 BAR=2", cc.Defines)
	}
	if len(cc.IncludeDirs) != 2 {
		t.Errorf("global IncludeDirs len = %d; want 2", len(cc.IncludeDirs))
	}
}
