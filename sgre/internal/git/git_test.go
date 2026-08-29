package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseUnifiedDiff(t *testing.T) {
	text := `diff --git a/src/foo.c b/src/foo.c
index 111..222 100644
--- a/src/foo.c
+++ b/src/foo.c
@@ -10,0 +11,3 @@
+int a;
+int b;
+int c;
diff --git a/src/added.c b/src/added.c
new file mode 100644
--- /dev/null
+++ b/src/added.c
@@ -0,0 +1,2 @@
+#include <stdio.h>
+int main(void) { return 0; }
diff --git a/src/deleted.c b/src/deleted.c
deleted file mode 100644
--- a/src/deleted.c
+++ /dev/null
@@ -1,3 +0,0 @@
-int x;
-int y;
-int z;
diff --git a/src/old.c b/src/new.c
similarity index 90%
rename from src/old.c
rename to src/new.c
`
	d := &Diff{Base: "b", Head: "h"}
	d.parseUnifiedDiff(text)

	if len(d.Files) != 4 {
		t.Fatalf("expected 4 files, got %d", len(d.Files))
	}

	m := d.Files[0]
	if m.Status != "M" || m.Path != "src/foo.c" {
		t.Errorf("modified file: got status=%q path=%q", m.Status, m.Path)
	}
	if !reflect.DeepEqual(m.Lines, []int{11, 12, 13}) {
		t.Errorf("modified file lines: got %v, want [11 12 13]", m.Lines)
	}

	a := d.Files[1]
	if a.Status != "A" || a.Path != "src/added.c" {
		t.Errorf("added file: got status=%q path=%q", a.Status, a.Path)
	}
	if !reflect.DeepEqual(a.Lines, []int{1, 2}) {
		t.Errorf("added file lines: got %v, want [1 2]", a.Lines)
	}

	del := d.Files[2]
	if del.Status != "D" || del.Path != "src/deleted.c" {
		t.Errorf("deleted file: got status=%q path=%q", del.Status, del.Path)
	}
	if len(del.Lines) != 0 {
		t.Errorf("deleted file should have no added lines, got %v", del.Lines)
	}

	r := d.Files[3]
	if r.Status != "R" || r.Path != "src/new.c" || r.OldPath != "src/old.c" {
		t.Errorf("renamed file: got status=%q path=%q old=%q", r.Status, r.Path, r.OldPath)
	}
}

func TestDiffIntegration(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}

	dir := t.TempDir()
	runGit := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}

	runGit("init", "-q")
	write("a.c", "int f(void){ return 0; }\nint g(void){ return 1; }\n")
	runGit("add", ".")
	runGit("commit", "-q", "-m", "base")

	// Second commit adds three lines after line 1.
	write("a.c", "int f(void){ return 0; }\nint added1;\nint added2;\nint added3;\nint g(void){ return 1; }\n")
	write("new.c", "int main(void){ return 0; }\n")
	runGit("add", ".")
	runGit("commit", "-q", "-m", "head")

	base, err := RevParse(dir, "HEAD~1")
	if err != nil {
		t.Fatalf("RevParse: %v", err)
	}
	head, err := RevParse(dir, "HEAD")
	if err != nil {
		t.Fatalf("RevParse: %v", err)
	}
	if base == head {
		t.Fatal("base and head should differ")
	}

	d, err := ComputeDiff(dir, base, head)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}

	byPath := map[string]FileDiff{}
	for _, f := range d.Files {
		byPath[f.Path] = f
	}

	m, ok := byPath["a.c"]
	if !ok {
		t.Fatalf("expected a.c in diff, got %v", d.Files)
	}
	if !reflect.DeepEqual(m.Lines, []int{2, 3, 4}) {
		t.Errorf("a.c added lines: got %v, want [2 3 4]", m.Lines)
	}
	if _, ok := byPath["new.c"]; !ok {
		t.Errorf("expected new.c in diff, got %v", d.Files)
	}
}

func TestMergeBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	dir := t.TempDir()
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte("int x;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "c")
	base, err := MergeBase(dir, "HEAD", "HEAD")
	if err != nil {
		t.Fatalf("MergeBase HEAD HEAD: %v", err)
	}
	if base == "" {
		t.Error("expected a merge-base sha")
	}
}
