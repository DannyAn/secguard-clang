package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Issue #253 P0-4: the stale sweep must classify a Go runtime fatal error from
// scan.log. The old classifier read only the last 40 lines, but the runtime
// prints "fatal error" first and then a huge traceback, so the signal was
// outside the tail — and runtime fatal output reaches scan.log only because
// newScanLogger mirrors it through debug.SetCrashOutput.
func TestMarkScanDirFailedClassifiesRuntimeFatal(t *testing.T) {
	root := t.TempDir()
	id := "sc_2026-11-10_120000_abcdef"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(`{"level":"INFO","msg":"phase timing","phase":"index"}` + "\n")
	b.WriteString("runtime: goroutine stack exceeds 1000000000-byte limit\n")
	b.WriteString("fatal error: stack overflow\n")
	for i := 0; i < 20000; i++ {
		b.WriteString("goroutine 1 [running]:\n\tinternal/evidence.boundedByParam(...)\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.log"), []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	markScanDirFailed(root, id)
	marker, err := os.ReadFile(filepath.Join(dir, ".failed"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if !strings.Contains(string(marker), "crash") {
		t.Errorf(".failed must classify a runtime fatal error as a crash, got %q", marker)
	}
}

func TestMarkScanDirFailedClassifiesInterrupted(t *testing.T) {
	root := t.TempDir()
	id := "sc_2026-11-10_120001_abcdef"
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scan.log"), []byte(`{"level":"INFO","msg":"phase timing","phase":"index"}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	markScanDirFailed(root, id)
	marker, err := os.ReadFile(filepath.Join(dir, ".failed"))
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if !strings.Contains(string(marker), "interrupted") || strings.Contains(string(marker), "fatal error in scan.log") {
		t.Errorf(".failed must not claim a crash without a fatal signal, got %q", marker)
	}
}
