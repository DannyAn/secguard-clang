package report

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUpdateLatest_CreatesSymlink(t *testing.T) {
	scansDir := t.TempDir()
	scanID := "2026-08-11_143022_a1b2"
	if err := os.MkdirAll(filepath.Join(scansDir, scanID), 0755); err != nil {
		t.Fatal(err)
	}

	if err := UpdateLatest(scansDir, scanID); err != nil {
		t.Fatalf("UpdateLatest failed: %v", err)
	}

	if runtime.GOOS == "windows" {
		t.Skip("symlink assertion skipped on Windows")
	}

	target, err := os.Readlink(filepath.Join(scansDir, LatestName))
	if err != nil {
		t.Fatalf("failed to read symlink: %v", err)
	}
	if target != scanID {
		t.Errorf("expected symlink target %q, got %q", scanID, target)
	}
}

func TestUpdateLatest_ReplacesExistingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test skipped on Windows")
	}

	scansDir := t.TempDir()
	scanA := "scan_a"
	scanB := "scan_b"
	os.MkdirAll(filepath.Join(scansDir, scanA), 0755)
	os.MkdirAll(filepath.Join(scansDir, scanB), 0755)

	if err := UpdateLatest(scansDir, scanA); err != nil {
		t.Fatalf("first UpdateLatest failed: %v", err)
	}
	target, _ := os.Readlink(filepath.Join(scansDir, LatestName))
	if target != scanA {
		t.Errorf("expected target %q, got %q", scanA, target)
	}

	if err := UpdateLatest(scansDir, scanB); err != nil {
		t.Fatalf("second UpdateLatest failed: %v", err)
	}
	target, _ = os.Readlink(filepath.Join(scansDir, LatestName))
	if target != scanB {
		t.Errorf("expected target %q after replace, got %q", scanB, target)
	}
}

func TestUpdateLatest_NoStaleTempRemains(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test skipped on Windows")
	}

	scansDir := t.TempDir()
	scanID := "scan_x"
	os.MkdirAll(filepath.Join(scansDir, scanID), 0755)

	staleTmp := filepath.Join(scansDir, fmt.Sprintf(latestTmpFmt, os.Getpid()))
	os.Symlink("old_scan", staleTmp)

	if err := UpdateLatest(scansDir, scanID); err != nil {
		t.Fatalf("UpdateLatest failed: %v", err)
	}

	if _, err := os.Lstat(staleTmp); err == nil {
		t.Error("stale temp symlink still exists after UpdateLatest")
	}
}

func TestUpdateLatest_FallbackLatestTxt(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("fallback test only runs on Windows without symlink support")
	}

	scansDir := t.TempDir()
	scanID := "2026-08-11_143022_a1b2"
	os.MkdirAll(filepath.Join(scansDir, scanID), 0755)

	if err := UpdateLatest(scansDir, scanID); err != nil {
		t.Fatalf("UpdateLatest failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(scansDir, LatestTxtName))
	if err != nil {
		t.Fatalf("failed to read latest.txt: %v", err)
	}
	if string(content) != scanID {
		t.Errorf("expected latest.txt content %q, got %q", scanID, string(content))
	}
}

func TestUpdateLatest_LatestTxtContentHasNoTrailingNewline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink path tested on Windows fallback instead")
	}

	scansDir := t.TempDir()
	scanID := "2026-08-11_143022_a1b2"
	os.MkdirAll(filepath.Join(scansDir, scanID), 0755)

	if err := writeLatestTxt(scansDir, scanID); err != nil {
		t.Fatalf("writeLatestTxt failed: %v", err)
	}

	content, err := os.ReadFile(filepath.Join(scansDir, LatestTxtName))
	if err != nil {
		t.Fatalf("failed to read latest.txt: %v", err)
	}
	if string(content) != scanID {
		t.Errorf("expected %q with no trailing newline, got %q", scanID, string(content))
	}
}
