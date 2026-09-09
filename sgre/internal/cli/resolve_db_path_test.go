package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/report"
)

// TestResolveExistingDBPath_FindsProjectDBFromScanDir locks in the "two
// databases" fix: a consumer command run from inside scans/<id>/ (or
// scans/latest/ via the symlink) must resolve to the PROJECT's sgre.db, never
// mint a second one under the scan dir. This mirrors the documented recovery
// step where the orchestrator `cd`s into the scan directory.
func TestResolveExistingDBPath_FindsProjectDBFromScanDir(t *testing.T) {
	root := t.TempDir()
	dbPath := report.GetDbPath(root)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}

	scanDir := filepath.Join(root, report.CodeagentDir, report.ProductDir, report.ScansDir, "sc_2026-01-01_000000_aaaaaa")
	if err := os.MkdirAll(scanDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Simulate the orchestrator cd'ing into the scan dir (and its latest symlink
	// alias) before re-running a consuming command.
	for _, cwd := range []string{scanDir, scanDir + "/candidates/null-deref"} {
		if err := os.MkdirAll(cwd, 0755); err != nil {
			t.Fatal(err)
		}
		t.Chdir(cwd)

		got, found := resolveExistingDBPath(false, "./sgre.db")
		if !found {
			t.Fatalf("cwd=%s: expected an existing DB to be found up the tree", cwd)
		}
		gotAbs, err := filepath.Abs(got)
		if err != nil {
			t.Fatal(err)
		}
		wantAbs, err := filepath.Abs(dbPath)
		if err != nil {
			t.Fatal(err)
		}
		if gotAbs != wantAbs {
			t.Fatalf("cwd=%s: resolved DB = %s, want project DB %s", cwd, gotAbs, wantAbs)
		}
		// The scan dir itself must NOT have gained a nested .codeagent.
		nested := filepath.Join(scanDir, report.CodeagentDir, report.ProductDir, report.SgreDir, report.DbName)
		if _, err := os.Stat(nested); err == nil {
			t.Fatalf("cwd=%s: a nested DB was created at %s", cwd, nested)
		}
	}
}

// TestResolveExistingDBPath_NotExists reports found=false when no DB exists
// anywhere up the tree, so consumers error instead of creating an empty DB.
func TestResolveExistingDBPath_NotExists(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)

	got, found := resolveExistingDBPath(false, "./sgre.db")
	if found {
		t.Fatalf("expected found=false, got path %s", got)
	}
	// Must not have created the DB anywhere under root.
	if _, err := os.Stat(report.GetDbPath(root)); err == nil {
		t.Fatal("resolveExistingDBPath must not create a DB")
	}
}

// TestResolveExistingDBPath_ExplicitWins reports the explicit --db verbatim.
func TestResolveExistingDBPath_ExplicitWins(t *testing.T) {
	got, found := resolveExistingDBPath(true, "/some/custom.db")
	if !found {
		t.Fatal("explicit --db must always report found=true")
	}
	if got != "/some/custom.db" {
		t.Fatalf("got %s, want /some/custom.db", got)
	}
}
