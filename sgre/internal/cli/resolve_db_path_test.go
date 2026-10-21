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

// TestResolveExistingDBPath_NotExists reports found=false when no DB exists in
// the searched tree, so consumers error instead of creating an empty DB.
//
// It drives resolveExistingDBPathFrom with an explicit boundary instead of the
// cwd-based entry point: the production walk climbs the real filesystem, so
// "nothing above this temp dir has a DB" is a property the test cannot control.
// It used to fail on any checkout whose TMPDIR sits inside the repository (the
// documented `TMPDIR=$PWD/.tmpcache` invocation puts t.TempDir() under
// sgre/.tmpcache, and a single scan artifact in sgre/.codeagent is then found on
// the way up). The boundary makes the assertion deterministic.
func TestResolveExistingDBPath_NotExists(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}

	got, found := resolveExistingDBPathFrom(false, "./sgre.db", sub, root)
	if found {
		t.Fatalf("expected found=false, got path %s", got)
	}
	// Must not have created the DB anywhere under root.
	if _, err := os.Stat(report.GetDbPath(root)); err == nil {
		t.Fatal("resolveExistingDBPath must not create a DB")
	}
}

// TestResolveExistingDBPath_StopBoundary pins the explicit stop: a DB above the
// boundary belongs to someone else and must not be adopted, while the same tree
// searched without a boundary does find it (the legacy unbounded walk).
func TestResolveExistingDBPath_StopBoundary(t *testing.T) {
	root := t.TempDir()
	// The enclosing project's DB sits at the temp root — an ANCESTOR of the
	// boundary (a sibling would never be visited by an upward walk).
	project := filepath.Join(root, "project")
	sub := filepath.Join(project, "a", "b")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	dbPath := report.GetDbPath(root)
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}

	if got, found := resolveExistingDBPathFrom(false, "./sgre.db", sub, project); found {
		t.Fatalf("must not escape the boundary: got %s", got)
	}
	got, found := resolveExistingDBPathFrom(false, "./sgre.db", sub, "")
	if !found {
		t.Fatalf("without a boundary the ancestor DB must be found")
	}
	if gotAbs, _ := filepath.Abs(got); gotAbs != dbPath {
		t.Fatalf("got %s, want %s", gotAbs, dbPath)
	}
}

// TestResolveExistingDBPath_StopsAtProjectRoot pins the production boundary: the
// walk stops at the first ancestor carrying `.git`, so a stale DB from an
// enclosing checkout is never adopted silently by a command run inside a
// different project.
func TestResolveExistingDBPath_StopsAtProjectRoot(t *testing.T) {
	base := t.TempDir()
	// A DB that belongs to an enclosing tree (the "wrong project").
	outer := report.GetDbPath(base)
	if err := os.MkdirAll(filepath.Dir(outer), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outer, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	sub := filepath.Join(project, "x", "y")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0755); err != nil {
		t.Fatal(err)
	}

	if got, found := resolveExistingDBPathFrom(false, "./sgre.db", sub, ""); found {
		t.Fatalf("the walk must stop at the project root, got %s", got)
	}
	// A DB AT the project root is still found (checked before the boundary).
	own := report.GetDbPath(project)
	if err := os.MkdirAll(filepath.Dir(own), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(own, []byte("fake"), 0644); err != nil {
		t.Fatal(err)
	}
	if got, found := resolveExistingDBPathFrom(false, "./sgre.db", sub, ""); !found || got != own {
		t.Fatalf("project-root DB must be found, got %s found=%v", got, found)
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
