package planner

import (
	"os"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
)

// TestMain pins the boundary auto-dismiss mode to "off" for the planner
// package's convergence tests. The package's null-deref fixtures are small
// snippets with no `main`, so they are classified as BOUNDARY scans by
// accident; their assertions target the convergence logic (tier classification,
// flow analysis, recall) — not the boundary pre-dismissal layer, which the
// production default now enables ("external"). Pinning the override here keeps
// those tests on their original intent; the tests that exercise the NEW default
// (e.g. TestNullDeref_BoundaryFailOpenDefaultDismisses) clear the override
// themselves and restore it in a cleanup.
// The complete-program precision tier is likewise pinned to "off": fixtures
// that DO contain a `main` would otherwise be complete-program scans whose
// non-proving tiers are pre-dismissed by the production default ("balanced",
// issue #253 P0-6). The dedicated precision-tier tests clear this override.
func TestMain(m *testing.M) {
	config.SetBoundaryAutoDismissOverride("off")
	config.SetPrecisionTierOverride("off")
	os.Exit(m.Run())
}
