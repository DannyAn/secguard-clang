package db_test

import (
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestSupportedFindingCWEs_DefaultIsRegistrySubset locks the db package's
// built-in CWE set to the planner registry: the default map exists only so
// standalone db tests can persist findings, and it must never accept a rule_id
// the registry cannot produce. A removed or renamed VulnTypeSpec.CWE therefore
// fails here instead of lingering as an accepted-but-undetectable rule id.
//
// The production path is unchanged: cli/root.go replaces this default with
// planner.AllCWEs() at startup, so this test asserts the fallback, not the
// source of truth.
func TestSupportedFindingCWEs_DefaultIsRegistrySubset(t *testing.T) {
	registry := planner.AllCWEs()
	for cwe := range db.SupportedFindingCWEs {
		if !registry[cwe] {
			t.Errorf("db.SupportedFindingCWEs contains %s, which planner.AllCWEs() does not; the default map drifted from the registry", cwe)
		}
		if vulnType := planner.TypeForCWE(cwe); vulnType == "" {
			t.Errorf("db.SupportedFindingCWEs contains %s, which planner.TypeForCWE cannot reverse-map to a vulnerability type", cwe)
		}
	}
}

// TestSupportedFindingCWEs_CLIInjectionParity locks the production path: after
// the CLI's startup injection, the db layer accepts exactly the registry's CWE
// set. Every type's canonical, legacy and per-category CWE must be writable, and
// no CWE outside the registry may be.
func TestSupportedFindingCWEs_CLIInjectionParity(t *testing.T) {
	previous := db.SupportedFindingCWEs
	t.Cleanup(func() { db.SetSupportedCWEs(previous) })

	injected := planner.AllCWEs()
	db.SetSupportedCWEs(injected)

	for cwe := range injected {
		if !db.SupportedFindingCWEs[cwe] {
			t.Errorf("after planner.AllCWEs() injection, db rejects registry CWE %s", cwe)
		}
	}
	for cwe := range db.SupportedFindingCWEs {
		if !injected[cwe] {
			t.Errorf("after planner.AllCWEs() injection, db accepts %s which the registry does not declare", cwe)
		}
	}
}

// TestSupportedFindingCWEs_CanonicalCWEForEveryType guards the other direction:
// every registered vulnerability type's canonical CWE must be in the injected
// set, so a type whose CWE is silently blank or misspelled cannot produce
// unwritable findings.
func TestSupportedFindingCWEs_CanonicalCWEForEveryType(t *testing.T) {
	injected := planner.AllCWEs()
	for _, vulnType := range planner.AllVulnTypes() {
		cwe := planner.CWEForType(vulnType)
		if cwe == "" {
			t.Errorf("vulnerability type %s has no canonical CWE", vulnType)
			continue
		}
		if !injected[cwe] {
			t.Errorf("planner.AllCWEs() omits %s, the canonical CWE of %s", cwe, vulnType)
		}
	}
}
