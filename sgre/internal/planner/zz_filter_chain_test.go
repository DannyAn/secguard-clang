//go:build !nosqlite

package planner

import (
	"testing"
)

// TestFilterChainMigration pins the Phase-7 migration contract: every
// registered vuln type exposes a non-empty FilterFactories after
// RegisterVulnType (either declared explicitly by the type or populated from
// FilterChain by the bridge). The ORDER of the factories must match the
// legacy switch's semantics — filter order is part of the pipeline contract
// (earlier filters drop cheap non-candidates before the expensive flow /
// interval filters run).
func TestFilterChainMigration(t *testing.T) {
	expectedOrder := map[string][]string{
		"null-deref":        {"sizeof_pseudo_deref", "non_nullable_array_suppress", "array_oob_precedence", "nullable_source", "macro_uncertain", "call_reach", "safe_function_exclude"},
		"memory-leak":       {"call_reach", "safe_function_exclude", "has_release", "ownership_transfer", "leak_proof"},
		"buffer-overflow":   {"call_reach", "safe_function_exclude", "range_oob", "buffer_range"},
		"out-of-bounds":     {"call_reach", "safe_function_exclude", "range_oob", "buffer_range"},
		"resource-leak":     {"call_reach", "safe_function_exclude", "has_release", "ownership_transfer", "leak_proof"},
		"use-after-free":    {"call_reach", "safe_function_exclude", "lifetime"},
		"uninit":            {"call_reach", "definite_init", "safe_function_exclude"},
		"double-free":       {"call_reach", "safe_function_exclude", "double_free_flow"},
		"injection":         {"call_reach", "safe_function_exclude", "taint_source"},
		"path-traversal":    {"call_reach", "safe_function_exclude", "taint_source"},
		"format-string":     {"call_reach", "safe_function_exclude", "taint_source"},
		"integer-overflow":  {"call_reach", "safe_function_exclude", "int_overflow_guard", "unsigned_sub_guard"},
		"divide-by-zero":    {"call_reach", "safe_function_exclude", "range"},
		"deadlock":          {"call_reach", "safe_function_exclude", "lock_order"},
		"race-condition":    {"call_reach", "safe_function_exclude", "shared_access"},
		"unchecked-return":  {"call_reach", "safe_function_exclude", "return_check"},
		"hardcoded-secret":  {"call_reach", "safe_function_exclude", "hardcoded_secret_proof"},
		"implicit-contract": {"call_reach", "safe_function_exclude", "contract_gap"},
	}

	for _, typeName := range AllVulnTypes() {
		spec, err := GetVulnTypeSpec(typeName)
		if err != nil {
			t.Fatalf("GetVulnTypeSpec(%q): %v", typeName, err)
		}
		if len(spec.FilterFactories) == 0 {
			t.Errorf("type %s: FilterFactories is empty after RegisterVulnType bridge", typeName)
			continue
		}
		// Build the filters and verify names match the expected order (when
		// the type has an explicit expectation registered).
		pl := &Planner{}
		filters, err := pl.buildFilters(spec)
		if err != nil {
			t.Errorf("type %s: buildFilters error: %v", typeName, err)
			continue
		}
		want, ok := expectedOrder[typeName]
		if !ok {
			// Types on the default chain (crypto-misuse, signed-compare,
			// sizeof-misuse, signal-handler, dangerous-function, argument-type,
			// data-representation) just need call_reach + safe_function_exclude.
			if len(filters) != 2 || filters[0].Name() != "call_reach" || filters[1].Name() != "safe_function_exclude" {
				t.Errorf("type %s (default chain): got %d filters [%v], want [call_reach safe_function_exclude]", typeName, len(filters), filterNames(filters))
			}
			continue
		}
		if len(filters) != len(want) {
			t.Errorf("type %s: got %d filters, want %d %v", typeName, len(filters), len(want), want)
			continue
		}
		for i, w := range want {
			if filters[i].Name() != w {
				t.Errorf("type %s filter[%d]: got %q, want %q", typeName, i, filters[i].Name(), w)
			}
		}
	}
}

func filterNames(filters []Filter) []string {
	out := make([]string, len(filters))
	for i, f := range filters {
		out[i] = f.Name()
	}
	return out
}
