package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/report"
)

// runTypesCmd prints every registered vulnerability type with its CWE mapping.
// It is the single source of truth the security-auditor agent uses to discover
// and validate the current type list at runtime, so the agent never hardcodes
// a stale list when new detectors are added.
func runTypesCmd() int {
	names := planner.AllVulnTypes()
	types := make([]map[string]string, 0, len(names))
	for _, n := range names {
		types = append(types, map[string]string{
			"name": n,
			"cwe":  report.VulnToCWE(n),
		})
	}
	out := map[string]interface{}{
		"count": len(names),
		"types": types,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("types: marshal: %v", err))
		return 1
	}
	fmt.Fprintln(os.Stdout, string(b))
	return 0
}
