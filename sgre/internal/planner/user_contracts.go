package planner

import (
	"sync"

	"github.com/DannyAn/secguard-clang/internal/config"
)

var (
	userContractsOnce sync.Once
	userContractsMap  map[string]config.Contract
)

// userContracts returns the user-declared tree-external contracts, loaded once
// per process (config is read at CLI startup, before any plan stage runs). The
// sync.Once avoids re-reading secguard.toml per candidate — buildHintParts runs
// per candidate and must not hit the filesystem.
func userContracts() map[string]config.Contract {
	userContractsOnce.Do(func() {
		userContractsMap = config.Load().ContractBySymbol()
	})
	return userContractsMap
}

// resetUserContractsForTest clears the cached contracts map so a test can re-load
// a fresh config (test seam).
func resetUserContractsForTest() {
	userContractsOnce = sync.Once{}
	userContractsMap = nil
}

// appendContractHints emits the contract tokens for a candidate whose callee
// (api@) has a user-declared contract. It is a pure function so it is testable
// without touching the global config; buildHintParts feeds it the cached map.
func appendContractHints(parts []string, c Candidate, contracts map[string]config.Contract) []string {
	if c.APIName == "" {
		return parts
	}
	ct, ok := contracts[c.APIName]
	if !ok {
		return parts
	}
	parts = append(parts, "user-contract@"+c.APIName)
	if ct.TakesOwnership != "" {
		parts = append(parts, "takes-ownership@"+ct.TakesOwnership)
	}
	for _, p := range ct.OutParams {
		parts = append(parts, "outparam@"+p)
	}
	if ct.Releases != "" {
		parts = append(parts, "release@"+ct.Releases)
	}
	return parts
}
