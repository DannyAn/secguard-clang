package planner

import (
	"fmt"
	"sort"
	"strings"
)

type VulnTypeSpec struct {
	Name             string
	SeedEventType    string
	EvidenceType     string
	DefaultSuspicion string
	FilterChain      string
	BuildEvidence    func(c Candidate) []EvidenceFragment
}

var vulnTypeRegistry = map[string]*VulnTypeSpec{}

func RegisterVulnType(spec *VulnTypeSpec) {
	vulnTypeRegistry[spec.Name] = spec
}

func GetVulnTypeSpec(name string) (*VulnTypeSpec, error) {
	spec, ok := vulnTypeRegistry[name]
	if !ok {
		return nil, fmt.Errorf("planner: unsupported vulnerability type %q (supported: %s)", name, AllVulnTypeNames())
	}
	return spec, nil
}

func AllVulnTypeNames() string {
	names := AllVulnTypes()
	return strings.Join(names, ", ")
}

func AllVulnTypes() []string {
	names := make([]string, 0, len(vulnTypeRegistry))
	for name := range vulnTypeRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func AllSeedEventTypes() []string {
	seen := make(map[string]bool)
	for _, spec := range vulnTypeRegistry {
		seen[spec.SeedEventType] = true
	}
	result := make([]string, 0, len(seen))
	for et := range seen {
		result = append(result, et)
	}
	sort.Strings(result)
	return result
}

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:             "null-deref",
		SeedEventType:    "DEREFERENCE",
		EvidenceType:     "NULL_DEREFERENCE",
		DefaultSuspicion: "confirmed",
		FilterChain:      "null-deref",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "nullable_source", Detail: fmt.Sprintf("variable %s has NULL_VALUE source", c.VariableName)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
				{Type: "data_flow", Detail: fmt.Sprintf("NULL value propagates to dereference at line %d", c.Line)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "buffer-overflow",
		SeedEventType:    "BUFFER_ACCESS",
		EvidenceType:     "BUFFER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "buffer_access", Detail: fmt.Sprintf("buffer access in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "memory-leak",
		SeedEventType:    "MEMORY_ALLOC",
		EvidenceType:     "MEMORY_LEAK",
		DefaultSuspicion: "suspected",
		FilterChain:      "memory-leak",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "memory_alloc", Detail: fmt.Sprintf("allocation in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "injection",
		SeedEventType:    "INJECTION",
		EvidenceType:     "INJECTION",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "unsafe_call", Detail: fmt.Sprintf("unsafe function call in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "resource-leak",
		SeedEventType:    "RESOURCE_ACQUIRE",
		EvidenceType:     "RESOURCE_LEAK",
		DefaultSuspicion: "suspected",
		FilterChain:      "resource-leak",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "resource_acquire", Detail: fmt.Sprintf("resource acquired in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "uninit",
		SeedEventType:    "VALUE_USE",
		EvidenceType:     "UNINIT_USE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "uninit_use", Detail: fmt.Sprintf("uninitialized variable used in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "use-after-free",
		SeedEventType:    "USE_AFTER_FREE",
		EvidenceType:     "USE_AFTER_FREE",
		DefaultSuspicion: "suspected",
		FilterChain:      "lifetime",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "use_after_free", Detail: fmt.Sprintf("variable freed then used in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "double-free",
		SeedEventType:    "DOUBLE_FREE",
		EvidenceType:     "DOUBLE_FREE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "double_free", Detail: fmt.Sprintf("variable freed twice in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "format-string",
		SeedEventType:    "FORMAT_STRING",
		EvidenceType:     "FORMAT_STRING_VULN",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "format_string", Detail: fmt.Sprintf("printf-family called with non-literal format in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "integer-overflow",
		SeedEventType:    "INTEGER_OVERFLOW",
		EvidenceType:     "INTEGER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "integer_overflow", Detail: fmt.Sprintf("arithmetic overflow in size calculation in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "race-condition",
		SeedEventType:    "RACE_CONDITION",
		EvidenceType:     "RACE_CONDITION",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "toctou", Detail: fmt.Sprintf("time-of-check-time-of-use in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "hardcoded-secret",
		SeedEventType:    "HARDCODED_SECRET",
		EvidenceType:     "HARDCODED_SECRET",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "hardcoded_secret", Detail: fmt.Sprintf("hardcoded secret in %s at line %d", c.FunctionName, c.Line)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "deadlock",
		SeedEventType:    "DEADLOCK",
		EvidenceType:     "DEADLOCK",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "deadlock", Detail: fmt.Sprintf("lock-order inversion (potential deadlock) in %s at line %d", c.FunctionName, c.Line)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "crypto-misuse",
		SeedEventType:    "CRYPTO_MISUSE",
		EvidenceType:     "CRYPTO_MISUSE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "crypto_misuse", Detail: fmt.Sprintf("weak crypto in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}
