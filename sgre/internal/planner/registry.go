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
	// ConvergeByVariable collapses multiple candidates for the same
	// (function, variable) into one. This is correct for variable-centric
	// types where a single nullable/tainted variable yields one DEREFERENCE
	// event per use site (null-deref) — one root cause should surface as one
	// finding, not one finding per dereferenced line.
	ConvergeByVariable bool
	// Categories, when non-empty, restricts the seed events to those whose
	// properties.category is listed. Detectors emit one event type with
	// multiple categories (BUFFER_ACCESS: unsafe call vs array OOB read vs
	// heap OOB write), and each category can seed a different vulnerability
	// type (e.g. buffer-overflow vs out-of-bounds).
	Categories []string
	// ConvergeKey overrides the dedup identity when multiple events in one
	// function/line/category represent the same root cause, e.g. srand() and
	// rand() for one weak PRNG defect, sprintf()+sqlite3_exec() for one SQL
	// injection, or the same integer overflow surfaced by two expressions on
	// one line.
	ConvergeKey   func(c Candidate) string
	BuildEvidence func(c Candidate) []EvidenceFragment
	// CategoryConfidence overrides DefaultSuspicion per event category. A
	// category is "confirmed" when the detector *proved* the defect (e.g. a
	// constant index past a known array size), versus "suspected" when it only
	// recognized a heuristic pattern (e.g. an unguarded strcpy). The AI agent
	// then spends its depth only on the suspected tier.
	CategoryConfidence map[string]string
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
		Name:               "null-deref",
		SeedEventType:      "DEREFERENCE",
		EvidenceType:       "NULL_DEREFERENCE",
		DefaultSuspicion:   "confirmed",
		FilterChain:        "null-deref",
		ConvergeByVariable: true,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			fragments := make([]EvidenceFragment, 0, 4)
			if c.HasDefiniteNull {
				fragments = append(fragments, EvidenceFragment{
					Type:   "definite_null",
					Detail: fmt.Sprintf("variable %s is assigned NULL and dereferenced at line %d with no intervening reassignment (certain null-deref)", c.VariableName, c.Line),
				})
			} else if c.HasNullableSource {
				fragments = append(fragments, EvidenceFragment{
					Type:   "nullable_source",
					Detail: fmt.Sprintf("variable %s is assigned a possibly-null value before the dereference at line %d", c.VariableName, c.Line),
				})
			}
			if c.IsReachable {
				fragments = append(fragments, EvidenceFragment{
					Type:   "call_path",
					Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName),
				})
			}
			if c.HasDataFlow {
				fragments = append(fragments, EvidenceFragment{
					Type:   "data_flow",
					Detail: fmt.Sprintf("NULL value propagates to dereference at line %d", c.Line),
				})
			}
			if len(fragments) == 0 {
				fragments = append(fragments, EvidenceFragment{
					Type:   "dereference",
					Detail: fmt.Sprintf("dereference of %s at line %d", c.VariableName, c.Line),
				})
			}
			return fragments
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "buffer-overflow",
		SeedEventType:    "BUFFER_ACCESS",
		EvidenceType:     "BUFFER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"buffer_overflow", "array_oob_write", "heap_oob_write", "format_overflow"},
		// Provable out-of-bounds writes (a constant index past a known array or
		// allocation size) are confirmed by the detector itself; an unguarded
		// unsafe call or sprintf remains a heuristic suspicion.
		CategoryConfidence: map[string]string{
			"array_oob_write": "confirmed",
			"heap_oob_write":  "confirmed",
		},
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
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("injection:%d:%s:%s", c.FileID, c.FunctionName, c.Category)
		},
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
		FilterChain:      "uninit",
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
		// One freed variable used at many sites is one defect, not one per use.
		ConvergeByVariable: true,
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
		FilterChain:      "double-free",
		// One variable freed twice is one defect, not one per (first,second) pair.
		ConvergeByVariable: true,
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
		// size_calc_overflow (malloc(a * b)) is a concrete CWE-190 pattern and
		// stays "suspected"; the wraparound-in-a-bounds-check pattern (the
		// arithmetic lives in the guard itself) is a theoretical wraparound —
		// correct code most of the time — so it is tiered down to "possible" so
		// the AI agent does not spend its depth budget on it.
		CategoryConfidence: map[string]string{
			"size_calc_overflow": "suspected",
			"integer_overflow":   "possible",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("integer-overflow:%d:%s:%d", c.FileID, c.FunctionName, c.Line)
		},
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
			if c.Category == "shared_data_race" {
				return []EvidenceFragment{
					{Type: "data_race", Detail: fmt.Sprintf("unsynchronized shared-variable access in %s at line %d", c.FunctionName, c.Line)},
					{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
				}
			}
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
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("crypto-misuse:%d:%s:%s", c.FileID, c.FunctionName, c.Category)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "crypto_misuse", Detail: fmt.Sprintf("weak crypto in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "out-of-bounds",
		SeedEventType:    "BUFFER_ACCESS",
		EvidenceType:     "OUT_OF_BOUNDS",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"array_oob_read", "heap_oob_read"},
		// A read-flavored OOB is only emitted when the detector proved the
		// index outruns the array/allocation, so it is confirmed, not suspected.
		CategoryConfidence: map[string]string{
			"array_oob_read": "confirmed",
			"heap_oob_read":  "confirmed",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "out_of_bounds", Detail: fmt.Sprintf("out-of-bounds access in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "divide-by-zero",
		SeedEventType:    "DIVIDE_BY_ZERO",
		EvidenceType:     "DIVIDE_BY_ZERO",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "divide_by_zero", Detail: fmt.Sprintf("possible division by zero in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "unchecked-return",
		SeedEventType:    "UNCHECKED_RETURN",
		EvidenceType:     "UNCHECKED_RETURN",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "unchecked_return", Detail: fmt.Sprintf("return value of %s is not checked in function %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "path-traversal",
		SeedEventType:    "PATH_TRAVERSAL",
		EvidenceType:     "PATH_TRAVERSAL",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "path_traversal", Detail: fmt.Sprintf("non-literal path passed to %s in function %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "sizeof-misuse",
		SeedEventType:    "SIZEOF_MISUSE",
		EvidenceType:     "SIZEOF_MISUSE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "sizeof_misuse", Detail: fmt.Sprintf("sizeof applied to pointer variable %s in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "signed-compare",
		SeedEventType:    "SIGNED_COMPARE",
		EvidenceType:     "SIGNED_COMPARE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signed_compare", Detail: fmt.Sprintf("unsigned value compared with zero/negative at line %d in function %s", c.Line, c.FunctionName)},
				{Type: "call_path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})
}

func containsString(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
