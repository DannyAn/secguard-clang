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
	// CWE is the canonical CWE identifier for this vulnerability type (e.g.
	// "CWE-476"). It is the single source of truth for the CWE↔vuln-type
	// mapping — every consumer (report, db, cli, extension) must derive from
	// here, never hardcode a parallel map.
	CWE string
	// LegacyCWEs are historically-used CWE identifiers still accepted for
	// backward-compatible finding persistence (e.g. CWE-89 for SQL injection
	// now mapped to CWE-78). They are included in AllCWEs() so old findings
	// remain writable, but VulnToCWE returns only the canonical CWE.
	LegacyCWEs []string
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

// CWEForType returns the canonical CWE identifier for a vulnerability type,
// or "" if the type is not registered. Callers that need a fallback (e.g.
// SARIF) should return "CWE-Other" themselves — this function stays pure.
func CWEForType(vulnType string) string {
	if spec, ok := vulnTypeRegistry[vulnType]; ok {
		return spec.CWE
	}
	return ""
}

// TypeForCWE returns the vulnerability type whose canonical or legacy CWE
// matches the given CWE identifier (uppercased, trimmed). Returns "" if no type
// matches. This is used by the audit report to bucket findings by vuln-type, so
// it must reverse-map LegacyCWEs too — otherwise a legacy-CWE finding passes
// --write validation but is silently dropped from audit counts and never gets a
// per-finding markdown rewrite.
func TypeForCWE(cwe string) string {
	cweNorm := strings.ToUpper(strings.TrimSpace(cwe))
	for name, spec := range vulnTypeRegistry {
		if strings.ToUpper(spec.CWE) == cweNorm {
			return name
		}
		for _, legacy := range spec.LegacyCWEs {
			if strings.ToUpper(legacy) == cweNorm {
				return name
			}
		}
	}
	return ""
}

// AllCWEs returns the set of all CWE identifiers the pipeline can detect and
// persist as findings — every registered type's canonical CWE plus all
// LegacyCWEs. This is the single source of truth for db.SupportedFindingCWEs;
// cli/root.go injects it at startup so the db layer never drifts from the
// registry.
func AllCWEs() map[string]bool {
	out := make(map[string]bool)
	for _, spec := range vulnTypeRegistry {
		if spec.CWE != "" {
			out[strings.ToUpper(spec.CWE)] = true
		}
		for _, legacy := range spec.LegacyCWEs {
			if legacy != "" {
				out[strings.ToUpper(legacy)] = true
			}
		}
	}
	return out
}

func init() {
	RegisterVulnType(&VulnTypeSpec{
		Name:               "null-deref",
		CWE:                "CWE-476",
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
					Role:   "condition",
					Detail: fmt.Sprintf("variable %s is assigned NULL and dereferenced at line %d with no intervening reassignment (certain null-deref)", c.VariableName, c.Line),
				})
			} else if c.HasNullableSource {
				fragments = append(fragments, EvidenceFragment{
					Type:   "nullable_source",
					Role:   "source",
					Detail: fmt.Sprintf("variable %s is assigned a possibly-null value before the dereference at line %d", c.VariableName, c.Line),
				})
			}
			if c.IsReachable {
				fragments = append(fragments, EvidenceFragment{
					Type:   "call_path",
					Role:   "path",
					Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName),
				})
			}
			if c.HasDataFlow {
				fragments = append(fragments, EvidenceFragment{
					Type:   "data_flow",
					Role:   "path",
					Detail: fmt.Sprintf("NULL value propagates to dereference at line %d", c.Line),
				})
			}
			if len(fragments) == 0 {
				fragments = append(fragments, EvidenceFragment{
					Type:   "dereference",
					Role:   "sink",
					Detail: fmt.Sprintf("dereference of %s at line %d", c.VariableName, c.Line),
				})
			}
			return fragments
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "buffer-overflow",
		CWE:              "CWE-787",
		SeedEventType:    "BUFFER_ACCESS",
		EvidenceType:     "BUFFER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"buffer_overflow", "array_oob_write", "heap_oob_write", "format_overflow", "format_overflow_var", "bounded_copy_overflow", "bounded_copy_var_size", "secure_copy_overflow", "secure_copy_var_size", "secure_constraint_violation", "secure_scanf_overflow", "secure_scanf_var_size"},
		// Provable out-of-bounds writes (a constant index past a known array or
		// allocation size, a constant copy size exceeding a known capacity, or
		// an Annex K `_s` function given a lying destination-capacity argument)
		// are confirmed by the detector itself; an unguarded unsafe call or
		// sprintf remains a heuristic suspicion. A variable copy size / capacity
		// that is caller-influenced is tiered to "possible", and a proven
		// `_s` constraint violation (required > declared capacity, no actual
		// overflow) is "suspected" — the AI agent weighs the handler's behavior.
		CategoryConfidence: map[string]string{
			"array_oob_write":             "confirmed",
			"heap_oob_write":              "confirmed",
			"bounded_copy_overflow":       "confirmed",
			"bounded_copy_var_size":       "possible",
			"secure_copy_overflow":        "confirmed",
			"secure_copy_var_size":        "possible",
			"secure_constraint_violation": "suspected",
			"secure_scanf_overflow":       "confirmed",
			"secure_scanf_var_size":       "possible",
			"format_overflow":             "confirmed",
			"format_overflow_var":         "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "buffer_access", Role: "sink", Detail: fmt.Sprintf("buffer access in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "memory-leak",
		CWE:              "CWE-401",
		SeedEventType:    "MEMORY_ALLOC",
		EvidenceType:     "MEMORY_LEAK",
		DefaultSuspicion: "suspected",
		FilterChain:      "memory-leak",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "memory_alloc", Role: "source", Detail: fmt.Sprintf("allocation in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "injection",
		CWE:              "CWE-78",
		LegacyCWEs:       []string{"CWE-89"},
		SeedEventType:    "INJECTION",
		EvidenceType:     "INJECTION",
		DefaultSuspicion: "suspected",
		FilterChain:      "injection",
		ConvergeKey: func(c Candidate) string {
			// Key on the sink/source variable (or the expression text as fallback)
			// so sprintf(source) + sqlite3_exec(sink) sharing one buffer merge, but
			// two independent sinks in the same function stay distinct findings.
			return fmt.Sprintf("injection:%d:%s:%s:%s", c.FileID, c.FunctionName, c.Category, c.VariableName)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "unsafe_call", Role: "sink", Detail: fmt.Sprintf("unsafe function call in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: fmt.Sprintf("user-controlled value reaches the sink at line %d", c.Line)})
			}
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "resource-leak",
		CWE:              "CWE-404",
		SeedEventType:    "RESOURCE_ACQUIRE",
		EvidenceType:     "RESOURCE_LEAK",
		DefaultSuspicion: "suspected",
		FilterChain:      "resource-leak",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "resource_acquire", Role: "source", Detail: fmt.Sprintf("resource acquired in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "uninit",
		CWE:              "CWE-457",
		SeedEventType:    "VALUE_USE",
		EvidenceType:     "UNINIT_USE",
		DefaultSuspicion: "suspected",
		FilterChain:      "uninit",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "uninit_use", Role: "sink", Detail: fmt.Sprintf("uninitialized variable used in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "use-after-free",
		CWE:              "CWE-416",
		SeedEventType:    "USE_AFTER_FREE",
		EvidenceType:     "USE_AFTER_FREE",
		DefaultSuspicion: "suspected",
		FilterChain:      "lifetime",
		// One freed variable used at many sites is one defect, not one per use.
		ConvergeByVariable: true,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "use_after_free", Role: "sink", Detail: fmt.Sprintf("variable freed then used in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "double-free",
		CWE:              "CWE-415",
		SeedEventType:    "DOUBLE_FREE",
		EvidenceType:     "DOUBLE_FREE",
		DefaultSuspicion: "suspected",
		FilterChain:      "double-free",
		// One variable freed twice is one defect, not one per (first,second) pair.
		ConvergeByVariable: true,
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "double_free", Role: "sink", Detail: fmt.Sprintf("variable freed twice in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "format-string",
		CWE:              "CWE-134",
		SeedEventType:    "FORMAT_STRING",
		EvidenceType:     "FORMAT_STRING_VULN",
		DefaultSuspicion: "suspected",
		FilterChain:      "format-string",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "format_string", Role: "sink", Detail: fmt.Sprintf("printf-family called with non-literal format in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: fmt.Sprintf("user-controlled value reaches the format argument at line %d", c.Line)})
			}
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "integer-overflow",
		CWE:              "CWE-190",
		SeedEventType:    "INTEGER_OVERFLOW",
		EvidenceType:     "INTEGER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "integer-overflow",
		// Value-analysis-lite tiers. size_calc_overflow (malloc(a * b)) and
		// size_mul_const_overflow (malloc(n * 2), n caller-influenced) are
		// concrete CWE-190 patterns and stay "suspected". size_add_overflow /
		// size_sub_overflow (malloc(n + 1) / malloc(n - 1), n caller-influenced)
		// require the variable to reach an extreme value, so they are tiered
		// down to "possible" — the AI agent proves or refutes reachability with
		// call-site/contract reasoning. The wraparound-in-a-bounds-check pattern
		// (integer_overflow) is a theoretical wraparound and is also "possible".
		CategoryConfidence: map[string]string{
			"size_calc_overflow":      "suspected",
			"size_mul_const_overflow": "suspected",
			"size_add_overflow":       "possible",
			"size_sub_overflow":       "possible",
			"integer_overflow":        "possible",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("integer-overflow:%d:%s:%d", c.FileID, c.FunctionName, c.Line)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "integer_overflow", Role: "sink", Detail: fmt.Sprintf("arithmetic overflow in size calculation in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "race-condition",
		CWE:              "CWE-362",
		SeedEventType:    "RACE_CONDITION",
		EvidenceType:     "RACE_CONDITION",
		DefaultSuspicion: "suspected",
		FilterChain:      "race-condition",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			if c.Category == "shared_data_race" {
				return []EvidenceFragment{
					{Type: "data_race", Role: "sink", Detail: fmt.Sprintf("unsynchronized shared-variable access in %s at line %d", c.FunctionName, c.Line)},
					{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
				}
			}
			return []EvidenceFragment{
				{Type: "toctou", Role: "sink", Detail: fmt.Sprintf("time-of-check-time-of-use in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "hardcoded-secret",
		CWE:              "CWE-798",
		SeedEventType:    "HARDCODED_SECRET",
		EvidenceType:     "HARDCODED_SECRET",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "hardcoded_secret", Role: "sink", Detail: fmt.Sprintf("hardcoded secret in %s at line %d", c.FunctionName, c.Line)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "deadlock",
		CWE:              "CWE-667",
		SeedEventType:    "DEADLOCK",
		EvidenceType:     "DEADLOCK",
		DefaultSuspicion: "suspected",
		FilterChain:      "deadlock",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "deadlock", Role: "sink", Detail: fmt.Sprintf("lock-order inversion (potential deadlock) in %s at line %d", c.FunctionName, c.Line)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "crypto-misuse",
		CWE:              "CWE-327",
		LegacyCWEs:       []string{"CWE-326", "CWE-338"},
		SeedEventType:    "CRYPTO_MISUSE",
		EvidenceType:     "CRYPTO_MISUSE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		// weak_algorithm (DES/MD5/SHA1/RC4) and undersized_key are deterministic
		// defects — the primitive itself is provably broken regardless of call
		// context, so the detector's verdict is final and these are confirmed,
		// not suspected. Only weak_random (rand/srand) depends on whether the
		// output feeds a security context, which is an AI judgment call.
		CategoryConfidence: map[string]string{
			"weak_algorithm": "confirmed",
			"undersized_key": "confirmed",
			"weak_random":    "suspected",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("crypto-misuse:%d:%s:%s", c.FileID, c.FunctionName, c.Category)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "crypto_misuse", Role: "sink", Detail: fmt.Sprintf("weak crypto in %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "out-of-bounds",
		CWE:              "CWE-125",
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
				{Type: "out_of_bounds", Role: "sink", Detail: fmt.Sprintf("out-of-bounds access in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "divide-by-zero",
		CWE:              "CWE-369",
		SeedEventType:    "DIVIDE_BY_ZERO",
		EvidenceType:     "DIVIDE_BY_ZERO",
		DefaultSuspicion: "suspected",
		FilterChain:      "divide-by-zero",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "divide_by_zero", Role: "sink", Detail: fmt.Sprintf("possible division by zero in function %s at line %d", c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "unchecked-return",
		CWE:              "CWE-252",
		SeedEventType:    "UNCHECKED_RETURN",
		EvidenceType:     "UNCHECKED_RETURN",
		DefaultSuspicion: "suspected",
		FilterChain:      "unchecked-return",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "unchecked_return", Role: "sink", Detail: fmt.Sprintf("return value of %s is not checked in function %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "path-traversal",
		CWE:              "CWE-22",
		SeedEventType:    "PATH_TRAVERSAL",
		EvidenceType:     "PATH_TRAVERSAL",
		DefaultSuspicion: "suspected",
		FilterChain:      "path-traversal",
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "path_traversal", Role: "sink", Detail: fmt.Sprintf("filesystem call %s receives a path that is not a fixed string literal — an attacker-controlled value could use ../ to escape the intended directory and read/overwrite/delete an arbitrary file", c.APIName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: fmt.Sprintf("user-controlled value reaches the path argument at line %d", c.Line)})
			}
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "sizeof-misuse",
		CWE:              "CWE-467",
		SeedEventType:    "SIZEOF_MISUSE",
		EvidenceType:     "SIZEOF_MISUSE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"sizeof_pointer", "sizeof_pointer_ambig"},
		// `sizeof(p)` on a single-level pointer `T *p` is provably the pointer
		// width where the object size is intended (CWE-467) — confirmed. A
		// pointer-to-pointer `T **p` is legitimately sized by `sizeof(p)` when
		// allocating an array of pointers, so it stays suspected.
		CategoryConfidence: map[string]string{
			"sizeof_pointer":       "confirmed",
			"sizeof_pointer_ambig": "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "sizeof_misuse", Role: "sink", Detail: fmt.Sprintf("sizeof applied to pointer variable %s in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "signed-compare",
		CWE:              "CWE-681",
		SeedEventType:    "SIGNED_COMPARE",
		EvidenceType:     "SIGNED_COMPARE",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		Categories:       []string{"signed_compare"},
		// The detector only emits when the compared variable's declared type is
		// provably unsigned (an `unsigned`/`size_t`/`uint*_t` spelling), and an
		// unsigned value is never `< 0` — the dead comparison is a confirmed
		// CWE-681 defect. The suspected default is a backstop, never reached in
		// practice.
		CategoryConfidence: map[string]string{
			"signed_compare": "confirmed",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signed_compare", Role: "sink", Detail: fmt.Sprintf("unsigned value compared with zero/negative at line %d in function %s", c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
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
