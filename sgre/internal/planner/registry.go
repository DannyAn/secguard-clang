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
	// CategoryCWEs maps an event category to a CWE identifier, letting one
	// vuln_type cover multiple CWEs distinguished by category (e.g. the
	// injection vuln_type maps command_injection→CWE-78, sql_injection→CWE-89,
	// argument_injection→CWE-88, …). When nil or when the category is not
	// listed, CWEForCategory falls back to spec.CWE. This is the mechanism by
	// which a single injection vuln_type + single injection/SKILL.md covers
	// six CWEs without splitting into separate vuln_types.
	CategoryCWEs      map[string]string
	ReviewAssumptions []string
	RequiredEvidence  []string
	KnownLimitations  []string
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

// VulnTypesToRuleIDs maps vuln-type names to the full set of CWE rule_ids that
// findings for those types can carry: canonical, legacy, and per-category CWEs.
// A single injection vuln_type, for example, covers CWE-78/CWE-89/CWE-88/...; a
// naive spec.CWE mapping would silently drop the category findings. An unknown
// type is an error, not a silent no-op (a typo must not widen the selection to
// everything).
func VulnTypesToRuleIDs(vulnTypes []string) ([]string, error) {
	if len(vulnTypes) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(vulnTypes))
	ruleIDs := make([]string, 0, len(vulnTypes))
	for _, vt := range vulnTypes {
		vt = strings.TrimSpace(vt)
		if vt == "" {
			continue
		}
		spec, err := GetVulnTypeSpec(vt)
		if err != nil {
			return nil, err
		}
		add := func(cwe string) {
			cwe = strings.ToUpper(strings.TrimSpace(cwe))
			if cwe == "" || seen[cwe] {
				return
			}
			seen[cwe] = true
			ruleIDs = append(ruleIDs, cwe)
		}
		add(spec.CWE)
		for _, legacy := range spec.LegacyCWEs {
			add(legacy)
		}
		// CategoryCWEs is a map, so sort its values for a deterministic rule-id
		// order (an unsorted map yields a different order every run).
		catCWEs := make([]string, 0, len(spec.CategoryCWEs))
		for _, cwe := range spec.CategoryCWEs {
			catCWEs = append(catCWEs, cwe)
		}
		sort.Strings(catCWEs)
		for _, cwe := range catCWEs {
			add(cwe)
		}
	}
	return ruleIDs, nil
}

// CWEsForType returns the full set of CWE rule_ids that findings for a single
// vulnerability type can carry: its canonical CWE plus every legacy and
// per-category CWE. It is the per-type form of VulnTypesToRuleIDs, used by the
// per-type status counter so a multi-CWE type (injection → CWE-78/89/88/91/93/117,
// crypto-misuse → CWE-327/326/338) counts its written findings under every one
// of its rule_ids instead of only the canonical CWE. Returns nil for an unknown
// type (the caller treats that as "no CWEs, zero written").
func CWEsForType(vulnType string) []string {
	ids, err := VulnTypesToRuleIDs([]string{vulnType})
	if err != nil {
		return nil
	}
	return ids
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

// ActiveVulnTypes returns the registered vulnerability types minus the disabled
// set, in the same sorted order as AllVulnTypes. It is the type switch applied
// at the SOURCE: the convergence Plan stage never runs for a disabled type, so
// it produces no candidates and the AI agent's skills never receive it. A nil or
// empty disabled set returns all types.
func ActiveVulnTypes(disabled map[string]bool) []string {
	if len(disabled) == 0 {
		return AllVulnTypes()
	}
	names := make([]string, 0, len(vulnTypeRegistry))
	for name := range vulnTypeRegistry {
		if disabled[name] {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// ValidateRegistry checks every registered vulnerability type's spec and filter
// chain, returning an error for any type whose FilterChain has no handler in
// getFilters. It is called once at pipeline startup so a registry typo fails
// immediately (before the expensive index/graph/detector phases) rather than
// mid-scan as a per-type Plan failure. TestAllVulnTypesHaveKnownFilterChain
// enforces the same invariant at test time; this is the runtime guard.
func ValidateRegistry() error {
	p := NewPlanner(nil, nil, nil)
	for _, name := range AllVulnTypes() {
		spec, err := GetVulnTypeSpec(name)
		if err != nil {
			return err
		}
		if _, err := p.getFilters(spec.FilterChain); err != nil {
			return fmt.Errorf("planner: vuln type %s: %w", name, err)
		}
	}
	return nil
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

// AuxEvidenceEventTypes lists the evidence event types that detectors emit as
// supporting facts but that are NOT a seed event type for any vulnerability
// type (NULL_VALUE/NULL_GUARD feed the null-deref and use-after-free filters;
// MEMORY_RELEASE/RESOURCE_RELEASE feed the leak filters; VALUE_INIT feeds the
// uninit filter). The status command sums these alongside AllSeedEventTypes so
// its total event count is complete without double-counting any seed type. It
// lives next to AllSeedEventTypes so the two stay in lockstep instead of a
// parallel hardcoded list drifting in the CLI layer.
func AuxEvidenceEventTypes() []string {
	return []string{"NULL_VALUE", "NULL_GUARD", "MEMORY_RELEASE", "RESOURCE_RELEASE", "VALUE_INIT"}
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

// CWEForCategory returns the CWE identifier for a specific category within a
// vulnerability type, using the CategoryCWEs map when available. When the
// vuln_type has no CategoryCWEs, or the category is not listed, it falls back
// to the type's canonical CWE. Returns "" if the vuln_type is not registered.
// This is the per-category CWE source of truth for vuln_types that cover
// multiple CWEs (e.g. injection: argument_injection→CWE-88,
// crlf_injection→CWE-93).
func CWEForCategory(vulnType, category string) string {
	spec, ok := vulnTypeRegistry[vulnType]
	if !ok {
		return ""
	}
	if spec.CategoryCWEs != nil {
		if cwe, found := spec.CategoryCWEs[category]; found {
			return cwe
		}
	}
	return spec.CWE
}

// TypeForCWE returns the vulnerability type whose canonical or legacy CWE
// matches the given CWE identifier (uppercased, trimmed). Returns "" if no type
// matches. This is used by the audit report to bucket findings by vuln-type, so
// it must reverse-map LegacyCWEs too — otherwise a legacy-CWE finding passes
// --write validation but is silently dropped from audit counts and never gets a
// per-finding markdown rewrite.
func TypeForCWE(cwe string) string {
	cweNorm := strings.ToUpper(strings.TrimSpace(cwe))
	for _, name := range AllVulnTypes() {
		spec := vulnTypeRegistry[name]
		if strings.ToUpper(spec.CWE) == cweNorm {
			return name
		}
		for _, legacy := range spec.LegacyCWEs {
			if strings.ToUpper(legacy) == cweNorm {
				return name
			}
		}
		for _, catCWE := range spec.CategoryCWEs {
			if strings.ToUpper(catCWE) == cweNorm {
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
		for _, catCWE := range spec.CategoryCWEs {
			if catCWE != "" {
				out[strings.ToUpper(catCWE)] = true
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
					Detail: fmt.Sprintf("variable %s is assigned NULL at line %d and dereferenced at line %d with no intervening reassignment (certain null-deref)", c.VariableName, c.SourceLine, c.Line),
				})
			} else if c.HasNullableSource {
				if c.CallerNullDetail != "" {
					fragments = append(fragments, EvidenceFragment{
						Type:   "caller_null",
						Role:   "source",
						Detail: fmt.Sprintf("parameter %s can be NULL: %s", c.VariableName, c.CallerNullDetail),
					})
				} else {
					fragments = append(fragments, EvidenceFragment{
						Type:   "nullable_source",
						Role:   "source",
						Detail: nullableSourceDetail(c),
					})
				}
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
		ReviewAssumptions: []string{
			"A dereference of a pointer that is provably NULL on some path is a real defect",
			"The pipeline tracks definite-null and nullable-source assignments",
		},
		RequiredEvidence: []string{"source of NULL value", "dereference location", "path from source to sink"},
		KnownLimitations: []string{
			"Macro context candidates are not auto-confirmed and excluded from review",
			"Pointer aliasing across function boundaries may not be fully tracked",
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "buffer-overflow",
		CWE:              "CWE-787",
		SeedEventType:    "BUFFER_ACCESS",
		EvidenceType:     "BUFFER_OVERFLOW",
		DefaultSuspicion: "suspected",
		FilterChain:      "buffer-overflow",
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
			frags := []EvidenceFragment{
				{Type: "buffer_access", Role: "sink", Detail: fmt.Sprintf("buffer access in function %s at line %d", c.FunctionName, c.Line)},
			}
			if c.APIName != "" {
				frags = append(frags, EvidenceFragment{Type: "api", Role: "sink", Detail: fmt.Sprintf("unsafe API: %s", c.APIName)})
			}
			if c.Array != "" {
				frags = append(frags, EvidenceFragment{Type: "buffer", Role: "sink", Detail: fmt.Sprintf("buffer: %s (capacity: %d elements)", c.Array, c.Size)})
			}
			if c.Index != "" {
				frags = append(frags, EvidenceFragment{Type: "index", Role: "condition", Detail: fmt.Sprintf("access index/copy size: %s", c.Index)})
			}
			if c.CopySize != "" {
				frags = append(frags, EvidenceFragment{Type: "copy_size", Role: "condition", Detail: fmt.Sprintf("copy size: %s", c.CopySize)})
			}
			if c.DstCapacity != "" {
				frags = append(frags, EvidenceFragment{Type: "dst_capacity", Role: "condition", Detail: fmt.Sprintf("destination capacity: %s", c.DstCapacity)})
			}
			if c.SizeArgument != "" {
				frags = append(frags, EvidenceFragment{Type: "size_argument", Role: "condition", Detail: fmt.Sprintf("_s size argument: %s", c.SizeArgument)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"A write past the end of a buffer is a real defect",
			"Constant indices/sizes past known bounds are confirmed by the detector",
		},
		RequiredEvidence: []string{"buffer allocation size", "access index or copy size", "bound check absence"},
		KnownLimitations: []string{
			"Variable indices/sizes require caller-influence analysis",
			"Byte vs element unit confusion may cause false positives",
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
			frags := []EvidenceFragment{
				{Type: "memory_alloc", Role: "source", Detail: fmt.Sprintf("allocation of %s in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
			}
			if c.DefiniteLeak {
				frags = append(frags, EvidenceFragment{Type: "definite", Role: "condition", Detail: "no free, escape, or ownership transfer is reachable on any path from the allocation to function exit"})
			} else {
				frags = append(frags, EvidenceFragment{Type: "conditional", Role: "condition", Detail: "released/escaped/transferred on some paths but potentially leaked on others — trace each error/early-return path for a missing free"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:       "injection",
		CWE:        "CWE-78",
		LegacyCWEs: []string{"CWE-89"},
		CategoryCWEs: map[string]string{
			"command_injection":   "CWE-78",
			"sql_injection":       "CWE-89",
			"argument_injection":  "CWE-88",
			"xml_xpath_injection": "CWE-91",
			"xml_injection":       "CWE-91",
			"crlf_injection":      "CWE-93",
			"log_injection":       "CWE-117",
		},
		SeedEventType:    "INJECTION",
		EvidenceType:     "INJECTION",
		DefaultSuspicion: "suspected",
		FilterChain:      "injection",
		ConvergeKey: func(c Candidate) string {
			// Key on (function, category, variable) so sprintf(source) +
			// sqlite3_exec(sink) sharing one buffer merge into one finding — the
			// same tainted variable is one root cause. Two sinks with DIFFERENT
			// categories (command_injection vs sql_injection) or different
			// variables stay distinct; two sinks with the SAME category and
			// variable deliberately collapse (same taint → same defect).
			return fmt.Sprintf("injection:%d:%s:%s:%s", c.FileID, c.FunctionName, c.Category, c.VariableName)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "unsafe_call", Role: "sink", Detail: fmt.Sprintf("unsafe function call %s in %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the sink")})
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
			frags := []EvidenceFragment{
				{Type: "resource_acquire", Role: "source", Detail: fmt.Sprintf("resource %s acquired in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
			}
			if c.DefiniteLeak {
				frags = append(frags, EvidenceFragment{Type: "definite", Role: "condition", Detail: "no release is reachable on any path from the acquire to function exit"})
			} else {
				frags = append(frags, EvidenceFragment{Type: "conditional", Role: "condition", Detail: "released on some paths but potentially leaked on others — trace each error/early-return path for a missing close/release"})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
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
			frags := []EvidenceFragment{
				{Type: "uninit_use", Role: "sink", Detail: fmt.Sprintf("uninitialized variable '%s' used in function %s at line %d", c.VariableName, c.FunctionName, c.Line)},
			}
			if c.DeclLine > 0 {
				if c.Origin == "heap_uninit" {
					frags = append(frags, EvidenceFragment{Type: "allocation", Role: "source", Detail: fmt.Sprintf("variable '%s' allocated at line %d", c.VariableName, c.DeclLine)})
				} else {
					frags = append(frags, EvidenceFragment{Type: "declaration", Role: "source", Detail: fmt.Sprintf("variable '%s' declared at line %d", c.VariableName, c.DeclLine)})
				}
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"Use of an uninitialized variable is a real defect",
			"The pipeline tracks initialization state through the CFG",
		},
		RequiredEvidence: []string{"declaration without initialization", "use location", "path from declaration to use"},
		KnownLimitations: []string{
			"Heap/struct initialization via calloc/memset may not be fully recognized",
			"Cross-function initialization via output parameters may be missed",
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
			frags := []EvidenceFragment{
				{Type: "use_after_free", Role: "sink", Detail: fmt.Sprintf("variable %s freed at line %d then used at line %d in function %s", c.VariableName, c.FreeLine, c.Line, c.FunctionName)},
			}
			if c.FreeLine > 0 {
				frags = append(frags, EvidenceFragment{Type: "free_site", Role: "source", Detail: fmt.Sprintf("free(%s) at line %d", c.VariableName, c.FreeLine)})
			}
			frags = append(frags, EvidenceFragment{Type: "use_site", Role: "sink", Detail: fmt.Sprintf("use of %s at line %d", c.VariableName, c.Line)})
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"Use of a pointer after it has been freed is a real defect",
			"The pipeline tracks freed-state through the CFG",
		},
		RequiredEvidence: []string{"free location", "use location", "path from free to use"},
		KnownLimitations: []string{
			"Pointer aliasing may cause missed freed-state propagation",
			"Cross-function free→use is not fully tracked",
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
			frags := []EvidenceFragment{
				{Type: "double_free", Role: "sink", Detail: fmt.Sprintf("variable %s freed twice in function %s", c.VariableName, c.FunctionName)},
			}
			if c.FirstFree > 0 {
				frags = append(frags, EvidenceFragment{Type: "first_free", Role: "source", Detail: fmt.Sprintf("first free(%s) at line %d", c.VariableName, c.FirstFree)})
			}
			secondFree := c.SecondFree
			if secondFree == 0 {
				secondFree = c.Line
			}
			frags = append(frags, EvidenceFragment{Type: "second_free", Role: "sink", Detail: fmt.Sprintf("second free(%s) at line %d", c.VariableName, secondFree)})
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
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
			}
			if c.APIName != "" {
				frags = append(frags, EvidenceFragment{Type: "api", Role: "sink", Detail: fmt.Sprintf("format function: %s", c.APIName)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			if c.HasTaintSource {
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the format argument")})
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
		// Value-analysis tiers. size_calc_overflow (malloc(a * b) / malloc(n *
		// sizeof(T))) and size_mul_const_overflow (malloc(n * CONST), CONST >= 256
		// and n caller-influenced) are concrete CWE-190 patterns and stay
		// "suspected". The wraparound-in-a-bounds-check pattern (integer_overflow)
		// is a theoretical wraparound and is "possible". Addition/subtraction
		// on size operands (n + 1 / n - 1) is not emitted — null-terminator /
		// off-by-one noise. An unsigned subtraction passed to an ordinary call is
		// kept as suspected: it has a concrete underflow path unless guarded.
		CategoryConfidence: map[string]string{
			"definite_overflow":       "confirmed",
			"size_calc_overflow":      "suspected",
			"size_mul_const_overflow": "suspected",
			"unsigned_sub_underflow":  "suspected",
			"integer_overflow":        "possible",
		},
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("integer-overflow:%d:%s:%d", c.FileID, c.FunctionName, c.Line)
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			detail := fmt.Sprintf("arithmetic overflow in size calculation in %s at line %d", c.FunctionName, c.Line)
			if c.Category == "unsigned_sub_underflow" {
				detail = fmt.Sprintf("unsigned subtraction can underflow before use in %s at line %d", c.FunctionName, c.Line)
			}
			return []EvidenceFragment{
				{Type: "integer_overflow", Role: "sink", Detail: detail},
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
				frags := []EvidenceFragment{
					{Type: "data_race", Role: "sink", Detail: fmt.Sprintf("unsynchronized shared-variable access to %s in %s at line %d", c.VariableName, c.FunctionName, c.Line)},
				}
				if c.ThreadFunctions != "" {
					frags = append(frags, EvidenceFragment{Type: "thread_functions", Role: "condition", Detail: fmt.Sprintf("accessed by thread functions: %s", c.ThreadFunctions)})
				}
				if c.ThreadInstances > 0 {
					frags = append(frags, EvidenceFragment{Type: "thread_instances", Role: "condition", Detail: fmt.Sprintf("%d distinct thread instances", c.ThreadInstances)})
				}
				if c.WriteLine > 0 {
					frags = append(frags, EvidenceFragment{Type: "write_line", Role: "source", Detail: fmt.Sprintf("conflicting write at line %d", c.WriteLine)})
				}
				frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
				return frags
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
		DefaultSuspicion: "suspected",
		FilterChain:      "hardcoded-secret",
		// A literal whose VALUE is secret-shaped (a known token prefix, high
		// Shannon entropy, URL-embedded credentials) is proven, so the
		// HardcodedSecretProofFilter auto-confirms it. A match on the
		// variable/field name ALONE may be a placeholder (`"REPLACE_ME"`) or a
		// test credential (`test_password = "test123"`), so it stays suspected
		// and the AI judges it, instead of the pipeline emitting a confirmed
		// false positive the skill's rules can never reach.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "hardcoded_secret", Role: "sink", Detail: fmt.Sprintf("hardcoded secret candidate in %s at line %d", c.FunctionName, c.Line)},
				{Type: "match_kind", Role: "condition", Detail: "name-only match: the variable/field name is secret-bearing but the value is low-entropy — judge whether it is a real credential, a placeholder, or a test value (value-proven secrets are auto-confirmed and never reach this stage)"},
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
			frags := []EvidenceFragment{
				{Type: "deadlock", Role: "sink", Detail: fmt.Sprintf("lock-order inversion (potential deadlock) in %s at line %d", c.FunctionName, c.Line)},
			}
			if c.MutexA != "" && c.MutexB != "" {
				frags = append(frags, EvidenceFragment{Type: "lock_pair", Role: "condition", Detail: fmt.Sprintf("this function locks %s then %s", c.MutexA, c.MutexB)})
			}
			if c.ReverseFunc != "" {
				frags = append(frags, EvidenceFragment{Type: "reverse_order", Role: "source", Detail: fmt.Sprintf("function %s acquires the same locks in the opposite order", c.ReverseFunc)})
			}
			return frags
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
		// weak_algorithm (DES/MD5/SHA1/RC4), weak_random (rand/srand) and
		// undersized_key are deterministic defects — the primitive itself is
		// provably broken regardless of call context, so the detector's verdict is
		// final and these are confirmed, not suspected. This matches the agent
		// prompt's "weak crypto is confirmed, period" rule (agent-body.md).
		CategoryConfidence: map[string]string{
			"weak_algorithm": "confirmed",
			"weak_random":    "confirmed",
			"undersized_key": "confirmed",
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
		FilterChain:      "buffer-overflow",
		Categories:       []string{"array_oob_read", "heap_oob_read"},
		// A read-flavored OOB is only emitted when the detector proved the
		// index outruns the array/allocation, so it is confirmed, not suspected.
		CategoryConfidence: map[string]string{
			"array_oob_read": "confirmed",
			"heap_oob_read":  "confirmed",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "out_of_bounds", Role: "sink", Detail: fmt.Sprintf("out-of-bounds access in function %s at line %d", c.FunctionName, c.Line)},
			}
			if c.Array != "" {
				capacity := ""
				if c.Size > 0 {
					capacity = fmt.Sprintf(" (capacity: %d elements)", c.Size)
				}
				frags = append(frags, EvidenceFragment{Type: "buffer", Role: "sink", Detail: fmt.Sprintf("array: %s%s", c.Array, capacity)})
			}
			if c.Index != "" {
				frags = append(frags, EvidenceFragment{Type: "index", Role: "condition", Detail: fmt.Sprintf("access index: %s", c.Index)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "divide-by-zero",
		CWE:              "CWE-369",
		SeedEventType:    "DIVIDE_BY_ZERO",
		EvidenceType:     "DIVIDE_BY_ZERO",
		DefaultSuspicion: "suspected",
		FilterChain:      "divide-by-zero",
		// Dedup the SAME divisor divided at many sites into one finding, but keep a
		// confirmed and a suspected division of that divisor distinct: the
		// higher-rank "confirmed" must not mask a suspected site (DBZ-18). The key
		// therefore carries the suspicion tier, not just the divisor.
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("dbz:%d:%s:%s:%s", c.FileID, c.FunctionName, c.VariableName, c.SuspicionLevel)
		},
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
			frags := []EvidenceFragment{
				{Type: "unchecked_return", Role: "sink", Detail: fmt.Sprintf("return value of %s is not checked in function %s at line %d", c.APIName, c.FunctionName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
			// contract@unknown puts the proof burden on the classifier, so the
			// evidence must say WHERE the callee body is: cross-file static
			// factories are the norm and a ±8 window cannot hold a callee from
			// another file. An external callee gets an explicit "no body in
			// scan" so the classifier goes to API knowledge instead of burning
			// READs on a search that cannot succeed.
			if c.APIName != "" && !c.ContractKnown {
				if c.CalleeDefFile != "" {
					detail := fmt.Sprintf("callee %s is defined in the scan at %s:%d", c.APIName, c.CalleeDefFile, c.CalleeDefLine)
					if c.CalleeDefSignature != "" {
						detail += fmt.Sprintf(" (signature: %s)", c.CalleeDefSignature)
					}
					detail += " — read the definition to prove or refute that it returns a failure sentinel"
					frags = append(frags, EvidenceFragment{Type: "callee_definition", Role: "callee", Detail: detail})
				} else {
					frags = append(frags, EvidenceFragment{Type: "callee_definition", Role: "callee", Detail: fmt.Sprintf("callee %s has no definition in the scan (external/library function) — there is no body to read; prove the contract from API knowledge or dismiss", c.APIName)})
				}
			}
			return frags
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
				frags = append(frags, EvidenceFragment{Type: "taint_source", Role: "source", Detail: taintSourceDetail(c, "the path argument")})
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

	RegisterVulnType(&VulnTypeSpec{
		Name:             "signal-handler",
		CWE:              "CWE-479",
		SeedEventType:    "SIGNAL_HANDLER",
		EvidenceType:     "SIGNAL_HANDLER",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		// A signal handler that DIRECTLY calls a known non-async-signal-safe libc
		// function (malloc, printf, pthread_mutex_lock, ...) is a certain CWE-479
		// defect: the POSIX async-signal-safe list is fixed and authoritative, so
		// the detector needs no taint or flow proof — "confirmed" is sound here.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "signal_handler_unsafe", Role: "sink", Detail: fmt.Sprintf("signal handler %s calls non-async-signal-safe %s() at line %d", c.FunctionName, c.VariableName, c.Line)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "dangerous-function",
		CWE:              "CWE-676",
		SeedEventType:    "DANGEROUS_FUNCTION",
		EvidenceType:     "DANGEROUS_FUNCTION",
		DefaultSuspicion: "confirmed",
		FilterChain:      "default",
		// A call to a banned function is a POLICY finding — the function itself
		// is the defect, no context matters — so every category is confirmed
		// soundly (a name match, not a may-analysis). EXCEPTION: `assert_usage`
		// is handed to the AI, because whether an assert() guards caller input
		// (a defect) or an internal invariant (fine) needs intent.
		CategoryConfidence: map[string]string{
			"assert_usage":             "suspected",
			"obsolete_api_conditional": "suspected",
		},
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "dangerous_function", Role: "sink", Detail: fmt.Sprintf("call to banned %s() (%s) at line %d in function %s", c.VariableName, c.Category, c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "argument-type",
		CWE:              "CWE-686",
		SeedEventType:    "ARGUMENT_TYPE_MISMATCH",
		EvidenceType:     "ARGUMENT_TYPE_MISMATCH",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		// An incompatible pointer cast is evidence of a type reinterpretation,
		// but an explicit cast is not proof of a defect (it can be an intentional
		// ABI/opaque boundary), so the AI agent judges intent rather than the
		// pipeline auto-confirming a cast.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "argument_type_mismatch", Role: "sink", Detail: fmt.Sprintf("call to %s passes %s as %s at line %d in function %s", c.APIName, c.ActualType, c.ExpectedType, c.Line, c.FunctionName)},
			}
			if c.CastType != "" {
				frags = append(frags, EvidenceFragment{Type: "explicit_cast", Role: "source", Detail: fmt.Sprintf("explicit cast %s reinterprets object %s (%s)", c.CastType, c.VariableName, c.ActualType)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "data-representation",
		CWE:              "CWE-843",
		SeedEventType:    "DATA_REPRESENTATION_MISMATCH",
		EvidenceType:     "DATA_REPRESENTATION_MISMATCH",
		DefaultSuspicion: "suspected",
		FilterChain:      "default",
		// A pointer-depth mismatch between a qsort/bsearch base element and the
		// comparator's void* cast is strong evidence of type confusion, but the
		// base's declared type can be a decayed/aliased array, so the AI agent
		// confirms the actual element representation.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			return []EvidenceFragment{
				{Type: "data_representation_mismatch", Role: "sink", Detail: fmt.Sprintf("comparator %s interprets a void* element as %s but the sort base %s holds %s elements at line %d in function %s", c.APIName, c.ActualType, c.VariableName, c.ExpectedType, c.Line, c.FunctionName)},
				{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)},
			}
		},
	})

	RegisterVulnType(&VulnTypeSpec{
		Name:             "implicit-contract",
		CWE:              "CWE-20",
		SeedEventType:    "CONTRACT_GAP",
		EvidenceType:     "IMPLICIT_CONTRACT",
		DefaultSuspicion: "suspected",
		FilterChain:      "implicit-contract",
		Categories:       []string{"ptr_guard"},
		// One candidate per dereference site: a field null-checked on one path but
		// dereferenced on several others has one defect PER unguarded site, and the
		// guard-dominance filter drops only the guarded sites. Keying on use_line
		// keeps the unguarded sites distinct instead of collapsing them to the
		// first (possibly guarded) site.
		ConvergeKey: func(c Candidate) string {
			return fmt.Sprintf("implicit-contract:%d:%s:%s:%d", c.FileID, c.FunctionName, c.VariableName, c.UseLine)
		},
		// This type is the OPEN-WORLD half of the entry-validation gap: a
		// caller/framework-supplied struct field is dereferenced without a null
		// guard, and the code itself treats the field as nullable somewhere
		// (evidence "self"/"caller"). It is NEVER auto-confirmed — the field's
		// nullness is not statically provable, so the AI agent judges the caller
		// contract / business semantics. The provable (definite null source)
		// cases belong to null-deref (CWE-476); this type only fires where the
		// field is never written in-scope, so there is no double report.
		BuildEvidence: func(c Candidate) []EvidenceFragment {
			frags := []EvidenceFragment{
				{Type: "contract_gap", Role: "sink", Detail: fmt.Sprintf("pointer field %s (of parameter %s) is dereferenced at line %d with no dominating null guard", c.VariableName, c.Subject, c.UseLine)},
			}
			if c.CountField != "" {
				frags = append(frags, EvidenceFragment{Type: "count_field", Role: "condition", Detail: fmt.Sprintf("the use is gated by count/length field %s", c.CountField)})
			}
			frags = append(frags, EvidenceFragment{Type: "missing", Role: "condition", Detail: fmt.Sprintf("missing precondition: %s != NULL", c.VariableName)})
			switch c.EvidenceKind {
			case "self":
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: fmt.Sprintf("function %s null-checks %s on another path, so it treats the field as nullable", c.FunctionName, c.VariableName)})
			case "caller":
				frags = append(frags, EvidenceFragment{Type: "contract_evidence", Role: "source", Detail: fmt.Sprintf("a caller null-checks %s before the call, so the field is nullable at the call boundary", c.VariableName)})
			}
			frags = append(frags, EvidenceFragment{Type: "call_path", Role: "path", Detail: fmt.Sprintf("function %s is reachable from entry", c.FunctionName)})
			return frags
		},
		ReviewAssumptions: []string{
			"A caller/framework-supplied struct field dereferenced without a guard may be NULL on the empty/unusual path",
			"The code null-checking the field elsewhere is evidence the field is nullable, not proof",
		},
		RequiredEvidence: []string{"dereference site", "count/length field gating the use", "nullable-field evidence (self/caller)"},
		KnownLimitations: []string{
			"Field nullness is open-world: a framework may guarantee non-null, which only the AI can judge",
			"Cross-function caller evidence (evidence=caller) is not yet emitted; only self-guard evidence is produced",
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

// nullableSourceDetail describes where a possibly-null value comes from without
// asserting an order that may not hold. A LOOP-CARRIED source is textually AFTER
// the dereference — only the loop back-edge reaches it — and the previous
// unconditional "before the dereference" wording produced self-contradictory
// evidence in production ("assigned a possibly-null value at line 87 before the
// dereference at line 85"), which the classifier then had to spend reasoning on
// to conclude the hint itself was broken.
func nullableSourceDetail(c Candidate) string {
	if c.SourceLine > 0 && c.SourceLine > c.Line {
		return fmt.Sprintf("variable %s is assigned a possibly-null value at line %d, which reaches the dereference at line %d only through a loop back-edge (the assignment textually follows the use, so the guard on this path decides it)", c.VariableName, c.SourceLine, c.Line)
	}
	return fmt.Sprintf("variable %s is assigned a possibly-null value at line %d before the dereference at line %d", c.VariableName, c.SourceLine, c.Line)
}

// taintSourceDetail states the taint-origin fact a classifier can act on. The
// old wording told the classifier to "identify the specific source in Code
// Context", but the taint source is frequently more than ±8 lines from the
// sink — or enters through a caller's argument — so the window physically
// cannot contain it, and the instruction sent the classifier hunting for
// evidence that was never in view (dismiss-by-budget false negatives). The
// line-numbered form carries the pipeline-proven origin; the param form says
// where the taint actually enters instead of pointing at an empty window.
func taintSourceDetail(c Candidate, sinkDesc string) string {
	if c.SourceLine > 0 {
		return fmt.Sprintf("user-controlled value originates at line %d and reaches %s at line %d — the evidence file's Taint Source section carries the origin statement", c.SourceLine, sinkDesc, c.Line)
	}
	return fmt.Sprintf("a tainted parameter of this function reaches %s at line %d — the taint enters from a CALLER argument (inter-procedural summary), so there is no in-function source statement to read", sinkDesc, c.Line)
}
