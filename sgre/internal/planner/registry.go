package planner

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type VulnTypeSpec struct {
	Name             string
	SeedEventType    string
	EvidenceType     string
	DefaultSuspicion string
	FilterChain      string
	// FilterFactories declares this type's filter chain next to the rest of
	// its metadata. When empty, Planner falls back to the legacy string-keyed
	// switch via FilterChain; RegisterVulnType populates it from FilterChain
	// if the caller did not set it explicitly, so new types can go declarative
	// while existing types migrate one at a time.
	FilterFactories []FilterFactory
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
	// BuildVerdictFacts, when set, renders the type's decisive facts as
	// short structured lines (VerdictFact: token + one sentence + provenance
	// line numbers) for the candidate file's "## Verdict Facts" section and
	// the auto-confirmed re-review payload. It is the per-type Evidence
	// Contract v2 hook (docs/evidence-contract-v2-design.md §3.1): the
	// pipeline computes the fact (a semantic-graph query: does the callee
	// return NULL, does a guard dominate, what is the divisor's interval)
	// and the AI reads the ANSWER, never the raw graph. Facts must carry
	// their provenance file:line so a targeted read can verify them. A nil
	// BuildVerdictFacts means the type's contract is not rolled out yet —
	// the section simply does not render.
	BuildVerdictFacts func(c Candidate) []VerdictFact
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
	// FilterFactories is authoritative: every registered type declares its
	// chain explicitly in registry_<type>.go (Phase 7 follow-up). A missing
	// FilterFactories is a registration-time bug — the legacy string fallback
	// was removed once every type was migrated.
	if len(spec.FilterFactories) == 0 {
		panic("RegisterVulnType: " + spec.Name + " has no FilterFactories (declare them explicitly in registry_<type>.go)")
	}
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

// ValidateRegistry checks every registered vulnerability type's spec has a
// non-empty FilterFactories (the authoritative declaration since Phase 7
// follow-up). It is called once at pipeline startup so a registry typo fails
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
		if _, err := p.buildFilters(spec); err != nil {
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

// derivedSuffix names the origin variable when the candidate is only a value-
// preserving copy/cast of it (`q = (T *)param`, `q = t` where t is the opaque
// field read), so the verdict sentence attributes the contract to the variable
// that actually holds it instead of the derived name.
func derivedSuffix(c Candidate) string {
	if c.DerivedFrom == "" {
		return ""
	}
	return fmt.Sprintf(" (reached through `%s`)", c.DerivedFrom)
}

// otherDerefLines returns the additional sink lines of a variable-converged
// candidate, i.e. every dereference site except the reported one.
func otherDerefLines(c Candidate) []int {
	out := make([]int, 0, len(c.DerefLines))
	for _, l := range c.DerefLines {
		if l > 0 && l != c.Line {
			out = append(out, l)
		}
	}
	return out
}

// joinLines renders sink line numbers for the evidence sentence.
func joinLines(lines []int) string {
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, strconv.Itoa(l))
	}
	return strings.Join(parts, ", ")
}

// buildNullDerefVerdictFacts distills the null-deref verdict basis into
// structured facts (token + one sentence). The tier is the headline: it states
// how the pipeline KNOWS the value can be null, which is exactly what the
// classifier must judge — and for external-unknown, that the pipeline does NOT
// know (fail-open assumption).
// buildCryptoMisuseVerdictFacts distills the crypto verdict basis: the
// detector's own rationale — not the API name — is what separates a broken
// primitive from a strong one, and an undersized key is a number, not a
// judgment call.
// buildBufferVerdictFacts distills the BO/OOB verdict basis: the
// buffer/capacity/index triple. A constant index or copy size that reached a
// candidate is detector-proved out-of-bounds; a variable one is exactly what
// the classifier must range-judge against cap@.
func buildBufferVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 3)
	if c.Array != "" {
		facts = append(facts, VerdictFact{
			Token:  "buf@" + c.Array,
			Detail: fmt.Sprintf("the buffer written/read at line %d", c.Line),
		})
	}
	if c.Size > 0 {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("cap@%d", c.Size),
			Detail: fmt.Sprintf("the detector-resolved capacity of %s is %d elements (from the array declaration or allocation size)", c.Array, c.Size),
		})
	}
	if c.SrcCapacity > 0 {
		facts = append(facts, VerdictFact{
			Token:  fmt.Sprintf("src-cap@%d", c.SrcCapacity),
			Detail: fmt.Sprintf("the SOURCE buffer's resolved capacity is %d elements — a source this size cannot feed more than %d bytes, so a copy into a cap@ ≥ src-cap@ destination is bounded (dismiss)", c.SrcCapacity, c.SrcCapacity),
		})
	}
	idx := c.Index
	if idx == "" {
		idx = c.CopySize
	}
	if idx == "" {
		idx = c.SizeArgument
	}
	if idx != "" {
		idx = compactHintValue(idx)
		if _, err := strconv.Atoi(strings.TrimSpace(idx)); err == nil {
			facts = append(facts, VerdictFact{
				Token:  "idx@" + idx,
				Detail: fmt.Sprintf("constant index/copy size %s against the capacity — the detector already proved it reaches past cap@, machine-proved out-of-bounds", idx),
			})
		} else {
			facts = append(facts, VerdictFact{
				Token:  "idx@" + idx,
				Detail: "variable index/copy size — judge its reachable range against cap@ (caller-influenced parameters are the dangerous case)",
			})
		}
	}
	if c.IndexSource != "" {
		symbol := ""
		if c.CapacitySymbol != "" {
			symbol = fmt.Sprintf(" (`%s`)", c.CapacitySymbol)
		}
		facts = append(facts, VerdictFact{
			Token:  "idx-src@" + c.IndexSource,
			Detail: fmt.Sprintf("the index is the struct field `%s`, and no bounds check against cap@%d%s dominates this access — judge the field's real range: an external/config-supplied index with no entry guard is the dangerous case (confirm); a bounded field or a validated caller contract dismisses", c.IndexSource, c.Size, symbol),
		})
	}
	if c.ElemField != "" {
		facts = append(facts, VerdictFact{
			Token:  "elem-field@" + c.ElemField,
			Detail: fmt.Sprintf("the indexed element's pointer member `%s` is read here — if the index is out of range this pointer comes from out-of-range memory (indeterminate), so its downstream dereference is the null-deref/use-of-wild-pointer leg of the chain", c.ElemField),
		})
	}
	if c.Escape != "" {
		deref := ""
		if c.EscapeDeref != "" {
			deref = fmt.Sprintf(", which reads its pointer member `%s`", strings.SplitN(c.EscapeDeref, "@", 2)[0])
		}
		facts = append(facts, VerdictFact{
			Token:  "oob-escape@" + c.Escape,
			Detail: fmt.Sprintf("the out-of-bounds element (or its address) is passed to `%s`%s — the OOB element feeds that sink, the second link of the CWE-125 → CWE-476 chain", c.Escape, deref),
		})
	}
	return facts
}

// buildLeakVerdictFacts distills the memory/resource-leak verdict basis: the
// acquire line, the certainty tier, and the ownership-release channel state.
// The channel split is the classifier's decision point — escape@none is a
// machine-proved loss, while a channel that exists alongside a surviving
// leak candidate means the CFG proved a bypass path.
func buildLeakVerdictFacts(c Candidate) []VerdictFact {
	facts := make([]VerdictFact, 0, 4)
	acquire := "acquisition"
	if c.APIName != "" {
		acquire = fmt.Sprintf("%s acquisition", c.APIName)
	}
	if c.Line > 0 {
		if c.Category == "resource_acquire" {
			facts = append(facts, VerdictFact{
				Token:  fmt.Sprintf("acquire@%d", c.Line),
				Detail: fmt.Sprintf("the resource is acquired at line %d (%s) in function %s", c.Line, acquire, c.FunctionName),
			})
		} else {
			facts = append(facts, VerdictFact{
				Token:  fmt.Sprintf("alloc@%d", c.Line),
				Detail: fmt.Sprintf("the memory is allocated at line %d (%s) in function %s", c.Line, acquire, c.FunctionName),
			})
		}
	}
	if c.DefiniteLeak {
		facts = append(facts, VerdictFact{
			Token:  "leak@definite",
			Detail: "no free/escape/transfer is reachable on ANY path from the allocation to function exit — machine-proved loss, verify the statement matches and confirm",
		})
	} else {
		facts = append(facts, VerdictFact{
			Token:  "leak@conditional",
			Detail: "a release channel exists but the CFG proved a leak path bypasses it — trace the error/early-return path and check it against free@",
		})
	}
	switch c.LeakEscapeKind {
	case "return":
		facts = append(facts, VerdictFact{
			Token:  "escape@return",
			Detail: "the value is returned to the caller somewhere — an ownership transfer exists; the leak path must be a NON-returning path",
		})
	case "store":
		facts = append(facts, VerdictFact{
			Token:  "escape@store",
			Detail: "the value is stored into a non-local (global/parameter/container) somewhere — the leak path must bypass that store",
		})
	case "none":
		facts = append(facts, VerdictFact{
			Token:  "escape@none",
			Detail: "no ownership-transfer channel exists anywhere in the function",
		})
	}
	if c.LeakFreeLines != "" {
		facts = append(facts, VerdictFact{
			Token:  "free@" + c.LeakFreeLines,
			Detail: "the release site(s) that exist but do not cover the leak path — the ## Code Context window covers them",
		})
	}
	if c.LeakFreeMismatch != "" {
		facts = append(facts, VerdictFact{
			Token:  "free-mismatch@" + c.LeakFreeMismatch,
			Detail: "release call(s) rejected by the library API family pairing (the acquire API's documented releaser differs) — they do NOT release this object; verify the intended releaser against the acquire API",
		})
	}
	if c.LeakTransferConditional != "" {
		facts = append(facts, VerdictFact{
			Token:  "transfer-cond@" + c.LeakTransferConditional,
			Detail: "guarded ownership-transfer call(s): ownership moves only on the success branch, so the FAILURE branch (error return without release) is the leak path",
		})
	}
	if c.LeakFreeOnBorrow != "" {
		facts = append(facts, VerdictFact{
			Token:  "free-on-borrow@" + c.LeakFreeOnBorrow,
			Detail: fmt.Sprintf("the variable holds a BORROWED pointer (from %s) and %s releases an object the caller does not own — an invalid free with use-after-free / double-free consequences when the real owner releases it; the correct fix is to drop the release, not add one", c.APIName, c.LeakFreeOnBorrow),
		})
	}
	return facts
}

func containsString(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}

// maskSecret renders a hardcoded-secret literal for the evidence file without
// echoing the full value: a report file must not become the leak it reports.
// The first 4 characters plus the total length are enough for the classifier
// to separate a placeholder (REPL…), a test value (test…), a URL credential
// (mysq…) from a real credential — the value-proven (high-entropy) branch is
// auto-confirmed and never reaches the AI, but the mask is applied uniformly
// so a confirmed finding's markdown cannot echo the secret either.
func maskSecret(value string) string {
	n := len(value)
	if n <= 4 {
		return fmt.Sprintf("\"%s\" (%d chars)", strings.Repeat("*", n), n)
	}
	return fmt.Sprintf("\"%s…\" (%d chars)", value[:4], n)
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

// victimSuffix names the stored values behind a collective global-slot double
// free (`g_entries[0]` held e1/e2), so the evidence says WHICH objects the
// release helper may have freed instead of only the slot name.
func victimSuffix(victims string) string {
	if victims == "" {
		return ""
	}
	return " (stored values: " + victims + ")"
}

// buildIntegerOverflowVerdictFacts renders the decisive facts for an
// integer-overflow candidate: the operand origins (param / local / global /
// const), whether they are caller-influenced, and the sink shape. The AI
// classifies from these + the whole-function Code Context without opening
// the raw source.
// buildUncheckedReturnVerdictFacts renders the decisive facts for an
// unchecked-return candidate: whether the callee's failure contract is known,
// whether the return value is deliberately discarded, and (for contract@unknown)
// where the callee definition is embedded so the classifier proves or refutes
// the sentinel without a source READ.
