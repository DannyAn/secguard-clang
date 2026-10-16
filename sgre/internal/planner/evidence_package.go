package planner

import (
	"encoding/json"
	"fmt"
	"strings"
)

type EvidenceItem struct {
	Type              string     `json:"type"`
	VulnerabilityType string     `json:"vulnerability_type"`
	SuspicionLevel    string     `json:"suspicion_level,omitempty"`
	HasDefiniteNull   bool       `json:"has_definite_null,omitempty"`
	MacroContext      bool       `json:"macro_context,omitempty"`
	Target            TargetInfo `json:"target"`
	SourceLine        int        `json:"source_line,omitempty"`
	// Category carries the event's sub-class (e.g. command_injection,
	// argument_injection, crlf_injection) so report consumers can resolve the
	// per-category CWE via CWEForCategory(vulnType, category) when a single
	// vuln_type covers multiple CWEs.
	Category string `json:"category,omitempty"`
	// Hint is a compact, Go-precomputed verdict hint rendered in the candidate
	// index (_index.md) so the AI classifier can usually decide from the row
	// alone — opening the evidence file / source only when the hint is
	// insufficient. It carries the flow facts the pipeline already computed.
	Hint     string             `json:"hint,omitempty"`
	Evidence []EvidenceFragment `json:"evidence"`
	// Signature is the enclosing function's declared signature (parameter names
	// + types), so the AI can read the operand types without a source READ.
	Signature string `json:"signature,omitempty"`
	// FunctionStartLine/FunctionEndLine are the enclosing function's body span
	// (1-based, inclusive). integer-overflow renders the whole span in its Code
	// Context ("signature → candidate, up to ~200 lines" — the promise
	// command-instructions.md and agent-body.md make to the classifier); other
	// types keep the ±8 local window around the reported line. 0 = span unknown.
	FunctionStartLine int `json:"function_start_line,omitempty"`
	FunctionEndLine   int `json:"function_end_line,omitempty"`
	// Contract carries the callee failure-contract provenance for an
	// unchecked-return candidate so the AI classifier can see — from the index
	// row or the evidence file alone — whether "the return is unchecked" is by
	// itself enough to confirm. "known": the pipeline holds a real contract (a
	// standard unchecked-return API, a declared allocator, or a body-verified
	// passthrough wrapper) — an unchecked call is a genuine CWE-252 defect.
	// "unknown": the callee is an allocator by NAME only (a `*_new` / `*_dup`
	// factory or copy helper, an `alloc` substring) whose failure behaviour is
	// unproven; it may be pool-, stack- or caller-buffer-backed and never fail,
	// so it must not be confirmed without evidence that the callee returns a
	// failure sentinel. Empty for every other vuln type.
	Contract string `json:"contract,omitempty"`
}

type TargetInfo struct {
	File     string `json:"file,omitempty"`
	Function string `json:"function"`
	Line     int    `json:"line"`
	Variable string `json:"variable"`
}

type EvidenceFragment struct {
	Type string `json:"type"`
	// Role classifies the fragment in the source→sink→path→condition chain so
	// the report can render a structured evidence narrative rather than a flat
	// list. Empty for generic fragments (rendered by Type).
	Role   string `json:"role,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type PipelineSummary struct {
	SeedCount       int            `json:"seed_count"`
	Filters         []FilterStats  `json:"filters"`
	FinalCount      int            `json:"final_count"`
	DedupedCount    int            `json:"deduped_count"`
	ShortCircuited  bool           `json:"short_circuited"`
	Dropped         []Dismissed    `json:"dropped,omitempty"`
	DroppedByReason map[string]int `json:"dropped_by_reason,omitempty"`
	// SeedRoutedByCategory counts seed events dropped BEFORE the filter chain
	// because their event category belongs to a sibling vuln type that shares
	// the same seed event (BUFFER_ACCESS write categories seed buffer-overflow,
	// read categories seed out-of-bounds). Keeping the breakdown makes the
	// raw-event reduction auditable: a type with seed_count==0 but a non-empty
	// SeedRoutedByCategory did receive events, it just routed them away.
	SeedRoutedByCategory map[string]int `json:"seed_routed_by_category,omitempty"`
}

type FilterStats struct {
	Name        string `json:"name"`
	InputCount  int    `json:"input_count"`
	OutputCount int    `json:"output_count"`
	Error       string `json:"error,omitempty"`
}

type PlanResult struct {
	VulnerabilityType string          `json:"vulnerability_type"`
	Candidates        []EvidenceItem  `json:"candidates"`
	Summary           PipelineSummary `json:"summary"`
}

func (r *PlanResult) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

func (r *PlanResult) CandidateCount() int {
	return len(r.Candidates)
}

// buildHint composes the compact verdict hint from the candidate's flow flags.
// It is deliberately terse: the classifier reads it from the _index.md row, and
// the exact statement is already in the Source column. "src@N" names the null
// source line (null-deref); "certain-null"/"maybe-null" is the null certainty
// tier; "tainted" marks an injection/taint source; "weak-guard" flags a partial
// guard that still needs human review. For divide-by-zero (which has none of
// those flow flags) it emits the divisor's syntactic shape ("divisor@bare" /
// "divisor@call" / "divisor@compound"), so the classifier can settle a bare
// divisor from the Source column instead of opening an evidence file per
// candidate — the per-candidate open that previously exhausted a subagent's
// turn budget before it could write.
//
// Every type also gets its API and category when present ("api@<name>",
// "cat@<name>"), and uninit gets a "certain-uninit"/"maybe-uninit" tier, so no
// type's Hint column is a bare "—": a subagent should never have to open every
// evidence file just to learn what a candidate is.
func buildHint(c Candidate, spec *VulnTypeSpec) string {
	var parts []string
	if spec != nil {
		switch spec.Name {
		case "unchecked-return":
			// The decisive fact for this type is the callee's failure contract.
			// "contract@unknown" means the source is only the allocator NAME
			// heuristic (a `*_new`/`*_dup` factory, an `alloc` substring): the
			// "return is unchecked" observation alone is NOT a defect, so the
			// classifier must prove the callee returns a failure sentinel or
			// dismiss. "contract@known" is a real contract (standard API /
			// declared allocator / body-verified passthrough).
			if c.ContractKnown {
				parts = append(parts, "contract@known")
			} else {
				parts = append(parts, "contract@unknown")
			}
		case "divide-by-zero":
			if shape := divisorShape(c.VariableName); shape != "" {
				parts = append(parts, "divisor@"+shape)
			}
		case "uninit":
			if c.SuspicionLevel == "confirmed" {
				parts = append(parts, "certain-uninit")
			} else if c.SuspicionLevel == "suspected" {
				parts = append(parts, "maybe-uninit")
			}
		case "integer-overflow":
			// unsigned_sub_underflow survivors have no same-function ordering
			// guard: the detector drops the tight `if (consumed <= total)` body
			// guard and UnsignedSubGuardFilter drops the entry-return guard, so
			// anything that reaches the hint has `guard@none`. The operand
			// provenance (`lhs@`/`rhs@` + `rhs-influenced` + `sink@`) is the
			// dataflow fact that lets the classifier judge the subtraction from
			// the _index row — `rhs@param`/`rhs-influenced` means the subtracted
			// amount is externally supplied (real underflow risk), `rhs@local`
			// without `rhs-influenced` means a bounded internal accumulator —
			// instead of opening the source to find the operand origins.
			if c.Category == "unsigned_sub_underflow" {
				if c.LHSKind != "" {
					parts = append(parts, "lhs@"+c.LHSKind)
				}
				if c.RHSKind != "" {
					parts = append(parts, "rhs@"+c.RHSKind)
				}
				if c.SubRHSInfluenced {
					parts = append(parts, "rhs-influenced")
				}
				if c.SubSink != "" {
					parts = append(parts, "sink@"+c.SubSink)
				}
				parts = append(parts, "guard@none")
			}
		}
	}
	if c.SourceLine > 0 {
		parts = append(parts, fmt.Sprintf("src@%d", c.SourceLine))
	}
	switch {
	case c.HasDefiniteNull:
		parts = append(parts, "certain-null")
	case c.HasNullableSource:
		parts = append(parts, "maybe-null")
	}
	if c.HasTaintSource {
		parts = append(parts, "tainted")
	}
	if c.GuardStrength == "weak" {
		parts = append(parts, "weak-guard")
	}
	if c.MacroContext {
		parts = append(parts, "macro-context")
	}
	if c.APIName != "" {
		parts = append(parts, "api@"+c.APIName)
	}
	if c.Category != "" {
		parts = append(parts, "cat@"+c.Category)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, " ")
}

func newEvidenceItem(c Candidate, spec *VulnTypeSpec, fileName string) EvidenceItem {
	item := EvidenceItem{
		Type:              spec.EvidenceType,
		VulnerabilityType: spec.Name,
		HasDefiniteNull:   c.HasDefiniteNull,
		MacroContext:      c.MacroContext,
		Target: TargetInfo{
			File:     fileName,
			Function: c.FunctionName,
			Line:     c.Line,
			Variable: c.VariableName,
		},
		SourceLine: c.SourceLine,
		Category:   c.Category,
		Hint:       buildHint(c, spec),
		Evidence:   spec.BuildEvidence(c),
		Signature:  c.FunctionSignature,

		FunctionStartLine: c.FuncStartLine,
		FunctionEndLine:   c.FuncEndLine,
	}
	if c.SuspicionLevel != "" {
		item.SuspicionLevel = c.SuspicionLevel
	} else {
		item.SuspicionLevel = spec.DefaultSuspicion
	}
	if spec.Name == "unchecked-return" {
		if c.ContractKnown {
			item.Contract = "known"
		} else {
			item.Contract = "unknown"
		}
	}
	if c.GuardStrength == "weak" {
		item.Evidence = append(item.Evidence, EvidenceFragment{
			Type:   "weak_guard",
			Detail: "guard exists but is insufficient (partial protection, needs AI review)",
		})
	}
	return item
}
