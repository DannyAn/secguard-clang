package planner

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

type EvidenceItem struct {
	Type              string `json:"type"`
	VulnerabilityType string `json:"vulnerability_type"`
	SuspicionLevel    string `json:"suspicion_level,omitempty"`
	// MayFree marks a double-free candidate whose first release is conditional
	// (a release helper that frees only on some paths). The candidate is a
	// possible double free; the report and the Hint say so explicitly.
	MayFree         bool       `json:"may_free,omitempty"`
	HasDefiniteNull bool       `json:"has_definite_null,omitempty"`
	MacroContext    bool       `json:"macro_context,omitempty"`
	Target          TargetInfo `json:"target"`
	SourceLine      int        `json:"source_line,omitempty"`
	// SourceLines collects every pipeline-proven decisive source line for the
	// candidate — the free-site of a use-after-free, the two frees of a
	// double-free, the declaration of an uninit read, the origin of a null or
	// taint value, the racing write, the unguarded dereference. The report
	// widens the Code Context window to cover the source→sink span so a
	// fragment's "free(p) at line N" is checkable in view, not just trusted.
	SourceLines []int `json:"source_lines,omitempty"`
	// Category carries the event's sub-class (e.g. command_injection,
	// argument_injection, crlf_injection) so report consumers can resolve the
	// per-category CWE via CWEForCategory(vulnType, category) when a single
	// vuln_type covers multiple CWEs.
	Category string `json:"category,omitempty"`
	// Hint is a compact, Go-precomputed verdict hint rendered in the candidate
	// index (_index.md) so the AI classifier can usually decide from the row
	// alone — opening the evidence file / source only when the hint is
	// insufficient. It carries the flow facts the pipeline already computed.
	Hint string `json:"hint,omitempty"`
	// HintTokens is the decomposed token sequence behind Hint (same order,
	// same content), so the report layer can render each token with its
	// registry description (the candidate file's "## Pipeline Tokens"
	// section) without re-parsing the joined hint. Empty = no tokens (Hint
	// is the "—" placeholder).
	HintTokens []string `json:"hint_tokens,omitempty"`
	// VerdictFacts are the type's decisive facts as short structured lines
	// (token + one sentence + provenance line numbers), rendered in the
	// candidate file's "## Verdict Facts" section. They are the distilled
	// semantic-graph answers the classifier needs — NOT raw CFG/DFG/call
	// dumps (those are pure noise to an LLM and blow the per-range context
	// budget). Empty = the type has not declared a facts contract yet
	// (Evidence Contract v2 rolls out per type; see
	// docs/evidence-contract-v2-design.md).
	VerdictFacts []VerdictFact      `json:"verdict_facts,omitempty"`
	Evidence     []EvidenceFragment `json:"evidence"`
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
	// CalleeDefFile/CalleeDefLine/CalleeDefEndLine/CalleeDefSignature carry the
	// unchecked-return callee's definition location and body span for
	// contract@unknown candidates: the classifier must prove the callee returns
	// a failure sentinel, and the definition is frequently in ANOTHER file
	// (static factory in pool.c called from server.c), so the report embeds the
	// body rather than sending the classifier on a source-READ search. Empty
	// CalleeDefFile = no definition in the scan (external/library callee).
	CalleeDefFile      string `json:"callee_def_file,omitempty"`
	CalleeDefLine      int    `json:"callee_def_line,omitempty"`
	CalleeDefEndLine   int    `json:"callee_def_end_line,omitempty"`
	CalleeDefSignature string `json:"callee_def_signature,omitempty"`
	// DivisorInterval renders the range engine's tighter-than-top interval
	// for a divide-by-zero divisor it could not clear (contains 0), e.g.
	// "[0, 1]". DivisorCallers summarizes the direct-call-site census for a
	// parameter divisor the verdict could not settle. Empty values mean the
	// engine had no fact worth reporting.
	DivisorInterval string `json:"divisor_interval,omitempty"`
	DivisorCallers  string `json:"divisor_callers,omitempty"`
	// Expression is the detector's full statement text (multi-line calls keep
	// their wrapped arguments), rendered in the evidence file's Location
	// section so a wrapped statement is not reduced to its first line.
	Expression string `json:"expression,omitempty"`
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

// VerdictFact is ONE distilled decisive fact for a candidate: the hint token
// it elaborates (when it has a token twin) plus a one-sentence answer with
// its provenance (file:line), e.g.
//
//	Token: "null@caller-arg"
//	Detail: "parameter `t` — caller `dispatch(t)` passes it unproven non-null (p5.c:119)"
//
// The distinction from EvidenceFragment: fragments are the narrative chain
// (source→sink→path→condition), VerdictFacts are the machine-distilled
// Q&A the classifier decides from — same registry vocabulary as the Hint,
// so the three rendering surfaces (index row, candidate file, re-review
// payload) stay coherent.
type VerdictFact struct {
	Token  string `json:"token,omitempty"`
	Detail string `json:"detail"`
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
// turn budget before it could write. Deadlock emits the inversion pair
// ("locks@A|B", plus "reverse@<fn>"), and use-after-free/double-free emit the
// free line(s) ("free@N" / "free@N,M"), so those types are settled from the
// row too.
//
// Every type also gets its API and category when present ("api@<name>",
// "cat@<name>"), and uninit gets a "certain-uninit"/"maybe-uninit" tier, so no
// type's Hint column is a bare "—": a subagent should never have to open every
// evidence file just to learn what a candidate is.
func buildHint(c Candidate, spec *VulnTypeSpec) string {
	parts := buildHintParts(c, spec)
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, " ")
}

// buildHintParts is the token-emitting core behind buildHint: it returns the
// ordered token sequence instead of the joined string, so newEvidenceItem can
// carry the decomposition (EvidenceItem.HintTokens) for the per-candidate
// "## Pipeline Tokens" rendering. Every token it emits must be declared in
// hintTokenRegistry (hint_tokens.go) — the guard test enforces it.
func buildHintParts(c Candidate, spec *VulnTypeSpec) []string {
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
				// The definition location for the contract@unknown proof burden:
				// the callee body is often in ANOTHER file, so the hint lets the
				// classifier jump straight to it. External callees (no definition
				// in the scan) get no token — the evidence file says so instead.
				if c.CalleeDefFile != "" {
					parts = append(parts, fmt.Sprintf("callee@%s:%d", filepath.Base(c.CalleeDefFile), c.CalleeDefLine))
				}
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
				if c.SubLHSInfluenced {
					parts = append(parts, "lhs-influenced")
				}
				if c.SubSink != "" {
					parts = append(parts, "sink@"+c.SubSink)
				}
				parts = append(parts, "guard@none")
			}
		case "deadlock":
			// The inversion pair and its reverse acquirer are the whole defect:
			// "locks@A|B" lets the classifier match the pair across functions
			// from the _index row alone.
			if c.MutexA != "" && c.MutexB != "" {
				parts = append(parts, "locks@"+c.MutexA+"|"+c.MutexB)
			}
			if c.ReverseFunc != "" {
				parts = append(parts, "reverse@"+c.ReverseFunc)
			}
		case "use-after-free":
			if c.FreeLine > 0 {
				parts = append(parts, fmt.Sprintf("free@%d", c.FreeLine))
			}
		case "double-free":
			if c.FirstFree > 0 && c.SecondFree > 0 {
				parts = append(parts, fmt.Sprintf("free@%d,%d", c.FirstFree, c.SecondFree))
			}
			// A conditional first release (a helper that frees only when its own
			// condition holds) is a POSSIBLE double free; the token stops the
			// classifier from treating the row as a proved defect.
			if c.MayFree {
				parts = append(parts, "may-free")
			}
		case "race-condition":
			// BuildEvidence already computed these facts; without them in the
			// Hint every race candidate needed an Evidence-file open just to
			// learn who races / where the lock ends. Each sub-shape carries the
			// pair that settles it:
			//   shared_data_race    -> threads@<fn> (+ instances@N, write@N)
			//   toctou_shared_state -> mutex@<name> lock@<lo>-<hi> (state write
			//                          at the candidate line is outside it)
			//   toctou              -> check@<fn>→use@<fn> arg@<expr>
			switch c.Category {
			case "shared_data_race":
				if c.ThreadFunctions != "" {
					parts = append(parts, "threads@"+c.ThreadFunctions)
				}
				if c.ThreadInstances > 0 {
					parts = append(parts, fmt.Sprintf("instances@%d", c.ThreadInstances))
				}
				if c.WriteLine > 0 {
					parts = append(parts, fmt.Sprintf("write@%d", c.WriteLine))
				}
			case "toctou_shared_state":
				if c.Mutex != "" {
					parts = append(parts, "mutex@"+c.Mutex)
				}
				if c.LockLine > 0 && c.UnlockLine > 0 {
					parts = append(parts, fmt.Sprintf("lock@%d-%d", c.LockLine, c.UnlockLine))
				}
			case "toctou":
				if c.CheckFunction != "" && c.UseFunction != "" {
					parts = append(parts, "check@"+c.CheckFunction+"→use@"+c.UseFunction)
				}
				if c.CheckPathArg != "" {
					parts = append(parts, "arg@"+c.CheckPathArg)
				}
			}
		}
	}
	// api@/cat@ sit RIGHT after the type-specific tokens (not at the tail):
	// the Hint column is markdownCell-truncated at 120 chars, and api@ (the
	// callee name) is the core classifier input for unchecked-return — the
	// longest hints are exactly that type's, so a tail position let the
	// callee name be the first thing the truncation ate.
	if c.APIName != "" {
		parts = append(parts, "api@"+c.APIName)
	}
	if c.Category != "" {
		parts = append(parts, "cat@"+c.Category)
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
	return parts
}

func newEvidenceItem(c Candidate, spec *VulnTypeSpec, fileName string) EvidenceItem {
	hintTokens := buildHintParts(c, spec)
	hint := "—"
	if len(hintTokens) > 0 {
		hint = strings.Join(hintTokens, " ")
	}
	item := EvidenceItem{
		Type:              spec.EvidenceType,
		VulnerabilityType: spec.Name,
		HasDefiniteNull:   c.HasDefiniteNull,
		MayFree:           c.MayFree,
		MacroContext:      c.MacroContext,
		Target: TargetInfo{
			File:     fileName,
			Function: c.FunctionName,
			Line:     c.Line,
			Variable: c.VariableName,
		},
		SourceLine: c.SourceLine,
		Category:   c.Category,
		Hint:       hint,
		HintTokens: hintTokens,
		Evidence:   spec.BuildEvidence(c),
		Signature:  c.FunctionSignature,

		FunctionStartLine: c.FuncStartLine,
		FunctionEndLine:   c.FuncEndLine,

		CalleeDefFile:      c.CalleeDefFile,
		CalleeDefLine:      c.CalleeDefLine,
		CalleeDefEndLine:   c.CalleeDefEndLine,
		CalleeDefSignature: c.CalleeDefSignature,

		DivisorInterval: c.DivisorInterval,
		DivisorCallers:  c.DivisorCallers,

		Expression: c.Expression,
	}
	if spec.BuildVerdictFacts != nil {
		item.VerdictFacts = spec.BuildVerdictFacts(c)
	}
	for _, ln := range []int{c.SourceLine, c.DeclLine, c.FreeLine, c.FirstFree, c.SecondFree, c.UseLine, c.WriteLine} {
		if ln > 0 {
			item.SourceLines = append(item.SourceLines, ln)
		}
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
