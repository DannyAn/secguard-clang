package planner

import (
	"encoding/json"
	"strconv"
	"strings"
)

// flexInt decodes a JSON number or a numeric string ("4"). Some detectors emit
// properties through map[string]string (numbers via strconv.Itoa), so a plain
// int field silently zeroes on unmarshal and the value never reaches the
// candidate. flexInt accepts both shapes; a non-numeric value (e.g. crypto
// key_size carrying source text) decodes to 0 without aborting the decode of
// the sibling fields.
type flexInt int

func (n *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		*n = 0
		return nil
	}
	*n = flexInt(v)
	return nil
}

// eventProps is the unified, typed view of the free-form JSON stored in
// security_events.properties. Detectors emit a loose subset of these keys;
// the planner reads them through this single struct so the field names live
// in one place instead of being re-declared per filter.
type eventProps struct {
	Variable    string `json:"variable"`
	Expression  string `json:"expression"`
	Function    string `json:"function"`
	Category    string `json:"category"`
	NonNullable string `json:"non_nullable"`
	IsTypeExpr  string `json:"is_type_expr"`
	// IsCallResultDeref is "true" when the dereferenced operand is the direct
	// result of a function call (`f()->field`, `*f()`, `f()[i]`) rather than a
	// tracked variable. The null-deref filter cannot reach such a deref via the
	// per-variable flow (there is no assignment `p = f()` to hang a null source
	// on), so it consults Callee against the inter-procedural retNullable set
	// instead of the intra-procedural reaching analysis.
	IsCallResultDeref string `json:"is_call_result_deref"`
	Condition         string `json:"condition"`
	ScopeStart        int    `json:"scope_start"`
	ScopeEnd          int    `json:"scope_end"`
	Strength          string `json:"strength"`
	FreeLine          int    `json:"free_line"`
	UseLine           int    `json:"use_line"`
	Origin            string `json:"origin"`
	DeclLine          int    `json:"decl_line"`
	// InitWrite is the machine-proven write-path fact of an uninit read:
	// "none" = the read target is never written before the read,
	// "loop" = the only writes sit inside a loop body the condition may skip
	// (InitWriteLine = the first such write). Empty = no proven fact.
	InitWrite     string  `json:"init_write"`
	InitWriteLine flexInt `json:"init_write_line"`
	// FieldPath is the full member/element access text of an uninit read
	// (`p->f`, `p[i]`, `s.f`), empty for whole/scalar reads. The definite-init
	// filter uses it to refine heap/struct candidates at field granularity.
	FieldPath string `json:"field_path"`
	// AllocLine is the allocation/acquire source line a MEMORY_RELEASE /
	// RESOURCE_RELEASE event releases. It lets ReleaseFilter correlate a release
	// to a specific candidate (candidate.Line == the source line) instead of a
	// coarse (function, variable) key that would drop a sibling leak site too.
	AllocLine   int    `json:"alloc_line"`
	Definite    string `json:"definite"` // "true" for an explicit null assignment
	Callee      string `json:"callee"`
	API         string `json:"api"` // hardcoded_secret RegSetValueEx branch
	Name        string `json:"name"`
	Value       string `json:"value"`
	MutexA      string `json:"mutex_a"`
	MutexB      string `json:"mutex_b"`
	ReverseFunc string `json:"reverse_function"`
	Array       string `json:"array"`
	Index       string `json:"index"`
	// Size is the resolved array element count the buffer-overflow detector
	// attached to a BUFFER_ACCESS event, used by the planner's range-oob filter
	// to re-verify the index interval against the capacity (BO-01/02).
	Size       flexInt `json:"size"`
	KeySize    flexInt `json:"key_size"`
	Reason     string  `json:"reason"`
	CheckFunc  string  `json:"check_function"`
	UseFunc    string  `json:"use_function"`
	PathArg    string  `json:"path_arg"`
	Path       string  `json:"path"`       // path-traversal sink argument text
	FormatArg  string  `json:"format_arg"` // format-string sink argument text
	Mutex      string  `json:"mutex"`
	LockLine   flexInt `json:"lock_line"`
	UnlockLine flexInt `json:"unlock_line"`
	Divisor    string  `json:"divisor"` // divide-by-zero divisor expression
	// DefinitelyZero is "true" when the divide-by-zero detector proved the
	// divisor is exactly zero (a literal `x/0` or a zero-valued constant symbol),
	// so the RangeFilter auto-confirms it instead of deferring to the AI agent.
	DefinitelyZero string `json:"definitely_zero"`
	// ContractKnown is "true" when the unchecked-return detector derived the
	// callee's failure contract from a built-in API table, a declared allocator,
	// or an inspected wrapper body. A name-only allocator match (the "alloc"
	// substring / "_dup" / "_new" heuristic) leaves it unset, so
	// ReturnCheckFilter keeps that candidate suspected for the AI — mirroring
	// ValueProven's name-vs-value split for hardcoded secrets.
	ContractKnown string `json:"contract_known"`
	// Consumed is "discard" when the unchecked-return result's only observable
	// use is an explicit `(void)` cast — the value is deliberately discarded, so
	// the ignored failure is unobservable; the AI dismisses from the hint.
	Consumed string `json:"consumed"`
	// ValueProven is "true" when the hardcoded-secret detector found the literal's
	// VALUE itself secret-shaped (known token prefix / high entropy / URL
	// credentials); the HardcodedSecretProofFilter auto-confirms those, while a
	// name-only match stays suspected for the AI.
	ValueProven string `json:"value_proven"`
	// Timed is "true" when the deadlock detector's cycle needs a
	// pthread_mutex_timedlock acquisition; LockOrderFilter keeps such a cycle
	// suspected (the timeout allows recovery) instead of confirming it.
	Timed string `json:"timed"`
	// ThreadFunctions is the comma-separated list of pthread thread function
	// names a shared_data_race event reports (race-condition detector).
	ThreadFunctions string `json:"thread_functions"`
	// ThreadInstances is the number of distinct pthread thread instances a
	// shared_data_race event reports (race-condition detector).
	ThreadInstances flexInt `json:"thread_instances"`
	// WriteLine is the line of the conflicting write in a shared_data_race
	// event (race-condition detector).
	WriteLine flexInt `json:"write_line"`
	// FirstFree/SecondFree are the two free-site lines a double-free event
	// reports (double-free detector). MayFree is "true" when the first free is a
	// conditional callee release (may-free), so the double free is possible but
	// not must-proven; FirstCallee/Victims carry the release helper and the
	// stored variables behind a global-slot double free.
	FirstFree   int    `json:"first_free"`
	SecondFree  int    `json:"second_free"`
	MayFree     string `json:"may_free"`
	FirstCallee string `json:"first_callee"`
	SecondCallee string `json:"second_callee"`
	Victims     string `json:"victims"`
	// CopySize/DstCapacity are the copy-size expression and destination capacity
	// a bounded-copy or secure-copy BUFFER_ACCESS event carries (buffer-overflow
	// detector). SizeArgument is the _s destination-capacity argument.
	CopySize     string `json:"copy_size"`
	DstCapacity  string `json:"dst_capacity"`
	SizeArgument string `json:"size_argument"`
	// SrcCapacity is the resolved capacity of the SOURCE buffer of an unbounded
	// copy (`strcpy(g_dst, g_src)`, `strcat`, `memcpy`): when the source is a
	// fixed-size array/global the detector already knows, its element count is
	// attached so the classifier can judge "is the source itself bounded" without
	// reading the source file — the round3 `dgf_string`/`dgf_format` dismissal
	// (both operands are 128-byte globals) needed exactly this fact.
	SrcCapacity flexInt `json:"src_capacity"`
	// Expected/Actual/Cast are the argument-type mismatch evidence: the callee's
	// declared parameter type (e.g. "uint *"), the argument's actual pointer type
	// before the cast (e.g. "bool *"), and the explicit cast target type.
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Cast     string `json:"cast"`
	// Tautology is "dead_branch" when a signed-compare comparison is provably
	// always false (`u < 0`), so the branch is dead code with no runtime impact.
	// The planner downgrades such findings from "confirmed" to "suspected".
	Tautology string `json:"tautology"`
	// LHSKind/RHSKind classify an integer-overflow unsigned_sub_underflow operand
	// origin (param/local/global/deref/subscript/const/expr); LHSInfluenced/
	// RHSInfluenced are "true" when that operand is caller/attacker-controlled;
	// Sink is call_arg/assign. The planner surfaces these as a dense Hint so the
	// AI classifies from the _index row instead of opening the source.
	LHSKind       string `json:"lhs_kind"`
	RHSKind       string `json:"rhs_kind"`
	LHSInfluenced string `json:"lhs_influenced"`
	RHSInfluenced string `json:"rhs_influenced"`
	Sink          string `json:"sink"`
	// Sanitizer names a caller-defined sanitizer/validator function guarding the
	// injection sink's argument (is_safe_input / *_validate / *_filter): a
	// partial validation signal, never a proof of safety.
	Sanitizer string `json:"sanitizer"`
	// Subject/CountField/Missing/EvidenceKind carry the implicit-contract
	// candidate's structured evidence: the struct-pointer parameter being
	// validated (subject), the count/length field gating the pointer use
	// (count), the missing precondition (missing), and the evidence kind
	// (self/caller) that proves the field is treated as nullable.
	Subject      string `json:"subject"`
	CountField   string `json:"count"`
	Missing      string `json:"missing"`
	EvidenceKind string `json:"evidence"`
	// GuardLine is the line of the same-function NULL check that guards the
	// field for the "self" evidence kind; the deref site sits OUTSIDE that
	// guard's scope (the contract gap). Surfacing it lets the classifier see
	// the guard structure without a source read.
	GuardLine flexInt `json:"guard_line"`
	// EscapeKind is the ownership-release channel summary a leak event carries
	// ("return"/"store"/"none", from leakEscapeKind); FreeLines is the comma-
	// separated release-line list. Together they let the classifier tell a
	// machine-proved loss from a conditional leak whose release exists but is
	// bypassed on the leak path.
	EscapeKind string `json:"escape_kind"`
	FreeLines  string `json:"free_lines"`
}

func parseEventProps(raw string) eventProps {
	var p eventProps
	_ = json.Unmarshal([]byte(raw), &p)
	return p
}
