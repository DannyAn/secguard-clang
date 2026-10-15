package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// Dismissed records a candidate removed by a filter, with the reason it was
// removed. The planner aggregates these into the pipeline summary and the
// persisted dismissed ledger, so convergence is auditable rather than a silent
// hard truncation.
type Dismissed struct {
	FunctionName string `json:"function_name"`
	VariableName string `json:"variable_name"`
	Line         int    `json:"line"`
	Filter       string `json:"filter"`
	Reason       string `json:"reason"`
}

// Filter is a single refinement stage in a vulnerability's filter chain.
// Apply keeps the candidates that pass and returns the candidates it dropped,
// each with a human-readable reason, so the planner can build an explicit
// convergence trail. A filter that cannot make a decision must return its
// error and a nil kept/dropped pair; the planner then preserves the input
// candidates and records the degradation rather than silently dropping them.
type Filter interface {
	Name() string
	Apply(ctx context.Context, candidates []Candidate) (kept []Candidate, dropped []Dismissed, err error)
}

// partition splits candidates into kept and dropped by keep, recording a
// per-candidate reason under filterName. reason is evaluated only for dropped
// candidates.
func partition(candidates []Candidate, keep func(Candidate) bool, reason func(Candidate) string, filterName string) ([]Candidate, []Dismissed) {
	kept := make([]Candidate, 0, len(candidates))
	dropped := make([]Dismissed, 0)
	for _, c := range candidates {
		if keep(c) {
			kept = append(kept, c)
			continue
		}
		dropped = append(dropped, Dismissed{
			FunctionName: c.FunctionName,
			VariableName: c.VariableName,
			Line:         c.Line,
			Filter:       filterName,
			Reason:       reason(c),
		})
	}
	return kept, dropped
}

// dismiss is a convenience for filters that mutate candidates before keeping
// them and need to record a drop inline rather than via a pure predicate.
func dismiss(dropped []Dismissed, c Candidate, filterName, reason string) []Dismissed {
	return append(dropped, Dismissed{
		FunctionName: c.FunctionName,
		VariableName: c.VariableName,
		Line:         c.Line,
		Filter:       filterName,
		Reason:       reason,
	})
}

// candidateFuncIDs returns the distinct function IDs of a byFunc bucket map.
func candidateFuncIDs(byFunc map[int64][]Candidate) []int64 {
	ids := make([]int64, 0, len(byFunc))
	for fid := range byFunc {
		ids = append(ids, fid)
	}
	return ids
}

// loadFuncFiles batch-loads the functions and files for the given function IDs,
// returning fnByID and fileByID maps. The flow filters iterate candidates by
// function and previously issued one GetFunctionByID + GetFileByID point query
// per function (an N+1 storm); this collapses the same work to one batched
// function query plus one file listing.
func loadFuncFiles(ctx context.Context, store db.Store, funcIDs []int64) (map[int64]*db.Function, map[int64]*db.File) {
	fnByID, err := store.ListFunctionsByIDs(ctx, funcIDs)
	if err != nil {
		fnByID = map[int64]*db.Function{}
	}
	return fnByID, listFilesByID(ctx, store)
}

// listFilesByID returns every indexed file keyed by ID in one query, or an empty
// map when the listing fails. It exists so a whole-program loop (`for _, fn :=
// range ListFunctions`) does not issue one GetFileByID per function.
func listFilesByID(ctx context.Context, store db.Store) map[int64]*db.File {
	fileByID := map[int64]*db.File{}
	if files, err := store.ListFiles(ctx); err == nil {
		for _, fl := range files {
			fileByID[fl.ID] = fl
		}
	}
	return fileByID
}

type Candidate struct {
	DerefEventID      int64  `json:"deref_event_id"`
	FunctionID        int64  `json:"function_id"`
	FunctionName      string `json:"function_name"`
	VariableName      string `json:"variable_name"`
	APIName           string `json:"api_name,omitempty"`
	Category          string `json:"category,omitempty"`
	LocationID        int64  `json:"location_id"`
	FileID            int64  `json:"file_id"`
	Line              int    `json:"line"`
	HasNullableSource bool   `json:"has_nullable_source"`
	HasDefiniteNull   bool   `json:"has_definite_null"`
	IsReachable       bool   `json:"is_reachable"`
	HasDataFlow       bool   `json:"has_data_flow"`
	HasTaintSource    bool   `json:"has_taint_source"`
	IsGuarded         bool   `json:"is_guarded"`
	GuardStrength     string `json:"guard_strength"`
	SuspicionLevel    string `json:"suspicion_level"`
	// MacroContext is true when the candidate's reported statement or its
	// surrounding context involves a function-like macro call. Macro semantics
	// (guard macros, iterator macros, accessor macros, alloc/free wrappers) are
	// exactly where the deterministic pipeline mis-models control flow, so a
	// macro-context candidate is never auto-confirmed: it is routed to the AI
	// agent for judgment.
	MacroContext bool `json:"macro_context,omitempty"`
	// ContractKnown marks an unchecked-return candidate whose callee's failure
	// contract is known (built-in API table / declared allocator / inspected
	// wrapper body) rather than inferred from the allocator name heuristic.
	// ReturnCheckFilter only promotes these to the deterministic tier.
	ContractKnown bool `json:"contract_known,omitempty"`
	NonNullable   bool `json:"non_nullable"`
	IsTypeExpr    bool `json:"is_type_expr"`
	// IsCallResultDeref marks a dereference of a direct function-call result
	// (`f()->field`, `*f()`, `f()[i]`); CalleeName is the called function. The
	// nullable_source filter resolves these against the inter-procedural
	// retNullable set (which callee can return NULL) rather than the
	// intra-procedural per-variable reaching analysis, because no assignment
	// `p = f()` exists to give the call result a tracked variable name.
	IsCallResultDeref bool    `json:"is_call_result_deref,omitempty"`
	CalleeName        string  `json:"callee_name,omitempty"`
	QualityScore      float64 `json:"quality_score"`
	SourceLine        int     `json:"source_line,omitempty"`
	DeclLine          int     `json:"decl_line,omitempty"`
	Origin            string  `json:"origin,omitempty"`
	// FieldPath is the full member/element access text of an uninit read
	// (`p->f`, `p[i]`, `s.f`); empty for whole/scalar reads.
	FieldPath string `json:"field_path,omitempty"`
	// Array/Index/Size carry the buffer-overflow detector's resolved access
	// (array name, index expression, element count) for the range-oob filter.
	Array string `json:"array,omitempty"`
	Index string `json:"index,omitempty"`
	Size  int    `json:"size,omitempty"`
	// ExpectedType/ActualType/CastType are the argument-type mismatch evidence
	// (parameter type, pre-cast argument type, explicit cast target type).
	ExpectedType string `json:"expected_type,omitempty"`
	ActualType   string `json:"actual_type,omitempty"`
	CastType     string `json:"cast_type,omitempty"`
	// CallerNullDetail describes the inter-procedural caller_null origin of a
	// parameter's nullability (e.g. "caller c passes NULL"), surfaced in the
	// evidence so the AI can judge the caller contract instead of a bare "line 0".
	CallerNullDetail string `json:"caller_null_detail,omitempty"`
	// FunctionSignature is the enclosing function's declared signature (parameter
	// names + types), propagated from the index so the AI classifier can read the
	// operand types without opening the source file.
	FunctionSignature string `json:"function_signature,omitempty"`
	// LHSKind/RHSKind classify an integer-overflow unsigned_sub_underflow operand
	// origin (param/local/global/deref/subscript/const/expr); SubRHSInfluenced is
	// true when the subtrahend is caller/attacker-controlled; SubSink is
	// call_arg/assign. These carry the operand provenance the detector already
	// computed into the dense Hint, so the AI classifies from the _index row.
	LHSKind          string `json:"lhs_kind,omitempty"`
	RHSKind          string `json:"rhs_kind,omitempty"`
	SubRHSInfluenced bool   `json:"sub_rhs_influenced,omitempty"`
	SubSink          string `json:"sub_sink,omitempty"`
	// Subject is the struct-pointer parameter the implicit-contract candidate
	// is about (e.g. "resp" for resp->group_data).
	Subject string `json:"subject,omitempty"`
	// CountField is the count/length field gating the pointer use
	// (e.g. "resp->group_num"), empty when no count gates the deref.
	CountField string `json:"count_field,omitempty"`
	// UseLine is the dereference line the missing guard fails to cover.
	UseLine int `json:"use_line,omitempty"`
	// Missing names the precondition that is absent ("ptr-null").
	Missing string `json:"missing,omitempty"`
	// EvidenceKind is the nullable-field evidence source ("self" / "caller").
	EvidenceKind string `json:"evidence_kind,omitempty"`
	// FreeLine is the free-site line for a use-after-free candidate (where the
	// variable was freed before the use at Line).
	FreeLine int `json:"free_line,omitempty"`
	// FirstFree/SecondFree are the two free-site lines for a double-free
	// candidate.
	FirstFree  int `json:"first_free,omitempty"`
	SecondFree int `json:"second_free,omitempty"`
	// DefiniteLeak is true when the leak detector proved no release/escape/
	// transfer is reachable on any path (memory-leak / resource-leak).
	DefiniteLeak bool `json:"definite_leak,omitempty"`
	// ThreadFunctions is the comma-separated list of pthread thread function
	// names for a shared_data_race candidate (race-condition).
	ThreadFunctions string `json:"thread_functions,omitempty"`
	// ThreadInstances is the number of distinct thread instances for a
	// shared_data_race candidate.
	ThreadInstances int `json:"thread_instances,omitempty"`
	// WriteLine is the line of the conflicting write for a shared_data_race
	// candidate.
	WriteLine int `json:"write_line,omitempty"`
	// CopySize/DstCapacity are the copy-size expression and destination capacity
	// for a bounded-copy or secure-copy buffer-overflow candidate.
	CopySize    string `json:"copy_size,omitempty"`
	DstCapacity string `json:"dst_capacity,omitempty"`
	// SizeArgument is the _s destination-capacity argument for a secure-copy
	// buffer-overflow candidate.
	SizeArgument string `json:"size_argument,omitempty"`
	// MutexA/MutexB are the two locks in a lock-order inversion (deadlock).
	// ReverseFunc is the function that acquires them in the opposite order.
	MutexA      string `json:"mutex_a,omitempty"`
	MutexB      string `json:"mutex_b,omitempty"`
	ReverseFunc string `json:"reverse_func,omitempty"`
}
