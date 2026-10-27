package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
)

// null_analysis.go implements the L1 (fact/semantic) null model for the
// null-deref pipeline. It is derived entirely from security_events — the
// NULL_VALUE rows emitted by the evidence detectors — and is keyed by
// (function, variable) rather than by function alone. This replaces the
// previous function-level `nullFuncs[FunctionID]` approximation that kept
// every dereference in a function as soon as that function had *any* null
// source.
//
// It is a pure event-index model (no CFG): the flow-sensitive CFG/DATA_FLOW
// analysis lives in null_flow.go, and this model only feeds it the NULL_VALUE
// source facts keyed by (function, variable).

// nullSource is a single variable-level origin of a possibly-null value.
type nullSource struct {
	variable string
	line     int
	// column is the source statement's column when the emitting detector
	// recorded one (currently the self-referential field-read update). It lets
	// the flow analysis resolve the source to the exact statement on its line —
	// a `for (init; cond; update)` header has three statements on one line.
	column int
	origin string
	// definite marks an EXPLICIT null assignment (`p = NULL`), as opposed to a
	// possible-null source (malloc/fopen/function-return). A definite source
	// reaching a dereference is a certain null-deref, not a maybe.
	definite bool
	// chainOpen marks a caller_null source that the open-chain fixpoint
	// graded OPEN (a possibly-null value can actually reach the parameter
	// from an unguarded entry), as opposed to a legacy "unproven" argument
	// event (an analyzer limitation, dismissible).
	chainOpen bool
	// caller / argText carry the inter-procedural origin for a caller_null
	// source (origin "caller_null"): the function that passed a possibly-null
	// argument, and that argument's text (e.g. caller "c", argText "NULL").
	caller  string
	argText string
	// argVarNames / argUnsafe carry the call-site argument facts for a
	// planner-synthesized `p = f(a, b)` source: which arguments are plain
	// identifiers (their nullability is checked against the reaching analysis
	// at the assignment line), and whether any argument is an opaque shape
	// (a NULL literal, another call, arithmetic) that cannot be proven
	// non-null syntactically.
	argVarNames []string
	argUnsafe   bool
	// argInfo records every argument's syntactic shape BY POSITION, so the
	// guard-mutex dismissal can correlate the callee's overflow parameter
	// index with the caller's actual argument (an identifier) and prove the
	// length argument is positive (a sizeof expression or a positive
	// literal). argVarNames alone drops the position information.
	argInfo []synthArgInfo
	// countField names the paired count/length field when this opaque
	// field-read source is a count-gated array buffer (`tree =
	// (T *)(resp->group_data)` gated by `resp->group_num`). It upgrades the
	// candidate's tier from the flat opaque-origin to array-buffer@<field>.
	countField string
}

// nullModel is the L1 null model for a single function.
type nullModel struct {
	sources []nullSource
}

// buildNullModel loads NULL_VALUE events for the whole scan and buckets them by
// function, producing the per-function variable-level model.
func buildNullModel(ctx context.Context, store db.Store) (map[int64]*nullModel, error) {
	models := make(map[int64]*nullModel)

	events, err := store.ListEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		return nil, err
	}
	// Batch-load the locations the NULL_VALUE events reference (one chunked query
	// instead of one point query per event).
	locIDs := make([]int64, 0, len(events))
	for _, e := range events {
		if e.LocationID > 0 {
			locIDs = append(locIDs, e.LocationID)
		}
	}
	locsByID, err := store.ListLocationsByIDs(ctx, locIDs)
	if err != nil {
		return nil, err
	}

	for _, e := range events {
		props := parseEventProps(e.Properties)
		if props.Variable == "" {
			continue
		}
		m := models[e.EntityID]
		if m == nil {
			m = &nullModel{}
			models[e.EntityID] = m
		}
		line := 0
		column := 0
		if loc := locsByID[e.LocationID]; loc != nil {
			line = loc.Line
			column = loc.Column
		}
		m.sources = append(m.sources, nullSource{
			variable:   props.Variable,
			line:       line,
			column:     column,
			origin:     props.Origin,
			definite:   props.Definite == "true",
			chainOpen:  props.Chain == "open",
			caller:     props.Function,
			argText:    props.Expression,
			countField: props.ArrayBufferCountField,
		})
	}

	return models, nil
}

// hasSource reports whether the candidate's variable has a NULL_VALUE source
// at or before the dereference line (line 0 means "unknown position", treated
// as before everything so that location-less fixtures still match).
func (m *nullModel) hasSource(variable string, line int) bool {
	if m == nil {
		return false
	}
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		if s.line == 0 || s.line <= line {
			return true
		}
	}
	return false
}

// onlyCertainNullableSources reports whether EVERY NULL_VALUE source for
// variable is a "certain nullable" source: a declared allocator (malloc/
// calloc/realloc/strdup/...) or a known maybe-null libc/POSIX function
// (strchr/fopen/getenv/...). Both inherently return NULL, so a dereference
// of their result with no guard is a textbook CWE-476 regardless of path —
// the filter keeps such candidates confirmed. An explicit `p = NULL` is NOT
// in this set (it is handled by the must-null `definite` analysis, which
// confirms only when the null reaches on every path), and an unknown
// external call stays suspected.
func (m *nullModel) onlyCertainNullableSources(variable string) bool {
	if m == nil {
		return false
	}
	seen := false
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		seen = true
		// Precise set only: a naming-heuristic guess (e.g. a NULL_VALUE whose
		// origin is a wrapper) must stay "suspected" for the AI, never confirm.
		if !apikb.IsDeclaredAllocator(s.origin) && !apikb.IsKnownNullableReturn(s.origin) {
			return false
		}
	}
	return seen
}

// certainNullableOrigin returns the origin name (a declared allocator or a
// known maybe-null libc function) of the variable's first certain-tier null
// source, or "" when none is certain. It powers the null@malloc-fail verdict
// detail, which names the exact proven-nullable origin.
func (m *nullModel) certainNullableOrigin(variable string) string {
	if m == nil {
		return ""
	}
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		if apikb.IsDeclaredAllocator(s.origin) || apikb.IsKnownNullableReturn(s.origin) {
			return s.origin
		}
	}
	return ""
}

// onlyUnprovenCallerNullSources reports whether the variable's only null source
// is a caller_null source that was neither graded open by the open-chain
// fixpoint nor carries a literal-NULL witness. That is an analyzer limitation,
// not evidence the caller can pass NULL; converging it before AI keeps the AI
// budget on candidates with a concrete source line or a literal NULL caller.
// (The fixpoint normally never seeds such an event anymore — this stays as a
// defensive gate should a seeding path regress.)
func (m *nullModel) onlyUnprovenCallerNullSources(variable string) bool {
	if m == nil {
		return false
	}
	seen := false
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		seen = true
		if s.origin != "caller_null" || s.definite || s.chainOpen {
			return false
		}
	}
	return seen
}

// hasExternalCallSource reports whether the variable has an external_call null
// source — a value produced by an unknown external function that the analyzer
// cannot prove non-null. Such a value might genuinely be NULL, so the void*
// contract convergence must NOT dismiss it (RISK-2: accessor that may return
// NULL is not a framework-guaranteed-non-null accessor).
func (m *nullModel) hasExternalCallSource(variable string) bool {
	if m == nil {
		return false
	}
	for _, s := range m.sources {
		if s.variable == variable && s.origin == "external_call" {
			return true
		}
	}
	return false
}

// hasDefiniteCallerNullSource reports whether the variable has a caller_null
// source with a literal-NULL witness (a caller actually passes NULL/0). That
// is the one case that violates the void* non-null contract; an unproven
// forwarding caller still honours the convention.
func (m *nullModel) hasDefiniteCallerNullSource(variable string) bool {
	if m == nil {
		return false
	}
	for _, s := range m.sources {
		if s.variable == variable && s.origin == "caller_null" && s.definite {
			return true
		}
	}
	return false
}

// hasOpaqueSource reports whether the variable has an opaque null source: an
// opaque_param source (a pointer parameter of a function whose callers are
// all outside the scan tree) or an opaque_field_read source (a field value of
// an externally-defined struct). These feed the null@opaque-origin tier.
func (m *nullModel) hasOpaqueSource(variable string) bool {
	if m == nil {
		return false
	}
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		switch s.origin {
		case "opaque_param", "opaque_field_read":
			return true
		case "field_read", "deref_read":
			// A self-referential field-read reassignment (`p = p->next`) and a
			// dereference-read assignment (`r = *(T **)msg`) yield values the
			// scan tree cannot see — open-world field / pointed-to content.
			// They belong to the opaque-origin tier; without this they fell
			// through to external-unknown, whose verdict fact claims an
			// unproven external CALL that does not exist.
			return true
		}
	}
	return false
}

// arrayBufferCountField returns the count/length field name when the variable's
// opaque field-read source is a count-gated array buffer (`tree =
// (T *)(resp->group_data)` gated by `resp->group_num`). Empty = no pairing. It
// powers the array-buffer@<field> origin tier: a count-gated buffer is a
// SHARPER fact than the flat opaque-origin tier (count == 0 ⇒ buffer NULL/empty),
// but it stays suspected — the count/data name pairing is a signal the classifier
// verifies, never an auto-confirm.
func (m *nullModel) arrayBufferCountField(variable string) string {
	if m == nil {
		return ""
	}
	for _, s := range m.sources {
		if s.variable == variable && s.origin == "opaque_field_read" && s.countField != "" {
			return s.countField
		}
	}
	return ""
}

// onlyExternalCallSources reports whether EVERY null source for variable is an
// unknown external call (origin "external_call") and there is at least one. A
// mixed model (an explicit NULL, an allocator, or a caller argument) is not
// "only external" and must not be converged by the grow-then-access rule, which
// reasons about an accessor's return value alone.
func (m *nullModel) onlyExternalCallSources(variable string) bool {
	if m == nil {
		return false
	}
	seen := false
	for _, s := range m.sources {
		if s.variable != variable {
			continue
		}
		seen = true
		if s.origin != "external_call" {
			return false
		}
	}
	return seen
}
