package planner

import (
	"context"

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
// It deliberately does not consult graph.BuildCFG / CanReach: those are pure
// line-number heuristics that degenerate to "unreachable" for flat functions,
// and the null-source decision needs only line ordering.

// nullSource is a single variable-level origin of a possibly-null value.
type nullSource struct {
	variable string
	line     int
	origin   string
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
		if e.LocationID > 0 {
			if loc, lerr := store.GetLocationByID(ctx, e.LocationID); lerr == nil && loc != nil {
				line = loc.Line
			}
		}
		m.sources = append(m.sources, nullSource{
			variable: props.Variable,
			line:     line,
			origin:   props.Origin,
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
