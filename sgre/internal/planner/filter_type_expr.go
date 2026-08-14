package planner

import "context"

// TypeExprFilter drops null-deref candidates whose dereference sits inside a
// sizeof/alignof type expression (sizeof(*p), sizeof(p->field), sizeof(arr[0])).
// Those are compile-time type expressions, not runtime pointer dereferences, so
// they can never be a null-dereference.
//
// The dereference detector tags such events is_type_expr=true rather than
// suppressing them at the source, so the raw DEREFERENCE stream other consumers
// read (interprocedural null propagation) is unchanged. This filter is the
// first stage of the null-deref chain, so pseudo-derefs are dropped before any
// other filter inspects them, and the drop lands in the Dismissed ledger rather
// than disappearing silently.
//
// It reads only the is_type_expr tag, so it cannot affect other vulnerability
// types: buffer-overflow / out-of-bounds seed from BUFFER_ACCESS, and no other
// chain routes through this filter.
type TypeExprFilter struct{}

func NewTypeExprFilter() *TypeExprFilter {
	return &TypeExprFilter{}
}

func (f *TypeExprFilter) Name() string { return "sizeof_pseudo_deref" }

func (f *TypeExprFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	kept, dropped := partition(candidates, func(c Candidate) bool {
		return !c.IsTypeExpr
	}, func(c Candidate) string {
		return "sizeof/alignof type expression, not a runtime dereference"
	}, f.Name())
	return kept, dropped, nil
}
