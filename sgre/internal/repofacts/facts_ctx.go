package repofacts

import "context"

// factsKey is the context key under which the pipeline injects the per-scan
// *Facts so detector and planner stages share the same tree-wide census
// (struct layouts, global arrays, macros) without rebuilding it per consumer.
type factsKey struct{}

// WithFacts attaches f to ctx. A nil f is a no-op (the consumer will rebuild).
func WithFacts(ctx context.Context, f *Facts) context.Context {
	if f == nil {
		return ctx
	}
	return context.WithValue(ctx, factsKey{}, f)
}

// FactsFromCtx returns the Facts attached by WithFacts, or nil. The caller is
// responsible for the nil fallback (rebuild via Build or skip layout queries).
func FactsFromCtx(ctx context.Context) *Facts {
	if ctx == nil {
		return nil
	}
	f, _ := ctx.Value(factsKey{}).(*Facts)
	return f
}
