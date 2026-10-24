package graph

import "context"

// aliasGraphKey is the context key under which the pipeline injects the
// per-scan *AliasGraph so detector and planner stages can query cross-
// function aliasing without rebuilding it per consumer.
type aliasGraphKey struct{}

// WithAliasGraph attaches g to ctx.
func WithAliasGraph(ctx context.Context, g *AliasGraph) context.Context {
	if g == nil {
		return ctx
	}
	return context.WithValue(ctx, aliasGraphKey{}, g)
}

// AliasGraphFromCtx returns the graph attached by WithAliasGraph, or nil.
func AliasGraphFromCtx(ctx context.Context) *AliasGraph {
	if ctx == nil {
		return nil
	}
	g, _ := ctx.Value(aliasGraphKey{}).(*AliasGraph)
	return g
}
