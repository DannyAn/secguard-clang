package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/graph"
)

// cfgCacheKey is the context key under which Plan() injects the per-scan
// *graph.CFGCache so that every filter can share statement-level CFGs instead
// of rebuilding them per function per filter.
type cfgCacheKey struct{}

// withCFGCache attaches c to ctx.
func withCFGCache(ctx context.Context, c *graph.CFGCache) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, cfgCacheKey{}, c)
}
