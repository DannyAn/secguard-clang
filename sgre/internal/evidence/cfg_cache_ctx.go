package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// cfgCacheKey is the context key under which RunAllDetectors injects the
// per-scan *graph.CFGCache so that every detector can share statement-level
// CFGs instead of rebuilding them per function per detector.
type cfgCacheKey struct{}

// withCFGCache attaches c to ctx.
func withCFGCache(ctx context.Context, c *graph.CFGCache) context.Context {
	if c == nil {
		return ctx
	}
	return context.WithValue(ctx, cfgCacheKey{}, c)
}

// cfgCacheFromCtx returns the cache attached by withCFGCache, or nil.
func cfgCacheFromCtx(ctx context.Context) *graph.CFGCache {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(cfgCacheKey{}).(*graph.CFGCache)
	return c
}

// buildStmtCFGFromCtx is the single choke point for statement-CFG construction
// inside the evidence stage. With a cache attached it returns a leased cached
// CFG for fn; the caller MUST hold the lease until it stops dereferencing
// cfg.Nodes and then Release it. Without a cache/tree it falls back to the
// uncached path and returns a nil lease.
func buildStmtCFGFromCtx(ctx context.Context, fn *db.Function, body parser.Node, tree *parser.Tree) (*graph.StmtCFG, *graph.CFGLease) {
	if fn == nil {
		return graph.BuildStmtCFG(body, 0), nil
	}
	c := cfgCacheFromCtx(ctx)
	if c == nil {
		return graph.BuildStmtCFG(body, fn.EndLine), nil
	}
	lease := c.Acquire(ctx, fn.ID, tree, func() *graph.StmtCFG {
		return graph.BuildStmtCFG(body, fn.EndLine)
	})
	return lease.CFG(), lease
}
