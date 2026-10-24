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
// inside the evidence stage. With a cache attached it returns the cached CFG
// for fn; otherwise it falls back to the legacy uncached path.
func buildStmtCFGFromCtx(ctx context.Context, fn *db.Function, body parser.Node) *graph.StmtCFG {
	if fn == nil {
		return graph.BuildStmtCFG(body, 0)
	}
	return graph.BuildStmtCFGWithCache(cfgCacheFromCtx(ctx), fn.ID, body, fn.EndLine)
}
