package graph

import (
	"sync"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

// CFGCache memoizes per-function *StmtCFG instances within one scan.
// The key is db.Function.ID; a non-positive key disables caching (the builder
// is invoked directly without memoization), which keeps mock tests that use
// zero-value functions working.
//
// BuildStmtCFG is deterministic for a given (body, funcEnd), so the cache is
// sound within one parse tree lifetime. Cross-scan reuse is the caller's
// responsibility (the pipeline creates a fresh cache per scan).
type CFGCache struct {
	mu     sync.RWMutex
	byFn   map[int64]*StmtCFG
	Builds int
	Hits   int
}

func NewCFGCache() *CFGCache {
	return &CFGCache{byFn: make(map[int64]*StmtCFG)}
}

// GetOrBuild returns the cached CFG for fnID, building it via builder at most
// once per fnID per cache lifetime. A builder that returns nil is NOT cached
// (nil means "no function body", a legitimate result that must not be sticky
// in case the caller later supplies a real body).
func (c *CFGCache) GetOrBuild(fnID int64, builder func() *StmtCFG) *StmtCFG {
	if c == nil || fnID <= 0 {
		return builder()
	}
	c.mu.RLock()
	if cfg, ok := c.byFn[fnID]; ok {
		c.mu.RUnlock()
		c.mu.Lock()
		c.Hits++
		c.mu.Unlock()
		return cfg
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if cfg, ok := c.byFn[fnID]; ok {
		c.Hits++
		return cfg
	}
	cfg := builder()
	if cfg != nil {
		c.byFn[fnID] = cfg
	}
	c.Builds++
	return cfg
}

// Invalidate drops the cached CFG for fnID. Reserved for incremental scanning.
func (c *CFGCache) Invalidate(fnID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.byFn, fnID)
}

// Reset drops all cached CFGs and zeroes the stats.
func (c *CFGCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byFn = make(map[int64]*StmtCFG)
	c.Builds = 0
	c.Hits = 0
}

// Stats returns (builds, hits) for diagnostics.
func (c *CFGCache) Stats() (builds, hits int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Builds, c.Hits
}

// BuildStmtCFGWithCache is BuildStmtCFG with a cache key. Callers that know
// the db.Function.ID should prefer this form so repeated builds for the same
// function hit the cache.
func BuildStmtCFGWithCache(cache *CFGCache, fnID int64, body parser.Node, funcEnd int) *StmtCFG {
	if cache == nil {
		return BuildStmtCFG(body, funcEnd)
	}
	return cache.GetOrBuild(fnID, func() *StmtCFG {
		return BuildStmtCFG(body, funcEnd)
	})
}
