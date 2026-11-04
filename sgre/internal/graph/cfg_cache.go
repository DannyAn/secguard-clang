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
//
// Bounded LRU: when MaxEntries > 0 the cache evicts the least-recently-used
// entry on insert to keep len(byFn) <= MaxEntries. When MaxTotalCFGNodes > 0
// the cache evicts LRU entries to keep the sum of len(cfg.Nodes) within budget.
// A zero value for either field means unbounded (the legacy default).
type CFGCache struct {
	mu sync.Mutex
	// byFn maps fnID → cfgEntry. The value is *cfgEntry (not *StmtCFG) so the
	// LRU timestamp and node-count bookkeeping live alongside the CFG.
	byFn map[int64]*cfgEntry

	// MaxEntries bounds the number of cached CFGs. 0 = unbounded.
	MaxEntries int
	// MaxTotalCFGNodes bounds the total node count across all cached CFGs.
	// 0 = unbounded. Prevents a single giant function from dominating memory.
	MaxTotalCFGNodes int

	totalCFGNodes int
	clock         uint64
	Builds        int
	Hits          int
	Evictions     int
}

type cfgEntry struct {
	cfg       *StmtCFG
	last      uint64 // LRU timestamp (higher = more recent)
	nodeCount int    // len(cfg.Nodes), for MaxTotalCFGNodes tracking
}

func NewCFGCache() *CFGCache {
	return &CFGCache{byFn: make(map[int64]*cfgEntry)}
}

// GetOrBuild returns the cached CFG for fnID, building it via builder at most
// once per fnID per cache lifetime. A builder that returns nil is NOT cached
// (nil means "no function body", a legitimate result that must not be sticky
// in case the caller later supplies a real body).
func (c *CFGCache) GetOrBuild(fnID int64, builder func() *StmtCFG) *StmtCFG {
	if c == nil || fnID <= 0 {
		return builder()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byFn[fnID]; ok {
		c.clock++
		e.last = c.clock
		c.Hits++
		return e.cfg
	}
	cfg := builder()
	c.Builds++
	if cfg == nil {
		return nil
	}
	nc := len(cfg.Nodes)
	c.clock++
	c.byFn[fnID] = &cfgEntry{cfg: cfg, last: c.clock, nodeCount: nc}
	c.totalCFGNodes += nc
	c.evictIfNeededLocked()
	return cfg
}

// evictIfNeededLocked evicts LRU entries until both MaxEntries and
// MaxTotalCFGNodes are satisfied. Caller must hold c.mu.
func (c *CFGCache) evictIfNeededLocked() {
	for {
		overEntries := c.MaxEntries > 0 && len(c.byFn) > c.MaxEntries
		overNodes := c.MaxTotalCFGNodes > 0 && c.totalCFGNodes > c.MaxTotalCFGNodes
		if !overEntries && !overNodes {
			return
		}
		if !c.evictOldestLocked() {
			return
		}
	}
}

// evictOldestLocked finds and removes the entry with the smallest LRU
// timestamp. Returns false if the cache is empty. Caller must hold c.mu.
func (c *CFGCache) evictOldestLocked() bool {
	var oldestKey int64 = -1
	var oldestLast uint64 = ^uint64(0)
	for k, e := range c.byFn {
		if e.last < oldestLast {
			oldestLast = e.last
			oldestKey = k
		}
	}
	if oldestKey < 0 {
		return false
	}
	e := c.byFn[oldestKey]
	delete(c.byFn, oldestKey)
	c.totalCFGNodes -= e.nodeCount
	c.Evictions++
	return true
}

// Invalidate drops the cached CFG for fnID. Reserved for incremental scanning.
func (c *CFGCache) Invalidate(fnID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byFn[fnID]; ok {
		delete(c.byFn, fnID)
		c.totalCFGNodes -= e.nodeCount
	}
}

// Reset drops all cached CFGs and zeroes the stats.
func (c *CFGCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byFn = make(map[int64]*cfgEntry)
	c.totalCFGNodes = 0
	c.clock = 0
	c.Builds = 0
	c.Hits = 0
	c.Evictions = 0
}

// Stats returns (builds, hits) for diagnostics.
func (c *CFGCache) Stats() (builds, hits int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Builds, c.Hits
}

// StatsFull returns (builds, hits, evictions, entries, totalNodes) for
// diagnostics. entries is the current cache size; totalNodes is the sum of
// len(cfg.Nodes) across all cached CFGs.
func (c *CFGCache) StatsFull() (builds, hits, evictions, entries, totalNodes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Builds, c.Hits, c.Evictions, len(c.byFn), c.totalCFGNodes
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
