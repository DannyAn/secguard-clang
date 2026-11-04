package graph

import (
	"context"
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
	tree      *parser.Tree // Tree whose C nodes the CFG references; Acquire'd on insert, Release'd on evict
	last      uint64       // LRU timestamp (higher = more recent)
	nodeCount int          // len(cfg.Nodes), for MaxTotalCFGNodes tracking
	// refs is the number of live CFGLease holders. An entry is evictable only
	// while refs == 0: a lease holder may still dereference n.Stmt on this CFG,
	// so evicting it would Release the tree under it (the P0 lifecycle bug).
	refs int
	// done is non-nil while a builder goroutine is constructing this entry
	// (cfg == nil). Waiters block on it and retry; a failed build closes it and
	// removes the placeholder.
	done chan struct{}
}

func NewCFGCache() *CFGCache {
	return &CFGCache{byFn: make(map[int64]*cfgEntry)}
}

// CFGLease pins one cached CFG for the duration of a caller's use. Release is
// idempotent; the entry becomes evictable again when the last lease is released.
type CFGLease struct {
	c     *CFGCache
	fnID  int64
	cfg   *StmtCFG
	entry *cfgEntry
	once  sync.Once
}

// CFG returns the leased CFG. It is nil only when the input was nil/invalid.
func (l *CFGLease) CFG() *StmtCFG {
	if l == nil {
		return nil
	}
	return l.cfg
}

// Release drops the lease. Repeated calls are a no-op.
func (l *CFGLease) Release() {
	if l == nil || l.c == nil || l.entry == nil {
		return
	}
	l.once.Do(func() {
		l.c.mu.Lock()
		if l.entry.refs > 0 {
			l.entry.refs--
		}
		l.c.evictIfNeededLocked()
		l.c.mu.Unlock()
	})
}

// Acquire returns a lease for fnID's CFG, building it once at most. A nil tree
// (or nil cache / non-positive fnID) builds directly and returns a lease with a
// nil cache, so callers can always defer Release.
//
// The lease MUST be held until the caller stops dereferencing cfg.Nodes; a
// cached entry is evicted only at refs==0 and its tree is released only then.
func (c *CFGCache) Acquire(ctx context.Context, fnID int64, tree *parser.Tree, builder func() *StmtCFG) *CFGLease {
	if c == nil || fnID <= 0 || tree == nil {
		return &CFGLease{cfg: builder()}
	}
	for {
		c.mu.Lock()
		if e, ok := c.byFn[fnID]; ok {
			if e.cfg == nil {
				// Another goroutine is building this key. Wait outside the
				// cache lock so different fnIDs build in parallel.
				done := e.done
				c.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					// The caller still needs a CFG; build it directly rather
					// than returning a nil lease body.
					return &CFGLease{cfg: builder()}
				}
			}
			e.refs++
			c.clock++
			e.last = c.clock
			c.Hits++
			c.mu.Unlock()
			return &CFGLease{c: c, fnID: fnID, cfg: e.cfg, entry: e}
		}
		// Claim the key with a building placeholder, then build OUTSIDE the
		// lock. This is the design invariant: build() is never serialized by
		// the global cache mutex.
		e := &cfgEntry{done: make(chan struct{})}
		c.byFn[fnID] = e
		c.Builds++
		c.mu.Unlock()

		var cfg *StmtCFG
		func() {
			defer func() {
				if r := recover(); r != nil {
					c.mu.Lock()
					if c.byFn[fnID] == e {
						delete(c.byFn, fnID)
					}
					close(e.done)
					c.mu.Unlock()
					panic(r)
				}
			}()
			cfg = builder()
		}()

		c.mu.Lock()
		if cfg == nil {
			if c.byFn[fnID] == e {
				delete(c.byFn, fnID)
			}
			close(e.done)
			c.mu.Unlock()
			return &CFGLease{}
		}
		e.cfg = cfg
		e.tree = tree
		e.nodeCount = len(cfg.Nodes)
		e.refs = 1
		c.clock++
		e.last = c.clock
		c.totalCFGNodes += e.nodeCount
		tree.Acquire()
		close(e.done)
		c.evictIfNeededLocked()
		c.mu.Unlock()
		return &CFGLease{c: c, fnID: fnID, cfg: cfg, entry: e}
	}
}

// GetOrBuild is the legacy non-AST-aware API, retained for unit tests with
// synthetic CFGs. Production callers must use Acquire: an entry cached here has
// no tree reference, so the parser can evict the AST under it.
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

// evictOldestLocked finds and removes the least-recently-used entry with
// refs==0. Returns false when every entry is leased (the budget temporarily
// overflows; callers' Release calls will make it evictable again). Caller must
// hold c.mu.
func (c *CFGCache) evictOldestLocked() bool {
	var oldestKey int64 = -1
	var oldestLast uint64 = ^uint64(0)
	for k, e := range c.byFn {
		if e.refs > 0 || e.cfg == nil {
			continue
		}
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
	if e.tree != nil {
		e.tree.Release()
	}
	return true
}

// Invalidate drops the cached CFG for fnID. Reserved for incremental scanning.
func (c *CFGCache) Invalidate(fnID int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.byFn[fnID]; ok {
		delete(c.byFn, fnID)
		c.totalCFGNodes -= e.nodeCount
		if e.tree != nil {
			e.tree.Release()
		}
	}
}

// Reset drops all cached CFGs and zeroes the stats.
func (c *CFGCache) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.byFn {
		if e.tree != nil {
			e.tree.Release()
		}
	}
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

// BuildStmtCFGWithCache builds a CFG directly. It deliberately does NOT cache:
// a cached CFG holds parser.Nodes pointing into a parse tree, so an entry that
// is not tied to a *parser.Tree borrow can outlive its AST and crash on the
// first n.Stmt.Kind(). Callers that have the tree should use
// BuildStmtCFGWithTree; callers that do not keep the historical (uncached)
// behavior rather than poisoning the shared cache.
func BuildStmtCFGWithCache(cache *CFGCache, fnID int64, body parser.Node, funcEnd int) *StmtCFG {
	return BuildStmtCFG(body, funcEnd)
}

// GetOrBuildWithTree is retained for callers that only need a CFG value. It
// does not cache: caching now requires a CFGLease (see Acquire), because an
// entry can only be evicted safely at refs==0.
func (c *CFGCache) GetOrBuildWithTree(fnID int64, tree *parser.Tree, builder func() *StmtCFG) *StmtCFG {
	return builder()
}

// BuildStmtCFGWithTree builds a CFG directly. Caching with the AST pinned is
// done through CFGCache.Acquire by the evidence choke point; keeping this
// wrapper uncached is deliberate so a caller cannot create an entry it cannot
// lease.
func BuildStmtCFGWithTree(cache *CFGCache, fnID int64, tree *parser.Tree, body parser.Node, funcEnd int) *StmtCFG {
	return BuildStmtCFG(body, funcEnd)
}
