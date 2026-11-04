package cli

import (
	"runtime"

	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// logPhaseResources emits one structured line per phase boundary: process
// memory (cgroup/RSS/HeapAlloc), parser cache borrows, and CFG cache occupancy.
// The three layers are logged together because a peak can be Go heap (events /
// candidates), pinned AST trees, or CFG entries holding AST borrows; without
// the split a regression cannot be attributed.
func logPhaseResources(logger *log.Logger, phase string, p *parser.Parser, cfg *graph.CFGCache) {
	if logger == nil {
		return
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fields := []any{
		"phase", phase,
		"process_mb", readMemoryBytes() >> 20,
		"heap_alloc_mb", ms.HeapAlloc >> 20,
		"heap_sys_mb", ms.HeapSys >> 20,
	}
	if p != nil {
		cached, transient := p.CacheStats()
		fields = append(fields,
			"cached_trees", cached,
			"transient_trees", transient,
			"pinned_trees", p.PinnedTrees(),
			"active_handles", p.ActiveTreeHandles(),
		)
	}
	if cfg != nil {
		b, h, e, n, tn := cfg.StatsFull()
		fields = append(fields,
			"cfg_builds", b,
			"cfg_hits", h,
			"cfg_evictions", e,
			"cfg_entries", n,
			"cfg_nodes", tn,
		)
	}
	logger.Info("phase resources", fields...)
}
