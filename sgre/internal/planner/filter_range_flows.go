package planner

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// buildRangeFlowsForCandidates loads the eligible candidates' functions/files,
// builds one range flow per function through a shared parse cache, and returns
// a cleanup that releases the flows before closing the cache. Both interval
// filters used to copy this pipeline verbatim; only their eligibility predicate
// and interval comparison differ.
func buildRangeFlowsForCandidates(ctx context.Context, store db.Store, p *parser.Parser, cfgCache *graph.CFGCache, byFunc map[int64][]Candidate) (map[int64]*rangeFlow, func(), error) {
	fnByID, fileByID, err := loadFuncFiles(ctx, store, candidateFuncIDs(byFunc))
	if err != nil {
		return nil, nil, err
	}
	cache := newFileParseCache(p)
	flows := make(map[int64]*rangeFlow, len(byFunc))
	for fid := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, _ := cache.get(file, fn)
		flows[fid] = analyzeRangesWithCalls(ctx, cfgCache, cache.treeFor(file), fn, body, nil)
	}
	cleanup := func() {
		releaseRangeFlows(flows)
		cache.Close()
	}
	return flows, cleanup, nil
}
