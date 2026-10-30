package cli

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
)

const (
	// settlementRTypeFallback is the conservative r_type used when no settlement
	// history exists for a type (mirrors command-instructions.md's first-run
	// default).
	settlementRTypeFallback = 0.30
	// settlementRTypeSamples caps the cross-scan settlement sample used to
	// estimate r_type (most recent first).
	settlementRTypeSamples = 50
	// maxEvidenceOpensPerType mirrors agent-body.md's evidence-open budget.
	// Keep it in lockstep with MAX_EVIDENCE_OPENS_PER_TYPE.
	maxEvidenceOpensPerType = 12
)

func normalizeSettlementRange(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return "all"
	}
	return r
}

// persistSettlementReports writes each valid settlement report's processed_types
// into settlement_stats (idempotent via the UNIQUE key). It is the engine-side
// data closure the orchestrator's r_type / already_covered_ranges read back —
// nothing here depends on the LLM aggregating anything.
func persistSettlementReports(ctx context.Context, store db.Store, res reportsResult) error {
	for _, rep := range res.Reports {
		if !rep.Valid || rep.ScanID == "" {
			continue
		}
		// needs_context is a report-level array without a per-type key; attribute
		// it only to single-type reports so multi-type batches never over-count.
		needsContext := 0
		if len(rep.Processed) == 1 {
			needsContext = len(rep.NeedsContext)
		}
		for _, pt := range rep.Processed {
			if err := store.UpsertSettlementStat(ctx, &db.SettlementStat{
				ScanID:        rep.ScanID,
				VulnType:      pt.Type,
				RangeStr:      normalizeSettlementRange(pt.Range),
				SubagentID:    rep.SubagentID,
				Written:       pt.Written,
				Dismissed:     pt.Dismissed,
				EvidenceOpens: pt.EvidenceOpens,
				SourceReads:   pt.SourceReads,
				RepoGreps:     pt.RepoGreps,
				NeedsContext:  needsContext,
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

// settlementEnriched is the `status --per-type` record with the engine-computed
// scheduling parameters attached. The orchestrator consumes these verbatim
// instead of doing its own statistics over settlement files.
type settlementEnriched struct {
	*db.PerTypeStatus
	RType                float64  `json:"r_type"`
	RSample              int      `json:"r_sample"`
	SuggestedBatchSize   int      `json:"suggested_batch_size"`
	SuggestedBatches     int      `json:"suggested_batches"`
	AvgWallMS            int64    `json:"avg_wall_ms,omitempty"`
	AlreadyCoveredRanges []string `json:"already_covered_ranges"`
}

func enrichPerTypeStatus(ctx context.Context, store db.Store, scanID string, statuses []*db.PerTypeStatus) ([]*settlementEnriched, error) {
	byScan, err := store.ListSettlementStatsByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	covered := map[string]map[string]bool{}
	for _, st := range byScan {
		if covered[st.VulnType] == nil {
			covered[st.VulnType] = map[string]bool{}
		}
		covered[st.VulnType][st.RangeStr] = true
	}

	out := make([]*settlementEnriched, 0, len(statuses))
	for _, s := range statuses {
		e := &settlementEnriched{PerTypeStatus: s, AlreadyCoveredRanges: []string{}}
		if ranges := covered[s.VulnType]; len(ranges) > 0 {
			for r := range ranges {
				e.AlreadyCoveredRanges = append(e.AlreadyCoveredRanges, r)
			}
			sort.Strings(e.AlreadyCoveredRanges)
		}
		agg := settlementAggregate(ctx, store, s.VulnType)
		e.RType = agg.rType
		e.RSample = agg.sample
		e.AvgWallMS = agg.avgWallMS
		if s.CandidateCount > 0 {
			e.SuggestedBatchSize = suggestedBatchSize(agg.rType)
			e.SuggestedBatches = suggestedBatches(s.CandidateCount, e.SuggestedBatchSize)
		}
		out = append(out, e)
	}
	return out, nil
}

type settlementAgg struct {
	rType     float64
	sample    int
	avgWallMS int64
}

func settlementAggregate(ctx context.Context, store db.Store, vulnType string) settlementAgg {
	rows, err := store.ListSettlementStatsByType(ctx, vulnType, settlementRTypeSamples)
	if err != nil || len(rows) == 0 {
		return settlementAgg{rType: settlementRTypeFallback}
	}
	var opens, cands int
	var wallSum, wallN int64
	for _, r := range rows {
		opens += r.EvidenceOpens
		cands += r.Written + r.Dismissed
		if r.WallMS > 0 {
			wallSum += r.WallMS
			wallN++
		}
	}
	if cands == 0 {
		return settlementAgg{rType: settlementRTypeFallback, sample: len(rows)}
	}
	agg := settlementAgg{rType: float64(opens) / float64(cands), sample: len(rows)}
	if wallN > 0 {
		agg.avgWallMS = wallSum / wallN
	}
	return agg
}

func suggestedBatchSize(rType float64) int {
	if rType <= 0 {
		rType = settlementRTypeFallback
	}
	n := int(math.Floor(float64(maxEvidenceOpensPerType) / rType))
	if n < 1 {
		n = 1
	}
	return n
}

func suggestedBatches(candidates, batchSize int) int {
	if candidates <= 0 || batchSize <= 0 {
		return 0
	}
	return (candidates + batchSize - 1) / batchSize
}
