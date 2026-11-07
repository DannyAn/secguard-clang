package cli

import (
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// settlementCoverage is the derived (never self-declared) completion picture of
// one vuln type: which candidate intervals carry a settled verdict, which are
// still uncovered, and whether anything is still in flight. A type is done ONLY
// when the done-range union covers [1,candidate_count] with no needs_context
// residue, no live claim and no unparseable done range — a single settled batch
// can no longer mark the whole type done.
type settlementCoverage struct {
	HasRows          bool
	Done             bool
	CoveredCount     int
	Uncovered        []string
	ActiveClaims     int
	HasNeedsContext  bool
	UnparseableDone  int
	LiveClaimHolders []string
}

func parseSettlementInterval(rangeStr string, candidateCount int) (int, int, bool) {
	return db.ParseSettlementRange(rangeStr, candidateCount)
}

type interval struct{ lo, hi int }

func unionIntervals(ivs []interval) []interval {
	if len(ivs) == 0 {
		return nil
	}
	sort.Slice(ivs, func(i, j int) bool {
		if ivs[i].lo != ivs[j].lo {
			return ivs[i].lo < ivs[j].lo
		}
		return ivs[i].hi < ivs[j].hi
	})
	out := []interval{ivs[0]}
	for _, iv := range ivs[1:] {
		last := &out[len(out)-1]
		if iv.lo <= last.hi+1 {
			if iv.hi > last.hi {
				last.hi = iv.hi
			}
			continue
		}
		out = append(out, iv)
	}
	return out
}

func formatInterval(iv interval) string {
	if iv.lo == iv.hi {
		return strconv.Itoa(iv.lo)
	}
	return fmt.Sprintf("%d-%d", iv.lo, iv.hi)
}

func deriveTypeCoverage(rows []*db.SettlementStat, candidateCount int, nowSec int64) settlementCoverage {
	cov := settlementCoverage{HasRows: len(rows) > 0}
	if candidateCount <= 0 {
		return cov
	}
	staleBefore := nowSec - int64(settlementClaimTTL/time.Second)
	var done []interval
	for _, st := range rows {
		switch {
		case st.Status == "dispatched":
			leaseAt := st.CreatedAt
			if st.HeartbeatAt > 0 {
				leaseAt = st.HeartbeatAt
			}
			if leaseAt >= staleBefore {
				cov.ActiveClaims++
				cov.LiveClaimHolders = append(cov.LiveClaimHolders, st.SubagentID)
			}
		case st.Status == "failed":
		case st.Status == "partial" || st.NeedsContext > 0:
			cov.HasNeedsContext = true
		case st.Status == "done":
			lo, hi, ok := parseSettlementInterval(st.RangeStr, candidateCount)
			if !ok {
				cov.UnparseableDone++
				continue
			}
			done = append(done, interval{lo, hi})
		}
	}
	merged := unionIntervals(done)
	next := 1
	for _, iv := range merged {
		if iv.lo > next {
			cov.Uncovered = append(cov.Uncovered, formatInterval(interval{next, iv.lo - 1}))
		}
		cov.CoveredCount += iv.hi - iv.lo + 1
		if iv.hi+1 > next {
			next = iv.hi + 1
		}
	}
	if next <= candidateCount {
		cov.Uncovered = append(cov.Uncovered, formatInterval(interval{next, candidateCount}))
	}
	cov.Done = cov.CoveredCount == candidateCount &&
		cov.ActiveClaims == 0 && !cov.HasNeedsContext && cov.UnparseableDone == 0
	return cov
}
