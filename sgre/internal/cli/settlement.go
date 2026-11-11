package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/DannyAn/secguard-clang/internal/config"
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
	// maxSourceReadsPerType mirrors agent-body.md's source-read budget
	// (≤5 source reads per type/range). Keep it in lockstep with
	// MAX_SOURCE_READS_PER_TYPE.
	maxSourceReadsPerType = 5
	// maxRepoGrepsPerType mirrors agent-body.md's repo-wide grep budget
	// (≤1 per type/range; `secguard def` does not count). A batch above it is a
	// read-source violation the orchestrator must surface, not silently absorb.
	maxRepoGrepsPerType = 1
	// settlementClaimTTL bounds how long a pre-dispatch claim stays "live". It
	// must exceed a batch's worst-case wall clock (hosts force-reject around
	// 660s while the subagent keeps running), so 30 minutes leaves ample room
	// while still letting the next planning pass recover a dead worker's claim.
	settlementClaimTTL = 30 * time.Minute
	// settlementHeartbeatStall is how long a settlement snapshot may go without
	// an mtime update before `status --reports` flags the batch as stalled. The
	// heartbeat contract asks for a chunk snapshot every ~10 candidates; a raw
	// source read or a large candidate index can take minutes, so 15 minutes
	// avoids a false "dead worker" verdict while still surfacing a stuck batch.
	settlementHeartbeatStall = 15 * time.Minute
	// aiHostMaxConcurrencyDefault is the documented default cap on concurrent
	// AI subagents per host (Claude Code / DSH). It is what F3a uses for the
	// first wave instead of probing the cap by hitting an error; a deployment
	// with a different host limit overrides it with
	// SECGUARD_AI_HOST_MAX_CONCURRENCY (see `status --show-limits`).
	aiHostMaxConcurrencyDefault = 10
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
// nothing here depends on the LLM aggregating anything. Reports are consumed
// OLDEST first: two workers can settle the same (type, range) under different
// subagent ids (a retry, or the duplicate dispatch this ticket prevents), and
// the row is last-write-wins, so applying the newest settlement last makes it
// the authoritative one instead of letting the older snapshot overwrite it.
//
// The whole absorption is ONE immediate transaction. A type's ai_stage_status
// is DERIVED from range coverage (deriveTypeCoverage) after all reports land —
// never self-declared by a single batch: a type is marked done only when its
// settled ranges cover every candidate with no needs_context residue and no
// live claim. A report carrying needs_context lands its ranges as 'partial'
// (not 'done'), so an unfinished range never reads as covered.
func persistSettlementReports(ctx context.Context, store db.Store, res reportsResult) error {
	// Incremental absorption: the cursor records each file's absorbed mtime, so
	// a poll whose files have not changed takes NO write lock and rewrites
	// nothing. The old every-poll full re-UPSERT of all history turned a long
	// scan's 30s liveness poll into a write storm against 8 concurrent
	// --write-json workers. A file whose mtime moved is re-absorbed (its
	// settlement is authoritative), an unchanged file is skipped entirely —
	// including lease renewal, which must only happen on real new evidence.
	cursor := readAbsorbCursor(ctx, store)
	changed := make([]subagentReport, 0, len(res.Reports))
	for _, rep := range res.Reports {
		if rep.ScanID == "" {
			continue
		}
		if rep.mtime.IsZero() || cursor[rep.File] != rep.mtime.UnixNano() {
			changed = append(changed, rep)
		}
	}
	if len(changed) == 0 {
		return nil
	}
	res.Reports = changed
	// A `status --reports` poll usually carries nothing new to absorb; avoid
	// taking the write lock for a pure read.
	hasValid := false
	for _, rep := range res.Reports {
		if rep.Valid || !rep.mtime.IsZero() {
			hasValid = true
			break
		}
	}
	if !hasValid {
		return nil
	}
	return store.WithImmediateTx(ctx, func(tx db.Store) error {
		knownByScan := map[string]map[string]bool{}
		candidateCountByScan := map[string]map[string]int{}
		type scanType struct{ scanID, vulnType string }
		touched := map[scanType]bool{}
		nowMS := time.Now().UnixMilli()
		// Renew each holder's lease from FRESH report files only (a chunk counts
		// as a heartbeat even though it is not a completion signal). A stale
		// file does NOT renew: a dead worker's claim must still expire.
		for _, rep := range res.Reports {
			if rep.ScanID == "" || rep.SubagentID == "" || rep.mtime.IsZero() {
				continue
			}
			if time.Since(rep.mtime) > settlementHeartbeatStall {
				continue
			}
			if err := tx.RenewSettlementLease(ctx, rep.ScanID, rep.SubagentID, nowMS); err != nil {
				return err
			}
		}
		for i := len(res.Reports) - 1; i >= 0; i-- {
			rep := res.Reports[i]
			if !rep.Valid || rep.ScanID == "" {
				continue
			}
			known, ok := knownByScan[rep.ScanID]
			if !ok {
				known = map[string]bool{}
				counts := map[string]int{}
				stats, err := tx.ListScanStats(ctx, rep.ScanID)
				if err != nil {
					return err
				}
				for _, st := range stats {
					known[st.VulnType] = true
					counts[st.VulnType] = st.FinalCount
				}
				knownByScan[rep.ScanID] = known
				candidateCountByScan[rep.ScanID] = counts
			}
			// needs_context is a report-level array without a per-type key; attribute
			// it only to single-type reports so multi-type batches never over-count.
			needsContext := 0
			if len(rep.Processed) == 1 {
				needsContext = len(rep.NeedsContext)
			}
			queueMS, workMS := settlementQueueWorkMS(rep)
			wallMS := settlementWallMS(ctx, tx, rep)
			if queueMS+workMS > 0 {
				// The report carried dispatch/start timestamps: wall_ms is the
				// batch's OWN queue+work time, not the scan-anchored fallback
				// (issue #253 P1-1 — the old epoch made avg_wall_ms useless).
				wallMS = queueMS + workMS
			}
			var finishedAt int64
			if !rep.mtime.IsZero() {
				finishedAt = rep.mtime.UnixMilli()
			}
			for _, pt := range rep.Processed {
				status := "done"
				if len(rep.NeedsContext) > 0 {
					status = "partial"
				}
				if err := tx.UpsertSettlementStat(ctx, &db.SettlementStat{
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
					Status:        status,
					WallMS:        wallMS,
					QueueMS:       queueMS,
					WorkMS:        workMS,
					FinishedAt:    finishedAt,
				}); err != nil {
					return err
				}
				touched[scanType{rep.ScanID, pt.Type}] = true
			}
		}
		rowsByScan := map[string][]*db.SettlementStat{}

		for key := range touched {
			if !knownByScan[key.scanID][key.vulnType] {
				continue
			}
			rows, ok := rowsByScan[key.scanID]
			if !ok {
				var err error
				rows, err = tx.ListSettlementStatsByScan(ctx, key.scanID)
				if err != nil {
					return err
				}
				rowsByScan[key.scanID] = rows
			}
			// Type completion is derived from the VERDICT LEDGER (unclassified
			// == 0), the same identity --complete-type and the audit gate use —
			// never from settlement-range coverage alone. A subagent that writes
			// verdicts via the MCP tool and never produces settlement files still
			// completes its type; a range that never ran keeps unclassified > 0.
			writtenCount := 0
			// Query on the SAME transaction connection (tx, not tx.DB()): a
			// second connection's read inside BEGIN IMMEDIATE can deadlock the
			// absorption transaction on some driver/locking paths.
			findings, err := tx.ListFindingsByScanID(ctx, key.scanID)
			if err != nil {
				return err
			}
			for _, f := range findings {
				if f.VulnType == key.vulnType && f.Status == "confirmed" {
					writtenCount++
				}
			}
			dismissedByType, err := tx.CountCandidateVerdictsByType(ctx, key.scanID)
			if err != nil {
				return err
			}
			unclassified := candidateCountByScan[key.scanID][key.vulnType] - writtenCount - dismissedByType[key.vulnType]
			if unclassified == 0 {
				if err := tx.MarkAIStageDone(ctx, key.scanID, key.vulnType); err != nil {
					return err
				}
			}
		}
		for _, rep := range res.Reports {
			if !rep.mtime.IsZero() {
				cursor[rep.File] = rep.mtime.UnixNano()
			}
		}
		return writeAbsorbCursor(ctx, tx, cursor)
	})
}

// readAbsorbCursor loads the (path -> absorbed mtime unix-nano) cursor that
// makes settlement absorption incremental (see persistSettlementReports).
func readAbsorbCursor(ctx context.Context, store db.Store) map[string]int64 {
	cursor := map[string]int64{}
	raw, ok, err := store.GetMeta(ctx, "settlement_absorb_cursor")
	if err != nil || !ok || raw == "" {
		return cursor
	}
	_ = json.Unmarshal([]byte(raw), &cursor)
	return cursor
}

func writeAbsorbCursor(ctx context.Context, store db.Store, cursor map[string]int64) error {
	data, err := json.Marshal(cursor)
	if err != nil {
		return fmt.Errorf("marshal settlement absorb cursor: %w", err)
	}
	return store.SetMeta(ctx, "settlement_absorb_cursor", string(data))
}

// aiStageTiming is the AI-classification stage as the ENGINE measured it, from
// the settlement rows `status --reports` persisted: each settled row carries the
// settlement file's finish time (finished_at) and its own queue/work split, so
// the stage spans the earliest reconstructed dispatch to the latest finish, and
// each type's span is derived the same way. This replaces the human-supplied
// `--ai-duration-ms` estimate; that flag remains only as an override for a host
// that cannot write settlement files.
type aiStageTiming struct {
	TotalMS   int64            `json:"total_ms"`
	PerTypeMS map[string]int64 `json:"per_type_ms,omitempty"`
	// PerTypeBatches is the number of settled batches behind each type's span;
	// a type split across ranges adds batches without necessarily widening its
	// span, so the count keeps the timing auditable.
	PerTypeBatches map[string]int `json:"per_type_batches,omitempty"`
	Batches        int            `json:"batches"`
	Source         string         `json:"source,omitempty"`
}

func measureAIStageTiming(rows []*db.SettlementStat) aiStageTiming {
	out := aiStageTiming{PerTypeMS: map[string]int64{}, PerTypeBatches: map[string]int{}}
	type span struct{ start, end int64 }
	spans := map[string]*span{}
	var first, last int64
	for _, st := range rows {
		// Only a settled row is a measurement: a pre-dispatch claim is a
		// reservation (created_at is when it was claimed, not finished), and a
		// failed row recorded no completed work.
		if st.Status != "done" {
			continue
		}
		end := st.FinishedAt
		if end <= 0 {
			// Older rows predate finished_at; the absorption time is the only
			// timestamp they carry, so it is the honest fallback.
			end = st.CreatedAt * 1000
		}
		if end <= 0 {
			continue
		}
		start := end - st.QueueMS - st.WorkMS
		if start <= 0 || start > end {
			start = end
		}
		s := spans[st.VulnType]
		if s == nil {
			s = &span{start: start, end: end}
			spans[st.VulnType] = s
		}
		if start < s.start {
			s.start = start
		}
		if end > s.end {
			s.end = end
		}
		out.PerTypeBatches[st.VulnType]++
		out.Batches++
		if first == 0 || start < first {
			first = start
		}
		if end > last {
			last = end
		}
	}
	if last > first {
		out.TotalMS = last - first
	}
	for vt, s := range spans {
		if d := s.end - s.start; d > 0 {
			out.PerTypeMS[vt] = d
		}
	}
	if out.TotalMS > 0 {
		out.Source = "self-measured"
	}
	return out
}

// sortedAITypes returns the per-type timing keys in a stable order for Markdown
// rendering.
func (t aiStageTiming) sortedAITypes() []string {
	out := make([]string, 0, len(t.PerTypeMS))
	for vt := range t.PerTypeMS {
		out = append(out, vt)
	}
	sort.Strings(out)
	return out
}

// settlementQueueWorkMS splits a settlement's wall clock into queue_ms
// (dispatched_at → started_at) and work_ms (started_at → finish mtime) when the
// report carries those RFC3339 timestamps. Reports written before those fields
// existed (or a partial write) return (0, 0), leaving wall_ms as the fallback.
func settlementQueueWorkMS(rep subagentReport) (queueMS, workMS int64) {
	if rep.DispatchedAt == "" || rep.StartedAt == "" {
		return 0, 0
	}
	dispatched, err := time.Parse(time.RFC3339Nano, rep.DispatchedAt)
	if err != nil {
		return 0, 0
	}
	started, err := time.Parse(time.RFC3339Nano, rep.StartedAt)
	if err != nil {
		return 0, 0
	}
	if q := started.UnixMilli() - dispatched.UnixMilli(); q >= 0 {
		queueMS = q
	}
	if rep.ModTime != "" {
		if mtime, err := time.Parse(time.RFC3339Nano, rep.ModTime); err == nil {
			if w := mtime.UnixMilli() - started.UnixMilli(); w >= 0 {
				workMS = w
			}
		}
	}
	return queueMS, workMS
}

// settlementWallMS estimates a settlement's wall-clock when the report carries
// no started_at split. The preferred anchor is the report's own dispatched_at
// (dispatch → finish = the batch's real lifespan, issue #253 P1-1); the legacy
// fallback is the settlement file's mtime minus the scan's start time, which
// over-counts by the pipeline + dispatch delay (constant per scan), so a
// straggler still stands out relative to its siblings.
func settlementWallMS(ctx context.Context, store db.Store, rep subagentReport) int64 {
	if rep.ModTime == "" {
		return 0
	}
	mtime, err := time.Parse(time.RFC3339, rep.ModTime)
	if err != nil {
		return 0
	}
	if rep.DispatchedAt != "" {
		if dispatched, derr := time.Parse(time.RFC3339Nano, rep.DispatchedAt); derr == nil {
			if w := mtime.UnixMilli() - dispatched.UnixMilli(); w > 0 {
				return w
			}
		}
	}
	run, err := store.GetScanRun(ctx, rep.ScanID)
	if err != nil || run == nil || run.CreatedAt == 0 {
		return 0
	}
	delta := mtime.Unix() - run.CreatedAt
	if delta <= 0 {
		return 0
	}
	return delta * 1000
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
	// InFlightRanges lists batches reserved by `status --claim-*` that no
	// settlement report has closed yet. A fresh entry is another worker's live
	// claim — do NOT dispatch it again; a stale claim is taken over by the next
	// claim call. This is the read-side counterpart of the atomic pre-dispatch
	// placeholder (F13), so a planner that skipped claiming still cannot
	// duplicate a live batch.
	InFlightRanges []inFlightRange `json:"in_flight_ranges,omitempty"`
	// DismissedCount is the AI-dismissed candidate count for this type (from the
	// candidate_verdicts ledger, P0-1). Remaining = candidates not yet classified
	// (candidate_count - written_count - dismissed_count), the breakpoint-recovery
	// number the orchestrator needs without re-reading every candidate index.
	DismissedCount int `json:"dismissed_count"`
	Remaining      int `json:"remaining"`
	// PreAICollapsed is the raw→final reduction for this type (seed_count −
	// candidate_count): the candidates removed by the convergence filter chain and
	// the same-location dedup BEFORE the AI ever sees them. It is a filtered-out
	// total (filtering + dedup), NOT a pure same-location dedup count, so the
	// name avoids misreading it as "deduplicated candidates". It lets an
	// orchestrator reconcile a positive remaining against how much was already
	// removed ahead of AI review.
	PreAICollapsed int `json:"pre_ai_collapsed"`
	// UncoveredRanges is the exact candidate-interval gap (e.g. ["41-80"]) the
	// orchestrator re-dispatches on recovery — replacing the old "re-dispatch
	// candidate_count-written-dismissed candidates" guess that could not name
	// WHICH candidates were missing. Empty when nothing is settled or the type
	// is fully covered.
	UncoveredRanges []string `json:"uncovered_ranges,omitempty"`
	// BudgetViolations lists the settled batches whose self-reported
	// source_reads / evidence_opens / repo_greps exceeded the agent-body.md
	// budgets. It is engine-computed so the orchestrator surfaces read-source
	// violations from one field instead of hand-aggregating every settlement
	// JSON (the F6 audit path).
	BudgetViolations []settlementBudgetViolation `json:"budget_violations,omitempty"`
}

// settlementBudgetViolation is one settled batch that exceeded an agent-body.md
// budget. Over names the exceeded budgets ("source_reads" / "evidence_opens" /
// "repo_greps").
type settlementBudgetViolation struct {
	VulnType      string   `json:"vuln_type"`
	Range         string   `json:"range"`
	SubagentID    string   `json:"subagent_id,omitempty"`
	SourceReads   int      `json:"source_reads"`
	EvidenceOpens int      `json:"evidence_opens"`
	RepoGreps     int      `json:"repo_greps"`
	Over          []string `json:"over"`
}

func (v settlementBudgetViolation) exceeds() []string {
	var over []string
	if v.SourceReads > maxSourceReadsPerType {
		over = append(over, "source_reads")
	}
	if v.EvidenceOpens > maxEvidenceOpensPerType {
		over = append(over, "evidence_opens")
	}
	if v.RepoGreps > maxRepoGrepsPerType {
		over = append(over, "repo_greps")
	}
	return over
}

// inFlightRange is one live pre-dispatch claim (F13): the batch is reserved but
// has no settlement report yet.
type inFlightRange struct {
	Range  string `json:"range"`
	Holder string `json:"holder"`
	AgeMS  int64  `json:"age_ms"`
}

func enrichPerTypeStatus(ctx context.Context, store db.Store, scanID string, statuses []*db.PerTypeStatus) ([]*settlementEnriched, error) {
	byScan, err := store.ListSettlementStatsByScan(ctx, scanID)
	if err != nil {
		return nil, err
	}
	dismissedByType, err := store.CountCandidateVerdictsByType(ctx, scanID)
	if err != nil {
		dismissedByType = map[string]int{}
	}
	nowMS := time.Now().UnixMilli()
	staleBefore := nowMS - int64(settlementClaimTTL/time.Millisecond)
	covered := map[string]map[string]bool{}
	inFlight := map[string][]inFlightRange{}
	rowsByType := map[string][]*db.SettlementStat{}
	for _, st := range byScan {
		rowsByType[st.VulnType] = append(rowsByType[st.VulnType], st)
		if st.Status == "dispatched" {
			leaseAt := st.CreatedAt
			if st.HeartbeatAt > 0 {
				leaseAt = st.HeartbeatAt
			}
			if leaseAt < staleBefore {
				// A stale claim is a dead worker's reservation: it is neither
				// covered nor in flight, so the next planning pass may reclaim it.
				continue
			}
			age := int64(0)
			if leaseAt > 0 && nowMS > leaseAt {
				age = nowMS - leaseAt
			}
			inFlight[st.VulnType] = append(inFlight[st.VulnType], inFlightRange{
				Range: st.RangeStr, Holder: st.SubagentID, AgeMS: age,
			})
			continue
		}
		// Only a fully settled range counts as covered: 'partial' (needs_context)
		// and 'failed' rows must never read as coverage, or an unfinished batch
		// would both block completion AND claim to be done.
		if st.Status != "done" || st.NeedsContext > 0 {
			continue
		}
		if covered[st.VulnType] == nil {
			covered[st.VulnType] = map[string]bool{}
		}
		covered[st.VulnType][st.RangeStr] = true
	}

	out := make([]*settlementEnriched, 0, len(statuses))
	for _, s := range statuses {
		e := &settlementEnriched{PerTypeStatus: s, AlreadyCoveredRanges: []string{}}
		e.DismissedCount = dismissedByType[s.VulnType]
		if s.SeedCount > s.CandidateCount {
			e.PreAICollapsed = s.SeedCount - s.CandidateCount
		}
		// Remaining is the verdict-ledger gap (candidate_count − AI confirmed −
		// dismissed), identical to the audit's unclassified: it is the ONLY
		// number that can never be gamed by a self-declared settlement. A done
		// type reads 0. uncovered_ranges (the scheduling view, from settlement
		// ranges) is still reported for re-dispatch.
		cov := deriveTypeCoverage(rowsByType[s.VulnType], s.CandidateCount, nowMS)
		if s.TerminalState == "done" {
			e.Remaining = 0
		} else {
			if rem := s.CandidateCount - s.WrittenCount - e.DismissedCount; rem > 0 {
				e.Remaining = rem
			}
			if cov.HasRows {
				e.UncoveredRanges = cov.Uncovered
			}
		}
		if ranges := covered[s.VulnType]; len(ranges) > 0 {
			for r := range ranges {
				e.AlreadyCoveredRanges = append(e.AlreadyCoveredRanges, r)
			}
			sort.Strings(e.AlreadyCoveredRanges)
		}
		// A type the orchestrator already declared done is never "in flight": a
		// lingering 'dispatched' placeholder (a claim the complete-type step did
		// not settle, e.g. on an older build) must not make a re-plan skip a type
		// that has nothing left to do.
		if s.TerminalState != "done" {
			if ranges := inFlight[s.VulnType]; len(ranges) > 0 {
				sort.Slice(ranges, func(i, j int) bool { return ranges[i].Range < ranges[j].Range })
				e.InFlightRanges = ranges
			}
		}
		agg := settlementAggregate(ctx, store, s.VulnType)
		e.RType = agg.rType
		e.RSample = agg.sample
		e.AvgWallMS = agg.avgWallMS
		if s.CandidateCount > 0 {
			e.SuggestedBatchSize = suggestedBatchSize(agg.rType)
			e.SuggestedBatches = suggestedBatches(s.CandidateCount, e.SuggestedBatchSize)
		}
		for _, st := range byScan {
			if st.VulnType != s.VulnType {
				continue
			}
			v := settlementBudgetViolation{
				VulnType:      st.VulnType,
				Range:         normalizeSettlementRange(st.RangeStr),
				SubagentID:    st.SubagentID,
				SourceReads:   st.SourceReads,
				EvidenceOpens: st.EvidenceOpens,
				RepoGreps:     st.RepoGreps,
			}
			if over := v.exceeds(); len(over) > 0 {
				v.Over = over
				e.BudgetViolations = append(e.BudgetViolations, v)
			}
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
	var opens, cands, sample, wallN int
	var wallSum int64
	for _, r := range rows {
		// A pre-dispatch claim row (status dispatched, no report yet) has no
		// accounting: counting it would inflate r_sample and skew the r_type
		// estimate. Only settled rows feed the sample.
		if r.Status != "done" {
			continue
		}
		sample++
		opens += r.EvidenceOpens
		cands += r.Written + r.Dismissed
		if r.WallMS > 0 {
			wallSum += r.WallMS
			wallN++
		}
	}
	if sample == 0 {
		return settlementAgg{rType: settlementRTypeFallback}
	}
	if cands == 0 {
		return settlementAgg{rType: settlementRTypeFallback, sample: sample}
	}
	agg := settlementAgg{rType: float64(opens) / float64(cands), sample: sample}
	if wallN > 0 {
		agg.avgWallMS = wallSum / int64(wallN)
	}
	return agg
}

// maxBatchCandidates is the hard per-range ceiling from the Batch Capacity
// Configuration (SPLIT_CANDIDATE_THRESHOLD): no r_type estimate may ever
// suggest a range larger than this, or a light type ends up with a batch whose
// index/context no longer fits the subagent.
const maxBatchCandidates = 100

func suggestedBatchSize(rType float64) int {
	if rType < 0 {
		rType = settlementRTypeFallback
	}
	if rType == 0 {
		// Measured zero Evidence opens: the evidence-open constraint is moot
		// (NOT "no history", which is the 0.30 fallback). Only the hard range
		// ceiling applies — light types finally get bigger batches.
		return maxBatchCandidates
	}
	// N <= evidence-open budget / expected opens per candidate. This is the
	// hard per-subagent budget documented in
	// extension/shared/command-instructions.md ("MAX_EVIDENCE_OPENS_PER_TYPE")
	// and extension/shared/agent-body.md; the engine's budget_violations check
	// uses the same constant. Do NOT add a fixed-cost term here without raising
	// that per-batch budget in the authoritative docs: N x r_type is the batch's
	// expected evidence opens, so a larger N would flag every batch as
	// over-budget (or force the agent to stop early and leave candidates
	// unclassified).
	n := int(math.Floor(float64(maxEvidenceOpensPerType) / rType))
	if n < 1 {
		n = 1
	}
	if n > maxBatchCandidates {
		n = maxBatchCandidates
	}
	return n
}

func suggestedBatches(candidates, batchSize int) int {
	if candidates <= 0 || batchSize <= 0 {
		return 0
	}
	return (candidates + batchSize - 1) / batchSize
}

// settlementAIStageMetrics computes the AI-stage batch concurrency and
// zero-output ratios from the persisted settlement rows, so `secguard metrics`
// surfaces the two diagnostics that let a user spot a queue-dominated or
// zero-yield AI stage without hand-summing settlement files. work_ms is the true
// agent work when the report carried timestamps; wall_ms (which over-counts the
// queue wait) is the fallback.
func settlementAIStageMetrics(rows []*db.SettlementStat, aiDurationMS int64, aiDurationSource string) map[string]interface{} {
	total := 0
	zeroOutput := 0
	var workSum int64
	var workN int64
	for _, st := range rows {
		if st.Status != "done" {
			// A claim has no accounting and a failed row has no completed work;
			// counting either would read as a zero-output batch and skew the ratio.
			continue
		}
		total++
		if st.Written == 0 {
			zeroOutput++
		}
		w := st.WorkMS
		if w <= 0 {
			w = st.WallMS
		}
		if w > 0 {
			workSum += w
			workN++
		}
	}
	timing := measureAIStageTiming(rows)
	out := map[string]interface{}{
		"total_batches":       total,
		"zero_output_batches": zeroOutput,
	}
	if total > 0 {
		out["zero_output_ratio"] = round1(float64(zeroOutput) / float64(total) * 100)
	}
	// The stage duration is the self-measured one when the persisted run row has
	// none: the engine reads its own settlement timestamps instead of requiring
	// the orchestrator to hand in a wall clock.
	if timing.TotalMS > 0 {
		out["measured_total_ms"] = timing.TotalMS
		out["per_type_ms"] = timing.PerTypeMS
	}
	duration := aiDurationMS
	if duration <= 0 {
		duration = timing.TotalMS
	}
	if duration > 0 {
		out["ai_duration_ms"] = duration
		src := aiDurationSource
		if aiDurationMS <= 0 {
			src = "self-measured (settlement timestamps)"
		}
		if src == "" {
			src = "unknown"
		}
		out["ai_duration_source"] = src
	}
	if workN > 0 && duration > 0 {
		out["effective_concurrency"] = round1(float64(workSum) / float64(duration))
	}
	return out
}

// formatMS renders a millisecond duration the way a report reader expects:
// sub-second, seconds with one decimal, then m/s and h/m.
func formatMS(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	if ms < 1000 {
		return fmt.Sprintf("%d ms", ms)
	}
	if ms < 60000 {
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	}
	totalSec := ms / 1000
	m := totalSec / 60
	s := totalSec % 60
	if m < 60 {
		return fmt.Sprintf("%d m %d s", m, s)
	}
	return fmt.Sprintf("%d h %d m", m/60, m%60)
}

// scanLimits is the `status --show-limits` payload: the caps the engine enforces
// plus the AI-stage budgets and host concurrency cap the orchestrator must
// respect. Surfacing them here lets the orchestrator read its concurrency
// ceiling instead of probing it by hitting a "maximum allowed N" spawn error.
func scanLimits() map[string]interface{} {
	cfg := config.Load()
	hostMax := aiHostMaxConcurrencyDefault
	hostSource := "documented default (Claude Code / DSH: 10 concurrent subagents)"
	if raw := strings.TrimSpace(os.Getenv("SECGUARD_AI_HOST_MAX_CONCURRENCY")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			hostMax = n
			hostSource = "SECGUARD_AI_HOST_MAX_CONCURRENCY"
		}
	}
	return map[string]interface{}{
		"ai_stage": map[string]interface{}{
			"host_max_concurrency":        hostMax,
			"host_max_concurrency_source": hostSource,
			"claim_ttl_ms":                int64(settlementClaimTTL / time.Millisecond),
			"heartbeat_stall_ms":          int64(settlementHeartbeatStall / time.Millisecond),
			"evidence_opens_per_type":     maxEvidenceOpensPerType,
			"source_reads_per_type":       maxSourceReadsPerType,
			"repo_greps_per_type":         maxRepoGrepsPerType,
			"r_type_fallback":             settlementRTypeFallback,
		},
		"pipeline": map[string]interface{}{
			"graph_builders_concurrency": cfg.GraphBuildersConcurrencyOr(7),
			"plan_concurrency":           cfg.PlanConcurrencyOr(8),
			"detector_concurrency":       cfg.DetectorConcurrencyOr(8),
			"memory_pressure_enabled":    cfg.Scan.MemoryPressureEnabled,
		},
		"backoff": "When a spawn is rejected with 'maximum allowed N', use N for the rest of the run and keep in_flight below it; never probe the cap again. Backfill one batch per completion while in_flight < host_max.",
	}
}
