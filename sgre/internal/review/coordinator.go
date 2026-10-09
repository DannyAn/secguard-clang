package review

import (
	"context"
	"fmt"
	"time"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type Coordinator struct {
	store     db.Store
	selector  *TargetSelector
	builder   *PayloadBuilder
	reviewer  Reviewer
	persister *ResultPersister
	cfg       *config.AIReview
	logger    *log.Logger
}

func NewCoordinator(store db.Store, reviewer Reviewer, cfg *config.AIReview, projectRoot string, logger *log.Logger) *Coordinator {
	return &Coordinator{
		store:     store,
		selector:  NewTargetSelector(store),
		builder:   NewPayloadBuilder(projectRoot, promptVersion(cfg), schemaVersion(cfg)),
		reviewer:  reviewer,
		persister: NewResultPersister(store),
		cfg:       cfg,
		logger:    logger,
	}
}

func (c *Coordinator) Run(ctx context.Context, filter RunFilter, opts RunOptions) (*RunResult, error) {
	start := time.Now()

	if !opts.DryRun && c.reviewer == nil {
		return nil, fmt.Errorf("review: coordinator: nil reviewer in non-dry-run mode")
	}

	targets, err := c.selector.SelectTargets(ctx, filter, opts)
	if err != nil {
		return nil, fmt.Errorf("review: select targets: %w", err)
	}

	records := make([]ReviewRecord, 0, len(targets))
	byVerdict := map[string]int{}
	byDetector := map[string]map[string]int{}
	evidenceSources := map[string]int{}
	revisionMismatches := 0
	aiStats := AICallStats{}
	costPerCall := costPerCall(c.cfg)
	budgetUSD := budgetUSD(c.cfg)
	var spentUSD float64

	for _, target := range targets {
		f := target.Finding
		if f == nil {
			continue
		}
		vulnType := planner.TypeForCWE(f.RuleID)

		if !target.RevisionVerified {
			revisionMismatches++
		}

		payload, perr := c.builder.BuildPayload(ctx, target)
		if perr != nil {
			byVerdict[VerdictReviewError]++
			addDetectorCount(byDetector, vulnType, VerdictReviewError)
			aiStats.Failed++
			records = append(records, ReviewRecord{
				FindingID:        f.ID,
				ScanID:           f.ScanID,
				RuleID:           f.RuleID,
				Verdict:          VerdictReviewError,
				Rationale:        perr.Error(),
				SourceRevision:   target.ScanSourceRev,
				ReviewedRevision: target.ReviewedRev,
				RevisionVerified: target.RevisionVerified,
			})
			if c.logger != nil {
				c.logger.Warn("review payload build failed; finding left unreviewed", "finding_id", f.ID, "error", perr)
			}
			continue
		}

		evidenceSources[payload.Evidence.EvidenceSource]++

		if opts.DryRun {
			byVerdict["dry_run"]++
			addDetectorCount(byDetector, vulnType, "dry_run")
			records = append(records, ReviewRecord{
				FindingID:        f.ID,
				ScanID:           f.ScanID,
				RuleID:           f.RuleID,
				Verdict:          "dry_run",
				SourceRevision:   target.ScanSourceRev,
				ReviewedRevision: target.ReviewedRev,
				RevisionVerified: target.RevisionVerified,
			})
			continue
		}

		if budgetUSD > 0 && costPerCall > 0 && spentUSD+costPerCall > budgetUSD {
			if c.logger != nil {
				c.logger.Warn("review budget exhausted, stopping", "spent_usd", spentUSD, "budget_usd", budgetUSD)
			}
			break
		}

		callStart := time.Now()
		verdict, verr := c.reviewer.Review(ctx, payload)
		durationMs := time.Since(callStart).Milliseconds()
		aiStats.TotalCalls++
		aiStats.TotalDurationMs += durationMs

		if verr != nil {
			byVerdict[VerdictReviewError]++
			addDetectorCount(byDetector, vulnType, VerdictReviewError)
			aiStats.Failed++
			records = append(records, ReviewRecord{
				FindingID:        f.ID,
				ScanID:           f.ScanID,
				RuleID:           f.RuleID,
				Verdict:          VerdictReviewError,
				Rationale:        verr.Error(),
				SourceRevision:   target.ScanSourceRev,
				ReviewedRevision: target.ReviewedRev,
				RevisionVerified: target.RevisionVerified,
				DurationMs:       durationMs,
			})
			if c.logger != nil {
				c.logger.Warn("review failed; finding left unreviewed", "finding_id", f.ID, "error", verr)
			}
			if costPerCall > 0 {
				spentUSD += costPerCall
			}
			continue
		}

		aiStats.Successful++
		byVerdict[verdict.Verdict]++
		addDetectorCount(byDetector, vulnType, verdict.Verdict)

		now := time.Now().Unix()
		audit := c.audit(target, durationMs, verdict.Confidence, now)

		if perr := c.persister.Persist(ctx, target, verdict, audit); perr != nil && c.logger != nil {
			c.logger.Warn("persist verdict failed", "finding_id", f.ID, "error", perr)
		}

		records = append(records, ReviewRecord{
			FindingID:        f.ID,
			ScanID:           f.ScanID,
			RuleID:           f.RuleID,
			Verdict:          verdict.Verdict,
			Rationale:        verdict.Rationale,
			ModelProvider:    audit.ModelProvider,
			SourceRevision:   target.ScanSourceRev,
			ReviewedRevision: target.ReviewedRev,
			RevisionVerified: target.RevisionVerified,
			ReviewedAt:       now,
			DurationMs:       durationMs,
		})

		if costPerCall > 0 {
			spentUSD += costPerCall
		}
	}

	return &RunResult{
		Total:              len(records),
		ByVerdict:          byVerdict,
		ByDetector:         byDetector,
		AIStats:            aiStats,
		EvidenceSources:    evidenceSources,
		RevisionMismatches: revisionMismatches,
		DurationMs:         time.Since(start).Milliseconds(),
	}, nil
}

func (c *Coordinator) audit(target ReviewTarget, durationMs int64, confidence float64, reviewedAt int64) *ReviewAudit {
	return &ReviewAudit{
		ModelProvider:    providerName(c.cfg),
		Model:            modelName(c.cfg),
		PromptVersion:    promptVersion(c.cfg),
		SchemaVersion:    schemaVersion(c.cfg),
		SourceRevision:   target.ScanSourceRev,
		ReviewedRevision: target.ReviewedRev,
		RevisionVerified: target.RevisionVerified,
		DurationMs:       durationMs,
		Confidence:       confidence,
		ReviewedAt:       reviewedAt,
	}
}

func addDetectorCount(m map[string]map[string]int, detector, verdict string) {
	if detector == "" {
		detector = "unknown"
	}
	if _, ok := m[detector]; !ok {
		m[detector] = map[string]int{}
	}
	m[detector][verdict]++
}

func providerName(cfg *config.AIReview) string {
	if cfg == nil {
		return ""
	}
	return cfg.Provider
}

func modelName(cfg *config.AIReview) string {
	if cfg == nil {
		return ""
	}
	return cfg.Model
}

func promptVersion(cfg *config.AIReview) string {
	if cfg == nil {
		return ""
	}
	return cfg.PromptVersion
}

func schemaVersion(cfg *config.AIReview) string {
	if cfg == nil {
		return ""
	}
	return cfg.SchemaVersion
}

func costPerCall(cfg *config.AIReview) float64 {
	if cfg == nil {
		return 0
	}
	return cfg.CostPerCallUSD
}

func budgetUSD(cfg *config.AIReview) float64 {
	if cfg == nil {
		return 0
	}
	return cfg.BudgetUSD
}
