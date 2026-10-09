package review

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// autoConfirmedFinder is the narrow store surface the selector needs, so it can
// be faked in tests without a full db.Store implementation.
type autoConfirmedFinder interface {
	ListAutoConfirmedForReview(ctx context.Context, scanID string, ruleIDs []string, limit int) ([]*db.Finding, error)
}

type TargetSelector struct {
	store autoConfirmedFinder
}

func NewTargetSelector(store autoConfirmedFinder) *TargetSelector {
	return &TargetSelector{store: store}
}

func (s *TargetSelector) SelectTargets(ctx context.Context, filter RunFilter, opts RunOptions) ([]ReviewTarget, error) {
	ruleIDs, err := vulnTypesToRuleIDs(filter.VulnTypes)
	if err != nil {
		return nil, err
	}
	findings, err := s.store.ListAutoConfirmedForReview(ctx, filter.ScanID, ruleIDs, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("review: select targets: %w", err)
	}

	revisionVerified := opts.ScanSourceRev != "" && opts.ReviewedRevision != "" &&
		opts.ScanSourceRev == opts.ReviewedRevision && !opts.TreeDirty

	targets := make([]ReviewTarget, 0, len(findings))
	for _, f := range findings {
		targets = append(targets, ReviewTarget{
			Finding:          f,
			ScanSourceRev:    opts.ScanSourceRev,
			ReviewedRev:      opts.ReviewedRevision,
			RevisionVerified: revisionVerified,
		})
	}
	return targets, nil
}

// vulnTypesToRuleIDs maps vuln-type names to the full set of CWE rule_ids that
// findings for those types can carry: canonical, legacy, and per-category CWEs.
// A single injection vuln_type, for example, covers CWE-78/CWE-89/CWE-88/...; a
// naive spec.CWE mapping would silently drop the category findings. An unknown
// type is an error, not a silent no-op (a typo must not widen the selection to
// everything).
func vulnTypesToRuleIDs(vulnTypes []string) ([]string, error) {
	if len(vulnTypes) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool, len(vulnTypes))
	ruleIDs := make([]string, 0, len(vulnTypes))
	for _, vt := range vulnTypes {
		vt = strings.TrimSpace(vt)
		if vt == "" {
			continue
		}
		spec, err := planner.GetVulnTypeSpec(vt)
		if err != nil {
			return nil, fmt.Errorf("review: %w", err)
		}
		add := func(cwe string) {
			cwe = strings.ToUpper(strings.TrimSpace(cwe))
			if cwe == "" || seen[cwe] {
				return
			}
			seen[cwe] = true
			ruleIDs = append(ruleIDs, cwe)
		}
		add(spec.CWE)
		for _, legacy := range spec.LegacyCWEs {
			add(legacy)
		}
		for _, catCWE := range spec.CategoryCWEs {
			add(catCWE)
		}
	}
	return ruleIDs, nil
}
