package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type suppressionIndex struct {
	byKey    map[string]bool
	wildcard map[string]bool
	count    int
	rules    map[string]int
}

func suppressionLocationKey(file string, line int, ruleID string) string {
	return fmt.Sprintf("%s:%d:%s", file, line, strings.ToUpper(ruleID))
}

func suppressionKey(file string, line int, ruleID string, variable string) string {
	return fmt.Sprintf("%s:%d:%s:%s", file, line, strings.ToUpper(ruleID), variable)
}

func buildSuppressionIndex(findings []*db.Finding) *suppressionIndex {
	idx := &suppressionIndex{
		byKey:    make(map[string]bool, len(findings)),
		wildcard: make(map[string]bool),
		rules:    make(map[string]int),
	}
	for _, f := range findings {
		if f.EffectiveStatus() != "dismissed" {
			continue
		}
		// A dismissed finding with a variable suppresses ONLY that variable at
		// the location (two variables on one statement are two findings, and
		// dismissing one must not swallow the other). A legacy finding without a
		// variable predates the variable identity and keeps the old whole-location
		// behavior via the wildcard set.
		if f.Variable == "" {
			idx.wildcard[suppressionLocationKey(f.FilePath, int(f.LineNumber), f.RuleID)] = true
		} else {
			idx.byKey[suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID, f.Variable)] = true
		}
		idx.count++
		idx.rules[f.RuleID]++
	}
	return idx
}

func (idx *suppressionIndex) isSuppressed(file string, line int, ruleID string, variable string) bool {
	if idx == nil || idx.count == 0 {
		return false
	}
	if idx.wildcard[suppressionLocationKey(file, line, ruleID)] {
		return true
	}
	return idx.byKey[suppressionKey(file, line, ruleID, variable)]
}

func (idx *suppressionIndex) suppressedCount() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func loadSuppressions(ctx context.Context, store db.Store) (*suppressionIndex, error) {
	// Fetch all findings and filter by EffectiveStatus, so A5-dismissed findings
	// (review_status="dismissed") are suppressed too, not just first-pass
	// dismissed ones.
	all, err := store.ListFindings(ctx)
	if err != nil {
		return nil, err
	}
	return buildSuppressionIndex(all), nil
}

type baselineIndex struct {
	existing map[string]bool
	wildcard map[string]bool
	count    int
}

func loadBaseline(ctx context.Context, store db.Store, baselineScanID string) (*baselineIndex, error) {
	if baselineScanID == "" {
		return &baselineIndex{existing: map[string]bool{}, wildcard: map[string]bool{}}, nil
	}
	findings, err := store.ListFindingsByScanID(ctx, baselineScanID)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return &baselineIndex{existing: map[string]bool{}, wildcard: map[string]bool{}}, nil
	}
	bi := &baselineIndex{
		existing: make(map[string]bool, len(findings)),
		wildcard: make(map[string]bool),
	}
	for _, f := range findings {
		if f.Variable == "" {
			bi.wildcard[suppressionLocationKey(f.FilePath, int(f.LineNumber), f.RuleID)] = true
		} else {
			bi.existing[suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID, f.Variable)] = true
		}
		bi.count++
	}
	return bi, nil
}

func (bi *baselineIndex) isExisting(file string, line int, ruleID string, variable string) bool {
	if bi == nil || bi.count == 0 {
		return false
	}
	if bi.wildcard[suppressionLocationKey(file, line, ruleID)] {
		return true
	}
	return bi.existing[suppressionKey(file, line, ruleID, variable)]
}

func filterSuppressedCandidates(items []planner.EvidenceItem, cwe string, sup *suppressionIndex, baseline *baselineIndex) (kept []planner.EvidenceItem, suppressed int, baselineExisting int) {
	kept = make([]planner.EvidenceItem, 0, len(items))
	for _, item := range items {
		file := item.Target.File
		line := item.Target.Line
		variable := item.Target.Variable
		if sup.isSuppressed(file, line, cwe, variable) {
			suppressed++
			continue
		}
		if baseline.isExisting(file, line, cwe, variable) {
			baselineExisting++
			continue
		}
		kept = append(kept, item)
	}
	return
}
