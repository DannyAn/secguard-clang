package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type suppressionIndex struct {
	byKey map[string]bool
	count int
	rules map[string]int
}

func suppressionKey(file string, line int, ruleID string) string {
	return fmt.Sprintf("%s:%d:%s", file, line, strings.ToUpper(ruleID))
}

func buildSuppressionIndex(findings []*db.Finding) *suppressionIndex {
	idx := &suppressionIndex{
		byKey: make(map[string]bool, len(findings)),
		rules: make(map[string]int),
	}
	for _, f := range findings {
		if f.Status != "dismissed" {
			continue
		}
		key := suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID)
		idx.byKey[key] = true
		idx.count++
		idx.rules[f.RuleID]++
	}
	return idx
}

func (idx *suppressionIndex) isSuppressed(file string, line int, ruleID string) bool {
	if idx == nil || idx.count == 0 {
		return false
	}
	return idx.byKey[suppressionKey(file, line, ruleID)]
}

func (idx *suppressionIndex) suppressedCount() int {
	if idx == nil {
		return 0
	}
	return idx.count
}

func loadSuppressions(ctx context.Context, store db.Store) *suppressionIndex {
	dismissed, err := store.ListFindingsByStatus(ctx, "dismissed")
	if err != nil {
		return &suppressionIndex{byKey: map[string]bool{}, rules: map[string]int{}}
	}
	return buildSuppressionIndex(dismissed)
}

type baselineIndex struct {
	existing map[string]bool
	count    int
}

func loadBaseline(ctx context.Context, store db.Store, baselineScanID string) *baselineIndex {
	findings, err := store.ListFindingsByScanID(ctx, baselineScanID)
	if err != nil || len(findings) == 0 {
		return &baselineIndex{existing: map[string]bool{}}
	}
	bi := &baselineIndex{existing: make(map[string]bool, len(findings))}
	for _, f := range findings {
		bi.existing[suppressionKey(f.FilePath, int(f.LineNumber), f.RuleID)] = true
		bi.count++
	}
	return bi
}

func (bi *baselineIndex) isExisting(file string, line int, ruleID string) bool {
	if bi == nil || bi.count == 0 {
		return false
	}
	return bi.existing[suppressionKey(file, line, ruleID)]
}

func filterSuppressedCandidates(items []planner.EvidenceItem, cwe string, sup *suppressionIndex, baseline *baselineIndex) (kept []planner.EvidenceItem, suppressed int, baselineExisting int) {
	kept = make([]planner.EvidenceItem, 0, len(items))
	for _, item := range items {
		file := item.Target.File
		line := item.Target.Line
		if sup.isSuppressed(file, line, cwe) {
			suppressed++
			continue
		}
		if baseline.isExisting(file, line, cwe) {
			baselineExisting++
			continue
		}
		kept = append(kept, item)
	}
	return
}
