package cli

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// maxScanIDHintDistance caps the "did you mean" suggestion. Scan ids share a
// fixed template (sc_<date>_<time>_<6-hex>), so a real transcription typo — the
// LLM-orchestrator single-character swap this guards against — is one or two
// edits. A larger distance means the input is unrelated to any known scan, and
// suggesting it would be noise, so the hint is suppressed.
const maxScanIDHintDistance = 3

// levenshtein returns the edit distance between two strings.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 0
			if ra[i-1] != rb[j-1] {
				cost = 1
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// nearestScanIDHint returns the known scan id closest to the input, or "" when
// none is close enough to be a plausible typo. Candidates come from scan_runs,
// the authoritative registry of every scan that began, ordered most-recent
// first, so a stale id naturally suggests the scan it most resembles.
func nearestScanIDHint(ctx context.Context, store db.Store, scanID string) string {
	runs, err := store.ListScanRuns(ctx, 0)
	if err != nil || len(runs) == 0 {
		return ""
	}
	best, bestDist := "", maxScanIDHintDistance+1
	for _, r := range runs {
		if r.ScanID == "" || r.ScanID == scanID {
			continue
		}
		if d := levenshtein(scanID, r.ScanID); d < bestDist {
			best, bestDist = r.ScanID, d
		}
	}
	if best != "" && bestDist <= maxScanIDHintDistance {
		return best
	}
	return ""
}

// validateAuditScanID fails an audit whose scan_id has no scan_stats rows — the
// exact gap that let `report --audit` mint a full set of empty artifacts for a
// typo'd id. A "did you mean" hint names the closest known scan id so an
// orchestrator's single-character transcription error is caught at the prompt
// instead of silently producing a vuln_count=0 report.
func validateAuditScanID(ctx context.Context, store db.Store, scanID string) error {
	stats, err := store.ListScanStats(ctx, scanID)
	if err != nil {
		return fmt.Errorf("failed to validate scan_id: %w", err)
	}
	if len(stats) > 0 {
		return nil
	}
	if hint := nearestScanIDHint(ctx, store, scanID); hint != "" {
		return fmt.Errorf("unknown scan_id %q: no scan_stats found for this id (did you mean %q?). Run 'secguard scan' first, or pass the scan_id from the scan output", scanID, hint)
	}
	return fmt.Errorf("unknown scan_id %q: no scan_stats found for this id. Run 'secguard scan' first, or pass the scan_id from the scan output", scanID)
}
