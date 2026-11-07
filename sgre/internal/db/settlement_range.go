package db

import (
	"strconv"
	"strings"
)

// NormalizeSettlementRange canonicalizes the range label used as the settlement
// key: empty means the whole type ("all"). Whitespace inside the label is
// dropped so "1 - 100" and "1-100" are the same claim, not two.
func NormalizeSettlementRange(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return "all"
	}
	return strings.ReplaceAll(r, " ", "")
}

// ParseSettlementRange parses "all" | "N-M" | "N" into an inclusive candidate
// interval. "all" needs candidateCount > 0. An end beyond candidateCount is
// clamped (a stale batch size must not fabricate uncovered candidates); an
// unparsable or empty interval returns ok=false and must never be treated as
// coverage.
func ParseSettlementRange(rangeStr string, candidateCount int) (lo, hi int, ok bool) {
	r := NormalizeSettlementRange(rangeStr)
	if r == "all" {
		if candidateCount <= 0 {
			return 0, 0, false
		}
		return 1, candidateCount, true
	}
	if a, b, found := strings.Cut(r, "-"); found {
		start, err1 := strconv.Atoi(a)
		end, err2 := strconv.Atoi(b)
		if err1 != nil || err2 != nil || start <= 0 || end < start {
			return 0, 0, false
		}
		if candidateCount > 0 && end > candidateCount {
			end = candidateCount
		}
		if start > end {
			return 0, 0, false
		}
		return start, end, true
	}
	n, err := strconv.Atoi(r)
	if err != nil || n <= 0 {
		return 0, 0, false
	}
	return n, n, true
}
