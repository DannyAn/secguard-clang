package planner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// RangeOOBFilter is the independent semantic convergence layer for
// buffer-overflow / out-of-bounds (BO-01/02). The detector's constant/text
// loop-bound heuristics emit array_oob_* / heap_oob_* candidates; this filter
// re-verifies each one with the CFG interval engine (range_flow.go) — the same
// engine divide-by-zero and integer-overflow use. An index whose interval
// provably fits the array is DROPPED (the heuristic over-flagged), and one whose
// interval provably equals-or-exceeds the capacity on every path is CONFIRMED.
type RangeOOBFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewRangeOOBFilter(store db.Store, p *parser.Parser, logger *log.Logger) *RangeOOBFilter {
	return &RangeOOBFilter{store: store, parser: p, logger: logger}
}

func (f *RangeOOBFilter) Name() string { return "range_oob" }

func (f *RangeOOBFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	// Only array/heap OOB candidates carry a resolved size + index; everything
	// else (bounded_copy_*, format_*, buffer_overflow) has no Size and passes
	// through untouched.
	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		if c.Size > 0 && c.Index != "" {
			byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
		}
	}
	if len(byFunc) == 0 {
		return candidates, nil, nil
	}

	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	cache := newFileParseCache(f.parser)
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
		flows[fid] = analyzeRanges(fn, body)
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		rf := flows[c.FunctionID]
		if rf == nil || c.Size <= 0 || c.Index == "" {
			kept = append(kept, c)
			continue
		}
		iv := indexIntervalAt(rf, c.Index, c.Line)
		size := int64(c.Size)
		switch {
		case iv.lo >= size:
			// Every value of the index reaches/exceeds the capacity → definite OOB.
			c.SuspicionLevel = "confirmed"
			kept = append(kept, c)
		case iv.lo >= 0 && iv.hi < size:
			// The interval is provably within [0, size) → the detector over-flagged.
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("index %s ∈ [%d,%d] fits %s[%d]", c.Index, iv.lo, iv.hi, c.Array, c.Size))
		default:
			kept = append(kept, c)
		}
	}
	return kept, dropped, nil
}

// indexIntervalAt computes the interval of an OOB index expression at a line:
// a constant literal, a bare variable (from the interval engine), or `var ± c`.
func indexIntervalAt(rf *rangeFlow, indexExpr string, line int) interval {
	indexExpr = strings.TrimSpace(indexExpr)
	if rf == nil || rf.cfg == nil {
		return topInterval()
	}
	if v, ok := parseOOBConst(indexExpr); ok {
		return constInterval(v)
	}
	if isBareIdent(indexExpr) {
		return rf.at(indexExpr, line)
	}
	for _, op := range []string{" - ", " + "} {
		if i := strings.Index(indexExpr, op); i > 0 {
			base := strings.TrimSpace(indexExpr[:i])
			if !isBareIdent(base) {
				continue
			}
			if c, ok := parseOOBConst(strings.TrimSpace(indexExpr[i+len(op):])); ok {
				if op == " - " {
					c = -c
				}
				return rf.at(base, line).shift(c)
			}
		}
	}
	for _, op := range []string{"-", "+"} {
		if i := strings.Index(indexExpr, op); i > 0 {
			base := strings.TrimSpace(indexExpr[:i])
			if !isBareIdent(base) {
				continue
			}
			if c, ok := parseOOBConst(strings.TrimSpace(indexExpr[i+1:])); ok {
				if op == "-" {
					c = -c
				}
				return rf.at(base, line).shift(c)
			}
		}
	}
	return topInterval()
}

// parseOOBConst parses a C integer constant (decimal/hex/octal, u/U/l/L suffix,
// leading sign) to an int64.
func parseOOBConst(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}
	s = strings.TrimRight(s, "uUlL")
	if s == "" {
		return 0, false
	}
	neg := false
	if s[0] == '-' || s[0] == '+' {
		neg = s[0] == '-'
		s = s[1:]
		if s == "" {
			return 0, false
		}
	}
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		v = -v
	}
	return v, true
}

func isBareIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
