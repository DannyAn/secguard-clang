package planner

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// BufferRangeFilter is the interval-based convergence layer for the
// buffer-overflow categories that RangeOOBFilter does not cover: bounded_copy_*,
// secure_copy_*, format_*, and the plain buffer_overflow shape. Those candidates
// carry a SizeArgument (copy size) expression and a DstCapacity expression —
// when both resolve to intervals and the copy size's lower bound provably
// exceeds the destination capacity's upper bound, the overflow is interval-
// proven (confirmed); when the copy size's upper bound is provably within the
// capacity's lower bound, the candidate is dismissed (interval-proven safe).
//
// The filter reuses the range-flow engine (analyzeRangesWithCalls) so the
// interval facts are the same ones divide-by-zero / integer-overflow consume.
type BufferRangeFilter struct {
	store    db.Store
	parser   *parser.Parser
	logger   *log.Logger
	cfgCache *graph.CFGCache
}

// NewBufferRangeFilter builds the filter. parser may be nil (the filter then
// passes every candidate through untouched).
func NewBufferRangeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *BufferRangeFilter {
	return &BufferRangeFilter{store: store, parser: p, logger: logger}
}

// SetCFGCache is the uniform-injection entrypoint used by Planner.Plan.
func (f *BufferRangeFilter) SetCFGCache(c *graph.CFGCache) { f.cfgCache = c }

// Name implements Filter.
func (f *BufferRangeFilter) Name() string { return "buffer_range" }

// Apply implements Filter.
func (f *BufferRangeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	// Only candidates that carry a copy-size AND a destination-capacity
	// expression are eligible; the rest pass through untouched.
	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		if c.SizeArgument != "" && c.DstCapacity != "" {
			byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
		} else if f.logger != nil && (c.SizeArgument != "" || c.DstCapacity != "") {
			f.logger.Info("buffer_range skip partial", "fn", c.FunctionName, "line", c.Line, "size_arg", c.SizeArgument, "dst_cap", c.DstCapacity)
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
		flows[fid] = analyzeRangesWithCalls(f.cfgCache, fn, body, nil)
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if c.SizeArgument == "" || c.DstCapacity == "" {
			kept = append(kept, c)
			continue
		}
		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		copyIv := resolveIntervalExpr(flow, c.SizeArgument, c.Line)
		capIv := resolveIntervalExpr(flow, c.DstCapacity, c.Line)
		if copyIv.isTop() || capIv.isTop() {
			kept = append(kept, c)
			continue
		}
		// Interval-proven overflow: copy size lower bound > capacity upper bound.
		if copyIv.lo > capIv.hi {
			c.SuspicionLevel = "confirmed"
			kept = append(kept, c)
			continue
		}
		// Interval-proven safe: copy size upper bound <= capacity lower bound.
		if copyIv.hi <= capIv.lo {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("copy size %s interval [%d,%d] is within destination capacity %s interval [%d,%d]",
					c.SizeArgument, copyIv.lo, copyIv.hi, c.DstCapacity, capIv.lo, capIv.hi))
			continue
		}
		// Overlapping intervals — keep as suspected for the AI.
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// resolveIntervalExpr resolves an expression string to an interval at the
// given line inside the function's range flow. A bare integer literal is a
// const interval; a bare identifier is the range flow's interval at the
// line; anything else (arithmetic, call, sizeof) is top (unknown).
func resolveIntervalExpr(flow *rangeFlow, expr string, line int) interval {
	if flow == nil {
		return topInterval()
	}
	expr = strings.TrimSpace(expr)
	// Strip a leading cast: `(int)n` → `n`.
	if strings.HasPrefix(expr, "(") {
		depth := 0
		end := -1
		for i, c := range expr {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					end = i
					break
				}
			}
		}
		if end > 0 && end+1 < len(expr) {
			expr = strings.TrimSpace(expr[end+1:])
		}
	}
	// Bare integer literal.
	if v, err := strconv.ParseInt(expr, 10, 64); err == nil {
		return interval{lo: v, hi: v}
	}
	// sizeof(T) / sizeof(x): the size of the type — a const when the type is
	// known, top otherwise. We do not resolve sizeof here (it needs the type
	// table); treat it as top.
	if strings.HasPrefix(expr, "sizeof") {
		return topInterval()
	}
	// Bare identifier: the range flow's interval at the line.
	if isIdent(expr) {
		return flow.at(expr, line)
	}
	return topInterval()
}

// isIdent reports whether s is a C identifier.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}
