package evidence

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UnboundedLengthDetector flags CWE-1284: an externally-sourced length
// (the return value of recv/recvfrom/recvmsg/read/pread/fread) flows, through
// a SINGLE local assignment, into an allocation/copy size argument with no
// upper-bound guard dominating the sink. The trust boundary is a semantic
// judgment the machine cannot prove, so every shape is suspected (never
// auto-confirmed).
type UnboundedLengthDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUnboundedLengthDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UnboundedLengthDetector {
	return &UnboundedLengthDetector{store: store, parser: p, logger: logger}
}

func (d *UnboundedLengthDetector) Name() string { return "unbounded_length" }

// taintSources are the length-returning network/file read calls (GAP-09 v1).
var lengthTaintSources = map[string]bool{
	"recv": true, "recvfrom": true, "recvmsg": true,
	"read": true, "pread": true, "fread": true,
}

// lengthSinks maps a sink name to its length-argument indices (GAP-09 v1).
var lengthSinks = map[string][]int{
	"malloc": {0}, "alloca": {0},
	"calloc": {1},
	"memcpy": {2}, "memmove": {2}, "strncpy": {2},
}

func (d *UnboundedLengthDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		calls := root.FindAll("call_expression")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		allIfs := root.FindAll("if_statement")

		for _, f := range funcs {
			bounds := AnalyzeBounds(IfsInFunc(allIfs, f.StartLine, f.EndLine), assignsInFunc(assigns, f.StartLine, f.EndLine))
			// taintedLen maps a local name to its source (fn:line) — a SINGLE
			// assignment from a length-taint source (GAP-09 v1: one hop only).
			taintedLen := d.collectTaintedLengths(calls, assigns, inits, f)

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				name := extractCallName(call)
				idxs, ok := lengthSinks[name]
				if !ok {
					continue
				}
				args := getCallArgs(call)
				for _, idx := range idxs {
					if idx >= len(args) {
						continue
					}
					lenVar := strings.TrimSpace(args[idx].Text())
					src, ok := taintedLen[lenVar]
					if !ok {
						continue
					}
					// Upper-bound guard dominates the sink → exempt.
					if bounds.UpperBoundAt(lenVar, call.StartLine()) > 0 {
						continue
					}
					if hasEarlyReturnUpperGuard(allIfs, f, lenVar, call.StartLine()) {
						continue
					}
					if d.clampedBefore(assigns, f, lenVar, call.StartLine()) {
						continue
					}
					props := map[string]string{
						"category":   "unbounded_length",
						"variable":   lenVar,
						"function":   name,
						"expression": call.OriginalText(),
						"origin":     src,
					}
					if emitEvent(ctx, d.store, d.logger, "UNBOUNDED_LENGTH", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
						result.EventsCreated++
					}
					break
				}
			}
		}
	})
	return result, err
}

// collectTaintedLengths returns the local variables assigned ONCE from a length
// taint source (recv/read/...), keyed name -> "fn:line".
func (d *UnboundedLengthDetector) collectTaintedLengths(calls, assigns, inits []parser.Node, f *db.Function) map[string]string {
	out := map[string]string{}
	consider := func(lhs, rhs parser.Node, line int) {
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		call := rhs
		for call.Kind() == "parenthesized_expression" || call.Kind() == "cast_expression" {
			kids := call.NamedChildren()
			if len(kids) == 0 {
				return
			}
			call = kids[len(kids)-1]
		}
		if call.Kind() != "call_expression" {
			return
		}
		callee := extractCallName(call)
		if !lengthTaintSources[callee] {
			return
		}
		out[name] = fmt.Sprintf("%s:%d", callee, line)
	}
	for _, a := range assigns {
		if !funcLineRange(f, a.StartLine()) {
			continue
		}
		named := a.NamedChildren()
		if len(named) < 2 {
			continue
		}
		consider(named[0], named[1], a.StartLine())
	}
	for _, i := range inits {
		if !funcLineRange(f, i.StartLine()) {
			continue
		}
		lhs, rhs, ok := i.AssignParts()
		if !ok {
			continue
		}
		consider(lhs, rhs, i.StartLine())
	}
	return out
}

// hasEarlyReturnUpperGuard reports whether an early-return guard
// (`if (len > MAX) return;`) establishes an upper bound on the fall-through
// before the sink — the "len > MAX error branch" exemption (GAP-09 v1).
func hasEarlyReturnUpperGuard(ifs []parser.Node, f *db.Function, lenVar string, sinkLine int) bool {
	for _, ifStmt := range ifs {
		if !funcLineRange(f, ifStmt.StartLine()) || ifStmt.StartLine() >= sinkLine {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		cons := ifStmt.ChildByFieldName("consequence")
		if cond == nil || cons == nil || !isExitStmt(*cons) {
			continue
		}
		c := stripCastParenNode(*cond)
		op := ""
		for _, ch := range c.Children() {
			switch ch.Kind() {
			case ">", ">=":
				op = ch.Kind()
			}
		}
		if op == "" {
			continue
		}
		named := c.NamedChildren()
		if len(named) != 2 {
			continue
		}
		if normalizeGuardText(named[0].Text()) == lenVar {
			return true
		}
	}
	return false
}

// clampedBefore reports whether lenVar is clamped (`len = min(len, cap)`) before
// the sink — the truncation idiom, exempted (GAP-09 v1).
func (d *UnboundedLengthDetector) clampedBefore(assigns []parser.Node, f *db.Function, lenVar string, sinkLine int) bool {
	for _, a := range assigns {
		if !funcLineRange(f, a.StartLine()) || a.StartLine() >= sinkLine {
			continue
		}
		named := a.NamedChildren()
		if len(named) < 2 {
			continue
		}
		if assignedVariable(named[0]) != lenVar {
			continue
		}
		if strings.Contains(named[1].Text(), "min(") || strings.Contains(named[1].Text(), "MIN(") {
			return true
		}
	}
	return false
}
