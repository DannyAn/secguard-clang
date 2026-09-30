package planner

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DoubleFreeFilter converges the double-free stream with the same freed-state
// dataflow as the UAF lifetime filter: gen = first free(p), kill = p = <non-alias
// reassignment>, copy = p = q. A candidate is suppressed when the freed state
// from the first free no longer reaches the second free (the pointer was
// reassigned in between, so the second free frees a different block).
type DoubleFreeFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDoubleFreeFilter(store db.Store, p *parser.Parser, logger *log.Logger) *DoubleFreeFilter {
	return &DoubleFreeFilter{store: store, parser: p, logger: logger}
}

func (f *DoubleFreeFilter) Name() string { return "double_free_flow" }

func (f *DoubleFreeFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}

	flows, exclusive, err := f.buildFlows(ctx, byFunc)
	if err != nil {
		return nil, nil, err
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		flow := flows[c.FunctionID]
		if flow == nil {
			kept = append(kept, c)
			continue
		}
		if !flow.reaching(c.VariableName, c.Line) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("variable %s is reassigned before the second free at line %d", c.VariableName, c.Line))
			continue
		}
		if exclusive[c.DerefEventID] {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("first free and second free at line %d are in mutually-exclusive if branches", c.Line))
			continue
		}
		// The first-free state reaches the second free. It is a CERTAIN double-
		// free only when the first free reaches on every path (must); otherwise
		// it stays a suspicion for the AI to confirm.
		if flow.mustReaching(c.VariableName, c.Line) {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

func (f *DoubleFreeFilter) buildFlows(ctx context.Context, byFunc map[int64][]Candidate) (map[int64]*flowResult, map[int64]bool, error) {
	flows := make(map[int64]*flowResult, len(byFunc))
	exclusive := make(map[int64]bool)
	cache := newFileParseCache(f.parser)
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	// Batch-load every candidate's event once: the per-candidate GetEventByID
	// below was an N+1 query storm.
	eventIDs := make([]int64, 0)
	for _, cs := range byFunc {
		for _, c := range cs {
			eventIDs = append(eventIDs, c.DerefEventID)
		}
	}
	eventsByID, err := f.store.ListEventsByIDs(ctx, eventIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("double free: load events: %w", err)
	}
	analyzer := newFlowAnalyzer(f.store, f.parser)
	aliases := analyzer.loadAliases(ctx, candidateFuncIDs(byFunc))
	for fid, cs := range byFunc {
		fn := fnByID[fid]
		if fn == nil {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			continue
		}

		// Seed the freed-state ONLY at each candidate's first-free site. The UAF
		// lifetime filter seeds every free site (loadFreeSites), but a double-free
		// analysis must NOT seed the second free too: seeding both makes the
		// second free "reach itself" via genAt and the filter never suppresses —
		// two mutually-exclusive frees (a guarded `free(p); return;` then a tail
		// `free(p)`) become a false confirmed double-free. Indirect frees have no
		// RELEASE edge, so their first_free also arrives via the detector's
		// event property here, exactly like a direct free.
		genByLine := make(map[int][]string)
		for _, c := range cs {
			event := eventsByID[c.DerefEventID]
			if event == nil {
				continue
			}
			var props struct {
				FirstFree int    `json:"first_free"`
				Variable  string `json:"variable"`
			}
			if json.Unmarshal([]byte(event.Properties), &props) != nil || props.FirstFree == 0 || props.Variable == "" {
				continue
			}
			if !freeAlreadySeeded(genByLine, props.FirstFree, props.Variable) {
				genByLine[props.FirstFree] = append(genByLine[props.FirstFree], props.Variable)
			}
			if mutuallyExclusiveIfs(body, props.FirstFree, c.Line) {
				exclusive[c.DerefEventID] = true
			}
		}

		killByLine := make(map[int][]string)
		forEachAssignment(body, func(lhs, rhs parser.Node) {
			name := assignTargetName(lhs)
			if name == "" {
				name = declaratorName(lhs)
			}
			if name == "" || rhsVarName(rhs) != "" {
				return
			}
			killByLine[lhs.StartLine()] = append(killByLine[lhs.StartLine()], name)
		})

		// free(p) dangles every alias of p, so the first-free source also reaches
		// a later free(q) where q aliases p (q = p; free(p); free(q)).
		expandGenToAliases(genByLine, aliases[fid])
		flows[fid] = analyzer.analyzeFlowMust(ctx, fn, body, root, genByLine, killByLine, false, false)
	}
	return flows, exclusive, nil
}
func mutuallyExclusiveIfs(body parser.Node, line1, line2 int) bool {
	if1 := findEnclosingIf(body, line1)
	if2 := findEnclosingIf(body, line2)
	if if1 == nil || if2 == nil {
		return false
	}
	if if1.StartLine() == if2.StartLine() {
		return false
	}
	v1, c1, ok1 := ifEqVarConst(*if1)
	v2, c2, ok2 := ifEqVarConst(*if2)
	if !ok1 || !ok2 {
		return false
	}
	return v1 == v2 && c1 != c2
}

func findEnclosingIf(body parser.Node, line int) *parser.Node {
	ifs := body.FindAll("if_statement")
	var best *parser.Node
	for i := range ifs {
		ifNode := ifs[i]
		if line < ifNode.StartLine() || line > ifNode.EndLine() {
			continue
		}
		if best == nil || ifNode.EndLine()-ifNode.StartLine() < best.EndLine()-best.StartLine() {
			best = &ifNode
		}
	}
	return best
}

func ifEqVarConst(ifNode parser.Node) (varName, constText string, ok bool) {
	cond := ifNode.ChildByFieldName("condition")
	if cond == nil {
		return "", "", false
	}
	node := *cond
	for node.Kind() == "parenthesized_expression" {
		children := node.NamedChildren()
		if len(children) == 0 {
			return "", "", false
		}
		node = children[0]
	}
	if node.Kind() != "binary_expression" {
		return "", "", false
	}
	if binaryOperatorToken(node) != "==" {
		return "", "", false
	}
	children := node.NamedChildren()
	if len(children) != 2 {
		return "", "", false
	}
	left, right := children[0], children[1]
	if left.Kind() == "identifier" && isLiteralNode(right) {
		return left.Text(), right.Text(), true
	}
	if right.Kind() == "identifier" && isLiteralNode(left) {
		return right.Text(), left.Text(), true
	}
	return "", "", false
}

func isLiteralNode(node parser.Node) bool {
	switch node.Kind() {
	case "number_literal", "string_literal", "char_literal":
		return true
	case "parenthesized_expression", "cast_expression":
		for _, c := range node.NamedChildren() {
			if isLiteralNode(c) {
				return true
			}
		}
	}
	return false
}
