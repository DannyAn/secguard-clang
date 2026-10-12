package planner

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UnsignedSubGuardFilter converges the unsigned_sub_underflow stream with a
// same-function entry-guard check: `if (consumed > total) return;` before
// `use(total - consumed)` proves `consumed <= total` on the fall-through path,
// so the subtraction cannot underflow. The detector's unsignedSubGuarded already
// drops the tight `if (consumed <= total) { use(total - consumed); }` body guard
// (the guard's consequence directly contains the subtraction); this filter covers
// the sibling entry-return idiom the detector's parent-walk cannot see.
//
// A candidate that survives therefore has no same-function ordering guard, which
// buildHint surfaces as `guard@none` so the classifier stops hunting for a guard
// that does not exist and focuses on the remaining question (accumulator/callee
// truncation boundedness).
type UnsignedSubGuardFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUnsignedSubGuardFilter(store db.Store, p *parser.Parser, logger *log.Logger) *UnsignedSubGuardFilter {
	return &UnsignedSubGuardFilter{store: store, parser: p, logger: logger}
}

func (f *UnsignedSubGuardFilter) Name() string { return "unsigned_sub_guard" }

func (f *UnsignedSubGuardFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		if c.Category == "unsigned_sub_underflow" {
			byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
		}
	}
	if len(byFunc) == 0 {
		return candidates, nil, nil
	}

	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	cache := newFileParseCache(f.parser)
	bodies := make(map[int64]parser.Node, len(byFunc))
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
		if body.Kind() == "compound_statement" {
			bodies[fid] = body
		}
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		if c.Category != "unsigned_sub_underflow" {
			kept = append(kept, c)
			continue
		}
		body, ok := bodies[c.FunctionID]
		if !ok {
			kept = append(kept, c)
			continue
		}
		sub, lhs, rhs, found := findUnsignedSub(body, c.VariableName, c.Line)
		if !found {
			kept = append(kept, c)
			continue
		}
		if unsignedSubEntryGuard(body, sub, lhs, rhs) {
			dropped = dismiss(dropped, c, f.Name(),
				"unsigned subtraction is protected by a preceding `consumed <= total` early-return guard")
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// findUnsignedSub locates the subtraction node whose text matches exprText and
// returns it with its lhs/rhs operands. Matching by normalized text re-resolves
// the exact node the detector recorded (it stored expr.Text()); the line match
// disambiguates when the same expression appears more than once in one function.
func findUnsignedSub(body parser.Node, exprText string, line int) (sub, lhs, rhs parser.Node, found bool) {
	var fallback parser.Node
	for _, e := range body.FindAll("binary_expression") {
		if binaryOperatorToken(e) != "-" {
			continue
		}
		if normExprText(e.Text()) != normExprText(exprText) {
			continue
		}
		kids := e.NamedChildren()
		if len(kids) != 2 {
			continue
		}
		if e.StartLine() == line {
			return e, kids[0], kids[1], true
		}
		if fallback.Kind() == "" {
			fallback = e
		}
	}
	if fallback.Kind() == "" {
		return parser.Node{}, parser.Node{}, parser.Node{}, false
	}
	kids := fallback.NamedChildren()
	return fallback, kids[0], kids[1], true
}

// unsignedSubEntryGuard reports whether a preceding early-return guard proves
// lhs >= rhs on the fall-through path. The safe forms (where !cond ⟹ lhs >= rhs)
// are `rhs > lhs` / `rhs >= lhs` and the mirrored `lhs < rhs` / `lhs <= rhs`.
// The guard must appear before the subtraction, exit early, and neither operand
// may be reassigned between the guard and the subtraction (an accumulator
// `length += f(...)` after the guard invalidates the bound).
func unsignedSubEntryGuard(body parser.Node, sub parser.Node, lhs, rhs parser.Node) bool {
	lhsKey := normExprText(lhs.Text())
	rhsKey := normExprText(rhs.Text())
	lhsName := bareIdentVar(lhs.Text())
	rhsName := bareIdentVar(rhs.Text())

	for _, ifNode := range body.FindAll("if_statement") {
		if ifNode.StartLine() >= sub.StartLine() {
			continue
		}
		cond := ifNode.ChildByFieldName("condition")
		cons := ifNode.ChildByFieldName("consequence")
		if cond == nil || cons == nil || !isEarlyExit(*cons) {
			continue
		}
		condition := unwrapParenNode(*cond)
		if condition.Kind() != "binary_expression" {
			continue
		}
		op := binaryOperatorToken(condition)
		kids := condition.NamedChildren()
		if len(kids) != 2 {
			continue
		}
		left := normExprText(kids[0].Text())
		right := normExprText(kids[1].Text())
		switch op {
		case ">", ">=":
			if left != rhsKey || right != lhsKey {
				continue
			}
		case "<", "<=":
			if left != lhsKey || right != rhsKey {
				continue
			}
		default:
			continue
		}
		if lhsName != "" && reassignedBetween(body, lhsName, ifNode.StartLine(), sub.StartLine()) {
			continue
		}
		if rhsName != "" && reassignedBetween(body, rhsName, ifNode.StartLine(), sub.StartLine()) {
			continue
		}
		return true
	}
	return false
}

// unwrapParenNode strips parenthesized_expression wrappers from a condition node.
func unwrapParenNode(node parser.Node) parser.Node {
	for node.Kind() == "parenthesized_expression" {
		children := node.NamedChildren()
		if len(children) == 0 {
			return node
		}
		node = children[0]
	}
	return node
}

// normExprText collapses all whitespace so two renderings of the same expression
// (different source spacing) compare equal, mirroring the detector's exprTextKey.
func normExprText(s string) string {
	return strings.Join(strings.Fields(s), "")
}
