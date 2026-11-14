package planner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// ContractGapFilter is the deterministic convergence stage for the
// implicit-contract type. It never promotes to confirmed — the field's nullness
// is open-world. It only DROPS provably-safe candidates, so the AI sees the
// small residual:
//
//  1. guard dominance (intra-procedural CFG): a field null-checked before the
//     dereference on every path is properly guarded → dropped;
//  2. caller validation (cross-function): when EVERY caller null-checks the
//     field before the call, the caller already proved non-null → dropped
//     (guide §7.1).
type ContractGapFilter struct {
	store    db.Store
	parser   *parser.Parser
	logger   *log.Logger
	cfgCache *graph.CFGCache
}

// SetCFGCache is the uniform-injection entrypoint used by Planner.Plan.
func (f *ContractGapFilter) SetCFGCache(c *graph.CFGCache) { f.cfgCache = c }

func NewContractGapFilter(store db.Store) *ContractGapFilter {
	return &ContractGapFilter{store: store}
}

func (f *ContractGapFilter) WithParser(p *parser.Parser, l *log.Logger) *ContractGapFilter {
	f.parser = p
	f.logger = l
	return f
}

func (f *ContractGapFilter) Name() string { return "contract_gap" }

type contractCallSite struct {
	fileID      int64
	callerStart int
	callerEnd   int
	callLine    int
	args        []string
	text        string
}

func (f *ContractGapFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	// Issue #200 tier policy (runs before the parser-dependent cuts so it also
	// applies when a fixture has no parseable body): only a SAME-FILE sibling
	// guard is strong enough to hand the classifier. A self-only scope gap has
	// no sibling reference (production: 25/25 dismissed), and a cross-file
	// type-anchored sibling guard is unrelated-TU evidence (the production
	// count dominated by it was ~2% precise). Both are pre-dismissed into the
	// ledger; the same-file `sibling` tier stays suspected for the AI.
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	remaining := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		switch c.EvidenceKind {
		case "self":
			dropped = dismiss(dropped, c, f.Name(),
				"self-guard-only evidence: the function's own null check does not dominate this deref and no same-file sibling proves the field is nullable (non-proving tier; auto-dismissed)")
		case "sibling":
			// Issue #206 (A.6): a type-anchored sibling null-check is weak
			// name/type evidence — it says the field MAY be nullable, not that
			// NULL reaches THIS deref. Production measured 459 sibling-only
			// candidates at 0 confirmed, so a sibling reference WITHOUT the
			// function's own null check (self-guard) is auto-dismissed. A
			// candidate that ALSO self-guards the field (GuardLine > 0) is the
			// kept residual: the function itself treats the field as nullable.
			if c.GuardLine == 0 {
				dropped = dismiss(dropped, c, f.Name(),
					"sibling-only evidence (no self-guard in this function): a type-anchored sibling null-check is weak evidence the field MAY be nullable, not that NULL reaches this deref (issue #206; auto-dismissed)")
			} else {
				remaining = append(remaining, c)
			}
		case "sibling-weak":
			dropped = dismiss(dropped, c, f.Name(),
				"cross-file type-anchored sibling guard only: no same-file sibling shows the field is nullable (weak evidence; auto-dismissed)")
		default:
			remaining = append(remaining, c)
		}
	}
	candidates = remaining

	if f.parser == nil {
		return candidates, dropped, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}
	fnByID, fileByID, err := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	if err != nil {
		return nil, nil, err
	}
	cache := newFileParseCache(f.parser)
	defer cache.Close()
	callees, sites := f.buildCallerIndex(ctx, fileByID, cache)

	for _, c := range candidates {
		fn := fnByID[c.FunctionID]
		if fn == nil {
			kept = append(kept, c)
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			kept = append(kept, c)
			continue
		}
		body, _ := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			kept = append(kept, c)
			continue
		}

		obj := c.Subject
		field := strings.TrimPrefix(c.VariableName, obj+"->")
		if field == "" || field == c.VariableName {
			kept = append(kept, c)
			continue
		}

		// 1. Intra-procedural guard dominance.
		targets := map[string]bool{obj + "->" + field: true}
		forEachAssignment(body, func(lhs, rhs parser.Node) {
			if copySourceKey(rhs) == obj+"->"+field {
				if n := assignTargetName(lhs); n != "" {
					targets[n] = true
				}
			}
		})
		if targetsGuardDominates(ctx, f.cfgCache, cache.treeFor(file), fn.ID, body, fn.EndLine, targets, c.UseLine, c.Expression) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("field %s is null-guarded on every path before its use at line %d", c.VariableName, c.UseLine))
			continue
		}

		// 2. Caller validation: every caller proves the field non-null.
		if f.allCallersValidate(ctx, c, callees, sites, fileByID, cache) {
			dropped = dismiss(dropped, c, f.Name(),
				fmt.Sprintf("every caller null-checks %s before the call", c.VariableName))
			continue
		}

		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// targetsGuardDominates reports whether every CFG path from entry to line passes
// through a null guard of one of targets — either an early-exit guard
// (`if (p == NULL) return;`), a same-block guard (the deref sits inside the
// `if (p != NULL)` body, the `else` of `if (p == NULL)`, or the right operand of
// a short-circuited `&&`), or a loop condition re-checked on every iteration.
// expr is the reported statement's text; it disambiguates a one-line branch from
// a following statement that shares the line, where the line number alone
// cannot (fail-open when it does not).
func targetsGuardDominates(ctx context.Context, cfgCache *graph.CFGCache, tree *parser.Tree, fnID int64, body parser.Node, funcEnd int, targets map[string]bool, line int, expr string) bool {
	if loopGuardsTarget(body, targets, line) {
		return true
	}
	if branchGuardsTarget(body, targets, line, expr) {
		return true
	}
	var cfg *graph.StmtCFG
	if cfgCache != nil && tree != nil && fnID > 0 {
		lease := cfgCache.Acquire(ctx, fnID, tree, func() *graph.StmtCFG { return graph.BuildStmtCFG(body, funcEnd) })
		defer lease.Release()
		cfg = lease.CFG()
	} else {
		cfg = graph.BuildStmtCFG(body, funcEnd)
	}
	var guardIDs map[int]bool
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" || n.Stmt.Kind() != "if_statement" {
			continue
		}
		cond := n.Stmt.ChildByFieldName("condition")
		cons := n.Stmt.ChildByFieldName("consequence")
		if cond == nil || cons == nil || !isEarlyExit(*cons) {
			continue
		}
		for _, v := range parser.NullCheckedVars(*cond) {
			if targets[v] {
				if guardIDs == nil {
					guardIDs = make(map[int]bool)
				}
				guardIDs[n.ID] = true
				break
			}
		}
	}
	if len(guardIDs) == 0 {
		return false
	}
	deref := cfg.NodeAt(line)
	if deref == nil {
		return false
	}
	return !cfg.ReachesAvoiding(cfg.Entry, guardIDs, deref.ID)
}

// branchGuardsTarget reports whether line sits inside a branch whose condition
// establishes one of targets non-null: the consequence of `if (p != NULL)`
// (also `if (p)`), the alternative of `if (p == NULL)`, or an operand to the
// right of a short-circuiting `&&` whose earlier operand null-tests the target.
// Issue #216: these same-block guards were not modelled (only the early-exit
// form was), so a dereference guarded by the very `if` it sits in was reported
// as an unguarded contract gap.
func branchGuardsTarget(body parser.Node, targets map[string]bool, line int, expr string) bool {
	for _, ifStmt := range body.FindAll("if_statement") {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if cons := ifStmt.ChildByFieldName("consequence"); cons != nil && branchCoversLine(*cons, *cond, line, expr) {
			if matched := guardedLvalues(parser.GuardedNonnullVars(*cond), targets); len(matched) > 0 &&
				!targetReassigned(body, matched, ifStmt.StartLine(), line) {
				return true
			}
		}
		if alt := ifStmt.ChildByFieldName("alternative"); alt != nil && branchCoversLine(*alt, *cond, line, expr) {
			if matched := guardedLvalues(parser.NullCheckedVars(*cond), targets); len(matched) > 0 &&
				!targetReassigned(body, matched, ifStmt.StartLine(), line) {
				return true
			}
		}
	}
	return shortCircuitGuardsTarget(body, targets, line)
}

// branchCoversLine reports whether the reported statement lies inside branch.
// A multi-line branch is resolved by line range. When the reported line is the
// line the condition itself sits on, the statement may equally be one of the
// condition's operands — which run BEFORE the branch is entered — so a reported
// expression that appears in the condition fails open. A branch that starts and
// ends on the reported line cannot be told apart from a following statement on
// the same line (`if (p == NULL) log(); p->field->x;`), so the reported
// expression must occur inside the branch text.
func branchCoversLine(branch, cond parser.Node, line int, expr string) bool {
	if line < branch.StartLine() || line > branch.EndLine() {
		return false
	}
	if line == branch.StartLine() && expr != "" && strings.Contains(cond.Text(), expr) {
		return false
	}
	if branch.StartLine() < line || line < branch.EndLine() {
		return true
	}
	return expr != "" && strings.Contains(branch.Text(), expr)
}

// shortCircuitGuardsTarget reports whether line sits in an operand of a `&&`
// chain that a preceding operand's null test already proves non-null
// (`if (p != NULL && p->field)`, `if (p->field && p->field->sub)`). C evaluates
// the operands left to right and skips the rest once one is false, so a later
// operand runs only when every earlier one held.
func shortCircuitGuardsTarget(body parser.Node, targets map[string]bool, line int) bool {
	for _, and := range body.FindAll("binary_expression") {
		if parser.BinaryOperator(and) != "&&" {
			continue
		}
		operands := and.NamedChildren()
		for i := 1; i < len(operands); i++ {
			if !nodeContainsLine(operands[i], line) {
				continue
			}
			for _, prev := range operands[:i] {
				if len(guardedLvalues(parser.GuardedNonnullVars(prev), targets)) > 0 {
					return true
				}
			}
		}
	}
	return false
}

// guardedLvalues returns the subset of vars that names one of the guarded
// locations (the field and every local derived from it).
func guardedLvalues(vars []string, targets map[string]bool) []string {
	var matched []string
	for _, v := range vars {
		if targets[v] {
			matched = append(matched, v)
		}
	}
	return matched
}

// targetReassigned reports whether one of the guarded locations — or the
// variable the location hangs off — is written between the guard and the use.
// A guard proves non-nullness only until the next write: in
// `if (p != NULL) { p = f(); p->field->x }` the reassignment reopens the gap,
// so the guard must not drop the candidate (fail-open).
func targetReassigned(body parser.Node, targets []string, fromLine, toLine int) bool {
	killed := false
	forEachAssignment(body, func(lhs, _ parser.Node) {
		if killed {
			return
		}
		l := lhs.StartLine()
		if l < fromLine || l > toLine {
			return
		}
		name := assignTargetName(lhs)
		if name == "" {
			return
		}
		for _, t := range targets {
			if name == t || name == fieldBaseName(t) {
				killed = true
				return
			}
		}
	})
	return killed
}

// loopGuardsTarget reports whether line sits inside the body of a for/while loop
// whose condition establishes one of targets non-null on the true branch
// (`for (...; cur != NULL && cur->data != NULL; ...) { ...line... }`). Every path
// into the body passes through the condition's true edge, so the target is
// non-null at line.
func loopGuardsTarget(body parser.Node, targets map[string]bool, line int) bool {
	loops := append(body.FindAll("for_statement"), body.FindAll("while_statement")...)
	for _, loop := range loops {
		cond := loop.ChildByFieldName("condition")
		loopBody := loop.ChildByFieldName("body")
		if cond == nil || loopBody == nil {
			continue
		}
		if line < loopBody.StartLine() || line > loopBody.EndLine() {
			continue
		}
		for _, v := range parser.GuardedNonnullVars(*cond) {
			if targets[v] {
				return true
			}
		}
	}
	return false
}

// allCallersValidate reports whether the candidate function has at least one
// call site and EVERY call site validates the field before the call.
func (f *ContractGapFilter) allCallersValidate(ctx context.Context, c Candidate, callees map[string][]string, sites map[string][]contractCallSite, fileByID map[int64]*db.File, cache *fileParseCache) bool {
	params := callees[c.FunctionName]
	if len(params) == 0 {
		return false
	}
	idx := -1
	for i, p := range params {
		if p == c.Subject {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	field := strings.TrimPrefix(c.VariableName, c.Subject+"->")
	list := sites[c.FunctionName]
	if len(list) == 0 {
		return false // no call sites → open world, keep
	}
	for _, s := range list {
		if idx >= len(s.args) {
			return false
		}
		arg := normalizeCallArg(s.args[idx])
		if arg == "" || !f.callerGuardsField(ctx, s, arg, field, fileByID, cache) {
			return false
		}
	}
	return true
}

// callerGuardsField reports whether the caller of one call site null-checks
// `arg->field` (or `arg.field` for a `&arg` argument) before the call.
func (f *ContractGapFilter) callerGuardsField(ctx context.Context, s contractCallSite, arg, field string, fileByID map[int64]*db.File, cache *fileParseCache) bool {
	target := arg + "->" + field
	if strings.HasPrefix(arg, "&") {
		target = strings.TrimPrefix(arg, "&") + "." + field
	}
	file := fileByID[s.fileID]
	if file == nil {
		return false
	}
	root := cache.rootForFile(file)
	if root.Kind() == "" {
		return false
	}
	body := functionBodyAt(root, s.callerStart)
	if body.Kind() != "compound_statement" {
		return false
	}
	return targetsGuardDominates(ctx, f.cfgCache, cache.treeFor(file), 0, body, s.callerEnd, map[string]bool{target: true}, s.callLine, s.text)
}

// normalizeCallArg trims a call argument to a bare lvalue path, or "" for a
// value we cannot resolve (a call result, a literal, a compound expression).
func normalizeCallArg(arg string) string {
	t := strings.TrimSpace(arg)
	t = strings.TrimPrefix(t, "*")
	t = strings.Trim(t, "()")
	if t == "" {
		return ""
	}
	return t
}

// functionBodyAt returns the compound_statement body of the function whose
// definition starts at startLine, or a zero node.
func functionBodyAt(root parser.Node, startLine int) parser.Node {
	for _, def := range root.FindAll("function_definition") {
		if def.StartLine() != startLine {
			continue
		}
		if body := def.FindFirst("compound_statement"); body != nil {
			return *body
		}
	}
	return parser.Node{}
}

// buildCallerIndex builds the cross-function (callee name -> param names) and
// (callee name -> call sites) indexes once per Apply. Same-name overloads are
// skipped (ambiguous, never guessed).
func (f *ContractGapFilter) buildCallerIndex(ctx context.Context, fileByID map[int64]*db.File, cache *fileParseCache) (map[string][]string, map[string][]contractCallSite) {
	callees := map[string][]string{}
	sites := map[string][]contractCallSite{}

	funcs, err := f.store.ListFunctions(ctx)
	if err != nil {
		return callees, sites
	}
	// Unambiguous names only.
	dup := map[string]bool{}
	seen := map[string]bool{}
	for _, fn := range funcs {
		if seen[fn.Name] {
			dup[fn.Name] = true
			continue
		}
		seen[fn.Name] = true
	}
	funcsByFile := map[int64][]*db.Function{}
	for _, fn := range funcs {
		funcsByFile[fn.FileID] = append(funcsByFile[fn.FileID], fn)
	}

	for _, fn := range funcs {
		if dup[fn.Name] {
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		if names := paramNamesOfDefAt(root, fn.StartLine); len(names) > 0 {
			callees[fn.Name] = names
		}
	}

	for _, file := range fileByID {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		if err := f.parser.WithParseCached(source, file.Path, func(tree *parser.Tree) {
			root := tree.RootNode()
			for _, call := range root.FindAll("call_expression") {
				callee := callName(call)
				if callee == "" || dup[callee] {
					continue
				}
				var caller *db.Function
				for _, cf := range funcsByFile[file.ID] {
					if call.StartLine() >= cf.StartLine && call.StartLine() <= cf.EndLine {
						caller = cf
						break
					}
				}
				if caller == nil {
					continue
				}
				args := callArgs(call)
				texts := make([]string, 0, len(args))
				for _, a := range args {
					texts = append(texts, a.Text())
				}
				sites[callee] = append(sites[callee], contractCallSite{
					fileID:      file.ID,
					callerStart: caller.StartLine,
					callerEnd:   caller.EndLine,
					callLine:    call.StartLine(),
					args:        texts,
					text:        call.Text(),
				})
			}
		}); err != nil {
			continue
		}
	}
	return callees, sites
}

// paramNamesOfDefAt returns the parameter names of the function whose definition
// starts at startLine.
func paramNamesOfDefAt(root parser.Node, startLine int) []string {
	for _, def := range root.FindAll("function_definition") {
		if def.StartLine() != startLine {
			continue
		}
		return paramNamesOfDef(def)
	}
	return nil
}
