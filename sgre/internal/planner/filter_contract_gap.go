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
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

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
}

func (f *ContractGapFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil {
		return candidates, nil, nil
	}

	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
	}
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	cache := newFileParseCache(f.parser)
	callees, sites := f.buildCallerIndex(ctx, fileByID, cache)

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		fn := fnByID[c.FunctionID]
		file := fileByID[fn.FileID]
		if fn == nil || file == nil {
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
		if targetsGuardDominates(body, fn.EndLine, targets, c.UseLine) {
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
// through an early-exit null guard of one of targets, or the line sits inside a
// loop whose condition establishes a target non-null on the body (the loop
// condition is re-checked each iteration, so every path into the body has the
// target non-null).
func targetsGuardDominates(body parser.Node, funcEnd int, targets map[string]bool, line int) bool {
	if loopGuardsTarget(body, targets, line) {
		return true
	}
	cfg := graph.BuildStmtCFG(body, funcEnd)
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
		if arg == "" || !f.callerGuardsField(s, arg, field, fileByID, cache) {
			return false
		}
	}
	return true
}

// callerGuardsField reports whether the caller of one call site null-checks
// `arg->field` (or `arg.field` for a `&arg` argument) before the call.
func (f *ContractGapFilter) callerGuardsField(s contractCallSite, arg, field string, fileByID map[int64]*db.File, cache *fileParseCache) bool {
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
	return targetsGuardDominates(body, s.callerEnd, map[string]bool{target: true}, s.callLine)
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
		tree, err := f.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
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
			})
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
