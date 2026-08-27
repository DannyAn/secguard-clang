package evidence

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type RaceConditionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewRaceConditionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *RaceConditionDetector {
	return &RaceConditionDetector{store: store, parser: p, logger: logger}
}

func (d *RaceConditionDetector) Name() string { return "race_condition" }

func (d *RaceConditionDetector) Domain() string { return "concurrency" }

func (d *RaceConditionDetector) Capabilities() []string {
	return []string{"toctou-filesystem", "toctou-shared-state", "shared-variable-data-race"}
}

var checkFunctions = map[string]bool{
	"access": true, "stat": true, "lstat": true, "faccessat": true,
}

var useFunctions = map[string]bool{
	"fopen": true, "open": true, "creat": true, "freopen": true, "openat": true,
}

func (d *RaceConditionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Pre-pass: per-file global variable sets, mutex names, and pthread_create
	// thread targets. The data-race detector needs cross-function context, so
	// it cannot run inside the per-function loop below.
	fileInfos := make(map[int64]*fileInfo)
	threadCounts := make(map[string]int)
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		fileInfos[file.ID] = &fileInfo{
			globals: d.collectGlobalVars(root, file.ID, funcs),
			mutexes: d.collectMutexVars(root),
		}
		for _, f := range funcs {
			d.collectThreadTargets(calls, f, threadCounts)
		}
	})
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		calls := root.FindAll("call_expression")
		assigns := root.FindAll("assignment_expression")
		updates := root.FindAll("update_expression")
		ids := root.FindAll("identifier")
		funcDefs := root.FindAll("function_definition")

		for _, f := range funcs {
			for _, ifStmt := range ifs {
				if !funcLineRange(f, ifStmt.StartLine()) {
					continue
				}
				cond := ifStmt.ChildByFieldName("condition")
				if cond == nil {
					continue
				}
				checkCall := d.findCheckCall(*cond)
				if checkCall == nil {
					continue
				}
				checkArg := extractFirstArg(*checkCall)
				if checkArg == "" {
					continue
				}
				consequence := ifStmt.ChildByFieldName("consequence")
				if consequence == nil {
					continue
				}
				for _, useCall := range consequence.FindAll("call_expression") {
					useName := extractCallName(useCall)
					if !useFunctions[useName] {
						continue
					}
					useArg := extractFirstArg(useCall)
					if useArg == checkArg {
						if emitEvent(ctx, d.store, d.logger, "RACE_CONDITION", f.ID, &db.Location{FileID: file.ID, Line: checkCall.StartLine(), Column: checkCall.StartColumn()}, map[string]string{
							"check_function": extractCallName(*checkCall),
							"use_function":   useName,
							"path_arg":       checkArg,
							"category":       "toctou",
						}) {
							result.EventsCreated++
						}
						break
					}
				}
			}

			d.detectLockUnlockPattern(ctx, calls, assigns, f, file, &result)
		}

		// Cross-function data race: aggregate every thread function's accesses
		// to each global and intersect their locksets, so a race between two
		// DIFFERENT thread functions (t1 under m1, t2 under m2) is caught — the
		// per-function pass only saw a single function's own accesses.
		d.detectCrossFunctionDataRace(ctx, file, funcs, funcDefs, fileInfos[file.ID], threadCounts, assigns, updates, ids, calls, &result)
	})
	return result, err
}

type fileInfo struct {
	globals map[string]bool
	mutexes map[string]bool
}

type globalAccess struct {
	funcs       map[string]bool
	writes      []int
	reads       []int
	unprotected []int
	writeFuncs  map[int]string
	// lockset is the intersection of the held-mutex sets across every access to
	// this global in the function. Empty means no single mutex consistently
	// protects the accesses — the classic lockset race signal.
	lockset map[string]bool
}

// collectGlobalVars gathers top-level (file-scope) variable names by
// excluding declarations that fall inside any function body.
func (d *RaceConditionDetector) collectGlobalVars(root parser.Node, fileID int64, funcs []*db.Function) map[string]bool {
	globals := make(map[string]bool)
	var localRanges [][2]int
	for _, fn := range funcs {
		if fn.FileID == fileID {
			localRanges = append(localRanges, [2]int{fn.StartLine, fn.EndLine})
		}
	}
	isLocal := func(line int) bool {
		for _, r := range localRanges {
			if line >= r[0] && line <= r[1] {
				return true
			}
		}
		return false
	}
	for _, decl := range root.FindAll("declaration") {
		if isLocal(decl.StartLine()) {
			continue
		}
		for _, id := range decl.FindAll("init_declarator") {
			children := id.NamedChildren()
			if len(children) > 0 {
				if v := extractVarFromDeclarator(children[0]); v != "" {
					globals[v] = true
				}
			}
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" {
				globals[child.Text()] = true
			}
			if child.Kind() == "pointer_declarator" {
				for _, id := range child.FindAll("identifier") {
					globals[id.Text()] = true
				}
			}
		}
	}
	return globals
}

func (d *RaceConditionDetector) collectMutexVars(root parser.Node) map[string]bool {
	mutexes := make(map[string]bool)
	for _, call := range root.FindAll("call_expression") {
		name := extractCallName(call)
		if !strings.HasPrefix(name, "pthread_mutex_") {
			continue
		}
		args := extractCallArgs(call)
		if len(args) > 0 {
			mutexes[strings.TrimPrefix(strings.TrimSpace(args[0]), "&")] = true
		}
	}
	for _, decl := range root.FindAll("declaration") {
		if strings.Contains(decl.Text(), "pthread_mutex_t") {
			for _, id := range decl.FindAll("identifier") {
				mutexes[id.Text()] = true
			}
		}
	}
	return mutexes
}

func (d *RaceConditionDetector) collectThreadTargets(calls []parser.Node, f *db.Function, counts map[string]int) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if extractCallName(call) != "pthread_create" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) >= 3 {
			counts[strings.TrimSpace(args[2])]++
		}
	}
}

// detectCrossFunctionDataRace flags classic data races across ALL thread
// functions of a file: a file-scope variable accessed (with at least one write)
// by two or more pthread_create thread instances whose locksets have no common
// mutex. Unlike the previous per-function pass, this intersects the locksets of
// DIFFERENT thread functions, so `t1` writing g under m1 while `t2` writes g
// under m2 is caught even though each function is created only once.
func (d *RaceConditionDetector) detectCrossFunctionDataRace(ctx context.Context, file *db.File, funcs []*db.Function, funcDefs []parser.Node, info *fileInfo, threadCounts map[string]int, assigns, updates, ids, calls []parser.Node, result *DetectResult) {
	if info == nil {
		return
	}

	type globalAgg struct {
		funcLocksets map[string]map[string]bool // function name -> its lockset intersection
		writeLine    int
		writeFuncID  int64
	}
	agg := make(map[string]*globalAgg)
	bodies := functionBodyMap(funcDefs)

	for _, f := range funcs {
		if threadCounts[f.Name] <= 0 {
			continue
		}
		body := bodies[f.StartLine]
		heldByLine := d.mustHoldByLine(body, f.EndLine, calls, f)
		accesses := d.functionGlobalAccesses(f, info, assigns, updates, ids, heldByLine)
		for name, acc := range accesses {
			if len(acc.writes) == 0 {
				continue // reads alone do not constitute a data race here
			}
			g := agg[name]
			if g == nil {
				g = &globalAgg{funcLocksets: make(map[string]map[string]bool)}
				agg[name] = g
			}
			g.funcLocksets[f.Name] = acc.lockset
			if g.writeLine == 0 {
				g.writeLine, _ = firstWrite(acc)
				g.writeFuncID = f.ID
			}
		}
	}

	names := make([]string, 0, len(agg))
	for name := range agg {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, globalName := range names {
		g := agg[globalName]
		instances := 0
		threadFuncs := make([]string, 0, len(g.funcLocksets))
		for fn := range g.funcLocksets {
			instances += threadCounts[fn]
			threadFuncs = append(threadFuncs, fn)
		}
		sort.Strings(threadFuncs)

		// Cross-function lockset intersection: every thread function's accesses
		// must share a common mutex; otherwise they race.
		common := map[string]bool{}
		first := true
		for _, ls := range g.funcLocksets {
			if first {
				for m := range ls {
					common[m] = true
				}
				first = false
				continue
			}
			for m := range common {
				if !ls[m] {
					delete(common, m)
				}
			}
		}
		if instances < 2 || len(common) != 0 {
			continue
		}

		if emitEvent(ctx, d.store, d.logger, "RACE_CONDITION", g.writeFuncID, &db.Location{FileID: file.ID, Line: g.writeLine}, map[string]string{
			"variable":         globalName,
			"category":         "shared_data_race",
			"thread_functions": strings.Join(threadFuncs, ","),
			"thread_instances": fmt.Sprintf("%d", instances),
			"write_line":       fmt.Sprintf("%d", g.writeLine),
		}) {
			result.EventsCreated++
		}
	}
}

func firstWrite(acc *globalAccess) (int, string) {
	line := 0
	fn := ""
	for l, fname := range acc.writeFuncs {
		if line == 0 || l < line {
			line = l
			fn = fname
		}
	}
	return line, fn
}

func (d *RaceConditionDetector) functionGlobalAccesses(f *db.Function, info *fileInfo, assigns, updates, ids []parser.Node, heldByLine map[int]map[string]bool) map[string]*globalAccess {
	accesses := make(map[string]*globalAccess)

	assignTargets := make(map[int]string)
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) >= 1 {
			assignTargets[assign.StartLine()] = children[0].Text()
		}
	}
	updateLines := make(map[int]bool)
	for _, upd := range updates {
		if !funcLineRange(f, upd.StartLine()) {
			continue
		}
		updateLines[upd.StartLine()] = true
	}

	for _, id := range ids {
		if !funcLineRange(f, id.StartLine()) {
			continue
		}
		name := id.Text()
		if !info.globals[name] || info.mutexes[name] {
			continue
		}
		line := id.StartLine()
		isWrite := updateLines[line]
		if lhs, ok := assignTargets[line]; ok && (lhs == name || strings.Contains(lhs, name)) {
			isWrite = true
		}
		acc := accesses[name]
		if acc == nil {
			acc = &globalAccess{funcs: map[string]bool{}, writeFuncs: map[int]string{}}
			accesses[name] = acc
		}
		acc.funcs[f.Name] = true
		if isWrite {
			if !containsInt(acc.writes, line) {
				acc.writes = append(acc.writes, line)
				acc.writeFuncs[line] = f.Name
			}
		} else if !containsInt(acc.reads, line) {
			acc.reads = append(acc.reads, line)
		}
		ls := heldByLine[line]
		if ls == nil {
			ls = map[string]bool{}
		}
		if acc.lockset == nil {
			// Deep-copy ls: acc.lockset is mutated by the intersection
			// delete() below, and ls may alias heldByLine[line] which is
			// shared across globals accessed on the same line.
			acc.lockset = make(map[string]bool, len(ls))
			for m := range ls {
				acc.lockset[m] = true
			}
		} else {
			for m := range acc.lockset {
				if !ls[m] {
					delete(acc.lockset, m)
				}
			}
		}
		if len(ls) == 0 && !containsInt(acc.unprotected, line) {
			acc.unprotected = append(acc.unprotected, line)
		}
	}
	return accesses
}

// mustHoldByLine returns, per source line, the set of mutexes DEFINITELY held
// when execution reaches that line — a forward must-analysis over the statement
// CFG. A mutex is held iff every path from the function entry to the line
// acquires it without a subsequent release, so a conditionally-acquired mutex
// (`if (c) lock(m); ...`) is NOT treated as protecting a later access (the
// previous line-range [lock, unlock] approximation wrongly treated it as held).
//
// It is computed per mutex via a two-state reachability (held / not-held): a
// node is "not held" iff it is reachable from the entry without holding the
// mutex, and "held" otherwise.
func (d *RaceConditionDetector) mustHoldByLine(body parser.Node, funcEnd int, calls []parser.Node, f *db.Function) map[int]map[string]bool {
	cfg := graph.BuildStmtCFG(body, funcEnd)

	mutexSet := make(map[string]bool)
	lockAt := make(map[int]string)
	unlockAt := make(map[int]string)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		if name != "pthread_mutex_lock" && name != "pthread_mutex_unlock" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) == 0 {
			continue
		}
		mutex := strings.TrimPrefix(strings.TrimSpace(args[0]), "&")
		mutexSet[mutex] = true
		if node := cfg.NodeAt(call.StartLine()); node != nil {
			switch name {
			case "pthread_mutex_lock":
				lockAt[node.ID] = mutex
			case "pthread_mutex_unlock":
				unlockAt[node.ID] = mutex
			}
		}
	}

	// notHeld[m] = set of nodes reachable from entry without holding m.
	notHeld := make(map[string]map[int]bool, len(mutexSet))
	for m := range mutexSet {
		notHeld[m] = make(map[int]bool)
		type state struct{ node, held int }
		visited := make(map[state]bool)
		queue := []state{{cfg.Entry, 0}}
		visited[state{cfg.Entry, 0}] = true
		notHeld[m][cfg.Entry] = true
		for len(queue) > 0 {
			s := queue[0]
			queue = queue[1:]
			for _, succ := range cfg.Nodes[s.node].Succs {
				held := s.held
				if lockAt[s.node] == m {
					held = 1
				}
				if unlockAt[s.node] == m {
					held = 0
				}
				ns := state{succ, held}
				if visited[ns] {
					continue
				}
				visited[ns] = true
				if held == 0 {
					notHeld[m][succ] = true
				}
				queue = append(queue, ns)
			}
		}
	}

	result := make(map[int]map[string]bool)
	for _, node := range cfg.Nodes {
		if node.Kind != "stmt" {
			continue
		}
		held := make(map[string]bool)
		for m := range mutexSet {
			if !notHeld[m][node.ID] {
				held[m] = true
			}
		}
		result[node.StartLine] = held
	}
	return result
}

func containsInt(s []int, n int) bool {
	for _, v := range s {
		if v == n {
			return true
		}
	}
	return false
}

func joinInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

func (d *RaceConditionDetector) findCheckCall(cond parser.Node) *parser.Node {
	for _, call := range cond.FindAll("call_expression") {
		if checkFunctions[extractCallName(call)] {
			return &call
		}
	}
	return nil
}

func (d *RaceConditionDetector) detectLockUnlockPattern(ctx context.Context, calls, assigns []parser.Node, f *db.Function, file *db.File, result *DetectResult) {
	lockLines := make(map[int]string)
	unlockLines := make(map[int]string)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName == "pthread_mutex_lock" {
			mutexArg := extractFirstArg(call)
			lockLines[call.StartLine()] = mutexArg
		}
		if callName == "pthread_mutex_unlock" {
			mutexArg := extractFirstArg(call)
			unlockLines[call.StartLine()] = mutexArg
		}
	}

	lockLine := 0
	unlockLine := 0
	var mutexName string
	for ll, mname := range lockLines {
		for ul, uname := range unlockLines {
			if ul > ll && mname == uname {
				if lockLine == 0 || ll < lockLine {
					lockLine = ll
					unlockLine = ul
					mutexName = mname
				}
			}
		}
	}
	if lockLine == 0 {
		return
	}

	for _, assign := range assigns {
		if assign.StartLine() <= unlockLine || assign.StartLine() > f.EndLine {
			continue
		}
		text := assign.Text()
		if strings.Contains(text, "g_") || strings.Contains(text, "global") || strings.Contains(text, "shared") {
			if emitEvent(ctx, d.store, d.logger, "RACE_CONDITION", f.ID, &db.Location{FileID: file.ID, Line: assign.StartLine(), Column: assign.StartColumn()}, map[string]string{
				"mutex":       mutexName,
				"lock_line":   fmt.Sprintf("%d", lockLine),
				"unlock_line": fmt.Sprintf("%d", unlockLine),
				"category":    "toctou_shared_state",
			}) {
				result.EventsCreated++
			}
			break
		}
	}
}

func extractFirstArg(call parser.Node) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			args := child.NamedChildren()
			if len(args) > 0 {
				return args[0].Text()
			}
		}
	}
	return ""
}
