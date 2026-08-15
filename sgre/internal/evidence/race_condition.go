package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
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
	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
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

	err = forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		ifs := root.FindAll("if_statement")
		calls := root.FindAll("call_expression")
		assigns := root.FindAll("assignment_expression")
		updates := root.FindAll("update_expression")
		ids := root.FindAll("identifier")

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
						locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: checkCall.StartLine(), Column: checkCall.StartColumn()})
						props, _ := json.Marshal(map[string]string{
							"check_function": extractCallName(*checkCall),
							"use_function":   useName,
							"path_arg":       checkArg,
							"category":       "toctou",
						})
						_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
							EventType:  "RACE_CONDITION",
							EntityID:   f.ID,
							LocationID: locID,
							Properties: string(props),
						})
						if err == nil {
							result.EventsCreated++
						}
						break
					}
				}
			}

			d.detectLockUnlockPattern(ctx, calls, assigns, f, file, &result)
			if threadCounts[f.Name] > 0 {
				d.detectSharedDataRace(ctx, f, file, fileInfos[file.ID], threadCounts, assigns, updates, ids, calls, &result)
			}
		}
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

// detectSharedDataRace flags classic data races: a file-scope variable that is
// accessed (at least one write) by two or more pthread_create thread instances
// without lock protection. Access inside a pthread_mutex_lock/unlock scope is
// considered protected; mutex variables themselves are ignored.
func (d *RaceConditionDetector) detectSharedDataRace(ctx context.Context, f *db.Function, file *db.File, info *fileInfo, threadCounts map[string]int, assigns, updates, ids, calls []parser.Node, result *DetectResult) {
	if info == nil {
		return
	}
	accesses := d.functionGlobalAccesses(f, info, assigns, updates, ids, d.lockRanges(calls, f))

	names := make([]string, 0, len(accesses))
	for name := range accesses {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, globalName := range names {
		acc := accesses[globalName]
		instances := 0
		for fnName := range acc.funcs {
			instances += threadCounts[fnName]
		}
		if instances < 2 || len(acc.writes) == 0 || len(acc.unprotected) == 0 {
			continue
		}
		writeLine, writeFunc := firstWrite(acc)
		if writeFunc != f.Name {
			// Emit once per variable, from the function holding the first write.
			continue
		}
		threadFuncs := make([]string, 0, len(acc.funcs))
		for fnName := range acc.funcs {
			threadFuncs = append(threadFuncs, fnName)
		}
		sort.Strings(threadFuncs)

		accessLines := append([]int{}, acc.writes...)
		accessLines = append(accessLines, acc.reads...)
		sort.Ints(accessLines)
		sort.Ints(acc.writes)

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: writeLine})
		props, _ := json.Marshal(map[string]interface{}{
			"variable":         globalName,
			"category":         "shared_data_race",
			"thread_functions": strings.Join(threadFuncs, ","),
			"thread_instances": fmt.Sprintf("%d", instances),
			"access_lines":     joinInts(accessLines),
			"write_lines":      joinInts(acc.writes),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "RACE_CONDITION",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
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

func (d *RaceConditionDetector) functionGlobalAccesses(f *db.Function, info *fileInfo, assigns, updates, ids []parser.Node, lockRanges [][2]int) map[string]*globalAccess {
	accesses := make(map[string]*globalAccess)

	inLock := func(line int) bool {
		for _, r := range lockRanges {
			if line >= r[0] && line <= r[1] {
				return true
			}
		}
		return false
	}

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
		if !inLock(line) && !containsInt(acc.unprotected, line) {
			acc.unprotected = append(acc.unprotected, line)
		}
	}
	return accesses
}

func (d *RaceConditionDetector) lockRanges(calls []parser.Node, f *db.Function) [][2]int {
	locks := make(map[int]string)
	unlocks := make(map[int]string)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		args := extractCallArgs(call)
		if len(args) == 0 {
			continue
		}
		mutex := strings.TrimPrefix(strings.TrimSpace(args[0]), "&")
		switch name {
		case "pthread_mutex_lock":
			locks[call.StartLine()] = mutex
		case "pthread_mutex_unlock":
			unlocks[call.StartLine()] = mutex
		}
	}
	var ranges [][2]int
	for ll, m1 := range locks {
		for ul, m2 := range unlocks {
			if ul > ll && m1 == m2 {
				ranges = append(ranges, [2]int{ll, ul})
			}
		}
	}
	return ranges
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
			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: assign.StartLine(), Column: assign.StartColumn()})
			props, _ := json.Marshal(map[string]string{
				"mutex":       mutexName,
				"lock_line":   fmt.Sprintf("%d", lockLine),
				"unlock_line": fmt.Sprintf("%d", unlockLine),
				"category":    "toctou_shared_state",
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "RACE_CONDITION",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
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
