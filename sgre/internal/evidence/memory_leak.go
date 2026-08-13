package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type MemoryLeakDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewMemoryLeakDetector(store db.Store, p *parser.Parser, logger *log.Logger) *MemoryLeakDetector {
	return &MemoryLeakDetector{store: store, parser: p, logger: logger}
}

func (d *MemoryLeakDetector) Name() string { return "memory_leak" }

func (d *MemoryLeakDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("memory_leak: list functions: %w", err)
	}

	funcMap := make(map[string]*db.Function, len(funcs))
	for _, f := range funcs {
		funcMap[f.Name] = f
	}

	raiiCreateFuncs := make(map[int64]bool)
	for _, f := range funcs {
		if destroyName := getDestroyCounterpart(f.Name); destroyName != "" {
			if destroyFunc, exists := funcMap[destroyName]; exists {
				if d.functionHasFrees(ctx, destroyFunc) {
					raiiCreateFuncs[f.ID] = true
				}
			}
		}
	}

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		allocs := d.findAllocations(ctx, f, file, root, &result)
		frees := d.findFrees(ctx, f, file, root)
		returnLines := findReturnLines(root, f)

		isRAII := raiiCreateFuncs[f.ID]

		cfg := graph.BuildCFG(root, f.StartLine, f.EndLine)
		cfgValid := cfg != nil && cfg.Root != nil && len(cfg.Root.Children) > 0
		if !cfgValid && d.logger != nil {
			d.logger.Debug("memory_leak: CFG construction degenerate, using path-insensitive fallback",
				"function", f.Name,
			)
		}

		for varName, allocLine := range allocs {
			freeLines, hasFree := frees[varName]
			isReturned := isReturnedToCaller(varName, root, f)
			filteredReturns := filterNullGuardReturns(root, returnLines, varName)

			shouldReportLeak := false
			shouldReportRelease := false

			if isReturned {
				shouldReportRelease = true
			} else if !hasFree {
				shouldReportLeak = true
			} else if cfgValid {
				if hasLeakingPath(cfg, allocLine, freeLines, filteredReturns) {
					shouldReportLeak = true
				} else {
					shouldReportRelease = true
				}
			} else {
				shouldReportRelease = true
			}

			if shouldReportLeak && !isRAII {
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: allocLine})
				props, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "malloc",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_ALLOC",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				result.EventsCreated++
			}

			if shouldReportRelease {
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: allocLine})
				props, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "malloc",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_ALLOC",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				releaseLine := allocLine
				if len(freeLines) > 0 {
					releaseLine = freeLines[0]
				}
				releaseLocID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: releaseLine})
				releaseProps, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "free",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "MEMORY_RELEASE",
					EntityID:   f.ID,
					LocationID: releaseLocID,
					Properties: string(releaseProps),
				})
				result.EventsCreated += 2
			}
		}

		tree.Close()
	}

	return result, nil
}

func (d *MemoryLeakDetector) findAllocations(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) map[string]int {
	allocs := make(map[string]int)
	allocators := []string{"malloc", "calloc", "realloc"}

	checkNode := func(node parser.Node) {
		text := node.Text()
		for _, a := range allocators {
			if strings.Contains(text, a) {
				children := node.NamedChildren()
				if len(children) < 2 {
					return
				}
				lhs := children[0]
				varName := ""
				if lhs.Kind() == "identifier" {
					varName = lhs.Text()
				} else {
					for _, child := range lhs.NamedChildren() {
						if child.Kind() == "identifier" {
							varName = child.Text()
							break
						}
					}
				}
				if varName != "" {
					allocs[varName] = node.StartLine()
				}
				return
			}
		}
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		checkNode(assign)
	}

	for _, init := range root.FindAll("init_declarator") {
		if init.StartLine() < f.StartLine || init.StartLine() > f.EndLine {
			continue
		}
		checkNode(init)
	}

	return allocs
}

func (d *MemoryLeakDetector) findFrees(ctx context.Context, f *db.Function, file *db.File, root parser.Node) map[string][]int {
	frees := make(map[string][]int)
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName != "free" {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() == "argument_list" {
				for _, arg := range child.NamedChildren() {
					if arg.Kind() == "identifier" {
						frees[arg.Text()] = append(frees[arg.Text()], call.StartLine())
					}
				}
			}
		}
	}
	return frees
}

func findReturnLines(root parser.Node, f *db.Function) []int {
	var returnLines []int
	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() >= f.StartLine && ret.StartLine() <= f.EndLine {
			returnLines = append(returnLines, ret.StartLine())
		}
	}
	return returnLines
}

func filterNullGuardReturns(root parser.Node, returnLines []int, varName string) []int {
	if varName == "" {
		return returnLines
	}
	guarded := make(map[int]bool)
	for _, ifStmt := range root.FindAll("if_statement") {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		if !isNullCheckCondition(cond, varName) {
			continue
		}
		consequence := ifStmt.ChildByFieldName("consequence")
		if consequence == nil {
			continue
		}
		for _, ret := range consequence.FindAll("return_statement") {
			guarded[ret.StartLine()] = true
		}
	}
	var result []int
	for _, line := range returnLines {
		if !guarded[line] {
			result = append(result, line)
		}
	}
	return result
}

func isNullCheckCondition(cond *parser.Node, varName string) bool {
	condText := cond.Text()
	if strings.Contains(condText, "!"+varName) {
		return true
	}
	if strings.Contains(condText, varName+" == NULL") || strings.Contains(condText, varName+" == 0") {
		return true
	}
	if strings.Contains(condText, "NULL == "+varName) || strings.Contains(condText, "0 == "+varName) {
		return true
	}
	return false
}

func hasLeakingPath(cfg *graph.CFG, allocLine int, freeLines []int, returnLines []int) bool {
	if cfg == nil || cfg.Root == nil {
		return false
	}
	for _, retLine := range returnLines {
		if retLine <= allocLine {
			continue
		}
		allFreesDominate := true
		for _, freeLine := range freeLines {
			if freeLine <= allocLine || freeLine >= retLine {
				allFreesDominate = false
				break
			}
			freeScope := cfg.FindInnermostScope(freeLine)
			if freeScope.HasExit && !freeScope.Contains(retLine) {
				allFreesDominate = false
				break
			}
			if !cfg.CanReach(freeLine, retLine) {
				allFreesDominate = false
				break
			}
		}
		if !allFreesDominate {
			return true
		}
	}
	if len(returnLines) == 0 {
		for _, freeLine := range freeLines {
			freeScope := cfg.FindInnermostScope(freeLine)
			if freeScope.HasExit && freeScope.ExitLine > allocLine {
				return true
			}
		}
	}
	return false
}

func isReturnedToCaller(varName string, root parser.Node, f *db.Function) bool {
	for _, ret := range root.FindAll("return_statement") {
		if ret.StartLine() < f.StartLine || ret.StartLine() > f.EndLine {
			continue
		}
		for _, child := range ret.NamedChildren() {
			if child.Kind() == "identifier" && child.Text() == varName {
				return true
			}
			if child.Kind() == "parenthesized_expression" {
				for _, inner := range child.NamedChildren() {
					if inner.Kind() == "identifier" && inner.Text() == varName {
						return true
					}
				}
			}
		}
	}
	return false
}

func getDestroyCounterpart(funcName string) string {
	suffixes := []struct{ create, destroy string }{
		{"_create", "_destroy"},
		{"_new", "_free"},
		{"_init", "_deinit"},
		{"_acquire", "_release"},
	}
	for _, s := range suffixes {
		if strings.HasSuffix(funcName, s.create) {
			prefix := funcName[:len(funcName)-len(s.create)]
			return prefix + s.destroy
		}
	}
	return ""
}

func (d *MemoryLeakDetector) functionHasFrees(ctx context.Context, f *db.Function) bool {
	file, _ := d.store.GetFileByID(ctx, f.FileID)
	if file == nil {
		return false
	}
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return false
	}
	tree, err := d.parser.ParseCached(source, file.Path)
	if err != nil {
		return false
	}
	defer tree.Close()

	root := tree.RootNode()
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		if extractCallName(call) == "free" {
			return true
		}
	}
	return false
}
