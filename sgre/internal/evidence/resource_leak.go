package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type ResourceLeakDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewResourceLeakDetector(store db.Store, p *parser.Parser, logger *log.Logger) *ResourceLeakDetector {
	return &ResourceLeakDetector{store: store, parser: p, logger: logger}
}

func (d *ResourceLeakDetector) Name() string { return "resource_leak" }

func (d *ResourceLeakDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")
		calls := root.FindAll("call_expression")
		binaries := root.FindAll("binary_expression")
		returns := root.FindAll("return_statement")
		decls := root.FindAll("declaration")
		ifs := root.FindAll("if_statement")
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)

		for _, f := range funcs {
			acquires := d.findAcquires(ctx, f, file, assigns, inits, calls, binaries, &result)
			releases := d.findReleases(ctx, f, file, calls)

			returnLines := findReturnLinesFrom(returns, f)
			localVars := findLocalVarsFrom(decls, f)
			body := bodies[f.StartLine]
			cfg := graph.BuildStmtCFG(body, f.EndLine)
			cfgValid := body.Kind() == "compound_statement"

			for varName, acquireLine := range acquires {
				releaseLines, hasRelease := releases[varName]
				isReturned := isReturnedToCaller(varName, returns, f)
				filteredReturns := filterNullGuardReturns(ifs, returnLines, varName)
				nullGuardReturns := subtractLines(returnLines, filteredReturns)
				// A lock/resource acquire whose failure is checked with an error
				// exit (`if (pthread_mutex_lock(&m) != 0) return;`) holds no
				// resource on that path, so those returns are not leaks.
				acquireFailureReturns := findAcquireFailureReturns(ifs, returnLines, acquireLine)
				allNonHeldReturns := append(append([]int{}, nullGuardReturns...), acquireFailureReturns...)
				escapeLines := findEscapeLines(assigns, f, varName, localVars)

				// shouldReportRelease=true emits a RESOURCE_RELEASE event, which
				// the planner's ReleaseFilter uses to drop the leak candidate. A
				// leak is therefore "ACQUIRE without RELEASE".
				shouldReportRelease := false

				if isReturned {
					// Ownership transferred to the caller.
					shouldReportRelease = true
				} else if !hasRelease {
					// Escaped at the acquisition site (stored to a non-local) is
					// transferred ownership; otherwise it is a leak.
					shouldReportRelease = containsLine(escapeLines, acquireLine)
				} else if isGuardedRelease(ifs, varName, releaseLines) {
					// Released only inside a positive guard (`if (f) { fclose(f); }` or
					// `if (fd >= 0) { close(fd); }`): the acquire-failure path carries no
					// resource, so this is not a leak.
					shouldReportRelease = true
				} else if cfgValid {
					// Path-sensitive: released on all paths iff no path from the
					// acquire reaches the exit avoiding every release/escape/guard.
					shouldReportRelease = !hasLeakingPath(cfg, acquireLine, releaseLines, allNonHeldReturns, escapeLines)
				} else {
					shouldReportRelease = true
				}

				if emitEvent(ctx, d.store, d.logger, "RESOURCE_ACQUIRE", f.ID, &db.Location{FileID: file.ID, Line: acquireLine}, map[string]string{
					"variable": varName,
					"origin":   "resource_acquire",
				}) {
					result.EventsCreated++
				}

				if shouldReportRelease {
					releaseLine := acquireLine
					if len(releaseLines) > 0 {
						releaseLine = releaseLines[0]
					}
					if emitEvent(ctx, d.store, d.logger, "RESOURCE_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]string{
						"variable": varName,
						"origin":   "resource_release",
					}) {
						result.EventsCreated++
					}
				}
			}
		}
	})
	return result, err
}

func isResourceAcquirer(name string) bool {
	// Safe wrappers (LockGuard_*, ResourceHandle_*) are RAII framework entry
	// points whose lifecycle is managed by the framework, not a leak.
	if apikb.IsSafeWrapper(name) {
		return false
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "unlock") || strings.Contains(lower, "release") || strings.Contains(lower, "destroy") || strings.Contains(lower, "close") || strings.Contains(lower, "join") || strings.Contains(lower, "deinit") {
		return false
	}
	// Note: "lock" is deliberately NOT in this list. Lock acquisition is
	// handled separately by isLockAcquirer on the `&mutex` argument, and a
	// substring "lock" here would match memory-allocator names like
	// allocate_new_datablock / block_get (which contain "lock" inside
	// "block"/"datablock") and misreport every datablock field write as a
	// resource leak.
	acquirers := []string{"fopen", "open", "socket", "connect", "accept", "acquire"}
	for _, a := range acquirers {
		if strings.Contains(lower, a) {
			return true
		}
	}
	// Windows resource-creating functions are prefixed with "create"
	// (CreateFileA, CreateMutexW, ...). A custom `Xxx_create` wrapper is a
	// memory allocator handled by the memory-leak detector, not a resource
	// leak, so match the prefix only.
	return strings.HasPrefix(lower, "create")
}

// isLockAcquirer reports whether name acquires a lock via a pointer argument
// (e.g. sg_lock(&mutex), pthread_mutex_lock(&m)). This is distinct from
// isResourceAcquirer: the `&arg` scan must only flag lock/semaphore
// acquisition, otherwise out-parameters of unrelated calls (CreateProcessA's
// &si/&pi, OpenProcessToken's &hToken) are misread as acquired resources.
func isLockAcquirer(name string) bool {
	if apikb.IsSafeWrapper(name) {
		return false
	}
	lower := strings.ToLower(name)
	if strings.Contains(lower, "unlock") {
		return false
	}
	// "block"/"datablock" contain "lock" as a suffix but are memory/block
	// helpers, not lock acquirers. block_init(&zip->block) was misreported as a
	// lock acquisition for every central-directory block field.
	if strings.Contains(lower, "block") {
		return false
	}
	return strings.Contains(lower, "lock") || strings.Contains(lower, "acquire")
}

func isResourceReleaser(name string) bool {
	lower := strings.ToLower(name)
	releasers := []string{"fclose", "close", "unlock", "release", "destroy", "disconnect", "join", "deinit"}
	for _, r := range releasers {
		if strings.Contains(lower, r) {
			return true
		}
	}
	return false
}

func (d *ResourceLeakDetector) findAcquires(ctx context.Context, f *db.Function, file *db.File, assigns, inits, calls, binaries []parser.Node, result *DetectResult) map[string]int {
	acquires := make(map[string]int)

	checkNode := func(node parser.Node) {
		children := node.NamedChildren()
		if len(children) < 2 {
			return
		}
		lhs := children[0]
		rhs := children[1]
		varName := extractVarName(lhs)
		if varName == "" {
			return
		}
		callExpr := rhs
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					callExpr = child
					break
				}
			}
		}
		if callExpr.Kind() != "call_expression" {
			return
		}
		callName := extractCallName(callExpr)
		if isResourceAcquirer(callName) {
			acquires[varName] = node.StartLine()
		}
	}

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkNode(assign)
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkNode(init)
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if isLockAcquirer(callName) {
			for _, child := range call.NamedChildren() {
				if child.Kind() == "argument_list" {
					for _, arg := range child.NamedChildren() {
						argText := arg.Text()
						if strings.HasPrefix(argText, "&") {
							varName := strings.TrimPrefix(argText, "&")
							acquires[varName] = call.StartLine()
						}
					}
				}
			}
		}
	}

	// An "open"-named call that actually returns an error code (e.g.
	// err = unzOpenCurrentFilePassword(...) compared against UNZ_OK) is not a
	// resource acquisition. Drop such variables.
	for varName := range acquires {
		if isErrorCodeVar(binaries, f, varName) {
			delete(acquires, varName)
		}
	}

	return acquires
}

// isErrorCodeVar reports whether varName is used as an error code — compared
// against a named constant ending in "_OK"/"OK" (UNZ_OK, Z_OK, ZIP_OK, ...) —
// rather than as a resource handle (compared against NULL, -1, or
// INVALID_HANDLE_VALUE). A variable compared against UNZ_OK holds a status
// code, so `err = unzOpenCurrentFilePassword(...)` is not a leaked resource.
func isErrorCodeVar(binaries []parser.Node, f *db.Function, varName string) bool {
	for _, be := range binaries {
		if !funcLineRange(f, be.StartLine()) {
			continue
		}
		children := be.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]
		if lhs.Kind() == "identifier" && lhs.Text() == varName && isOKConstant(rhs) {
			return true
		}
		if rhs.Kind() == "identifier" && rhs.Text() == varName && isOKConstant(lhs) {
			return true
		}
	}
	return false
}

// isOKConstant reports whether node is a named constant that looks like an
// error-success code: "OK" or something ending in "_OK" (Z_OK, UNZ_OK, ZIP_OK).
func isOKConstant(node parser.Node) bool {
	if node.Kind() != "identifier" {
		return false
	}
	upper := strings.ToUpper(node.Text())
	return upper == "OK" || strings.HasSuffix(upper, "_OK")
}

func (d *ResourceLeakDetector) findReleases(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node) map[string][]int {
	releases := make(map[string][]int)

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !isResourceReleaser(callName) {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() == "argument_list" {
				for _, arg := range child.NamedChildren() {
					argText := arg.Text()
					if strings.HasPrefix(argText, "&") {
						releases[strings.TrimPrefix(argText, "&")] = append(releases[strings.TrimPrefix(argText, "&")], call.StartLine())
					}
					if arg.Kind() == "identifier" {
						releases[argText] = append(releases[argText], call.StartLine())
					}
				}
			}
		}
	}

	return releases
}

func extractVarName(node parser.Node) string {
	if node.Kind() == "identifier" {
		return node.Text()
	}
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" {
			return child.Text()
		}
	}
	return ""
}

// isGuardedRelease reports whether every release of varName sits inside a
// positive guard on that same variable (`if (f) { fclose(f); }` or
// `if (fd >= 0) { close(fd); }`). In that shape the acquire-failure path
// (var NULL / negative) carries no resource, so a CFG path that skips the
// release on failure is not a leak.
func isGuardedRelease(ifs []parser.Node, varName string, releaseLines []int) bool {
	if varName == "" || len(releaseLines) == 0 {
		return false
	}
	for _, ifStmt := range ifs {
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil || !positiveGuardOn(cond, varName) {
			continue
		}
		cons := ifStmt.ChildByFieldName("consequence")
		if cons == nil {
			continue
		}
		all := true
		for _, rl := range releaseLines {
			if rl < cons.StartLine() || rl > cons.EndLine() {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// positiveGuardOn reports whether cond is a positive guard on varName:
// `if (var)`, `if (var >= 0)`, `if (var > 0)`, or `if (var != NULL)`.
func positiveGuardOn(cond *parser.Node, varName string) bool {
	// `if (f)`'s condition node is a parenthesized_expression, so its text is
	// "(f)" / "(dir_fd >= 0)" — strip one level of parens before matching.
	ct := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(cond.Text()), "("), ")"))
	if ct == varName {
		return true
	}
	for _, op := range []string{" >=", " >", " !="} {
		if strings.Contains(ct, varName+op) {
			return true
		}
	}
	return false
}

// findAcquireFailureReturns returns the return statements guarded by an
// error-check on the acquire call at acquireLine — `if (pthread_mutex_lock(&m)
// != 0) return;` or `rc = lock(&m); if (rc != 0) return;`. On that branch the
// acquire FAILED, so no resource is held and the return is not a leak.
func findAcquireFailureReturns(ifs []parser.Node, returnLines []int, acquireLine int) []int {
	guarded := make(map[int]bool)
	for _, ifStmt := range ifs {
		if ifStmt.StartLine() < acquireLine || ifStmt.StartLine() > acquireLine+1 {
			continue
		}
		cond := ifStmt.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		ct := cond.Text()
		if !isErrorCheck(ct) {
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
		if guarded[line] {
			result = append(result, line)
		}
	}
	return result
}

// isErrorCheck reports whether an acquire-guard condition tests the acquire
// result for failure (`!= 0`, `== -1`, `< 0`, `== NULL`), as opposed to a
// success test (`== 0`).
func isErrorCheck(condText string) bool {
	for _, pat := range []string{"!= 0", "!=0", "== -1", "==-1", "< 0", "<0", "== NULL"} {
		if strings.Contains(condText, pat) {
			return true
		}
	}
	return false
}
