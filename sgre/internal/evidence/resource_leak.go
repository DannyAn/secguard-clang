package evidence

import (
	"context"
	"fmt"
	"sort"
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

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
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
			releases := d.findReleases(ctx, f, file, calls, inits, assigns)

			returnLines := findReturnLinesFrom(returns, f)
			localVars := findLocalVarsFrom(decls, f)
			body := bodies[f.StartLine]
			cfg := graph.BuildStmtCFG(body, f.EndLine)
			cfgValid := body.Kind() == "compound_statement"

			for varName, acquireLines := range acquires {
				releaseLines, hasRelease := releases[varName]
				filteredReturns := filterNullGuardReturns(ifs, returnLines, varName)
				nullGuardReturns := subtractLines(returnLines, filteredReturns)
				escapeLines := findEscapeLines(assigns, f, varName, localVars)
				overwriteLines := writeLinesFor(assigns, inits, f, varName)

				for _, acquireLine := range acquireLines {
					// A lock/resource acquire whose failure is checked with an error
					// exit (`if (pthread_mutex_lock(&m) != 0) return;`) holds no
					// resource on that path, so those returns are not leaks.
					acquireFailureReturns := findAcquireFailureReturns(ifs, returnLines, acquireLine)
					allNonHeldReturns := append(append([]int{}, nullGuardReturns...), acquireFailureReturns...)
					// A `return fd` inside `if (fd < 0) return fd;` is an error exit, not
					// an ownership transfer: fd holds no resource on that path. Only a
					// return OUTSIDE every acquire-failure branch transfers the resource,
					// and that transfer holds only on the paths that reach it — a
					// function-level "is returned" flag would suppress a leak on a
					// sibling non-returning path.
					transferLines := nonFailureReturnLines(varName, returns, f, acquireFailureReturns)

					// shouldReportRelease=true emits a RESOURCE_RELEASE event, which
					// the planner's ReleaseFilter uses to drop the leak candidate. A
					// leak is therefore "ACQUIRE without RELEASE".
					shouldReportRelease := false

					if isGuardedRelease(ifs, varName, releaseLines) {
						// Released only inside a positive guard (`if (f) { fclose(f); }` or
						// `if (fd >= 0) { close(fd); }`): the acquire-failure path carries no
						// resource, so this is not a leak.
						shouldReportRelease = true
					} else if cfgValid {
						// Path-sensitive: released on all paths iff no path from the
						// acquire reaches the exit (or a later overwrite that drops the
						// handle) avoiding every release/escape/guard/transfer.
						shouldReportRelease = !hasLostResource(cfg, acquireLine, releaseLines, allNonHeldReturns, escapeLines, transferLines, overwriteLines)
					} else if !hasRelease {
						// Escaped at the acquisition site (stored to a non-local) or
						// returned anywhere is transferred ownership; otherwise a leak.
						shouldReportRelease = containsLine(escapeLines, acquireLine) || len(transferLines) > 0
					} else {
						shouldReportRelease = true
					}

					// RL-03: a handle with NO release/escape/transfer anywhere is
					// DEFINITELY lost (hasLostResource proved a leak path AND no node
					// releases/hands it off), so mark it for the planner's confirmed tier.
					definiteLeak := !shouldReportRelease && len(releaseLines) == 0 && len(escapeLines) == 0 && len(transferLines) == 0
					acquireProps := map[string]string{
						"variable": varName,
						"origin":   "resource_acquire",
					}
					if definiteLeak {
						acquireProps["definite"] = "true"
					}
					if emitEvent(ctx, d.store, d.logger, "RESOURCE_ACQUIRE", f.ID, &db.Location{FileID: file.ID, Line: acquireLine}, acquireProps) {
						result.EventsCreated++
					}

					if shouldReportRelease {
						releaseLine := acquireLine
						if len(releaseLines) > 0 {
							releaseLine = releaseLines[0]
						}
						// alloc_line ties this release to its specific acquisition
						// site, so ReleaseFilter drops only the released site and not
						// a sibling acquire site that leaks.
						if emitEvent(ctx, d.store, d.logger, "RESOURCE_RELEASE", f.ID, &db.Location{FileID: file.ID, Line: releaseLine}, map[string]any{
							"variable":   varName,
							"origin":     "resource_release",
							"alloc_line": acquireLine,
						}) {
							result.EventsCreated++
						}
					}
				}
			}
		}
	})
	return result, err
}

// outParamAcquirers are resource factories that return their handle through an
// OUT-PARAMETER (`sqlite3_open(path, &db)`, `fopen_s(&f, ...)`), not the return
// value. findAcquires scans their address-of arguments for the acquired variable.
// Deliberately an exact-name whitelist: the generic `&arg` scan must not treat
// every out-param (CreateProcessA's &pi, OpenProcessToken's &hToken) as a
// resource acquisition.
var outParamAcquirers = map[string]bool{
	"sqlite3_open":    true,
	"sqlite3_open_v2": true,
	"fopen_s":         true,
	"RegCreateKeyExA": true,
	"RegCreateKeyExW": true,
	"RegOpenKeyExA":   true,
	"RegOpenKeyExW":   true,
}

// pipeFactories are fd factories that write TWO fds into an out-param ARRAY
// (`pipe(fds)` → fds[0], fds[1]). The return value is an error code, not a
// handle, so findAcquires records each array element as a separate resource.
var pipeFactories = map[string]bool{
	"pipe":       true,
	"pipe2":      true,
	"socketpair": true,
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
	//
	// "connect" is also deliberately NOT in this list: connect(fd, ...) returns
	// an error code, not a resource handle, and a `db_create_sub_connect(...)`
	// wrapper compared against != 0 is a connection ESTABLISHER, not a resource
	// factory — treating it as an acquirer produced a phantom `ret` resource.
	// "epoll"/"eventfd"/"signalfd"/"timerfd"/"inotify"/"mkstemp" cover the
	// fd-factory syscall wrappers (epoll_create, MESH_EpollCreate, eventfd,
	// mkstemp, ...).
	// mmap covers the memory-mapped-region factory (mmap/mmap64) whose mapping
	// must be released with munmap; the "open"/"create" substrings do not match
	// it, so a `p = mmap(...)` with no munmap was previously missed.
	acquirers := []string{"fopen", "open", "socket", "accept", "acquire", "epoll", "eventfd", "signalfd", "timerfd", "inotify", "mkstemp", "mkostemp", "mkstemps", "mkostemps", "mmap"}
	for _, a := range acquirers {
		if strings.Contains(lower, a) {
			return true
		}
	}
	// dup/dup2/dup3 are short fd-factory names a bare substring would over-match
	// (duplicate); match exactly or as a `_dup` suffix (a wrapper like os_dup).
	// (pipe/pipe2/socketpair are OUT-PARAM array factories — `pipe(fds[2])` — and
	// deliberately NOT here: the return-value path would misread their int error
	// code as a resource handle.)
	for _, w := range []string{"dup", "dup2", "dup3"} {
		if lower == w || strings.HasSuffix(lower, "_"+w) {
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
	if apikb.IsSafeWrapper(name) {
		return false
	}
	lower := strings.ToLower(name)
	exact := map[string]bool{
		"close": true, "fclose": true, "pclose": true, "closedir": true,
		"closesocket": true, "close_range": true, "munmap": true,
		"pthread_join": true, "thrd_join": true,
		"pthread_mutex_unlock": true, "pthread_mutex_destroy": true,
		"pthread_cond_destroy": true, "pthread_rwlock_destroy": true,
		"sem_destroy": true, "sem_close": true, "sem_unlink": true,
		"shutdown": true, "FreeLibrary": true, "RegCloseKey": true, "CloseHandle": true,
	}
	if exact[lower] {
		return true
	}
	// Wrapper suffix (os_close, db_disconnect, ...). A `_` boundary only, so
	// close_log / enclose / string_join / path_join / destroy_temp_string — which
	// are NOT resource releases — no longer match (RL-01, the FN direction).
	for _, suffix := range []string{"_close", "_fclose", "_munmap", "_unlock", "_release", "_disconnect", "_deinit"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	// Thread join wrappers must be thread-typed; a bare "_join" would match
	// string_join / path_join (string concatenation).
	if strings.Contains(lower, "thread_join") {
		return true
	}
	// Mutex/sem/cond/rwlock destroy wrappers; a bare "_destroy" would match
	// destroy_temp_string (a memory reclaimer handled by memory-leak).
	for _, pat := range []string{"mutex_destroy", "sem_destroy", "cond_destroy", "rwlock_destroy"} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func (d *ResourceLeakDetector) findAcquires(ctx context.Context, f *db.Function, file *db.File, assigns, inits, calls, binaries []parser.Node, result *DetectResult) map[string][]int {
	acquires := make(map[string][]int)

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
			acquires[varName] = append(acquires[varName], node.StartLine())
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
						if target, ok := addressOfTarget(arg); ok && target.Kind() == "identifier" {
							acquires[target.Text()] = append(acquires[target.Text()], call.StartLine())
						}
					}
				}
			}
		}
		// Out-param acquirers write the acquired handle through an address-of
		// argument (`sqlite3_open(path, &db)`, `fopen_s(&f, ...)`), not the return
		// value. Scan their `&arg` for the acquired variable.
		if outParamAcquirers[callName] {
			for _, child := range call.NamedChildren() {
				if child.Kind() != "argument_list" {
					continue
				}
				for _, arg := range child.NamedChildren() {
					target, ok := addressOfTarget(arg)
					if !ok || target.Kind() != "identifier" {
						continue
					}
					acquires[target.Text()] = append(acquires[target.Text()], call.StartLine())
				}
			}
		}
		// pipe/pipe2/socketpair write TWO fds into an out-param ARRAY
		// (`pipe(fds)` → fds[0], fds[1]); the return value is an error code, not a
		// handle. Record each array element as its own acquired resource so a
		// `close(fds[0])`/`close(fds[1])` release matches one element, not the
		// whole array.
		if pipeFactories[callName] {
			for _, child := range call.NamedChildren() {
				if child.Kind() != "argument_list" {
					continue
				}
				args := child.NamedChildren()
				if len(args) == 0 || args[0].Kind() != "identifier" {
					continue
				}
				base := args[0].Text()
				for idx := 0; idx < 2; idx++ {
					key := fmt.Sprintf("%s[%d]", base, idx)
					acquires[key] = append(acquires[key], call.StartLine())
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

	for name := range acquires {
		sort.Ints(acquires[name])
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

func (d *ResourceLeakDetector) findReleases(ctx context.Context, f *db.Function, file *db.File, calls, inits, assigns []parser.Node) map[string][]int {
	releases := make(map[string][]int)
	aliases := findAliases(f, inits, assigns)

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
					arg = unwrapCastParen(arg)
					// `close(&fd)` / `fclose(&fp)` — an address-of handle.
					if target, ok := arg.AddressTakenTarget(); ok && target.Kind() == "identifier" {
						releases[target.Text()] = append(releases[target.Text()], call.StartLine())
					}
					// `close(fd)` / `fclose(fp)` and `close(fds[0])`.
					if arg.Kind() == "identifier" || arg.Kind() == "subscript_expression" {
						name := arg.Text()
						releases[name] = append(releases[name], call.StartLine())
						// Alias release: fd2 = fd; close(fd2) also releases fd (RL-02).
						if arg.Kind() == "identifier" {
							if base := terminalBaseVar(aliases, name); base != name {
								releases[base] = append(releases[base], call.StartLine())
							}
						}
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
// `if (var)`, `if (var >= 0)`, `if (var > 0)`, or `if (var != NULL)`. The
// operand is compared exactly, so `if (nfd >= 0)` does NOT guard `fd` (the
// previous strings.Contains matched the "fd >=" substring in "nfd >=").
func positiveGuardOn(cond *parser.Node, varName string) bool {
	inner := *cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		inner = kids[0]
	}
	if inner.Kind() == "identifier" {
		return inner.Text() == varName
	}
	if inner.Kind() != "binary_expression" {
		return false
	}
	switch parser.BinaryOperator(inner) {
	case ">=", ">", "!=":
	default:
		return false
	}
	for _, k := range inner.NamedChildren() {
		if k.Kind() == "identifier" && k.Text() == varName {
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

// returnReturnsVar reports whether a return statement returns varName (bare or
// parenthesized).
func returnReturnsVar(ret parser.Node, varName string) bool {
	for _, child := range ret.NamedChildren() {
		if returnOperandIs(child, varName) {
			return true
		}
	}
	return false
}

// returnOperandIs reports whether a return operand is varName, unwrapping cast and
// parenthesized expressions (`return (T *)p`, `return ((p))` both return p —
// ML-15). The previous version only matched a bare identifier or one level of
// parentheses, so `return (T *)p` was misread as a leak instead of a transfer.
func returnOperandIs(node parser.Node, varName string) bool {
	switch node.Kind() {
	case "identifier":
		return node.Text() == varName
	case "parenthesized_expression", "cast_expression":
		for _, c := range node.NamedChildren() {
			if returnOperandIs(c, varName) {
				return true
			}
		}
	}
	return false
}

// nonFailureReturnLines returns the lines of return statements that hand varName
// to the caller on a path that is NOT an acquire-failure exit. A `return fd`
// inside `if (fd < 0) return fd;` is an error exit — fd holds no resource there
// — so it is excluded; only a return outside every failure branch transfers the
// resource. These lines are transfer points fed to hasLostResource's avoid set,
// so a transfer on one path does not suppress a leak on a sibling path.
func nonFailureReturnLines(varName string, returns []parser.Node, f *db.Function, failureReturns []int) []int {
	fail := make(map[int]bool, len(failureReturns))
	for _, l := range failureReturns {
		fail[l] = true
	}
	var lines []int
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) || fail[ret.StartLine()] {
			continue
		}
		if returnReturnsVar(ret, varName) {
			lines = append(lines, ret.StartLine())
		}
	}
	return lines
}
