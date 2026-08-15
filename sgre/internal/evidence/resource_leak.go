package evidence

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
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

		for _, f := range funcs {
			acquires := d.findAcquires(ctx, f, file, assigns, inits, calls, binaries, &result)
			releases := d.findReleases(ctx, f, file, calls)

			for varName, acquireLine := range acquires {
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: acquireLine})
				props, _ := json.Marshal(map[string]string{
					"variable": varName,
					"origin":   "resource_acquire",
				})
				d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "RESOURCE_ACQUIRE",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				result.EventsCreated++

				if releaseLine, released := releases[varName]; released {
					releaseLocID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: releaseLine})
					releaseProps, _ := json.Marshal(map[string]string{
						"variable": varName,
						"origin":   "resource_release",
					})
					d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "RESOURCE_RELEASE",
						EntityID:   f.ID,
						LocationID: releaseLocID,
						Properties: string(releaseProps),
					})
					result.EventsCreated++
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

func (d *ResourceLeakDetector) findReleases(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node) map[string]int {
	releases := make(map[string]int)

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
						releases[strings.TrimPrefix(argText, "&")] = call.StartLine()
					}
					if arg.Kind() == "identifier" {
						releases[argText] = call.StartLine()
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
