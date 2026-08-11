package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("resource_leak: list functions: %w", err)
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
		tree, err := d.parser.Parse(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		acquires := d.findAcquires(ctx, f, file, root, &result)
		releases := d.findReleases(ctx, f, file, root)

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

		tree.Close()
	}

	return result, nil
}

func isResourceAcquirer(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "unlock") || strings.Contains(lower, "release") || strings.Contains(lower, "destroy") || strings.Contains(lower, "close") || strings.Contains(lower, "join") || strings.Contains(lower, "deinit") {
		return false
	}
	acquirers := []string{"fopen", "open", "socket", "connect", "accept", "lock", "acquire", "create"}
	for _, a := range acquirers {
		if strings.Contains(lower, a) {
			return true
		}
	}
	return false
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

func (d *ResourceLeakDetector) findAcquires(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) map[string]int {
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

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if isResourceAcquirer(callName) && !isAllocator(callName) {
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

	return acquires
}

func (d *ResourceLeakDetector) findReleases(ctx context.Context, f *db.Function, file *db.File, root parser.Node) map[string]int {
	releases := make(map[string]int)

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
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
