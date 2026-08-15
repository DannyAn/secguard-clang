package evidence

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// PathTraversalDetector flags filesystem sinks whose path argument is not a
// string literal (CWE-22). A variable/computed path that can be influenced by
// input is a path-traversal risk. This is a source-agnostic heuristic: it does
// not track taint back to a source, so it tiers the candidate as "suspected"
// and leaves source attribution to the AI agent.
type PathTraversalDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewPathTraversalDetector(store db.Store, p *parser.Parser, logger *log.Logger) *PathTraversalDetector {
	return &PathTraversalDetector{store: store, parser: p, logger: logger}
}

func (d *PathTraversalDetector) Name() string { return "path_traversal" }

func (d *PathTraversalDetector) Domain() string { return "input" }

func (d *PathTraversalDetector) Capabilities() []string {
	return []string{"file-path", "directory-path"}
}

var pathSinks = map[string]bool{
	"fopen": true, "open": true, "openat": true, "unlink": true, "remove": true,
	"rename": true, "access": true, "stat": true, "lstat": true, "opendir": true,
	"chmod": true, "chown": true, "mkdir": true, "rmdir": true,
}

func (d *PathTraversalDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				name := extractCallName(call)
				if !pathSinks[name] {
					continue
				}
				pathArg := pathArgument(call, name)
				if pathArg == "" || isStringLiteralText(pathArg) {
					continue
				}

				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
				props, _ := json.Marshal(map[string]string{
					"function": name,
					"path":     pathArg,
					"category": "path_traversal",
				})
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "PATH_TRAVERSAL",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(props),
				})
				if err == nil {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// pathArgument returns the path argument of a filesystem call. openat takes
// the path as its second argument (dirfd is first); every other sink takes it
// as the first argument.
func pathArgument(call parser.Node, name string) string {
	argIdx := 0
	if name == "openat" {
		argIdx = 1
	}
	for _, child := range call.NamedChildren() {
		if child.Kind() != "argument_list" {
			continue
		}
		args := child.NamedChildren()
		if len(args) <= argIdx {
			return ""
		}
		return args[argIdx].Text()
	}
	return ""
}

func isStringLiteralText(text string) bool {
	t := strings.TrimSpace(text)
	return strings.HasPrefix(t, "\"") || strings.HasPrefix(t, "L\"") || strings.HasPrefix(t, "u\"")
}
