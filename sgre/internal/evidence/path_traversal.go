package evidence

import (
	"context"
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

// pathSinks are the filesystem calls where an attacker-controlled path can read,
// overwrite, or delete an arbitrary file (classic CWE-22). Query-only sinks
// (stat/lstat/access), permission changes (chmod/chown), and directory creation
// (mkdir/rmdir) are excluded — they are not content-traversal and are covered by
// other detectors (race-condition for access+fopen TOCTOU), so flagging them
// here only floods the developer with low-signal file operations.
var pathSinks = map[string]bool{
	"fopen": true, "open": true, "openat": true, "opendir": true,
	"unlink": true, "remove": true, "rename": true,
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

				if emitEvent(ctx, d.store, d.logger, "PATH_TRAVERSAL", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function": name,
					"path":     pathArg,
					"category": "path_traversal",
				}) {
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
