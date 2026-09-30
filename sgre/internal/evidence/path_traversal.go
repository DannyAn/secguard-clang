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
	globalConsts := buildGlobalConstants(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		// Build a set of function start lines that are pure passthrough
		// wrappers — their body is just `return sink(param);` or
		// `sink(param);` with the path argument forwarded from a function
		// parameter. The traversal risk is at the caller, not the wrapper.
		wrapperLines := make(map[int]bool)
		for _, fnNode := range root.FindAll("function_definition") {
			params := make(map[string]bool)
			for _, p := range findParamsInDefinition(fnNode) {
				params[p] = true
			}
			if body := fnNode.FindFirst("compound_statement"); body != nil && isPassthroughPathWrapper(*body, params) {
				wrapperLines[fnNode.StartLine()] = true
			}
		}
		for _, f := range funcs {
			if wrapperLines[f.StartLine] {
				continue
			}
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
				if globalConsts.NonZero(pathArg) || globalConsts.IsZero(pathArg) {
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

// isPassthroughPathWrapper reports whether a function body is a pure
// passthrough wrapper for a path sink: the body contains only return/expression
// statements (no declarations, no if/for/while), at least one of which calls a
// path sink with a function-parameter argument. Such a wrapper
// (`bool is_file_exist(const char *p) { return fopen(p, F_OK) == 0; }`)
// forwards the path without constructing it — the traversal risk is at the
// caller, not at the wrapper definition.
func isPassthroughPathWrapper(body parser.Node, params map[string]bool) bool {
	if body.Kind() != "compound_statement" {
		return false
	}
	stmts := body.NamedChildren()
	if len(stmts) == 0 || len(stmts) > 2 {
		return false
	}
	for _, stmt := range stmts {
		switch stmt.Kind() {
		case "return_statement", "expression_statement":
		default:
			return false
		}
	}
	for _, call := range body.FindAll("call_expression") {
		name := extractCallName(call)
		if !pathSinks[name] {
			continue
		}
		if params[pathArgument(call, name)] {
			return true
		}
	}
	return false
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

// isStringLiteralText reports whether the sink argument text is a string literal,
// possibly wrapped in casts/parentheses: `(const char *)"/etc/x"` and
// `("/etc/x")` are constants, never attacker-controlled, so they must not be
// flagged. It strips leading balanced `(...)` groups (cast or plain parens) and
// then checks the C string-literal prefixes.
func isStringLiteralText(text string) bool {
	t := strings.TrimSpace(text)
	for {
		if t == "" {
			return false
		}
		if t[0] != '(' {
			break
		}
		depth := 0
		end := -1
		for i := 0; i < len(t); i++ {
			switch t[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = i
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return false // unbalanced
		}
		t = strings.TrimSpace(t[end+1:])
	}
	return strings.HasPrefix(t, "\"") || strings.HasPrefix(t, "L\"") || strings.HasPrefix(t, "u\"")
}
