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
// and leaves source attribution to the AI agent. A path that is provably a
// compile-time string — a literal, a string-valued macro, a `static const char`
// object, or a buffer assembled only from those — is suppressed, because no
// caller can influence it.
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
		strConsts := buildStringConstants(root)
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
				// A compile-time string constant is not attacker-influenceable.
				// Two shapes: the argument names a constant directly
				// (`fopen(DB_PATH, ...)`), or it is a local buffer assembled
				// earlier in this function from constants only
				// (`snprintf(path, sizeof path, "%s", DB_PATH)`).
				if strConsts[stripCastsAndParens(pathArg)] {
					continue
				}
				if constantBuiltPath(calls, f, pathArg, call.StartLine(), strConsts) {
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

// pathBuildCalls are the same-function calls that write a formatted or copied
// string into their first argument. They are consulted only to decide whether a
// sink's path buffer was assembled entirely from compile-time constants.
var pathBuildCalls = map[string]bool{
	"snprintf": true, "sprintf": true, "vsnprintf": true, "vsprintf": true,
	"snprintf_s": true, "sprintf_s": true, "vsnprintf_s": true, "vsprintf_s": true,
	"strcpy": true, "strncpy": true, "strlcpy": true,
	"strcpy_s": true, "strncpy_s": true, "strcat": true, "strncat": true,
	"strcat_s": true, "strncat_s": true, "strlcat": true,
}

// buildStringConstants collects a file's compile-time string constants: an
// object-like macro that expands to string literals and/or other known string
// constants (`#define DB_PATH "/var/db"`, `#define LOG DIR "/log"`), and a
// `static const char` object initialized with a string literal that the file
// never reassigns (`static const char g_path[] = "/x"`). A filesystem sink whose
// path argument is one of these names is a constant path: no caller can
// influence it, so it is not a traversal candidate.
//
// The table is per file and conservative: a macro whose value is not fully
// composed of string literals/known constants is dropped, so `#define P DIR
// user_input` never counts as constant.
func buildStringConstants(root parser.Node) map[string]bool {
	out := make(map[string]bool)
	defs := root.FindAll("preproc_def")
	// Fixpoint over macro references (`#define A B`, `#define C A "/x"`); the
	// depth is tiny, so bound it rather than risk a self-referential loop.
	for round := 0; round < 4; round++ {
		changed := false
		for _, def := range defs {
			name := def.ChildByFieldName("name")
			value := def.ChildByFieldName("value")
			if name == nil || value == nil {
				continue
			}
			n := strings.TrimSpace(name.Text())
			if n == "" || out[n] {
				continue
			}
			if macroStringConstant(value.Text(), out) {
				out[n] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for _, decl := range root.FindAll("declaration") {
		if !isStaticConstDeclaration(decl) {
			continue
		}
		declarator := decl.ChildByFieldName("declarator")
		if declarator == nil || declarator.Kind() != "init_declarator" {
			continue
		}
		named := declarator.NamedChildren()
		if len(named) < 2 || !isStringLiteralNode(named[1]) {
			continue
		}
		name := extractVarFromDeclarator(named[0])
		if name == "" {
			continue
		}
		// `static const char *p = "..."` constrains the pointee, not the
		// pointer: the file may reassign p (and only a file-scope static is out
		// of other translation units' reach), so require no assignment to it.
		if named[0].Kind() == "pointer_declarator" && assignedInFile(root, name) {
			continue
		}
		out[name] = true
	}
	return out
}

// macroStringConstant reports whether a preprocessor definition's raw value text
// is composed only of string literals and names already known to be string
// constants — `"/a" "/b"`, `DIR "/db"`, `OTHER` — i.e. it expands to a
// compile-time string.
func macroStringConstant(value string, known map[string]bool) bool {
	tokens := splitCStringTokens(value)
	if len(tokens) == 0 {
		return false
	}
	for _, tk := range tokens {
		if strings.HasPrefix(tk, "\"") || known[tk] {
			continue
		}
		return false
	}
	return true
}

// splitCStringTokens splits C source text on whitespace, keeping a quoted string
// (with escapes, and therefore embedded spaces) as a single token.
func splitCStringTokens(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		if s[i] == '"' {
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
				i++
			}
		}
		out = append(out, s[start:i])
	}
	return out
}

// isStaticConstDeclaration reports whether a declaration carries both the
// `static` storage class and the `const` qualifier, so its object cannot be
// replaced from another translation unit and its (array) contents cannot be
// written.
func isStaticConstDeclaration(decl parser.Node) bool {
	var static, const_ bool
	for _, child := range decl.Children() {
		switch child.Kind() {
		case "storage_class_specifier":
			if child.Text() == "static" {
				static = true
			}
		case "type_qualifier":
			if child.Text() == "const" {
				const_ = true
			}
		}
	}
	return static && const_
}

// isStringLiteralNode reports whether an expression node is a string literal
// (a single literal, or adjacent literals that C concatenates).
func isStringLiteralNode(node parser.Node) bool {
	switch node.Kind() {
	case "string_literal", "concatenated_string":
		return true
	}
	return false
}

// assignedInFile reports whether the file assigns to the named variable anywhere
// outside its declaration, i.e. whether a `static const char *` global can stop
// pointing at its literal.
func assignedInFile(root parser.Node, name string) bool {
	for _, assign := range root.FindAll("assignment_expression") {
		named := assign.NamedChildren()
		if len(named) == 0 {
			continue
		}
		if assignedVariable(named[0]) == name {
			return true
		}
	}
	return false
}

// constantBuiltPath reports whether the sink's path argument is a local buffer
// assembled earlier in the same function entirely from compile-time constants —
// `snprintf(path, sizeof path, "%s", DB_PATH)` or `strcpy(path, DB_PATH)`.
//
// The whole argument list must be constant, so a construction that consumes a
// run-time value is NOT suppressed:
// `snprintf(path, sizeof path, "%s/%s", BASE, filename)` stays a candidate.
// A constant BASE does not by itself prove safety — `filename` containing
// `../` still escapes it — so whether that construction is safe is left to the
// AI, which can see the validation the pipeline cannot.
func constantBuiltPath(calls []parser.Node, f *db.Function, pathArg string, sinkLine int, strConsts map[string]bool) bool {
	target := stripCastsAndParens(pathArg)
	if bareIdentString(target) == "" {
		return false
	}
	for _, call := range calls {
		line := call.StartLine()
		if line >= sinkLine || !funcLineRange(f, line) {
			continue
		}
		if !pathBuildCalls[extractCallName(call)] {
			continue
		}
		// The builder writes into its destination argument (`snprintf(path, ...)`,
		// `strcpy(path, ...)`), so link on arg 0 rather than on an assignment.
		args := getCallArgs(call)
		if len(args) == 0 || bareIdentString(stripCastsAndParens(args[0].Text())) != target {
			continue
		}
		if callArgsAllConstant(call, strConsts) {
			return true
		}
	}
	return false
}

// callArgsAllConstant reports whether every argument of a path-building call
// except the destination buffer (arg 0) is a compile-time constant: a string
// literal, a known string-constant name, a number, or a sizeof expression (the
// destination-size argument). An unknown identifier — a parameter, a getenv
// result, an unmodelled expression — makes the built value non-constant.
func callArgsAllConstant(call parser.Node, strConsts map[string]bool) bool {
	args := getCallArgs(call)
	if len(args) < 2 {
		return false
	}
	for _, arg := range args[1:] {
		switch arg.Kind() {
		case "string_literal", "concatenated_string", "number_literal", "sizeof_expression":
			continue
		case "identifier":
			if strConsts[arg.Text()] {
				continue
			}
		}
		return false
	}
	return true
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
// flagged. It strips the leading balanced `(...)` groups (cast or plain parens)
// and then checks the C string-literal prefixes.
func isStringLiteralText(text string) bool {
	t := stripCastsAndParens(text)
	return strings.HasPrefix(t, "\"") || strings.HasPrefix(t, "L\"") || strings.HasPrefix(t, "u\"")
}
