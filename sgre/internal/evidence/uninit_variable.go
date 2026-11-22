package evidence

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type UninitVariableDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	// iterMacros is the merged iterator-macro table (built-in apikb set +
	// secguard.toml [iterator_macros]). A call to one of these writes its
	// iterator parameter(s) in the for-init clause, so those arguments are
	// WRITE targets, not reads — skipping them prevents a just-declared
	// iterator (`SLL_SCAN(list, iter, type)` writing `iter`) from being
	// misreported as use-before-init at the call site.
	iterMacros map[string][]int
}

// uninitScanInputs bundles the per-file facts and per-function context shared
// by the three uninit sub-detectors. Named fields replace the former 20/14/13
// positional parameters, where two same-typed AST slices could be swapped
// without a compile error.
type uninitScanInputs struct {
	f                 *db.Function
	file              *db.File
	bound             map[string]bool
	decls             []parser.Node
	assigns           []parser.Node
	calls             []parser.Node
	exprStmts         []parser.Node
	returns           []parser.Node
	inits             []parser.Node
	ifs               []parser.Node
	whiles            []parser.Node
	fors              []parser.Node
	asms              []parser.Node
	unarys            []parser.Node
	ptrs              []parser.Node
	fields            []parser.Node
	subscripts        []parser.Node
	bodies            map[int]parser.Node
	summaries         summaryMap
	macroWrites       map[string]macros.WriteSummary
	objectMacroWrites map[string]map[string]bool
	unionTypedefs     map[string]bool
	result            *DetectResult
	tree              *parser.Tree
}

func NewUninitVariableDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UninitVariableDetector {
	return &UninitVariableDetector{
		store:      store,
		parser:     p,
		logger:     logger,
		iterMacros: config.Load().MergedIteratorMacros(),
	}
}

func (d *UninitVariableDetector) Name() string { return "uninit_variable" }

func (d *UninitVariableDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	summaries, err := buildFuncSummaries(ctx, d.store, d.parser, d.logger)
	if err != nil {
		return result, err
	}
	// Macro write-summaries are collected across the whole scan tree: a macro
	// defined in a .h header (POOL_FOR, LIST_FOR_EACH, ...) and called in a .c
	// source is invisible to the per-file WriteSummaries of the source file, so
	// a macro-initialized iterator would be misreported as uninitialized. The
	// parser cache makes the second pass cheap.
	macroWrites := d.collectMacroWrites(ctx)
	// Object-like macro write-summaries (MSG_INIT do { a = 0; b = 0; } while
	// (0)) are the command-initialization idiom: the macro takes no parameters
	// and assigns local variables, so WrittenArgs never sees it. Collecting the
	// assigned-variable sets across the tree makes the `MSG_INIT;` call a write
	// to those locals instead of a certain-uninit false positive.
	objectMacroWrites, unionTypedefs := d.collectObjectMacroWrites(ctx)

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		// The three sub-detectors plus BuildCFG used to issue ~21 whole-tree
		// FindAll walks per function when handed the file root (and one
		// full-file walk per function just to locate the function subtree);
		// hoisting every scan here collapses that to a single walk per kind
		// per file. The per-function loops below filter by line range.
		decls := root.FindAll("declaration")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")
		exprStmts := root.FindAll("expression_statement")
		inits := root.FindAll("init_declarator")
		returns := root.FindAll("return_statement")
		unarys := root.FindAll("unary_expression")
		ptrs := root.FindAll("pointer_expression")
		fields := root.FindAll("field_expression")
		subscripts := root.FindAll("subscript_expression")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		asms := root.FindAll("gnu_asm_expression")
		funcDefs := root.FindAll("function_definition")
		bodies := functionBodyMap(funcDefs)
		funcDefsByLine := functionDefinitionMap(funcDefs)

		in := uninitScanInputs{
			file: file, tree: tree,
			decls: decls, assigns: assigns, calls: calls, exprStmts: exprStmts,
			returns: returns, inits: inits, ifs: ifs, whiles: whiles, fors: fors, asms: asms,
			unarys: unarys, ptrs: ptrs, fields: fields, subscripts: subscripts,
			bodies: bodies, summaries: summaries,
			macroWrites: macroWrites, objectMacroWrites: objectMacroWrites,
			unionTypedefs: unionTypedefs, result: &result,
		}
		for _, f := range funcs {
			in.f = f
			// The scope oracle for the `(A) & x` disambiguation: the function's
			// parameter names plus its local declarator names. A type name must
			// never be in this set (see parser.FunctionBoundNames).
			in.bound = parser.FunctionBoundNames(funcDefsByLine[f.StartLine])
			d.detectStackUninit(ctx, &in)
			d.detectHeapUninit(ctx, &in)
			d.detectStructPartialUninit(ctx, &in)
		}
	})
	return result, err
}

// collectMacroWrites merges the per-file macro write-summaries across the whole
// scan tree so a macro defined in one file (a .h header) is visible at call
// sites in every other file.
func (d *UninitVariableDetector) collectMacroWrites(ctx context.Context) map[string]macros.WriteSummary {
	var perFile []map[string]macros.WriteSummary
	if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, tree *parser.Tree) {
		perFile = append(perFile, macros.WriteSummaries(root))
	}); err != nil {
		// A top-level traversal failure leaves the whole whitelist empty, which
		// would misreport every macro-initialized iterator as uninitialized.
		// Degrade (empty whitelist) but record it so the false-positive flood is
		// attributable in the scan log.
		if d.logger != nil {
			d.logger.Warn("collect_macro_writes: top-level traversal failed; macro-based initialization whitelist is incomplete", "error", err)
		}
	}
	return macros.MergeWriteSummaries(perFile...)
}

// collectObjectMacroWrites merges the per-file object-like macro write-sets
// across the whole scan tree, mirroring collectMacroWrites so a
// command-initialization macro defined in a .h header is visible at every
// `MSG_INIT;` call site in every .c source.
//
// It also collects the TREE-WIDE set of typedef-aliased unions (issue #253
// P2-1a). A union is normally declared in a header (`int.h`:
// `typedef union { int vlan; int id; } vlan_u;`) and used in the matching .c;
// tree-sitter parses the .c WITHOUT expanding the include, so a per-file
// typedef map never sees the union and the shared-storage rule silently stops
// firing. The pass is shared with the object-macro collection so this does not
// add another full-tree traversal.
func (d *UninitVariableDetector) collectObjectMacroWrites(ctx context.Context) (map[string]map[string]bool, map[string]bool) {
	merged := make(map[string]map[string]bool)
	unionTypedefs := make(map[string]bool)
	if err := forEachIndexedFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, tree *parser.Tree) {
		for name, writes := range macros.ObjectLikeWrites(root) {
			if merged[name] == nil {
				merged[name] = make(map[string]bool)
			}
			for v := range writes {
				merged[name][v] = true
			}
		}
		for name := range unionTypedefNames(root) {
			unionTypedefs[name] = true
		}
	}); err != nil {
		if d.logger != nil {
			d.logger.Warn("collect_object_macro_writes: top-level traversal failed; object-like macro initialization whitelist and union typedefs are incomplete", "error", err)
		}
	}
	return merged, unionTypedefs
}

// varDecl describes one declaration of a local variable for scope-aware uninit
// tracking. C allows the same name in two nested blocks (`int v;` in two
// different `if` bodies); tracking every fact by bare name would let one
// occurrence's output-parameter init line suppress (or, worse, hide) the other's
// genuinely-uninitialized use. varKey scopes each fact to its declaration line.
type varDecl struct {
	name     string
	declLine int
	scopeEnd int
}

// varKey returns a scope-aware key for a variable occurrence: name plus the line
// of the declaration that introduced it. Two `int v` in different blocks get
// different keys, so their init/assign facts no longer collide.
func varKey(name string, declLine int) string {
	return fmt.Sprintf("%s@%d", name, declLine)
}

// enclosingScopeEnd returns the end line of the innermost scope that contains
// node: the enclosing compound_statement, or — for a single-statement
// if/loop/switch body without braces — the enclosing control-flow statement.
// It bounds a declaration's shadowing range for varKey resolution.
func enclosingScopeEnd(node parser.Node) int {
	for n := node.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "compound_statement":
			return n.EndLine()
		case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
			return n.EndLine()
		}
	}
	return node.EndLine()
}

// resolveVarKey maps a bare identifier use at useLine to the varKey of the
// declaration that is in scope there: the latest declaration (innermost shadow)
// whose declLine is before the use and whose scopeEnd covers it. It returns ""
// when no such declaration exists (e.g. a global or a macro-typed identifier).
func resolveVarKey(declsByName map[string][]varDecl, name string, useLine int) string {
	var best int = -1
	for _, d := range declsByName[name] {
		if d.declLine < useLine && d.scopeEnd >= useLine && d.declLine > best {
			best = d.declLine
		}
	}
	if best < 0 {
		return ""
	}
	return varKey(name, best)
}

// resolveVarDecl returns the innermost declaration of name in scope at line. It
// is resolveVarKey but yields the full varDecl (declLine AND scopeEnd) so a
// malloc assignment can adopt the DECLARATION's scope, not the assignment's own
// (a `p = malloc()` inside an `if` writes a variable declared at function scope,
// whose scope is the function, not the if body).
func resolveVarDecl(declsByName map[string][]varDecl, name string, useLine int) (varDecl, bool) {
	best := -1
	var d varDecl
	for _, cand := range declsByName[name] {
		if cand.declLine < useLine && cand.scopeEnd >= useLine && cand.declLine > best {
			best = cand.declLine
			d = cand
		}
	}
	return d, best >= 0
}

// localVarDecls collects every local variable a declarations list introduces,
// including init_declarator names (`S *p = malloc(...)` declares p), keyed by
// name with each declaration's scopeEnd for scope-aware resolution.
func localVarDecls(decls []parser.Node) map[string][]varDecl {
	m := make(map[string][]varDecl)
	for _, decl := range decls {
		scopeEnd := enclosingScopeEnd(decl)
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" && !parser.IsCTypeKeyword(child.Text()) {
				m[child.Text()] = append(m[child.Text()], varDecl{name: child.Text(), declLine: decl.StartLine(), scopeEnd: scopeEnd})
			}
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			dc := child.NamedChildren()
			if len(dc) >= 1 {
				if name := extractVarName(dc[0]); name != "" {
					m[name] = append(m[name], varDecl{name: name, declLine: decl.StartLine(), scopeEnd: scopeEnd})
				}
			}
		}
	}
	return m
}
