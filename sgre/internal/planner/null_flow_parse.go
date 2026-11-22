package planner

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// fileParseCache lazily parses each file once and caches its root plus a map
// from function-definition start line to the function's compound_statement
// body. It replaces the per-function readFunctionBody, which re-walked the
// whole tree looking for function_definition once per function — a dominant
// remaining cost of the flow filters over a large codebase.
type fileParseCache struct {
	parser *parser.Parser
	roots  map[int64]parser.Node
	bodies map[int64]map[int]parser.Node
	defs   map[int64]map[int]parser.Node
	trees  map[int64]*parser.Tree
	// order is the LRU list of cached file IDs (oldest first); maxEntries
	// bounds how many files' ASTs this cache may pin at once. Without it,
	// ParseCached's own max_cached_trees was decorative: every borrowed tree
	// here was unevictable there, so a whole-repo filter could pin GBs.
	//
	// maxEntries follows the parser's configured max_cached_trees (0 =
	// unbounded) rather than a fixed constant. A smaller, hardcoded value
	// evicted files whose trees were still resident in the parser cache, so the
	// flow filters re-read and re-walked the same files over and over on any
	// codebase larger than the magic number — pure thrash with no memory win,
	// since the parser cache already bounds tree memory at max_cached_trees.
	order      []int64
	maxEntries int
}

var liveFileParseCaches sync.Map // *fileParseCache -> creator file:line

func newFileParseCache(p *parser.Parser) *fileParseCache {
	fc := &fileParseCache{
		parser:     p,
		roots:      make(map[int64]parser.Node),
		bodies:     make(map[int64]map[int]parser.Node),
		defs:       make(map[int64]map[int]parser.Node),
		trees:      make(map[int64]*parser.Tree),
		maxEntries: p.MaxCachedTrees(),
	}
	if _, file, line, ok := runtime.Caller(1); ok {
		liveFileParseCaches.Store(fc, fmt.Sprintf("%s:%d", file, line))
	}
	return fc
}

// LiveFileParseCaches lists parse caches that have not been Close()d. A
// non-empty result at scan end is a leaked AST borrow (and names the creator).
func LiveFileParseCaches() []string {
	var out []string
	liveFileParseCaches.Range(func(_, v any) bool {
		out = append(out, fmt.Sprint(v))
		return true
	})
	return out
}

// get returns fn's compound_statement body and the file root, parsing the file
// at most once. The (body, root) order matches the old readFunctionBody.
func (fc *fileParseCache) get(file *db.File, fn *db.Function) (parser.Node, parser.Node) {
	if _, ok := fc.bodies[file.ID]; !ok {
		fc.prime(file)
	}
	fc.touch(file.ID)
	return fc.bodies[file.ID][fn.StartLine], fc.roots[file.ID]
}

// rootForFile returns the parsed file root, parsing at most once. It is the
// file-level analogue of get, for callers that need the whole tree (e.g. to
// collect macro definitions) without a specific function.
func (fc *fileParseCache) rootForFile(file *db.File) parser.Node {
	if _, ok := fc.roots[file.ID]; !ok {
		fc.prime(file)
	}
	fc.touch(file.ID)
	return fc.roots[file.ID]
}

// prime parses file once and populates roots, bodies and defs. It is the single
// parse site shared by get/rootForFile/defFor so a file is parsed at most once
// per cache.
func (fc *fileParseCache) prime(file *db.File) {
	root, bodies, defs, tree := functionBodiesForFile(fc.parser, file)
	fc.roots[file.ID] = root
	fc.bodies[file.ID] = bodies
	fc.defs[file.ID] = defs
	if tree != nil {
		// ParseCached already returned the borrow this cache owns; Close
		// releases it. Do not Acquire a second time.
		fc.trees[file.ID] = tree
	}
	fc.touch(file.ID)
	fc.evictIfNeeded()
}

// touch moves id to the MRU end of the LRU list (deduplicated).
func (fc *fileParseCache) touch(id int64) {
	for i, v := range fc.order {
		if v == id {
			fc.order = append(fc.order[:i], fc.order[i+1:]...)
			break
		}
	}
	fc.order = append(fc.order, id)
}

// evictIfNeeded releases the oldest cached trees once maxEntries is exceeded.
// Releasing a tree here also drops its roots/bodies/defs, so a later access
// simply re-parses that file — memory stays bounded instead of the whole repo
// being pinned for the filter's lifetime.
func (fc *fileParseCache) evictIfNeeded() {
	for fc.maxEntries > 0 && len(fc.trees) > fc.maxEntries && len(fc.order) > 0 {
		oldest := fc.order[0]
		fc.order = fc.order[1:]
		if t := fc.trees[oldest]; t != nil {
			t.Release()
		}
		delete(fc.trees, oldest)
		delete(fc.roots, oldest)
		delete(fc.bodies, oldest)
		delete(fc.defs, oldest)
	}
}

func (fc *fileParseCache) treeFor(file *db.File) *parser.Tree {
	if _, ok := fc.trees[file.ID]; !ok {
		fc.prime(file)
	}
	fc.touch(file.ID)
	return fc.trees[file.ID]
}

func (fc *fileParseCache) Close() {
	for _, t := range fc.trees {
		if t != nil {
			t.Release()
		}
	}
	fc.trees = make(map[int64]*parser.Tree)
	liveFileParseCaches.Delete(fc)
}

// defFor returns the function_definition node of fn, parsed at most once per
// file. It removes the per-function whole-file FindAll("function_definition")
// that paramsOf/paramListOf used to issue — over a large codebase that was an
// O(functions × file) re-walk of the same AST and the dominant remaining cost of
// the null-deref plan phase.
func (fc *fileParseCache) defFor(file *db.File, fn *db.Function) parser.Node {
	if _, ok := fc.defs[file.ID]; !ok {
		fc.prime(file)
	}
	return fc.defs[file.ID][fn.StartLine]
}

// paramsFor returns fn's parameter names keyed by name with their ordinal index,
// derived from the cached function_definition node.
func (fc *fileParseCache) paramsFor(file *db.File, fn *db.Function) map[string]int {
	def := fc.defFor(file, fn)
	if def.Kind() == "" {
		return nil
	}
	out := make(map[string]int)
	for i, p := range paramNamesOfDef(def) {
		if p != "" {
			out[p] = i
		}
	}
	return out
}

// paramListFor returns fn's ordered parameter names from the cached
// function_definition node.
func (fc *fileParseCache) paramListFor(file *db.File, fn *db.Function) []string {
	def := fc.defFor(file, fn)
	if def.Kind() == "" {
		return nil
	}
	return paramNamesOfDef(def)
}

// voidPtrParamsFor returns fn's void*/const void* parameter names from the
// cached function_definition node (no whole-file re-walk per function).
func (fc *fileParseCache) voidPtrParamsFor(file *db.File, fn *db.Function) map[string]bool {
	def := fc.defFor(file, fn)
	if def.Kind() == "" {
		return nil
	}
	out := map[string]bool{}
	for _, pd := range def.FindAll("parameter_declaration") {
		if !isVoidPointerDecl(pd) {
			continue
		}
		if n := declaratorName(pd); n != "" {
			out[n] = true
		}
	}
	return out
}

// functionBodiesForFile parses file and returns its root, a map from each
// function definition's start line to its compound_statement body, and a map
// from start line to the function_definition node itself.
func functionBodiesForFile(p *parser.Parser, file *db.File) (parser.Node, map[int]parser.Node, map[int]parser.Node, *parser.Tree) {
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return parser.Node{}, nil, nil, nil
	}
	tree, err := p.ParseCached(source, file.Path)
	if err != nil {
		return parser.Node{}, nil, nil, nil
	}
	root := tree.RootNode()
	bodies := make(map[int]parser.Node)
	defs := make(map[int]parser.Node)
	for _, def := range root.FindAll("function_definition") {
		if _, seen := defs[def.StartLine()]; !seen {
			defs[def.StartLine()] = def
		}
		if body := def.FindFirst("compound_statement"); body != nil {
			bodies[def.StartLine()] = *body
		}
	}
	return root, bodies, defs, tree
}

// buildGuardCtx supplies the guard comparison with the two facts the AST alone
// does not carry: which identifiers are compile-time zero (the file's constant
// table: `NAT_OK` / `STMP_OK` / an enum's success value), and which variables
// hold a helper call before a given line (`ret = check(p); if (ret != OK) ...`).
//
// The variable map is "last assignment wins, and only when that assignment is a
// call": if `ret` is reassigned to anything else before the guard, the guard no
// longer tests the helper's result and nothing is proven.
func buildGuardCtx(body parser.Node, zero *parser.ConstantEnv) guardCtx {
	type callAssign struct {
		line int
		call parser.Node
	}
	byVar := map[string][]callAssign{}
	record := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok || lhs.Kind() != "identifier" {
			return
		}
		var call parser.Node
		inner := rhs
		for inner.Kind() == "cast_expression" || inner.Kind() == "parenthesized_expression" {
			kids := inner.NamedChildren()
			if len(kids) == 0 {
				break
			}
			inner = kids[len(kids)-1]
		}
		if inner.Kind() == "call_expression" {
			call = inner
		}
		name := strings.TrimSpace(lhs.Text())
		byVar[name] = append(byVar[name], callAssign{line: node.StartLine(), call: call})
	}
	for _, assign := range body.FindAll("assignment_expression") {
		record(assign)
	}
	for _, init := range body.FindAll("init_declarator") {
		record(init)
	}
	return guardCtx{
		isZero: func(name string) bool {
			return zero != nil && zero.IsZero(name)
		},
		callOf: func(name string, line int) parser.Node {
			best := -1
			bestLine := 0
			for i, a := range byVar[name] {
				if a.line < line && a.line >= bestLine {
					best, bestLine = i, a.line
				}
			}
			if best < 0 {
				return parser.Node{}
			}
			return byVar[name][best].call
		},
	}
}
