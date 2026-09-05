package parser

import (
	"fmt"
	"sync"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_c "github.com/tree-sitter/tree-sitter-c/bindings/go"
)

// cTypeKeywords are C keywords that can never be variable names. When a macro
// appears in a type position (`z_const unsigned char FAR *p`), tree-sitter can
// mis-parse `char`/`int`/... as an identifier instead of a primitive_type, so
// detectors must treat these tokens as types, not as variable names.
var cTypeKeywords = map[string]bool{
	"char": true, "int": true, "unsigned": true, "signed": true,
	"short": true, "long": true, "float": true, "double": true, "void": true,
	"const": true, "volatile": true, "static": true, "auto": true,
	"register": true, "extern": true, "typedef": true, "inline": true,
	"restrict": true, "struct": true, "union": true, "enum": true,
	"_Bool": true, "_Complex": true, "_Imaginary": true, "sizeof": true,
}

// IsCTypeKeyword reports whether name is a C keyword that cannot be a variable
// name. Detectors use it to avoid treating type keywords mis-parsed as
// identifiers (from macros in type positions) as variables.
func IsCTypeKeyword(name string) bool {
	return cTypeKeywords[name]
}

type Parser struct {
	lang   *sitter.Language
	parser *sitter.Parser
	// mu guards cache and parsers: the parallel graph builders, detectors and
	// planners all share one Parser and call ParseCached concurrently, so map
	// reads/writes and the tree-sitter Language refcount (SetLanguage) must be
	// serialized. The returned *Tree is immutable after parse and safe to read
	// concurrently once the lock is released.
	mu      sync.Mutex
	cache   map[string]*Tree
	parsers map[string]*sitter.Parser
}

type Tree struct {
	tree   *sitter.Tree
	src    []byte
	cached bool
}

func NewParser() *Parser {
	lang := sitter.NewLanguage(tree_sitter_c.Language())
	p := sitter.NewParser()
	p.SetLanguage(lang)
	return &Parser{
		lang:    lang,
		parser:  p,
		cache:   make(map[string]*Tree),
		parsers: make(map[string]*sitter.Parser),
	}
}

// Parse parses source with the parser's shared instance. This is only safe for
// sequential callers that finish using (and Close) the returned tree before the
// next Parse on this parser — the indexer follows that pattern (the planner
// filters use ParseCached, which is internally synchronized).
func (p *Parser) Parse(source []byte, filename string) (*Tree, error) {
	tree := p.parser.Parse(source, nil)
	return &Tree{tree: tree, src: source}, nil
}

// ParseCached is Parse with a per-file cache keyed by filename. The scan runs
// every detector and graph builder over the same set of files, and each of them
// previously re-parsed every file once per function — ~15K parses on a
// 1000-function codebase, which dominated the wall clock. Caching collapses that
// to one parse per file.
//
// tree-sitter reuses the memory of trees a parser returns on its *next* parse,
// so a cached tree would be invalidated the moment another file was parsed on
// the same parser. Each file therefore gets its own dedicated parser, used
// exactly once; the parser is kept alive alongside the tree and released in
// CloseAll. The returned tree is owned by this Parser (Close is a no-op).
func (p *Parser) ParseCached(source []byte, filename string) (*Tree, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t, ok := p.cache[filename]; ok {
		return t, nil
	}
	ps := sitter.NewParser()
	ps.SetLanguage(p.lang)
	tree := ps.Parse(source, nil)
	t := &Tree{tree: tree, src: source, cached: true}
	p.cache[filename] = t
	p.parsers[filename] = ps
	return t, nil
}

// CloseAll releases every cached tree and its dedicated parser. Call it once,
// after the scan, instead of relying on per-detector Close (which is a no-op for
// cached trees).
func (p *Parser) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, t := range p.cache {
		if t != nil && t.tree != nil {
			t.tree.Close()
		}
	}
	for _, ps := range p.parsers {
		if ps != nil {
			ps.Close()
		}
	}
	p.cache = nil
	p.parsers = nil
}

func (t *Tree) RootNode() Node {
	return Node{node: *t.tree.RootNode(), src: t.src}
}

func (t *Tree) HasError() bool {
	return t.tree.RootNode().HasError()
}

func (t *Tree) Source() []byte {
	return t.src
}

func (t *Tree) Close() {
	if t.cached {
		return // owned by the Parser cache; released in CloseAll
	}
	t.tree.Close()
}

type Node struct {
	node sitter.Node
	src  []byte
}

// isNull reports whether the wrapped tree-sitter node is the zero value (no
// underlying C TSNode). Calling Kind()/HasError()/Children() on a null node
// dereferences a nil C pointer and segfaults the whole process (unrecoverable
// by Go's recover), so the flow filters — which read function bodies through
// fileParseCache and can miss a body when a file re-read fails or a
// function_definition has no compound_statement — must be able to ask "is this
// a real node?" safely.
func (n Node) isNull() bool {
	return n.node.Id() == 0
}

func (n Node) Kind() string {
	if n.isNull() {
		return ""
	}
	return n.node.Kind()
}

func (n Node) Text() string {
	if n.isNull() {
		return ""
	}
	return string(n.src[n.node.StartByte():n.node.EndByte()])
}

func (n Node) StartByte() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.StartByte())
}

func (n Node) EndByte() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.EndByte())
}

func (n Node) StartLine() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.StartPosition().Row) + 1
}

func (n Node) StartColumn() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.StartPosition().Column) + 1
}

func (n Node) EndLine() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.EndPosition().Row) + 1
}

func (n Node) EndColumn() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.EndPosition().Column) + 1
}

func (n Node) HasError() bool {
	if n.isNull() {
		return false
	}
	return n.node.HasError()
}

func (n Node) ChildCount() int {
	if n.isNull() {
		return 0
	}
	return int(n.node.ChildCount())
}

func (n Node) Children() []Node {
	if n.isNull() {
		return nil
	}
	count := n.node.ChildCount()
	children := make([]Node, 0, count)
	for i := 0; i < int(count); i++ {
		child := n.node.Child(uint(i))
		if child == nil {
			continue
		}
		children = append(children, Node{node: *child, src: n.src})
	}
	return children
}

func (n Node) NamedChildren() []Node {
	if n.isNull() {
		return nil
	}
	count := n.node.NamedChildCount()
	children := make([]Node, 0, count)
	for i := 0; i < int(count); i++ {
		child := n.node.NamedChild(uint(i))
		if child == nil {
			continue
		}
		children = append(children, Node{node: *child, src: n.src})
	}
	return children
}

func (n Node) ChildByFieldName(name string) *Node {
	if n.isNull() {
		return nil
	}
	child := n.node.ChildByFieldName(name)
	if child == nil {
		return nil
	}
	return &Node{node: *child, src: n.src}
}

// Parent returns the enclosing node, or nil at the root. It lets detectors walk
// from a node up to an enclosing construct (e.g. a sizeof_expression) without
// re-searching the whole tree.
func (n Node) Parent() *Node {
	if n.isNull() {
		return nil
	}
	parent := n.node.Parent()
	if parent == nil {
		return nil
	}
	return &Node{node: *parent, src: n.src}
}

func (n Node) FindAll(kind string) []Node {
	var results []Node
	walkNode(n, func(node Node) {
		if node.Kind() == kind {
			results = append(results, node)
		}
	})
	return results
}

func (n Node) FindFirst(kind string) *Node {
	var found *Node
	walkNode(n, func(node Node) {
		if found == nil && node.Kind() == kind {
			found = &node
		}
	})
	return found
}

func (n Node) TypeName() string {
	if n.isNull() {
		return ""
	}
	return n.node.Kind()
}

func (n Node) String() string {
	return fmt.Sprintf("%s at line %d", n.Kind(), n.StartLine())
}

// walkNode visits n and every named descendant in pre-order. It deliberately
// avoids n.NamedChildren(), which allocates a fresh []Node on every node — with
// ~50K nodes per file re-walked once per function across ~15 detectors, that
// per-node allocation adds up to hundreds of millions of allocations and is the
// dominant cost of the whole scan. An explicit stack with NamedChildCount/
// NamedChild keeps the traversal allocation-light (one amortized slice).
func walkNode(n Node, visit func(Node)) {
	// A null node (the zero sitter.Node, e.g. a fileParseCache miss in the flow
	// filters) dereferences a nil C pointer on NamedChildCount and segfaults the
	// process unrecoverably (see isNull). Every other wrapper guards isNull;
	// walkNode is the raw traversal entry, so it must too.
	if n.isNull() {
		return
	}
	stack := make([]Node, 0, 64)
	stack = append(stack, n)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		visit(node)
		count := int(node.node.NamedChildCount())
		for i := count - 1; i >= 0; i-- {
			child := node.node.NamedChild(uint(i))
			if child == nil {
				continue
			}
			stack = append(stack, Node{node: *child, src: node.src})
		}
	}
}
