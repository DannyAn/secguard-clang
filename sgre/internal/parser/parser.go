package parser

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

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
	// mu guards cache and lifecycle state: the parallel graph builders,
	// detectors and planners all share one Parser and call ParseCached
	// concurrently, so map reads/writes and the refcount transitions that
	// decide eviction/close must be serialized.
	mu    sync.Mutex
	cache map[string]*Tree
	// maxCachedTrees bounds the number of cached parse trees. 0 = unbounded
	// (legacy default). When >0, ParseCached evicts the least-recently-used
	// tree with refs==0 to make room. If every entry is borrowed, the parse
	// still succeeds: the new tree is returned as a transient borrow that owns
	// its own parser and is closed by the caller's Release.
	maxCachedTrees int
	clock          uint64
	// transientActive counts out-of-cache trees whose borrow has not been
	// released yet. They are not tracked individually: each closes itself on
	// the final Release, so CloseAll only reports the count for diagnostics.
	transientActive atomic.Int64
	// closed is set by CloseAll; ParseCached after it returns an error instead
	// of building a tree on a closed parser.
	closed bool
	// leakedTrees records cached trees that still had borrows when CloseAll
	// ran. Their close is deferred to the final Release; this is the leak
	// diagnostic CloseAll surfaces.
	leakedTrees []string
}

// transientOrigins records still-borrowed transient trees and the ParseCached
// call site that created them. It exists so CloseAll can name the consumer that
// forgot a Release instead of only reporting a count.
var transientOrigins sync.Map // *Tree -> string

func callerSite() string {
	if _, file, line, ok := runtime.Caller(2); ok {
		return fmt.Sprintf("%s:%d", file, line)
	}
	return "unknown"
}

type Tree struct {
	// tree is nil after Close/close; use Load/Swap so RootNode never observes
	// a torn pointer.
	tree atomic.Pointer[sitter.Tree]
	src  []byte
	// cached is true for a tree owned by the parser cache. Such trees are
	// closed by eviction/CloseAll (only at refs==0), never by Tree.Close.
	cached bool
	// ownsParser is true when the tree was parsed by a dedicated parser that
	// must be closed together with the tree.
	ownsParser bool
	parser     *sitter.Parser
	owner      *Parser
	name       string
	transient  bool
	// refs counts borrows, including the borrow ParseCached returns to its
	// caller. A tree is evicted and closed only while refs==0. Every
	// ParseCached/Acquire must be paired with exactly one Release.
	refs atomic.Int64
	// retired marks a tree no longer owned by the cache (evicted, transient,
	// or CloseAll); the last Release closes it.
	retired   atomic.Bool
	closeOnce sync.Once
	// last is the LRU timestamp; updated on cache hit and insert.
	last uint64
}

// Acquire adds a borrow. ParseCached already returns one borrow; Acquire is for
// ownership transfer (a helper hands a tree to a long-lived cache) or a
// consumer that keeps nodes across calls. Every Acquire needs a Release.
func (t *Tree) Acquire() {
	if t == nil {
		return
	}
	t.refs.Add(1)
}

// Release drops one borrow. The ParseCached borrow MUST be released by the
// caller; on the final Release of a retired/transient tree the underlying C
// tree and its dedicated parser are closed exactly once.
func (t *Tree) Release() {
	if t == nil {
		return
	}
	if t.refs.Add(-1) == 0 && t.retired.Load() {
		t.close()
	}
}

// Refs returns the current borrow count (diagnostics/tests).
func (t *Tree) Refs() int64 {
	if t == nil {
		return 0
	}
	return t.refs.Load()
}

// retire makes the tree non-cache-owned; the last Release closes it. Called
// by the evictor and by CloseAll.
func (t *Tree) retire() {
	if t == nil {
		return
	}
	t.retired.Store(true)
	if t.refs.Load() == 0 {
		t.close()
	}
}

func (t *Tree) close() {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() {
		if tr := t.tree.Swap(nil); tr != nil {
			tr.Close()
		}
		if t.ownsParser && t.parser != nil {
			t.parser.Close()
			t.parser = nil
		}
		if t.transient && t.owner != nil {
			t.owner.transientActive.Add(-1)
		}
		transientOrigins.Delete(t)
	})
}

func NewParser() *Parser {
	lang := sitter.NewLanguage(tree_sitter_c.Language())
	p := sitter.NewParser()
	p.SetLanguage(lang)
	return &Parser{
		lang:   lang,
		parser: p,
		cache:  make(map[string]*Tree),
	}
}

// SetMaxCachedTrees sets the AST cache bound. 0 = unbounded (legacy default);
// a negative value is treated as 0. Must be called before the first
// ParseCached. When the cache is full and every entry is borrowed, ParseCached
// still succeeds by returning a transient borrow that owns its own parser and
// is closed by the caller's Release.
func (p *Parser) SetMaxCachedTrees(n int) {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxCachedTrees = n
}

// Parse parses source with the parser's shared instance. This is only safe for
// sequential callers that finish using (and Close) the returned tree before the
// next Parse on this parser — the indexer follows that pattern (the planner
// filters use ParseCached, which is internally synchronized).
func (p *Parser) Parse(source []byte, filename string) (*Tree, error) {
	p.mu.Lock()
	ps := p.parser
	closed := p.closed
	p.mu.Unlock()
	if closed || ps == nil {
		return nil, fmt.Errorf("parser: closed")
	}
	tree := ps.Parse(source, nil)
	if tree == nil {
		return nil, fmt.Errorf("parser: parse %s failed", filename)
	}
	t := &Tree{src: source, owner: p, name: filename}
	t.tree.Store(tree)
	return t, nil
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
// exactly once.
//
// Ownership: ParseCached returns a tree with ONE borrow already held for the
// caller. Every call MUST be paired with exactly one tree.Release() when the
// caller stops using the tree's nodes. The cache will not evict a tree while
// its borrow count is non-zero, so holding the borrow across a callback is what
// keeps the C nodes alive.
//
// When maxCachedTrees > 0 and the cache is full, the least-recently-used entry
// with refs==0 is evicted (its tree and parser are closed). If every entry is
// borrowed, the new tree is parsed on its own parser and returned as a
// transient borrow (not cached); Release closes the tree and parser
// immediately, so a transient tree never accumulates in a list.
func (p *Parser) ParseCached(source []byte, filename string) (*Tree, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, fmt.Errorf("parser: closed")
	}
	if t, ok := p.cache[filename]; ok {
		p.clock++
		t.last = p.clock
		t.refs.Add(1)
		return t, nil
	}
	ps := sitter.NewParser()
	ps.SetLanguage(p.lang)
	tree := ps.Parse(source, nil)
	if tree == nil {
		ps.Close()
		return nil, fmt.Errorf("parser: parse %s failed", filename)
	}
	p.clock++
	t := &Tree{src: source, cached: true, ownsParser: true, parser: ps, owner: p, name: filename, last: p.clock}
	t.tree.Store(tree)

	if p.maxCachedTrees > 0 && len(p.cache) >= p.maxCachedTrees {
		if !p.evictOldestUnreferencedLocked() {
			t.cached = false
			t.transient = true
			t.retired.Store(true)
			p.transientActive.Add(1)
			transientOrigins.Store(t, callerSite())
			t.refs.Add(1)
			return t, nil
		}
	}
	p.cache[filename] = t
	t.refs.Add(1)
	return t, nil
}

// evictOldestUnreferencedLocked finds and removes the cache entry with the
// smallest LRU timestamp among entries with refs==0. Returns false if no
// entry is evictable. Caller must hold p.mu.
func (p *Parser) evictOldestUnreferencedLocked() bool {
	var oldestKey string
	var oldestLast uint64 = ^uint64(0)
	found := false
	for k, t := range p.cache {
		if t.refs.Load() > 0 {
			continue
		}
		if t.last < oldestLast {
			oldestLast = t.last
			oldestKey = k
			found = true
		}
	}
	if !found {
		return false
	}
	t := p.cache[oldestKey]
	delete(p.cache, oldestKey)
	t.retire()
	return true
}

// CloseAll retires every cached tree and closes the shared parser. Cached trees
// with an outstanding borrow are not force-closed (that would reintroduce the
// use-after-free this lifecycle exists to prevent); their close is deferred to
// the final Release and recorded in LeakedTrees for diagnostics. Call it once,
// after the scan.
func (p *Parser) CloseAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for name, t := range p.cache {
		if t == nil {
			continue
		}
		t.retired.Store(true)
		if t.refs.Load() == 0 {
			t.close()
		} else {
			p.leakedTrees = append(p.leakedTrees, fmt.Sprintf("%s(refs=%d)", name, t.refs.Load()))
		}
	}
	p.cache = make(map[string]*Tree)
	if n := p.transientActive.Load(); n > 0 {
		p.leakedTrees = append(p.leakedTrees, fmt.Sprintf("%d transient tree(s) still borrowed", n))
		transientOrigins.Range(func(k, v any) bool {
			if t, ok := k.(*Tree); ok {
				p.leakedTrees = append(p.leakedTrees, fmt.Sprintf("transient %s @ %v", t.name, v))
			}
			return true
		})
	}
	if p.parser != nil {
		p.parser.Close()
		p.parser = nil
	}
}

// LeakedTrees lists the trees that still had borrows when CloseAll ran. An
// empty result means every ParseCached borrow was released.
func (p *Parser) LeakedTrees() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.leakedTrees...)
}

// CacheStats returns (cachedEntries, transientBorrows) for diagnostics.
func (p *Parser) CacheStats() (cached, transient int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.cache), int(p.transientActive.Load())
}

// PinnedTrees counts cached trees that currently have an outstanding borrow.
// They are protected from LRU eviction; a persistently non-zero value at a
// phase boundary is the signal that a consumer forgot a Release.
func (p *Parser) PinnedTrees() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, t := range p.cache {
		if t != nil && t.refs.Load() > 0 {
			n++
		}
	}
	return n
}

// ActiveTreeHandles counts cached trees plus still-borrowed transient trees.
func (p *Parser) ActiveTreeHandles() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.cache) + int(p.transientActive.Load())
}

// WithParseCached parses filename, lends the tree to fn, and releases the
// caller borrow when fn returns (including on panic). Use it for short-lived
// consumers that do not retain parser.Nodes; consumers that keep nodes across
// calls must call ParseCached and Release at the end of their own lifetime.
func (p *Parser) WithParseCached(source []byte, filename string, fn func(*Tree)) error {
	t, err := p.ParseCached(source, filename)
	if err != nil {
		return err
	}
	defer t.Release()
	fn(t)
	return nil
}

func (t *Tree) RootNode() Node {
	tr := t.tree.Load()
	if tr == nil {
		return Node{}
	}
	return Node{node: *tr.RootNode(), src: t.src}
}

func (t *Tree) HasError() bool {
	tr := t.tree.Load()
	if tr == nil {
		return false
	}
	return tr.RootNode().HasError()
}

func (t *Tree) Source() []byte {
	return t.src
}

// Close closes a non-cached tree (the parser.Parse path used by the indexer).
// Trees returned by ParseCached are owned by the cache/borrow lifecycle and
// must be released with Release; Close is a no-op for them.
func (t *Tree) Close() {
	if t == nil || t.cached {
		return
	}
	t.close()
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

// OriginalText returns the node's text as written on disk. tree-sitter-c v0.24.3
// parses GCC typeof natively (typeof_specifier), so no preprocessing rewrite is
// applied and the parsed source is the original source; this is therefore
// identical to Text(). It is retained as a stable API so the evidence detectors
// can report the author's exact spelling without per-call churn.
func (n Node) OriginalText() string {
	return n.Text()
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
	if n.isNull() {
		return nil
	}
	var results []Node
	stack := make([]Node, 0, 64)
	stack = append(stack, n)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		// node.node.Kind() skips the isNull guard on every accessor: every node
		// on the stack is a NamedChild result we already nil-checked (or the
		// entry node, null-checked above), so the guard would only re-issue the
		// same cgo Id() call per node. FindAll is the dominant tree-walk path of
		// the whole scan, so the guard is measurable overhead here.
		if node.node.Kind() == kind {
			results = append(results, node)
		}
		count := int(node.node.NamedChildCount())
		for i := count - 1; i >= 0; i-- {
			child := node.node.NamedChild(uint(i))
			if child == nil {
				continue
			}
			stack = append(stack, Node{node: *child, src: node.src})
		}
	}
	return results
}

func (n Node) FindFirst(kind string) *Node {
	if n.isNull() {
		return nil
	}
	stack := make([]Node, 0, 64)
	stack = append(stack, n)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if node.node.Kind() == kind {
			return &node
		}
		count := int(node.node.NamedChildCount())
		for i := count - 1; i >= 0; i-- {
			child := node.node.NamedChild(uint(i))
			if child == nil {
				continue
			}
			stack = append(stack, Node{node: *child, src: node.src})
		}
	}
	return nil
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
