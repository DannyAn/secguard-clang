package parser

import (
	"bytes"
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
	// origSrc is the source as written on disk, before preprocessGccExtensions
	// rewrote typeof(...) to a padded `void *`. The rewrite is length-preserving,
	// so byte offsets are identical between src and origSrc; Node.OriginalText
	// reads origSrc to let detectors report evidence text as the author wrote it.
	origSrc []byte
	// rewrites records every typeof(...) construct the preprocessor rewrote, for
	// detectors that need to know a declaration's real type was masked to void *.
	rewrites []TypeofRewrite
}

// TypeofRewrite records one typeof(expr) construct rewritten to a padded `void *`.
// Start/End are byte offsets valid in BOTH src and origSrc (length-preserving).
type TypeofRewrite struct {
	Start int
	End   int
	Param string // the original parameter text inside the parens, e.g. "nodes->leafs"
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
	src, rewrites := preprocessGccExtensions(source)
	tree := p.parser.Parse(src, nil)
	return &Tree{tree: tree, src: src, origSrc: source, rewrites: rewrites}, nil
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
	src, rewrites := preprocessGccExtensions(source)
	ps := sitter.NewParser()
	ps.SetLanguage(p.lang)
	tree := ps.Parse(src, nil)
	t := &Tree{tree: tree, src: src, origSrc: source, rewrites: rewrites, cached: true}
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
	p.cache = make(map[string]*Tree)
	p.parsers = make(map[string]*sitter.Parser)
	if p.parser != nil {
		p.parser.Close()
	}
}

// gccTypeofKeywords are the GCC/Clang spellings of the typeof type-of
// operator, longest first so that `__typeof__` and `typeof_unqual` win over
// their bare `typeof` prefix when both could match at a position.
var gccTypeofKeywords = []string{
	"typeof_unqual", // 13
	"__typeof__",    // 10
	"__typeof",      // 8
	"typeof",        // 6
}

// preprocessGccExtensions replaces GCC `typeof(expr)` (and its `__typeof`,
// `__typeof__`, `typeof_unqual` spellings) with `void *` so that tree-sitter-c
// (which does not support the typeof keyword in v0.24.2) can parse declarations
// and casts that use it. Without this, `typeof(x) v = ...` is mis-parsed:
// `typeof(x)` becomes a call_expression, `v` becomes an ERROR node, and the
// initializer is split into a separate expression_statement — breaking every
// detector that relies on the assignment chain (unchecked-return, null-source,
// resource-leak). The replacement is padded with spaces to preserve source
// positions (line/column) for accurate diagnostics.
func preprocessGccExtensions(source []byte) ([]byte, []TypeofRewrite) {
	// Every supported spelling contains "typeof", so this cheap check is the
	// fast path for the vast majority of files that never use the extension.
	if !bytes.Contains(source, []byte("typeof")) {
		return source, nil
	}
	result := make([]byte, len(source))
	copy(result, source)
	replacement := []byte("void *")
	var rewrites []TypeofRewrite
	for i := 0; i < len(result); {
		// A preprocessor directive line (`#define`, `#include`, ...) is not code:
		// rewriting a typeof(...) inside a macro body would silently delete the
		// macro's parameter references and diverge scanner semantics from the
		// compiler's. Skip the whole logical line (following `\` continuations).
		if result[i] == '#' && atLineStart(result, i) {
			i = skipDirective(result, i)
			continue
		}
		// Never rewrite a `typeof(` that lives inside a string/char literal or a
		// comment — the byte-level match would silently corrupt that text (same
		// length, so no parse error, but detectors reading string content would
		// see `void *` instead of the original `typeof(...)`).
		if n := skipNonCode(result, i); n > i {
			i = n
			continue
		}
		end, param, ok := replaceTypeofAt(result, i, replacement)
		if !ok {
			i++
			continue
		}
		rewrites = append(rewrites, TypeofRewrite{Start: i, End: end, Param: param})
		i = end
	}
	return result, rewrites
}

// atLineStart reports whether result[i] is the first non-whitespace byte on its
// line (or i==0). It distinguishes a real `#` directive from a `#` that merely
// follows code on a line.
func atLineStart(result []byte, i int) bool {
	for j := i - 1; j >= 0; j-- {
		switch result[j] {
		case '\n':
			return true
		case ' ', '\t', '\r':
			continue
		default:
			return false
		}
	}
	return true
}

// skipDirective returns the index just past a preprocessor directive's logical
// line (result[i] must be '#'), following backslash-newline continuations so a
// multi-line `#define` is skipped as a unit.
func skipDirective(result []byte, i int) int {
	j := i
	for j < len(result) {
		switch result[j] {
		case '\\':
			if j+1 < len(result) && result[j+1] == '\n' {
				j += 2
				continue
			}
			if j+2 < len(result) && result[j+1] == '\r' && result[j+2] == '\n' {
				j += 3
				continue
			}
		case '\n':
			return j + 1
		}
		j++
	}
	return len(result)
}

// skipNonCode returns the index just past the string literal, char literal,
// line comment, or block comment that starts at result[i], or i when result[i]
// is not the start of any of those. It is escape-aware so `"a\"b"` and `'\\'`
// do not terminate early.
func skipNonCode(result []byte, i int) int {
	switch result[i] {
	case '"', '\'':
		quote := result[i]
		for j := i + 1; j < len(result); j++ {
			if result[j] == '\\' {
				j++
				continue
			}
			// An unterminated string/char literal cannot span a newline in C, so
			// stop at the line boundary instead of jumping to EOF: that way a
			// later typeof(...) on a following line is still rewritten.
			if result[j] == '\n' {
				return j
			}
			if result[j] == quote {
				return j + 1
			}
		}
		return len(result)
	case '/':
		if i+1 < len(result) && result[i+1] == '/' {
			for j := i + 2; j < len(result); j++ {
				if result[j] == '\n' {
					return j
				}
			}
			return len(result)
		}
		if i+1 < len(result) && result[i+1] == '*' {
			for j := i + 2; j+1 < len(result); j++ {
				if result[j] == '*' && result[j+1] == '/' {
					return j + 2
				}
			}
			return len(result)
		}
	}
	return i
}

// replaceTypeofAt rewrites a typeof-spelling construct starting at result[i]
// (`typeof(x)`, `__typeof__ (x)`, ...) into `void *` padded with spaces to keep
// the byte length (and therefore line/column) unchanged. It returns the byte
// index just past the rewritten construct, the original parameter text between
// the outer parens, and whether a rewrite happened.
func replaceTypeofAt(result []byte, i int, replacement []byte) (int, string, bool) {
	for _, kw := range gccTypeofKeywords {
		n := len(kw)
		if i+n > len(result) || string(result[i:i+n]) != kw {
			continue
		}
		// Word boundary on both sides: `x__typeof(y)` is a different identifier,
		// and `__typeof__` must not be treated as its shorter `__typeof` prefix.
		if i > 0 && isIdentChar(result[i-1]) {
			continue
		}
		if i+n < len(result) && isIdentChar(result[i+n]) {
			continue
		}
		j := i + n
		for j < len(result) && (result[j] == ' ' || result[j] == '\t') {
			j++
		}
		if j >= len(result) || result[j] != '(' {
			continue
		}
		// The parenthesis-balance scan must share the outer loop's string/comment
		// skipping: a `)` or `(` inside a comment or string literal must not move
		// depth. Otherwise `typeof(x /* ) */)` truncates the rewrite inside the
		// comment (corrupting it) and `typeof(x /* ( */)` never balances (leaving
		// typeof intact and silently mis-parsing the declaration).
		depth := 1
		k := j + 1
		for k < len(result) && depth > 0 {
			if n2 := skipNonCode(result, k); n2 > k {
				k = n2
				continue
			}
			switch result[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
			k++
		}
		if depth != 0 {
			continue
		}
		// Copy before the rewrite below overwrites result[i:k] (param aliases that
		// backing array, so a bare slice would turn into spaces by the time the
		// caller reads it).
		param := string(result[j+1 : k-1])
		for pos := i; pos < k; pos++ {
			if pos-i < len(replacement) {
				result[pos] = replacement[pos-i]
			} else {
				result[pos] = ' '
			}
		}
		return k, param, true
	}
	return i, "", false
}

func isIdentChar(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func (t *Tree) RootNode() Node {
	if t.tree == nil {
		return Node{}
	}
	return Node{node: *t.tree.RootNode(), src: t.src, origSrc: t.origSrc, rewrites: t.rewrites}
}

func (t *Tree) HasError() bool {
	if t.tree == nil {
		return false
	}
	return t.tree.RootNode().HasError()
}

func (t *Tree) Source() []byte {
	return t.src
}

// TypeofRewrites returns every typeof(...) construct the preprocessor rewrote to
// `void *`, in source order. Empty for files that use no GCC typeof extension.
func (t *Tree) TypeofRewrites() []TypeofRewrite {
	return t.rewrites
}

func (t *Tree) Close() {
	if t.cached {
		return // owned by the Parser cache; released in CloseAll
	}
	t.tree.Close()
	t.tree = nil
}

type Node struct {
	node     sitter.Node
	src      []byte
	origSrc  []byte
	rewrites []TypeofRewrite
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

// OriginalText returns the node's text from the source as written on disk,
// before typeof(...) was rewritten to a padded `void *`. The rewrite is
// length-preserving, so the byte range is valid in both buffers; this lets
// detectors emit evidence text that matches what the AI classifier reads from
// the file (e.g. `typeof(x)` instead of `void *` + spaces). It falls back to
// Text() when the file used no typeof extension.
func (n Node) OriginalText() string {
	if n.isNull() {
		return ""
	}
	if n.origSrc == nil {
		return n.Text()
	}
	return string(n.origSrc[n.node.StartByte():n.node.EndByte()])
}

// TypeofTypeSpecifier reports whether this declaration/parameter node's leading
// type specifier was produced by a typeof(...) rewrite. Such a declaration's
// real type is unknowable from the AST (the rewrite masks it as `void *`), so
// type-sensitive detectors should treat the declared variable's type as UNKNOWN
// rather than misreading it as a pointer.
func (n Node) TypeofTypeSpecifier() bool {
	if len(n.rewrites) == 0 {
		return false
	}
	for _, ch := range n.NamedChildren() {
		switch ch.Kind() {
		case "primitive_type", "sized_type_specifier", "type_identifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			start, end := ch.StartByte(), ch.EndByte()
			for _, r := range n.rewrites {
				if r.Start <= start && end <= r.End {
					return true
				}
			}
			return false
		}
	}
	return false
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
		children = append(children, Node{node: *child, src: n.src, origSrc: n.origSrc, rewrites: n.rewrites})
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
		children = append(children, Node{node: *child, src: n.src, origSrc: n.origSrc, rewrites: n.rewrites})
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
	return &Node{node: *child, src: n.src, origSrc: n.origSrc, rewrites: n.rewrites}
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
	return &Node{node: *parent, src: n.src, origSrc: n.origSrc, rewrites: n.rewrites}
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
			stack = append(stack, Node{node: *child, src: node.src, origSrc: node.origSrc, rewrites: node.rewrites})
		}
	}
}
