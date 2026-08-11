package parser

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	tree_sitter_c "github.com/tree-sitter/tree-sitter-c/bindings/go"
)

type Parser struct {
	parser *sitter.Parser
}

type Tree struct {
	tree *sitter.Tree
	src  []byte
}

func NewParser() *Parser {
	p := sitter.NewParser()
	lang := sitter.NewLanguage(tree_sitter_c.Language())
	p.SetLanguage(lang)
	return &Parser{parser: p}
}

func (p *Parser) Parse(source []byte, filename string) (*Tree, error) {
	tree := p.parser.Parse(source, nil)
	return &Tree{tree: tree, src: source}, nil
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
	t.tree.Close()
}

type Node struct {
	node sitter.Node
	src  []byte
}

func (n Node) Kind() string {
	return n.node.Kind()
}

func (n Node) Text() string {
	return string(n.src[n.node.StartByte():n.node.EndByte()])
}

func (n Node) StartLine() int {
	return int(n.node.StartPosition().Row) + 1
}

func (n Node) StartColumn() int {
	return int(n.node.StartPosition().Column) + 1
}

func (n Node) EndLine() int {
	return int(n.node.EndPosition().Row) + 1
}

func (n Node) EndColumn() int {
	return int(n.node.EndPosition().Column) + 1
}

func (n Node) HasError() bool {
	return n.node.HasError()
}

func (n Node) ChildCount() int {
	return int(n.node.ChildCount())
}

func (n Node) Children() []Node {
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
	child := n.node.ChildByFieldName(name)
	if child == nil {
		return nil
	}
	return &Node{node: *child, src: n.src}
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
	return n.node.Kind()
}

func (n Node) String() string {
	return fmt.Sprintf("%s at line %d", n.Kind(), n.StartLine())
}

func walkNode(n Node, visit func(Node)) {
	visit(n)
	for _, child := range n.NamedChildren() {
		walkNode(child, visit)
	}
}
