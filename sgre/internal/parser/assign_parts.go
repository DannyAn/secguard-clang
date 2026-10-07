package parser

// AssignParts returns the (lhs, rhs) of an assignment_expression or an
// init_declarator node. init_declarator is read by field name (declarator/value)
// because tree-sitter-c v0.24.4 inserts attribute_specifier between the
// declarator and the value, so positional NamedChildren()[1] would return the
// attribute instead of the initializer. assignment_expression keeps positional
// access because a macro call site can mangle its named children.
func (n Node) AssignParts() (lhs, rhs Node, ok bool) {
	switch n.Kind() {
	case "assignment_expression":
		children := n.NamedChildren()
		if len(children) < 2 {
			return Node{}, Node{}, false
		}
		return children[0], children[1], true
	case "init_declarator":
		d := n.ChildByFieldName("declarator")
		v := n.ChildByFieldName("value")
		if d == nil || v == nil {
			return Node{}, Node{}, false
		}
		return *d, *v, true
	}
	return Node{}, Node{}, false
}
