package parser

import "strings"

// AddressTakenTarget resolves a call argument that takes the address of a
// variable to the addressed operand: `&x`, `&(x)`, `(T *)&x`, `(T)&(x)` and
// `(T)&x` all yield x (a field/subscript operand `&s.f` yields the
// field_expression — the caller decides by Kind). It reports ok=false when the
// argument is not an address-of expression at all (a by-value argument, a
// dereference `*p`, a plain bit-and `a & b`).
//
// It is the PERMISSIVE form: the ambiguous `(A) & x` shape (see
// AddressTakenTargetScoped) is accepted whenever A is type-shaped. Callers that
// can tell a type name from a value name should use AddressTakenTargetScoped so
// a genuine bit-and (`sink((flags) & mask)`) is not misread as `&mask`.
func (n Node) AddressTakenTarget() (Node, bool) {
	return n.addressTakenTarget(nil)
}

// AddressTakenTargetScoped is AddressTakenTarget with a scope oracle that
// disambiguates the one shape tree-sitter-c cannot resolve on its own:
// `(A) & x`.
//
// tree-sitter-c has no typedef table, so `(A) & x` parses as a BIT-AND
// binary_expression for EVERY A that has no `*` in the parentheses — whether A
// is a type (`(shm_handle)&prfs_list`, `(handle_t)&x`) or a value
// (`(flags) & mask`). It is NOT a matter of the typedef being visible: the same
// binary reading appears when the typedef is declared in the very file being
// parsed (only builtin spellings such as `size_t` and any `(T *)` with a star
// parse as a real cast_expression). Syntactically the two forms are therefore
// identical, and the ONLY available discriminator is scope knowledge: `&x` is
// the cast idiom when A names a type, and a bit-and when A names a value.
//
// isValue reports whether name is bound to a value in the enclosing scope (a
// parameter, local, or global variable). A nil oracle keeps the permissive
// legacy behavior. The oracle is consulted only for the ambiguous shape; the
// unambiguous spellings above never call it.
func (n Node) AddressTakenTargetScoped(isValue func(string) bool) (Node, bool) {
	return n.addressTakenTarget(isValue)
}

func (n Node) addressTakenTarget(isValue func(string) bool) (Node, bool) {
	node := n
	for {
		switch node.Kind() {
		case "cast_expression", "parenthesized_expression":
			inner := node.NamedChildren()
			if len(inner) == 0 {
				return Node{}, false
			}
			// A cast's last named child is its operand (`(T)&x`); a
			// parenthesized expression wraps a single child, so last == first.
			node = inner[len(inner)-1]
		case "binary_expression":
			rhs, ok := castBinaryOperand(node, isValue)
			if !ok {
				return Node{}, false
			}
			// The "&" here is the binary operator itself, so the right
			// operand IS the addressed expression (`(T) & x` → x) — there is
			// no pointer_expression below it to unwrap.
			for rhs.Kind() == "parenthesized_expression" {
				inner := rhs.NamedChildren()
				if len(inner) == 0 {
					return Node{}, false
				}
				rhs = inner[0]
			}
			return rhs, true
		default:
			return addressOfOperand(node)
		}
	}
}

// castBinaryOperand recovers the right operand of a `(T) & x` argument that
// tree-sitter parsed as a bit-and binary_expression. The shape is: the "&"
// operator (a logical "&&" is a different operator node), a parenthesized LEFT
// operand holding a single type-shaped token run, and exactly two named
// children.
//
// Because `(flags) & mask` has the IDENTICAL parse (tree-sitter-c does not
// resolve typedefs), the shape alone cannot prove a cast. When an isValue
// oracle is supplied, a LEFT operand that names a value in scope rejects the
// match: `(flags) & mask` stays a bit-and, while `(shm_handle)&prfs_list` — a
// typedef name from an excluded header, which no scope binds to a value — is
// still recovered. Without an oracle the shape is accepted, which is the
// permissive legacy behavior (a false match can only over-suppress, never
// invent, a finding; see the callers).
func castBinaryOperand(n Node, isValue func(string) bool) (Node, bool) {
	if op := n.ChildByFieldName("operator"); op == nil || op.Text() != "&" {
		return Node{}, false
	}
	kids := n.NamedChildren()
	if len(kids) != 2 || kids[0].Kind() != "parenthesized_expression" {
		return Node{}, false
	}
	inner := kids[0].NamedChildren()
	if len(inner) != 1 {
		return Node{}, false
	}
	if isValue != nil && inner[0].Kind() == "identifier" && isValue(inner[0].Text()) {
		return Node{}, false
	}
	if !typeShapedText(inner[0].Text()) {
		return Node{}, false
	}
	return kids[1], true
}

// addressOfOperand validates that node is a `&` address-of and returns its
// operand, unwrapping parentheses around the operand (`&(x)` parses the
// operand as a parenthesized_expression, not a bare identifier).
func addressOfOperand(node Node) (Node, bool) {
	if node.Kind() != "pointer_expression" || !strings.HasPrefix(strings.TrimSpace(node.Text()), "&") {
		return Node{}, false
	}
	operand := node.NamedChildren()
	if len(operand) == 0 {
		return Node{}, false
	}
	op := operand[0]
	for op.Kind() == "parenthesized_expression" {
		inner := op.NamedChildren()
		if len(inner) == 0 {
			return Node{}, false
		}
		op = inner[0]
	}
	return op, true
}

// typeShapedText reports whether s is built only from characters a C type
// spelling can contain (`shm_handle`, `struct S *`, `unsigned char *`):
// letters, digits, underscore, whitespace and `*`. Any operator or separator
// (`+`, `(`, `,`, ...) means the operand is an expression, not a type.
func typeShapedText(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_', r == ' ', r == '\t', r == '*':
		default:
			return false
		}
	}
	return true
}
