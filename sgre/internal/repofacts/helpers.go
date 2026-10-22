package repofacts

import (
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
)

func readFile(path string) ([]byte, error) { return os.ReadFile(path) }

// typeKeys returns the names a struct/union layout can be referenced by: its
// tag (`struct X`) and, for `typedef struct {...} X_t;`, the alias.
func typeKeys(ss parser.Node) []string {
	var keys []string
	for _, c := range ss.NamedChildren() {
		if c.Kind() == "type_identifier" {
			keys = append(keys, strings.TrimSpace(c.Text()))
			break
		}
	}
	if p := ss.Parent(); p != nil && p.Kind() == "type_definition" {
		if kids := p.NamedChildren(); len(kids) > 0 {
			if last := kids[len(kids)-1]; last.Kind() == "type_identifier" {
				keys = append(keys, strings.TrimSpace(last.Text()))
			}
		}
	}
	return keys
}

// typeSpelling returns the specifier text of a declaration / field declaration.
func typeSpelling(n parser.Node) string {
	var parts []string
	for _, c := range n.NamedChildren() {
		switch c.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier",
			"struct_specifier", "union_specifier", "enum_specifier":
			parts = append(parts, strings.TrimSpace(c.Text()))
		}
	}
	return strings.Join(parts, " ")
}

// fieldFacts expands one field_declaration into member facts.
func fieldFacts(fd parser.Node, typ string, macros map[string]int) []FieldFact {
	var out []FieldFact
	seen := map[string]bool{}
	add := func(f FieldFact) {
		if f.Name == "" || seen[f.Name] {
			return
		}
		seen[f.Name] = true
		f.Type = typ
		out = append(out, f)
	}
	for _, ad := range fd.FindAll("array_declarator") {
		name := declaratorName(ad)
		if name == "" {
			continue
		}
		f := FieldFact{Name: name, Array: true}
		if n, sym, ok := arrayCapacity(ad, macros); ok {
			f.Count, f.Symbol = n, sym
		}
		add(f)
	}
	for _, pd := range fd.FindAll("pointer_declarator") {
		if name := declaratorName(pd); name != "" {
			// An array-of-pointers is handled by the array pass above; here the
			// declarator is the field itself.
			if !isInsideArrayDeclarator(pd) {
				add(FieldFact{Name: name, Pointer: true})
			}
		}
	}
	for _, c := range fd.NamedChildren() {
		if c.Kind() == "field_identifier" {
			add(FieldFact{Name: strings.TrimSpace(c.Text())})
		}
	}
	return out
}

func isInsideArrayDeclarator(n parser.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "array_declarator" {
			return true
		}
		if p.Kind() == "field_declaration" {
			return false
		}
	}
	return false
}

// declaratorName returns the declared name of a declarator (covering plain
// identifiers and struct field identifiers).
func declaratorName(n parser.Node) string {
	switch n.Kind() {
	case "identifier", "field_identifier":
		return strings.TrimSpace(n.Text())
	case "pointer_declarator", "array_declarator", "function_declarator", "parenthesized_declarator":
		for _, c := range n.NamedChildren() {
			if name := declaratorName(c); name != "" {
				return name
			}
		}
	}
	return ""
}

// arrayCapacity resolves an array declarator's element count (numeric literal or
// object-like macro) and the macro spelling when one was used.
func arrayCapacity(ad parser.Node, macros map[string]int) (int, string, bool) {
	for _, child := range ad.NamedChildren() {
		switch child.Kind() {
		case "number_literal":
			if n := parseInt(child.Text()); n > 0 {
				return n, "", true
			}
		case "identifier":
			if n, ok := macros[strings.TrimSpace(child.Text())]; ok && n > 0 {
				return n, strings.TrimSpace(child.Text()), true
			}
		}
	}
	return 0, "", false
}

// parseInt parses a decimal/hex integer literal, -1 when not a plain literal.
func parseInt(text string) int {
	t := strings.TrimSpace(text)
	t = strings.TrimRight(t, "uUlL")
	if t == "" {
		return -1
	}
	v := 0
	if strings.HasPrefix(t, "0x") || strings.HasPrefix(t, "0X") {
		for _, r := range t[2:] {
			var d int
			switch {
			case r >= '0' && r <= '9':
				d = int(r - '0')
			case r >= 'a' && r <= 'f':
				d = int(r-'a') + 10
			case r >= 'A' && r <= 'F':
				d = int(r-'A') + 10
			default:
				return -1
			}
			v = v*16 + d
		}
		return v
	}
	for _, r := range t {
		if r < '0' || r > '9' {
			return -1
		}
		v = v*10 + int(r-'0')
	}
	return v
}

// insideFunction reports whether a node is nested in a function body.
func insideFunction(n parser.Node) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "function_definition" {
			return true
		}
	}
	return false
}
