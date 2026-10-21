package parser

import (
	"path/filepath"
	"strings"
)

// ValueReferencedNames returns the identifiers used as VALUES: not a callee
// name, not a declarator/type name. C decays a bare function name to a pointer,
// so `{"get", getCommand, ...}` and `.proc = handler` take the function's
// address exactly like `&handler` does. Callers intersect the result with their
// function table to build the address-taken census; over-marking is the safe
// direction (an over-marked function is treated as externally invoked, never as
// dead code).
func ValueReferencedNames(root Node) map[string]bool {
	out := map[string]bool{}
	for _, id := range root.FindAll("identifier") {
		name := strings.TrimSpace(id.Text())
		if name == "" {
			continue
		}
		p := id.Parent()
		if p == nil {
			continue
		}
		switch p.Kind() {
		case "call_expression":
			// The first named child is the callee: a call, not a value use.
			if kids := p.NamedChildren(); len(kids) > 0 && kids[0].StartByte() == id.StartByte() {
				continue
			}
		case "function_declarator", "declaration", "parameter_declaration",
			"field_declaration", "field_identifier", "type_identifier",
			"enumerator", "labeled_statement", "goto_statement",
			"preproc_def", "preproc_function_def", "preproc_include",
			"pointer_declarator", "array_declarator", "parenthesized_declarator":
			continue
		case "init_declarator":
			// Only the LAST named child is the initializer value; the declarator
			// name sits under a declarator node.
			kids := p.NamedChildren()
			if len(kids) > 0 && kids[len(kids)-1].StartByte() == id.StartByte() {
				out[name] = true
			}
			continue
		}
		out[name] = true
	}
	return out
}

// QuotedIncludePaths resolves the quoted `#include "..."` targets of a file
// relative to that file's directory. Angle-bracket includes (system headers) and
// absolute paths are skipped. The result is cleaned but NOT checked for
// existence: the caller decides how to read it.
func QuotedIncludePaths(filePath string, root Node) []string {
	dir := filepath.Dir(filePath)
	var out []string
	for _, inc := range root.FindAll("preproc_include") {
		for _, c := range inc.NamedChildren() {
			if c.Kind() != "string_literal" {
				continue
			}
			lit := strings.Trim(strings.TrimSpace(c.Text()), `"`)
			if lit == "" || filepath.IsAbs(lit) {
				break
			}
			out = append(out, filepath.Clean(filepath.Join(dir, lit)))
			break
		}
	}
	return out
}
