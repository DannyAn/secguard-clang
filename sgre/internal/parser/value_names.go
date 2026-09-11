package parser

// FunctionBoundNames returns the names bound to VALUES in the function defined
// by funcDef — every parameter name plus every local declarator name, including
// declarations nested in inner blocks.
//
// It is the scope oracle for AddressTakenTargetScoped, which has to tell a type
// name from a value name to disambiguate the `(A) & x` bit-and shape that
// tree-sitter-c parses identically for a cast and for a genuine bit-and.
//
// The dangerous direction is over-collection: a TYPE name wrongly reported as a
// value would make `(T)&x` look like a bit-and, so the address-of would be
// missed and the out-parameter false positives this oracle exists to prevent
// would come back. Only declarators are therefore collected, never type
// positions: tree-sitter-c parses `typedef ...` as type_definition (not
// declaration) and a typedef used in a declaration as type_identifier, neither
// of which is an `identifier`. Under-collection is harmless by comparison — a
// missing name only falls back to the permissive recognition.
func FunctionBoundNames(funcDef Node) map[string]bool {
	names := make(map[string]bool)
	if funcDef.isNull() || funcDef.Kind() != "function_definition" {
		return names
	}

	// Parameters: each parameter_declaration has exactly one declarator, whose
	// first identifier is the bound name (`unsigned char *in` -> in).
	if decl := funcDef.ChildByFieldName("declarator"); decl != nil {
		if params := decl.ChildByFieldName("parameters"); params != nil {
			for _, p := range params.NamedChildren() {
				if p.Kind() != "parameter_declaration" {
					continue
				}
				pd := p.ChildByFieldName("declarator")
				if pd == nil {
					continue // `void`, `...`
				}
				if name := firstIdentifierName(*pd); name != "" {
					names[name] = true
				}
			}
		}
	}

	// Locals: a declaration carries one or more declarators (`int a = 0, b;`),
	// each contributing its first identifier. Type-position children are skipped
	// wholesale so a type spelling can never leak in.
	if body := funcDef.ChildByFieldName("body"); body != nil {
		for _, decl := range body.FindAll("declaration") {
			for _, child := range decl.NamedChildren() {
				if isTypePositionKind(child.Kind()) {
					continue
				}
				if name := firstIdentifierName(child); name != "" {
					names[name] = true
				}
			}
		}
	}
	return names
}

// FunctionBoundNamesByBody resolves the enclosing function_definition of a
// function body and returns its bound value names. It returns nil when the body
// is not a function body (or the tree was built without parents), which callers
// must treat as "no oracle available": the permissive recognition is then used.
func FunctionBoundNamesByBody(body Node) map[string]bool {
	if body.isNull() || body.Kind() != "compound_statement" {
		return nil
	}
	fn := body.Parent()
	if fn == nil || fn.Kind() != "function_definition" {
		return nil
	}
	return FunctionBoundNames(*fn)
}

// isTypePositionKind reports whether a declaration child kind denotes the type
// (never a bound value). Anything else in a declaration is a declarator.
func isTypePositionKind(kind string) bool {
	switch kind {
	case "primitive_type", "sized_type_specifier", "type_identifier",
		"struct_specifier", "union_specifier", "enum_specifier",
		"storage_class_specifier", "type_qualifier", "attribute_specifier",
		"attribute_declaration", "comment":
		return true
	}
	return false
}

// firstIdentifierName returns the first `identifier` in the subtree, in source
// order. It never matches `field_identifier` or `type_identifier`, so a type or
// member name is not mistaken for a bound variable.
func firstIdentifierName(n Node) string {
	if n.isNull() {
		return ""
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	for _, c := range n.NamedChildren() {
		if name := firstIdentifierName(c); name != "" {
			return name
		}
	}
	return ""
}
