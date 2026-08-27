package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// AliasBuilder persists ALIAS edges: a variable assigned another variable's
// value (q = p), a field of it (q = p->f), or an element of it (q = p[i])
// becomes an alias of that variable. The edge points from the aliasing variable
// (q) to the aliased base variable (p) and carries a `field` property ("" for a
// whole-variable alias, "f" for q = p->f, "[]" for q = p[i]).
//
// This is the graph-native replacement for the detector-side findAliases name
// matching: the flow engine consumes these edges to propagate a freed/null fact
// from a variable to every variable that aliases it (p=malloc(); q=p; free(p);
// *q), which was previously only caught for same-function whole-variable copies.
type AliasBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewAliasBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *AliasBuilder {
	return &AliasBuilder{store: store, parser: p, logger: logger}
}

// aliasRecord is one extracted alias assignment (aliasVar aliases baseVar, or
// baseVar.field / baseVar[]).
type aliasRecord struct {
	alias string
	base  string
	field string
}

func (b *AliasBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	err := forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")

		for _, f := range funcs {
			for _, a := range assigns {
				if !funcLineRange(f, a.StartLine()) {
					continue
				}
				if rec, ok := aliasFromAssign(a); ok && b.persistAlias(ctx, f, rec, a.StartLine()) {
					result.EdgesCreated++
				}
			}
			for _, init := range inits {
				if !funcLineRange(f, init.StartLine()) {
					continue
				}
				if rec, ok := aliasFromAssign(init); ok && b.persistAlias(ctx, f, rec, init.StartLine()) {
					result.EdgesCreated++
				}
			}
		}
	})
	return result, err
}

func (b *AliasBuilder) persistAlias(ctx context.Context, f *db.Function, rec aliasRecord, line int) bool {
	aliasNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, rec.alias, line))
	if err != nil {
		return false
	}
	baseNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, rec.base, line))
	if err != nil {
		return false
	}
	props, _ := json.Marshal(map[string]string{"field": rec.field, "variable": rec.alias})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      aliasNode,
		DstID:      baseNode,
		EdgeType:   "ALIAS",
		Properties: string(props),
	})
	return err == nil
}

// aliasFromAssign extracts (aliasVar, baseVar, field) from an assignment_expression
// or init_declarator whose RHS is an identifier, a field access, or a subscript
// access. It returns ok=false for anything that is not a value alias (e.g. a
// call result, an address-of, or a literal).
func aliasFromAssign(node parser.Node) (aliasRecord, bool) {
	children := node.NamedChildren()
	if len(children) < 2 {
		return aliasRecord{}, false
	}
	lhs, rhs := children[0], children[1]
	aliasVar := assignTargetName(lhs)
	if aliasVar == "" {
		return aliasRecord{}, false
	}
	switch rhs.Kind() {
	case "identifier":
		return aliasRecord{alias: aliasVar, base: rhs.Text()}, true
	case "field_expression":
		b, fld := fieldBase(rhs)
		if b == "" {
			return aliasRecord{}, false
		}
		return aliasRecord{alias: aliasVar, base: b, field: fld}, true
	case "subscript_expression":
		b := subscriptBase(rhs)
		if b == "" {
			return aliasRecord{}, false
		}
		return aliasRecord{alias: aliasVar, base: b, field: "[]"}, true
	}
	return aliasRecord{}, false
}

// assignTargetName returns the tracked variable name an assignment writes to.
// Writing through a dereference (`*p = ...`) returns "" because it does not
// change p itself (it is a write to the pointee, not an alias of p).
func assignTargetName(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		return lhs.Text()
	case "field_expression", "subscript_expression":
		return lhs.Text()
	case "pointer_declarator", "array_declarator", "function_declarator":
		return declaratorName(lhs)
	}
	return ""
}

// declaratorName extracts the identifier a declarator names, recursing through
// pointer/array/function declarators.
func declaratorName(n parser.Node) string {
	if n.Kind() == "identifier" {
		return n.Text()
	}
	for _, c := range n.NamedChildren() {
		if c.Kind() == "identifier" {
			return c.Text()
		}
		if name := declaratorName(c); name != "" {
			return name
		}
	}
	return ""
}

// fieldBase returns (base, field) for a field_expression `p->f` or `p.f`.
func fieldBase(node parser.Node) (string, string) {
	children := node.NamedChildren()
	if len(children) < 2 {
		return "", ""
	}
	base := ""
	if children[0].Kind() == "identifier" {
		base = children[0].Text()
	}
	field := ""
	if children[1].Kind() == "field_identifier" {
		field = children[1].Text()
	}
	return base, field
}

// subscriptBase returns the base identifier of a subscript_expression `p[i]`.
func subscriptBase(node parser.Node) string {
	children := node.NamedChildren()
	if len(children) >= 1 && children[0].Kind() == "identifier" {
		return children[0].Text()
	}
	return ""
}
