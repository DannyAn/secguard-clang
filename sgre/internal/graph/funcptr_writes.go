package graph

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// FuncPtrWriteBuilder records function-pointer slot -> target wirings (GAP-02):
// `ops->open = my_open`, `.open = my_open`, and `fp = my_fn` write which function
// a slot (a struct field or a function-pointer variable) is wired to. It runs
// BEFORE the CallGraphBuilder so an indirect call `ops->open(p)` can resolve to
// a real CALL edge instead of an external edge (or no edge for `(*fp)(p)`).
//
// The slot key is the field name (or variable name) — the design's "档 2" field
// tier. The typed (type_name, field) tier is a future precision upgrade; the
// field-only tier can conflate two same-named fields wired to different targets,
// which only makes the summary more conservative (it never fabricates a FP).
type FuncPtrWriteBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewFuncPtrWriteBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *FuncPtrWriteBuilder {
	return &FuncPtrWriteBuilder{store: store, parser: p, logger: logger}
}

func (b *FuncPtrWriteBuilder) Build(ctx context.Context) error {
	var funcs []*db.Function
	if ri := RepoIndexFromCtx(ctx); ri != nil {
		funcs = ri.Functions()
	} else {
		var err error
		funcs, err = b.store.ListFunctions(ctx)
		if err != nil {
			return fmt.Errorf("func ptr writes: list functions: %w", err)
		}
	}
	funcMap := make(map[string]bool, len(funcs))
	for _, f := range funcs {
		funcMap[f.Name] = true
	}

	var writes []db.FuncPtrWrite
	var err error
	err = forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, _ []*db.Function) {
		for _, assign := range root.FindAll("assignment_expression") {
			named := assign.NamedChildren()
			if len(named) < 2 {
				continue
			}
			slot := funcPtrSlotName(named[0])
			target := funcPtrTargetName(named[1], funcMap)
			if slot == "" || target == "" {
				continue
			}
			writes = append(writes, db.FuncPtrWrite{SlotName: slot, TargetName: target, File: file.Path, Line: assign.StartLine()})
		}
		for _, pair := range root.FindAll("initializer_pair") {
			named := pair.NamedChildren()
			if len(named) < 2 {
				continue
			}
			slot := fieldDesignatorName(named[0])
			target := funcPtrTargetName(named[1], funcMap)
			if slot == "" || target == "" {
				continue
			}
			writes = append(writes, db.FuncPtrWrite{SlotName: slot, TargetName: target, File: file.Path, Line: pair.StartLine()})
		}
	})
	if err != nil {
		return err
	}
	return b.store.ReplaceFuncPtrWrites(ctx, writes)
}

// funcPtrSlotName returns the slot key of a write target: the field name of a
// field_expression LHS (`ops->open` → "open"), or the bare variable name of an
// identifier LHS (`fp` → "fp").
func funcPtrSlotName(lhs parser.Node) string {
	l := stripParenNode(lhs)
	switch l.Kind() {
	case "identifier":
		return l.Text()
	case "field_expression":
		return fieldNameOf(l)
	}
	return ""
}

// fieldNameOf returns the field_identifier of a field_expression (`ops->open` →
// "open"), or "" when the node is not a clean field access.
func fieldNameOf(n parser.Node) string {
	for _, c := range n.NamedChildren() {
		if c.Kind() == "field_identifier" {
			return c.Text()
		}
	}
	return ""
}

// funcPtrTargetName returns the RHS function name when it is a bare (or
// cast/parenthesized) identifier that names an in-scan function.
func funcPtrTargetName(rhs parser.Node, funcMap map[string]bool) string {
	r := stripParenNode(rhs)
	if r.Kind() != "identifier" {
		return ""
	}
	if !funcMap[r.Text()] {
		return ""
	}
	return r.Text()
}

func stripParenNode(n parser.Node) parser.Node {
	for n.Kind() == "parenthesized_expression" || n.Kind() == "cast_expression" {
		kids := n.NamedChildren()
		if len(kids) == 0 {
			return n
		}
		n = kids[len(kids)-1]
	}
	return n
}

func fieldDesignatorName(d parser.Node) string {
	if d.Kind() != "field_designator" {
		return ""
	}
	for _, c := range d.NamedChildren() {
		if c.Kind() == "field_identifier" {
			return c.Text()
		}
	}
	return ""
}
