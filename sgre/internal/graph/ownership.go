package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// OwnershipBuilder persists the ownership edges that memory-leak / resource-leak
// analysis needs to reason about pointer escape and release:
//
//   - OWNERSHIP_TRANSFER: the object pointed to by p leaves this function's
//     ownership — either `return p` (ownership passes to the caller) or a store
//     into a global (`g_x = p`, `g_arr[i] = p`). Edge: variable_ref(p) ->
//     return_slot / global_var.
//   - RELEASE: ownership of p is released at a deallocation call (free/fclose/
//     close/...). Edge: variable_ref(p) -> the external_function node of the
//     release function.
//
// These were previously computed in-memory by the evidence package's
// buildFuncSummaries (ReturnStores / GlobalFrees) and never persisted, so the
// graph layer's OWNERSHIP_TRANSFER / RELEASE edge types were declared but empty.
type OwnershipBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewOwnershipBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *OwnershipBuilder {
	return &OwnershipBuilder{store: store, parser: p, logger: logger}
}

// releaseFunctions are the deallocation/release sinks whose single pointer
// argument's ownership is destroyed by the call.
var releaseFunctions = map[string]bool{
	"free": true, "fclose": true, "close": true, "pclose": true,
	"closedir": true, "fcloseall": true, "freopen": true,
}

func (b *OwnershipBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	err := forEachFile(ctx, b.store, b.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")

		for _, f := range funcs {
			for _, ret := range returns {
				if !funcLineRange(f, ret.StartLine()) {
					continue
				}
				for _, child := range ret.NamedChildren() {
					if child.Kind() != "identifier" {
						continue
					}
					if b.persistTransfer(ctx, f, child.Text(), "return", "", ret.StartLine()) {
						result.EdgesCreated++
					}
				}
			}

			for _, assign := range assigns {
				if !funcLineRange(f, assign.StartLine()) {
					continue
				}
				children := assign.NamedChildren()
				if len(children) < 2 {
					continue
				}
				globalName := globalStoreTarget(children[0])
				if globalName == "" {
					continue
				}
				if rhs := rhsIdentifier(children[1]); rhs != "" {
					if b.persistTransfer(ctx, f, rhs, "global", globalName, assign.StartLine()) {
						result.EdgesCreated++
					}
				}
			}

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callName := extractCallName(call)
				if !releaseFunctions[callName] {
					continue
				}
				arg := firstArgIdentifier(call)
				if arg == "" {
					continue
				}
				if b.persistRelease(ctx, f, arg, callName, call.StartLine()) {
					result.EdgesCreated++
				}
			}
		}
	})
	return result, err
}

// persistTransfer emits an OWNERSHIP_TRANSFER edge from the variable_ref of the
// escaped pointer to the return_slot (kind "return") or a global_var node (kind
// "global").
func (b *OwnershipBuilder) persistTransfer(ctx context.Context, f *db.Function, variable, kind, globalName string, line int) bool {
	srcNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, variable, line))
	if err != nil {
		return false
	}

	var dstNode int64
	if kind == "return" {
		dstNode, err = b.store.GetOrCreateGraphNode(ctx, "return_slot", f.ID, "")
	} else {
		dstNode, err = b.store.GetOrCreateGraphNode(ctx, "global_var", 0, fmt.Sprintf(`{"name":"%s"}`, globalName))
	}
	if err != nil {
		return false
	}

	props, _ := json.Marshal(map[string]string{"kind": kind, "variable": variable, "global": globalName})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      srcNode,
		DstID:      dstNode,
		EdgeType:   "OWNERSHIP_TRANSFER",
		Properties: string(props),
	})
	return err == nil
}

// persistRelease emits a RELEASE edge from the variable_ref of the released
// pointer to the external_function node of the release function.
func (b *OwnershipBuilder) persistRelease(ctx context.Context, f *db.Function, variable, callName string, line int) bool {
	srcNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, variable, line))
	if err != nil {
		return false
	}
	props, _ := json.Marshal(map[string]bool{"external": true})
	dstNode, err := b.store.GetOrCreateGraphNode(ctx, "external_function", 0, string(props))
	if err != nil {
		return false
	}

	edgeProps, _ := json.Marshal(map[string]string{"variable": variable, "release_fn": callName})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      srcNode,
		DstID:      dstNode,
		EdgeType:   "RELEASE",
		Properties: string(edgeProps),
	})
	return err == nil
}

// globalStoreTarget returns the global name when lhs is a store into a global
// (g_x = ... or g_arr[i] = ... or g_obj.f = ...), matching the evidence package's
// g_-prefix convention, else "".
func globalStoreTarget(lhs parser.Node) string {
	switch lhs.Kind() {
	case "identifier":
		if isGlobalName(lhs.Text()) {
			return lhs.Text()
		}
	case "subscript_expression", "field_expression":
		children := lhs.NamedChildren()
		if len(children) >= 1 {
			return globalStoreTarget(children[0])
		}
	}
	return ""
}

func isGlobalName(name string) bool {
	return len(name) >= 2 && name[0] == 'g' && name[1] == '_'
}

// rhsIdentifier returns the bare identifier on the RHS (unwrapping one level of
// parenthesization/cast), else "".
func rhsIdentifier(rhs parser.Node) string {
	switch rhs.Kind() {
	case "identifier":
		return rhs.Text()
	case "parenthesized_expression", "cast_expression":
		for _, c := range rhs.NamedChildren() {
			if id := rhsIdentifier(c); id != "" {
				return id
			}
		}
	}
	return ""
}

// firstArgIdentifier returns the first argument when it is a bare identifier,
// else "".
func firstArgIdentifier(call parser.Node) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() != "argument_list" {
			continue
		}
		args := child.NamedChildren()
		if len(args) >= 1 && args[0].Kind() == "identifier" {
			return args[0].Text()
		}
	}
	return ""
}
