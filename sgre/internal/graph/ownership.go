package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
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
//
// Contract: these edges are a NARROW safety net, not the primary escape
// analysis. The evidence detectors' findEscapeLines treats any store to a
// non-local (global/static/field/subscript base) as ownership escape, while the
// graph layer only recognizes the `g_`-prefixed globals (isGlobalName). The
// detector is the wide, authoritative decision; OwnershipTransferFilter drops a
// leak candidate only when the graph caught a transfer the detector missed.
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
	"munmap": true, "g_free": true, "av_free": true, "xmlFree": true,
	"sqlite3_free": true, "Py_DECREF": true, "XFree": true, "kfree": true,
	"HeapFree": true,
}

func (b *OwnershipBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	err := forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		returns := root.FindAll("return_statement")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")

		for _, f := range funcs {
			for _, ret := range nodesInRange(returns, f.StartLine, f.EndLine) {
				if isErrorReturn(ret) {
					continue // error exit (`if (fd < 0) return fd`) is not a transfer
				}
				for _, child := range ret.NamedChildren() {
					if id := rhsIdentifier(child); id != "" {
						if b.persistTransfer(ctx, f, id, "return", "", ret.StartLine()) {
							result.EdgesCreated++
						}
					}
				}
			}

			for _, assign := range nodesInRange(assigns, f.StartLine, f.EndLine) {
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

			for _, call := range nodesInRange(calls, f.StartLine, f.EndLine) {
				callName := extractCallName(call)
				if !releaseFunctions[callName] && !apikb.IsDeallocator(callName) {
					continue
				}
				arg := releaseArgIdentifier(call, callName)
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
		warnEdge(b.logger, "OWNERSHIP_TRANSFER", f.Name, err)
		return false
	}

	var dstNode int64
	if kind == "return" {
		dstNode, err = b.store.GetOrCreateGraphNode(ctx, "return_slot", f.ID, "")
	} else {
		dstNode, err = b.store.GetOrCreateGraphNode(ctx, "global_var", 0, fmt.Sprintf(`{"name":"%s"}`, globalName))
	}
	if err != nil {
		warnEdge(b.logger, "OWNERSHIP_TRANSFER", f.Name, err)
		return false
	}

	props := marshalProps(b.logger, "OWNERSHIP_TRANSFER", map[string]string{"kind": kind, "variable": variable, "global": globalName})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      srcNode,
		DstID:      dstNode,
		EdgeType:   "OWNERSHIP_TRANSFER",
		Properties: props,
	})
	if err != nil {
		warnEdge(b.logger, "OWNERSHIP_TRANSFER", f.Name, err)
		return false
	}
	return true
}

// persistRelease emits a RELEASE edge from the variable_ref of the released
// pointer to the external_function node of the release function.
func (b *OwnershipBuilder) persistRelease(ctx context.Context, f *db.Function, variable, callName string, line int) bool {
	srcNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", f.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, variable, line))
	if err != nil {
		warnEdge(b.logger, "RELEASE", f.Name, err)
		return false
	}
	// Name the external_function node so free/fclose/close/etc. resolve to
	// distinct nodes instead of collapsing onto one anonymous external node.
	props := marshalProps(b.logger, "RELEASE", map[string]string{"name": callName, "external": "true"})
	dstNode, err := b.store.GetOrCreateGraphNode(ctx, "external_function", 0, props)
	if err != nil {
		warnEdge(b.logger, "RELEASE", f.Name, err)
		return false
	}

	edgeProps := marshalProps(b.logger, "RELEASE", map[string]string{"variable": variable, "release_fn": callName})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      srcNode,
		DstID:      dstNode,
		EdgeType:   "RELEASE",
		Properties: edgeProps,
	})
	if err != nil {
		warnEdge(b.logger, "RELEASE", f.Name, err)
		return false
	}
	return true
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
	return argIdentifierAt(call, 0)
}

// argIdentifierAt returns the argument at position index when it is a bare
// identifier, else "".
func argIdentifierAt(call parser.Node, index int) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() != "argument_list" {
			continue
		}
		args := child.NamedChildren()
		if index < len(args) && args[index].Kind() == "identifier" {
			return args[index].Text()
		}
	}
	return ""
}

// releaseArgIdentifier returns the argument whose ownership a release call
// destroys. Most release functions take the object as their first argument, but
// freopen(path, mode, stream) releases the third (stream) and HeapFree(hHeap,
// flags, lpMem) releases the third (lpMem).
func releaseArgIdentifier(call parser.Node, callName string) string {
	if callName == "freopen" || callName == "HeapFree" {
		return argIdentifierAt(call, 2)
	}
	return argIdentifierAt(call, 0)
}

// isErrorReturn reports whether ret is an error exit that returns the checked
// variable itself (`if (fd < 0) return fd;` / `if (p == NULL) return p;`). On
// that path the variable holds no resource (fd is -1, p is NULL), so it is an
// error-code exit, not an ownership transfer to the caller. Without this, the
// OWNERSHIP_TRANSFER edge would swallow a real leak whose acquire-failure return
// was misread as a transfer.
func isErrorReturn(ret parser.Node) bool {
	var name string
	for _, child := range ret.NamedChildren() {
		if id := rhsIdentifier(child); id != "" {
			name = id
			break
		}
	}
	if name == "" {
		return false
	}
	for p := ret.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "if_statement":
			cond := p.ChildByFieldName("condition")
			return cond != nil && errorCheckedVarIs(*cond, name)
		case "compound_statement":
			// A braced if body (`if (fd < 0) { return fd; }`) puts the return under
			// a compound_statement whose parent is the if; keep walking to reach the
			// if. Stop only at the FUNCTION body compound_statement, whose parent is
			// a function_definition (not an error exit).
			gp := p.Parent()
			if gp != nil && gp.Kind() == "if_statement" {
				continue
			}
			return false
		}
	}
	return false
}

// errorCheckedVarIs reports whether a condition tests name for failure
// (`fd < 0`, `fd == NULL`, `fd == -1`, `fd <= 0`). It compares the AST operand
// exactly, so `if (nfd < 0) return fd` does NOT match name "fd" (the previous
// strings.Contains("fd < 0") matched the "nfd < 0" substring and misread the
// return as an error exit, swallowing the transfer) — ML-10.
func errorCheckedVarIs(cond parser.Node, name string) bool {
	inner := cond
	for inner.Kind() == "parenthesized_expression" || inner.Kind() == "cast_expression" {
		kids := inner.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		inner = kids[0]
	}
	if inner.Kind() != "binary_expression" {
		return false
	}
	op := parser.BinaryOperator(inner)
	kids := inner.NamedChildren()
	if len(kids) < 2 {
		return false
	}
	nameIdx := -1
	for i, k := range kids {
		if k.Kind() == "identifier" && k.Text() == name {
			nameIdx = i
			break
		}
	}
	if nameIdx < 0 {
		return false
	}
	other := kids[1-nameIdx]
	switch op {
	case "==":
		return isFailureConstant(other)
	case "<", "<=":
		// `name < 0` / `name <= 0` require name on the LEFT side.
		return nameIdx == 0 && strings.TrimSpace(other.Text()) == "0"
	}
	return false
}

func isFailureConstant(n parser.Node) bool {
	t := strings.TrimSpace(n.Text())
	return t == "0" || t == "-1" || parser.IsNullOperand(n)
}
