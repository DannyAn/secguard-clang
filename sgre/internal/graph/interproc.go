package graph

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// InterprocBuilder persists the inter-procedural dataflow edges that the null /
// ownership flow engine needs to propagate facts across function boundaries:
//
//   - PARAM_BINDING: at a call site, a positional actual argument (a bare
//     identifier) is bound to the callee's formal parameter. Edge:
//     variable_ref(actual) -> parameter(callee). This is the graph-native
//     replacement for the evidence package's ad-hoc event-index join in
//     interprocedural.go.
//   - RETURN: the callee's return value flows into the caller's receiving
//     variable (x = f(...)). Edge: return_slot(callee) -> variable_ref(x).
//
// Previously this cross-function dataflow was computed on demand via name
// matching and event-index joins, never persisted as graph edges.
type InterprocBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	edges  *edgeBatchWriter
}

func NewInterprocBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *InterprocBuilder {
	return &InterprocBuilder{store: store, parser: p, logger: logger}
}

func (b *InterprocBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}
	b.edges = newEdgeBatchWriter(b.store, b.logger, 0)

	var funcs []*db.Function
	if ri := RepoIndexFromCtx(ctx); ri != nil {
		funcs = ri.Functions()
	} else {
		var err error
		funcs, err = b.store.ListFunctions(ctx)
		if err != nil {
			return nil, fmt.Errorf("interproc: list functions: %w", err)
		}
	}

	funcByName := make(map[string][]int64)
	nameByID := make(map[int64]string)
	for _, f := range funcs {
		funcByName[f.Name] = append(funcByName[f.Name], f.ID)
		nameByID[f.ID] = f.Name
	}

	// Function-pointer slot -> target wirings (GAP-02), loaded once so an
	// indirect call `ops->open(p)` binds its positional args to the RESOLVED
	// target's parameters (mirrors CallGraphBuilder's CALL-edge resolution).
	slotTargets := make(map[string][]string)
	if fpWrites, ferr := b.store.ListFuncPtrWrites(ctx); ferr == nil {
		for _, w := range fpWrites {
			slotTargets[w.SlotName] = append(slotTargets[w.SlotName], w.TargetName)
		}
	} else if b.logger != nil {
		b.logger.Warn("interproc: func ptr writes load failed (indirect PARAM_BINDING unresolved)", "error", ferr)
	}

	// paramsByFunc maps function ID -> positional parameter names. It is built in
	// a dedicated first pass over ALL files, because a call site may reference a
	// callee whose definition lives in a file that forEachFile has not reached
	// yet. The previous single-pass version accumulated paramsByFunc while it was
	// being consumed, so any such forward cross-file reference saw an empty
	// paramsByFunc[calleeID] and silently dropped the PARAM_BINDING edge.
	paramsByFunc := make(map[int64][]string)

	var err error
	err = forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		paramsByLine := make(map[int][]string)
		for _, def := range root.FindAll("function_definition") {
			paramsByLine[def.StartLine()] = extractParams(def)
		}
		for _, f := range fileFuncs {
			if p, ok := paramsByLine[f.StartLine]; ok {
				paramsByFunc[f.ID] = p
			}
		}
	})
	if err != nil {
		return nil, err
	}

	// Second pass: emit PARAM_BINDING / RETURN edges, now that paramsByFunc is
	// complete for every function regardless of file order.
	err = forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		calls := root.FindAll("call_expression")
		assigns := root.FindAll("assignment_expression")
		inits := root.FindAll("init_declarator")

		for _, f := range fileFuncs {
			for _, call := range nodesInRange(calls, f.StartLine, f.EndLine) {
				calleeName := extractCallName(call)
				calleeIDs := funcByName[calleeName]
				// An unresolved direct name is an indirect call through a
				// function-pointer slot (GAP-02): `ops->open(p)` / `(*fp)(p)`.
				// Resolve the slot to its target(s) so the positional args bind
				// to the REAL callee's parameters (a missed binding was a silent
				// null/ownership-flow false negative for slot-registered calls).
				if len(calleeIDs) == 0 {
					if slot := indirectSlotName(call); slot != "" {
						for _, target := range slotTargets[slot] {
							calleeIDs = append(calleeIDs, funcByName[target]...)
						}
					}
				}
				if len(calleeIDs) == 0 {
					continue
				}
				args := callArgs(call)
				for _, calleeID := range calleeIDs {
					params := paramsByFunc[calleeID]
					resolvedName := nameByID[calleeID]
					if resolvedName == "" {
						resolvedName = calleeName
					}
					for i, arg := range args {
						if i >= len(params) {
							break
						}
						// An unnamed parameter (void handler(int, void *data))
						// leaves a "" entry in params; skip it and keep binding the
						// remaining positional args. A break here would silently
						// sever the taint flow into every parameter after the
						// anonymous one.
						if params[i] == "" {
							continue
						}
						if arg.Kind() != "identifier" {
							continue
						}
						if b.persistParamBinding(ctx, f, calleeID, resolvedName, params[i], i, arg.Text(), call.StartLine()) {
							result.EdgesCreated++
						}
					}
				}
			}

			// RETURN edges: x = f(...) as either a plain assignment (assignment_expression)
			// or a declaration initializer (init_declarator: int x = f(...)).
			for _, assign := range nodesInRange(assigns, f.StartLine, f.EndLine) {
				children := assign.NamedChildren()
				if len(children) < 2 {
					continue
				}
				if b.bindReturn(ctx, f, funcByName, children[0], children[1], assign.StartLine()) {
					result.EdgesCreated++
				}
			}
			for _, init := range nodesInRange(inits, f.StartLine, f.EndLine) {
				lhs, rhs, ok := init.AssignParts()
				if !ok {
					continue
				}
				if b.bindReturn(ctx, f, funcByName, lhs, rhs, init.StartLine()) {
					result.EdgesCreated++
				}
			}
		}
	})
	b.edges.flush(ctx)
	return result, err
}

func (b *InterprocBuilder) persistParamBinding(ctx context.Context, caller *db.Function, calleeID int64, calleeName, paramName string, index int, argName string, line int) bool {
	actualNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", caller.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, argName, line))
	if err != nil {
		warnEdge(b.logger, "PARAM_BINDING", caller.Name, err)
		return false
	}
	formalProps := marshalProps(b.logger, "PARAM_BINDING", map[string]interface{}{"name": paramName, "index": index})
	formalNode, err := b.store.GetOrCreateGraphNode(ctx, "parameter", calleeID, formalProps)
	if err != nil {
		warnEdge(b.logger, "PARAM_BINDING", caller.Name, err)
		return false
	}
	props := marshalProps(b.logger, "PARAM_BINDING", map[string]interface{}{"callee": calleeName, "index": index, "param": paramName})
	b.edges.add(ctx, actualNode, formalNode, "PARAM_BINDING", props)
	return true
}

func (b *InterprocBuilder) persistReturn(ctx context.Context, caller *db.Function, calleeID int64, calleeName, lhsName string, line int) bool {
	retNode, err := b.store.GetOrCreateGraphNode(ctx, "return_slot", calleeID, "")
	if err != nil {
		warnEdge(b.logger, "RETURN", caller.Name, err)
		return false
	}
	dstNode, err := b.store.GetOrCreateGraphNode(ctx, "variable_ref", caller.ID, fmt.Sprintf(`{"name":"%s","line":%d}`, lhsName, line))
	if err != nil {
		warnEdge(b.logger, "RETURN", caller.Name, err)
		return false
	}
	props := marshalProps(b.logger, "RETURN", map[string]string{"callee": calleeName, "variable": lhsName})
	b.edges.add(ctx, retNode, dstNode, "RETURN", props)
	return true
}

// bindReturn emits RETURN edges for a single (lhs, rhs) assignment/initializer
// pair when rhs is a call to a known function. It reports whether any edge was
// created, so the caller can count it.
func (b *InterprocBuilder) bindReturn(ctx context.Context, f *db.Function, funcByName map[string][]int64, lhs, rhs parser.Node, line int) bool {
	lhsName := assignTargetName(lhs)
	if lhsName == "" {
		return false
	}
	calleeName := callNameFromExpr(rhs)
	if calleeName == "" {
		return false
	}
	created := false
	for _, calleeID := range funcByName[calleeName] {
		if b.persistReturn(ctx, f, calleeID, calleeName, lhsName, line) {
			created = true
		}
	}
	return created
}

// extractParams returns the positional parameter names of a function_definition.
func extractParams(fnNode parser.Node) []string {
	for _, child := range fnNode.NamedChildren() {
		if child.Kind() == "function_declarator" {
			return extractParamsFromDeclarator(child)
		}
		if child.Kind() == "pointer_declarator" {
			for _, gc := range child.NamedChildren() {
				if gc.Kind() == "function_declarator" {
					return extractParamsFromDeclarator(gc)
				}
			}
		}
	}
	return nil
}

func extractParamsFromDeclarator(decl parser.Node) []string {
	var params []string
	for _, child := range decl.NamedChildren() {
		if child.Kind() != "parameter_list" {
			continue
		}
		for _, param := range child.NamedChildren() {
			if param.Kind() != "parameter_declaration" {
				continue
			}
			params = append(params, paramName(param))
		}
	}
	return params
}

// paramName extracts the identifier a parameter_declaration declares.
func paramName(param parser.Node) string {
	for _, pc := range param.NamedChildren() {
		if pc.Kind() == "identifier" {
			return pc.Text()
		}
		if pc.Kind() == "pointer_declarator" || pc.Kind() == "array_declarator" {
			if name := declaratorName(pc); name != "" {
				return name
			}
		}
	}
	return ""
}

// callArgs returns the argument_list children of a call_expression.
func callArgs(call parser.Node) []parser.Node {
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			return child.NamedChildren()
		}
	}
	return nil
}

// callNameFromExpr returns the called function name when expr is a call_expression
// (possibly wrapped in a cast or parentheses), else "".
func callNameFromExpr(expr parser.Node) string {
	switch expr.Kind() {
	case "call_expression":
		return extractCallName(expr)
	case "parenthesized_expression", "cast_expression":
		for _, c := range expr.NamedChildren() {
			if name := callNameFromExpr(c); name != "" {
				return name
			}
		}
	}
	return ""
}
