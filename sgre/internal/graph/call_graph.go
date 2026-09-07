package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type CallGraphBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

type BuildResult struct {
	EdgesCreated  int `json:"edges_created"`
	ExternalFuncs int `json:"external_funcs"`
}

func NewCallGraphBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *CallGraphBuilder {
	return &CallGraphBuilder{store: store, parser: p, logger: logger}
}

func (b *CallGraphBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	funcs, err := b.store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("call graph: list functions: %w", err)
	}

	// C allows distinct static functions with the same name across files; a
	// name->single-ID map silently shadows all but the last one and would drop
	// every CALL edge into the shadowed functions (and, via call_reach, every
	// candidate in them). Track one ID per definition, mirroring interproc.go.
	funcMap := make(map[string][]int64)
	for _, f := range funcs {
		funcMap[f.Name] = append(funcMap[f.Name], f.ID)
	}

	// Functions whose address is referenced outside a direct call (function
	// pointer tables, pthread_create thread fn, callback registration) are
	// invoked indirectly, so the direct CALL graph has no edge into them. Mark
	// them with a self ADDR_TAKEN edge; call_reach treats those as entry points
	// so a static function wired up through a pointer table is not dropped as
	// "unreachable" (a systematic false negative across every vuln type).
	addrRefs := make(map[string]bool)

	err = forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, fileFuncs []*db.Function) {
		callNodes := root.FindAll("call_expression")
		for name := range collectAddrRefNames(root, funcMap) {
			addrRefs[name] = true
		}

		for _, f := range fileFuncs {
			callerNodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", f.ID, "")
			if err != nil {
				if b.logger != nil {
					b.logger.Warn("failed to create graph node", "function", f.Name, "error", err)
				}
				continue
			}

			for _, callNode := range nodesInRange(callNodes, f.StartLine, f.EndLine) {
				callName := extractCallName(callNode)
				if callName == "" {
					continue
				}

				calleeIDs := funcMap[callName]
				if len(calleeIDs) == 0 {
					props := marshalProps(b.logger, "CALL", map[string]string{"name": callName, "external": "true"})
					calleeNodeID, err := b.store.GetOrCreateGraphNode(ctx, "external_function", 0, props)
					if err != nil {
						warnEdge(b.logger, "CALL", f.Name, err)
						continue
					}
					b.insertCallEdge(ctx, f, callerNodeID, calleeNodeID, callNode.StartLine(), result)
					result.ExternalFuncs++
					continue
				}
				// Emit one CALL edge per same-name callee (each is a distinct
				// function node) so no definition is silently shadowed.
				for _, calleeID := range calleeIDs {
					calleeNodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", calleeID, "")
					if err != nil {
						warnEdge(b.logger, "CALL", f.Name, err)
						continue
					}
					b.insertCallEdge(ctx, f, callerNodeID, calleeNodeID, callNode.StartLine(), result)
				}
			}
		}
	})
	if err != nil {
		return nil, err
	}

	for name := range addrRefs {
		for _, fid := range funcMap[name] {
			nodeID, err := b.store.GetOrCreateGraphNode(ctx, "function", fid, "")
			if err != nil {
				warnEdge(b.logger, "ADDR_TAKEN", name, err)
				continue
			}
			if err := b.insertSelfEdge(ctx, nodeID); err != nil {
				warnEdge(b.logger, "ADDR_TAKEN", name, err)
			}
		}
	}

	return result, nil
}

// insertSelfEdge persists a self-loop ADDR_TAKEN edge marking the function as
// address-referenced (indirectly invocable). call_reach consumes the edge's
// source node as an entry point.
func (b *CallGraphBuilder) insertSelfEdge(ctx context.Context, nodeID int64) error {
	props := marshalProps(b.logger, "ADDR_TAKEN", map[string]string{"indirect": "true"})
	_, err := b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      nodeID,
		DstID:      nodeID,
		EdgeType:   "ADDR_TAKEN",
		Properties: props,
	})
	return err
}

// collectAddrRefNames returns the names of functions whose address is referenced
// outside a direct call: taken via `&f`, listed in an initializer (`g_fns[] =
// {f1, f2}`), passed as a call argument (`pthread_create(..., f, ...)`), or
// assigned. It deliberately skips an identifier sitting in a declarator/
// declaration (the function's own definition/prototype) and one that is the
// direct callee of a call expression, so a plain `f()` call is never read as an
// address reference.
func collectAddrRefNames(root parser.Node, funcMap map[string][]int64) map[string]bool {
	refs := make(map[string]bool)
	for _, id := range root.FindAll("identifier") {
		name := id.Text()
		if _, ok := funcMap[name]; !ok {
			continue
		}
		parent := id.Parent()
		if parent == nil {
			continue
		}
		if strings.Contains(parent.Kind(), "declarator") || parent.Kind() == "declaration" {
			continue
		}
		if parent.Kind() == "call_expression" && isDirectCallee(*parent, id) {
			continue
		}
		refs[name] = true
	}
	return refs
}

// isDirectCallee reports whether id is the function-position child of a call
// expression (a plain `f(...)` call), as opposed to an argument that happens to
// name a function.
func isDirectCallee(call parser.Node, id parser.Node) bool {
	children := call.NamedChildren()
	if len(children) == 0 {
		return false
	}
	fn := children[0]
	return fn.Kind() == "identifier" && fn.StartByte() == id.StartByte() && fn.EndByte() == id.EndByte()
}

// insertCallEdge persists one CALL edge with call_line set to the call site
// line (previously it stamped the callee function's start line, a latent bug).
func (b *CallGraphBuilder) insertCallEdge(ctx context.Context, f *db.Function, callerNodeID, calleeNodeID int64, callLine int, result *BuildResult) {
	props := marshalProps(b.logger, "CALL", map[string]int{"call_line": callLine})
	_, err := b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      callerNodeID,
		DstID:      calleeNodeID,
		EdgeType:   "CALL",
		Properties: props,
	})
	if err != nil {
		warnEdge(b.logger, "CALL", f.Name, err)
		return
	}
	result.EdgesCreated++
}

func extractCallName(node parser.Node) string {
	for _, child := range node.NamedChildren() {
		if child.Kind() == "identifier" || child.Kind() == "field_expression" {
			return child.Text()
		}
	}
	return ""
}
