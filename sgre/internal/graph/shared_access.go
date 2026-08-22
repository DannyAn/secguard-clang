package graph

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// SharedAccessBuilder persists GLOBAL_ACCESS edges: function -> global_var, with
// a read/write access kind. It is the persisted form of the race detector's
// cross-function global read/write order, so a shared-data-race candidate can be
// confirmed against the graph instead of re-derived from syntax alone.
type SharedAccessBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewSharedAccessBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *SharedAccessBuilder {
	return &SharedAccessBuilder{store: store, parser: p, logger: logger}
}

func (b *SharedAccessBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	err := forEachFile(ctx, b.store, b.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		globals := collectGlobalNames(root, funcs)
		assigns := root.FindAll("assignment_expression")
		updates := root.FindAll("update_expression")
		ids := root.FindAll("identifier")

		for _, f := range funcs {
			writes := make(map[string]bool)
			reads := make(map[string]bool)

			for _, a := range assigns {
				if !funcLineRange(f, a.StartLine()) {
					continue
				}
				children := a.NamedChildren()
				if len(children) < 1 {
					continue
				}
				for _, id := range children[0].FindAll("identifier") {
					if globals[id.Text()] {
						writes[id.Text()] = true
					}
				}
			}
			for _, u := range updates {
				if !funcLineRange(f, u.StartLine()) {
					continue
				}
				for _, id := range u.FindAll("identifier") {
					if globals[id.Text()] {
						writes[id.Text()] = true
					}
				}
			}
			for _, id := range ids {
				if !funcLineRange(f, id.StartLine()) {
					continue
				}
				if !globals[id.Text()] {
					continue
				}
				if !writes[id.Text()] {
					reads[id.Text()] = true
				}
			}

			for g := range globals {
				access := ""
				if writes[g] && reads[g] {
					access = "read_write"
				} else if writes[g] {
					access = "write"
				} else if reads[g] {
					access = "read"
				}
				if access == "" {
					continue
				}
				if b.persistAccess(ctx, f, g, access) {
					result.EdgesCreated++
				}
			}
		}
	})
	return result, err
}

func (b *SharedAccessBuilder) persistAccess(ctx context.Context, f *db.Function, global, access string) bool {
	fnNode, err := b.store.GetOrCreateGraphNode(ctx, "function", f.ID, fmt.Sprintf(`{"name":"%s"}`, f.Name))
	if err != nil {
		return false
	}
	gNode, err := b.store.GetOrCreateGraphNode(ctx, "global_var", 0, fmt.Sprintf(`{"name":"%s"}`, global))
	if err != nil {
		return false
	}
	props, _ := json.Marshal(map[string]string{"function": f.Name, "variable": global, "access": access})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      fnNode,
		DstID:      gNode,
		EdgeType:   "GLOBAL_ACCESS",
		Properties: string(props),
	})
	return err == nil
}

// collectGlobalNames returns the set of file-scope variable names: identifiers
// declared at the top level of the file, outside any function body. This mirrors
// the race detector's collectGlobalVars (g_-prefix plus any top-level declarator).
func collectGlobalNames(root parser.Node, funcs []*db.Function) map[string]bool {
	globals := make(map[string]bool)
	var localRanges [][2]int
	for _, fn := range funcs {
		localRanges = append(localRanges, [2]int{fn.StartLine, fn.EndLine})
	}
	isLocal := func(line int) bool {
		for _, r := range localRanges {
			if line >= r[0] && line <= r[1] {
				return true
			}
		}
		return false
	}
	for _, decl := range root.FindAll("declaration") {
		if isLocal(decl.StartLine()) {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "identifier" {
				globals[child.Text()] = true
			}
			for _, id := range child.FindAll("identifier") {
				globals[id.Text()] = true
			}
		}
	}
	return globals
}
