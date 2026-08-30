package graph

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// LockOrderBuilder persists LOCK_ORDER edges: mutex A -> mutex B when B is
// acquired while A is held (the A→B acquisition order). This moves the deadlock
// detector's in-memory lock-order graph into the persisted layer, so the
// planner's LockOrderFilter can confirm a cycle instead of re-deriving it from
// syntax alone.
type LockOrderBuilder struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLockOrderBuilder(store db.Store, p *parser.Parser, logger *log.Logger) *LockOrderBuilder {
	return &LockOrderBuilder{store: store, parser: p, logger: logger}
}

var lockCalls = map[string]bool{
	"pthread_mutex_lock": true, "pthread_rwlock_wrlock": true, "EnterCriticalSection": true,
}

var unlockCalls = map[string]bool{
	"pthread_mutex_unlock": true, "pthread_rwlock_unlock": true, "LeaveCriticalSection": true,
}

func (b *LockOrderBuilder) Build(ctx context.Context) (*BuildResult, error) {
	result := &BuildResult{}

	err := forEachFile(ctx, b.store, b.parser, b.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			held := []string{}
			for _, call := range nodesInRange(calls, f.StartLine, f.EndLine) {
				callName := extractCallName(call)
				mutexName := firstArgText(call)
				if mutexName == "" {
					continue
				}
				if lockCalls[callName] {
					for _, h := range held {
						if h != mutexName && b.persistEdge(ctx, f, h, mutexName, call.StartLine()) {
							result.EdgesCreated++
						}
					}
					held = append(held, mutexName)
				}
				if unlockCalls[callName] {
					newHeld := held[:0]
					for _, h := range held {
						if h != mutexName {
							newHeld = append(newHeld, h)
						}
					}
					held = newHeld
				}
			}
		}
	})
	return result, err
}

func (b *LockOrderBuilder) persistEdge(ctx context.Context, f *db.Function, from, to string, line int) bool {
	fromNode, err := b.store.GetOrCreateGraphNode(ctx, "mutex", 0, fmt.Sprintf(`{"name":"%s"}`, from))
	if err != nil {
		warnEdge(b.logger, "LOCK_ORDER", f.Name, err)
		return false
	}
	toNode, err := b.store.GetOrCreateGraphNode(ctx, "mutex", 0, fmt.Sprintf(`{"name":"%s"}`, to))
	if err != nil {
		warnEdge(b.logger, "LOCK_ORDER", f.Name, err)
		return false
	}
	props := marshalProps(b.logger, "LOCK_ORDER", map[string]interface{}{"function": f.Name, "line": line})
	_, err = b.store.InsertGraphEdge(ctx, &db.GraphEdge{
		SrcID:      fromNode,
		DstID:      toNode,
		EdgeType:   "LOCK_ORDER",
		Properties: props,
	})
	if err != nil {
		warnEdge(b.logger, "LOCK_ORDER", f.Name, err)
		return false
	}
	return true
}

// firstArgText returns the first call argument's text with a leading & stripped,
// matching the deadlock detector's mutex-name extraction.
func firstArgText(call parser.Node) string {
	for _, child := range call.NamedChildren() {
		if child.Kind() != "argument_list" {
			continue
		}
		args := child.NamedChildren()
		if len(args) == 0 {
			return ""
		}
		return strings.TrimPrefix(strings.TrimSpace(args[0].Text()), "&")
	}
	return ""
}
