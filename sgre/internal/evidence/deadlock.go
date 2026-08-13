package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type DeadlockDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDeadlockDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DeadlockDetector {
	return &DeadlockDetector{store: store, parser: p, logger: logger}
}

func (d *DeadlockDetector) Name() string { return "deadlock" }

func (d *DeadlockDetector) Domain() string { return "concurrency" }

func (d *DeadlockDetector) Capabilities() []string {
	return []string{"lock-order-inversion", "cycle-detection"}
}

func (d *DeadlockDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("deadlock: list functions: %w", err)
	}

	type lockEdge struct {
		from string
		to   string
		file *db.File
		line int
		fn   string
		fnID int64
	}

	var allEdges []lockEdge

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
		if file == nil {
			continue
		}
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		held := []string{}
		for _, call := range root.FindAll("call_expression") {
			if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
				continue
			}
			callName := extractCallName(call)
			mutexName := extractMutexArg(call)
			if mutexName == "" {
				continue
			}

			if callName == "pthread_mutex_lock" || callName == "pthread_rwlock_wrlock" || callName == "EnterCriticalSection" {
				for _, h := range held {
					if h != mutexName {
						allEdges = append(allEdges, lockEdge{from: h, to: mutexName, file: file, line: call.StartLine(), fn: f.Name, fnID: f.ID})
					}
				}
				held = append(held, mutexName)
			}
			if callName == "pthread_mutex_unlock" || callName == "pthread_rwlock_unlock" || callName == "LeaveCriticalSection" {
				newHeld := []string{}
				for _, h := range held {
					if h != mutexName {
						newHeld = append(newHeld, h)
					}
				}
				held = newHeld
			}
		}

		tree.Close()
	}

	edges := make(map[string][]lockEdge)
	for _, e := range allEdges {
		key := e.from + "->" + e.to
		edges[key] = append(edges[key], e)
	}

	for _, e1 := range allEdges {
		reverseKey := e1.to + "->" + e1.from
		if reverse, ok := edges[reverseKey]; ok {
			for _, e2 := range reverse {
				if e1.from != e1.to && e2.fn != e1.fn {
					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: e1.file.ID, Line: e1.line})
					props, _ := json.Marshal(map[string]string{
						"mutex_a":          e1.from,
						"mutex_b":          e1.to,
						"function":         e1.fn,
						"reverse_function": e2.fn,
						"category":         "deadlock",
					})
					_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "DEADLOCK",
						EntityID:   e1.fnID,
						LocationID: locID,
						Properties: string(props),
					})
					if err == nil {
						result.EventsCreated++
					}
					break
				}
			}
			break
		}
	}

	return result, nil
}

func extractMutexArg(call parser.Node) string {
	arg := extractFirstArg(call)
	if arg == "" {
		return ""
	}
	arg = strings.TrimPrefix(arg, "&")
	return arg
}
