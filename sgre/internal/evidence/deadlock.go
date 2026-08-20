package evidence

import (
	"context"
	"sort"
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

	type lockEdge struct {
		from string
		to   string
		file *db.File
		line int
		fn   string
		fnID int64
	}

	var allEdges []lockEdge

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			held := []string{}
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
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
		}
	})
	if err != nil {
		return result, err
	}

	// Lock-order graph: mutex -> set of mutexes acquired while holding it.
	adj := make(map[string]map[string]bool)
	for _, e := range allEdges {
		if adj[e.from] == nil {
			adj[e.from] = make(map[string]bool)
		}
		adj[e.from][e.to] = true
		if adj[e.to] == nil {
			adj[e.to] = make(map[string]bool)
		}
	}

	// Strongly connected components of size ≥2 are lock-order cycles: any cycle
	// (A→B, B→C, C→A) is a deadlock risk, not only the 2-cycles the previous
	// reverse-pair check found.
	for _, scc := range tarjanSCC(adj) {
		if len(scc) < 2 {
			continue
		}
		sort.Strings(scc)
		var anchor lockEdge
		ok := false
		for _, e := range allEdges {
			if containsString(scc, e.from) && containsString(scc, e.to) {
				anchor, ok = e, true
				break
			}
		}
		if !ok {
			continue
		}
		if emitEvent(ctx, d.store, d.logger, "DEADLOCK", anchor.fnID, &db.Location{FileID: anchor.file.ID, Line: anchor.line}, map[string]string{
			"mutex_a":  scc[0],
			"mutex_b":  scc[1],
			"function": anchor.fn,
			"category": "deadlock",
			"cycle":    strings.Join(scc, "->"),
		}) {
			result.EventsCreated++
		}
	}

	return result, nil
}

// tarjanSCC returns the strongly connected components of the directed graph adj
// (node -> successor set). A component of ≥2 nodes, or a self-loop, is a cycle.
func tarjanSCC(adj map[string]map[string]bool) [][]string {
	index := 0
	indices := make(map[string]int)
	low := make(map[string]int)
	onStack := make(map[string]bool)
	var stack []string
	var sccs [][]string

	var strongConnect func(v string)
	strongConnect = func(v string) {
		indices[v] = index
		low[v] = index
		index++
		stack = append(stack, v)
		onStack[v] = true

		for w := range adj[v] {
			if _, seen := indices[w]; !seen {
				strongConnect(w)
				if low[w] < low[v] {
					low[v] = low[w]
				}
			} else if onStack[w] {
				if indices[w] < low[v] {
					low[v] = indices[w]
				}
			}
		}

		if low[v] == indices[v] {
			var scc []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				onStack[w] = false
				scc = append(scc, w)
				if w == v {
					break
				}
			}
			sccs = append(sccs, scc)
		}
	}

	nodes := make([]string, 0, len(adj))
	for n := range adj {
		nodes = append(nodes, n)
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		if _, seen := indices[n]; !seen {
			strongConnect(n)
		}
	}
	return sccs
}

// containsString reports whether ss contains s.
func containsString(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

func extractMutexArg(call parser.Node) string {
	arg := extractFirstArg(call)
	if arg == "" {
		return ""
	}
	arg = strings.TrimPrefix(arg, "&")
	return arg
}
