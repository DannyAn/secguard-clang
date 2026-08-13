package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type InterproceduralDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewInterproceduralDetector(store db.Store, p *parser.Parser, logger *log.Logger) *InterproceduralDetector {
	return &InterproceduralDetector{store: store, parser: p, logger: logger}
}

func (d *InterproceduralDetector) Name() string { return "interprocedural" }

func (d *InterproceduralDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("interprocedural: list functions: %w", err)
	}

	funcByName := make(map[string][]*db.Function)
	for i := range funcs {
		funcByName[funcs[i].Name] = append(funcByName[funcs[i].Name], funcs[i])
	}

	// Load the three event tables ONCE and index them by (function, variable).
	// The previous implementation re-issued these queries inside the per-function
	// and per-callee/caller loops, which made the detector quadratic in the
	// number of functions — roughly 172K full-file parses on a 1000-function
	// codebase, which presented as a hang.
	derefVars, err := d.loadEventVarIndex(ctx, "DEREFERENCE")
	if err != nil {
		return result, fmt.Errorf("interprocedural: load dereference events: %w", err)
	}
	guardVars, err := d.loadEventVarIndex(ctx, "NULL_GUARD")
	if err != nil {
		return result, fmt.Errorf("interprocedural: load guard events: %w", err)
	}
	nullVars, err := d.loadEventVarIndex(ctx, "NULL_VALUE")
	if err != nil {
		return result, fmt.Errorf("interprocedural: load null events: %w", err)
	}

	// Parse each source file exactly once and reuse the tree for both parameter
	// extraction and call-site scanning.
	treeCache := make(map[int64]*parser.Tree)
	defer func() {
		for _, t := range treeCache {
			if t != nil {
				t.Close()
			}
		}
	}()

	// Group functions by file, then parse each file exactly once to collect both
	// parameter names and the call expressions inside each function body.
	funcsByFile := make(map[int64][]*db.Function)
	for i := range funcs {
		funcsByFile[funcs[i].FileID] = append(funcsByFile[funcs[i].FileID], funcs[i])
	}

	callsByFunc := make(map[int64][]parser.Node)
	paramsByFunc := make(map[int64][]string, len(funcs))
	for fileID, fileFuncs := range funcsByFile {
		tree := d.treeFor(ctx, treeCache, fileID)
		if tree == nil {
			continue
		}
		root := tree.RootNode()

		paramsByLine := make(map[int][]string, len(fileFuncs))
		for _, fnNode := range root.FindAll("function_definition") {
			paramsByLine[fnNode.StartLine()] = findParamsInDefinition(fnNode)
		}
		for _, f := range fileFuncs {
			if params := paramsByLine[f.StartLine]; len(params) > 0 {
				paramsByFunc[f.ID] = params
			}
		}

		for _, call := range root.FindAll("call_expression") {
			for _, f := range fileFuncs {
				if call.StartLine() >= f.StartLine && call.StartLine() <= f.EndLine {
					callsByFunc[f.ID] = append(callsByFunc[f.ID], call)
					break
				}
			}
		}
	}

	// Per callee: the positional indices of parameters that are both dereferenced
	// in the callee body and not null-guarded there.
	unguardedByCallee := make(map[int64]map[int]string)
	for calleeID, derefSet := range derefVars {
		guarded := guardVars[calleeID]
		unguarded := make(map[int]string)
		for idx, param := range paramsByFunc[calleeID] {
			if derefSet[param] && !guarded[param] {
				unguarded[idx] = param
			}
		}
		if len(unguarded) > 0 {
			unguardedByCallee[calleeID] = unguarded
		}
	}

	// Walk each caller's call expressions once; for every call to a callee with
	// an unguarded dereferenced parameter, emit a DEREFERENCE where the caller
	// passes a NULL_VALUE variable into that parameter position.
	for _, caller := range funcs {
		for _, call := range callsByFunc[caller.ID] {
			callees := funcByName[extractCallName(call)]
			if len(callees) == 0 {
				continue
			}
			args := callNamedArguments(call)
			for _, callee := range callees {
				unguarded := unguardedByCallee[callee.ID]
				if len(unguarded) == 0 {
					continue
				}
				for argIdx, arg := range args {
					paramName, isUnguarded := unguarded[argIdx]
					if !isUnguarded || arg.Kind() != "identifier" {
						continue
					}
					argVarName := arg.Text()
					if !nullVars[caller.ID][argVarName] {
						continue
					}

					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: caller.FileID, Line: call.StartLine()})
					props, _ := json.Marshal(map[string]string{
						"variable":   argVarName,
						"expression": argVarName + "->" + paramName,
						"origin":     "interprocedural",
						"callee":     callee.Name,
					})
					d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "DEREFERENCE",
						EntityID:   caller.ID,
						LocationID: locID,
						Properties: string(props),
					})
					result.EventsCreated++
				}
			}
		}
	}

	return result, nil
}

// loadEventVarIndex returns, for a given event type, a map from function ID to
// the set of variable names that event type references.
func (d *InterproceduralDetector) loadEventVarIndex(ctx context.Context, eventType string) (map[int64]map[string]bool, error) {
	events, err := d.store.ListEventsByType(ctx, eventType)
	if err != nil {
		return nil, err
	}
	index := make(map[int64]map[string]bool)
	for _, e := range events {
		var props map[string]string
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		varName := props["variable"]
		if varName == "" {
			continue
		}
		if index[e.EntityID] == nil {
			index[e.EntityID] = make(map[string]bool)
		}
		index[e.EntityID][varName] = true
	}
	return index, nil
}

// treeFor parses the file once and caches the tree, keyed by file ID.
func (d *InterproceduralDetector) treeFor(ctx context.Context, cache map[int64]*parser.Tree, fileID int64) *parser.Tree {
	if t, ok := cache[fileID]; ok {
		return t
	}
	file, _ := d.store.GetFileByID(ctx, fileID)
	if file == nil {
		return nil
	}
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return nil
	}
	tree, err := d.parser.ParseCached(source, file.Path)
	if err != nil {
		return nil
	}
	cache[fileID] = tree
	return tree
}

// findParamsInDefinition returns the parameter names of a single
// function_definition node, or nil if no declarator is found.
func findParamsInDefinition(fnNode parser.Node) []string {
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
			for _, pc := range param.NamedChildren() {
				if pc.Kind() == "identifier" {
					params = append(params, pc.Text())
					break
				}
				if pc.Kind() == "pointer_declarator" {
					for _, gc := range pc.NamedChildren() {
						if gc.Kind() == "identifier" {
							params = append(params, gc.Text())
							break
						}
					}
					break
				}
			}
		}
	}
	return params
}
