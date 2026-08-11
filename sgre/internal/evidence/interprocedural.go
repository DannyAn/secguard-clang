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

	funcByID := make(map[int64]*db.Function)
	for i := range funcs {
		funcByID[funcs[i].ID] = funcs[i]
	}

	type paramDeref struct {
		paramName string
		paramIdx  int
	}
	derefParams := make(map[int64][]paramDeref)
	guardedParams := make(map[int64]map[string]bool)

	for _, f := range funcs {
		params := d.extractParamNames(ctx, f)
		if len(params) == 0 {
			continue
		}

		derefEvents, _ := d.store.ListEventsByType(ctx, "DEREFERENCE")
		for _, e := range derefEvents {
			if e.EntityID != f.ID {
				continue
			}
			var props map[string]string
			json.Unmarshal([]byte(e.Properties), &props)
			varName := props["variable"]
			for idx, p := range params {
				if p == varName {
					derefParams[f.ID] = append(derefParams[f.ID], paramDeref{paramName: varName, paramIdx: idx})
				}
			}
		}

		guardEvents, _ := d.store.ListEventsByType(ctx, "NULL_GUARD")
		for _, e := range guardEvents {
			if e.EntityID != f.ID {
				continue
			}
			var props map[string]string
			json.Unmarshal([]byte(e.Properties), &props)
			varName := props["variable"]
			if guardedParams[f.ID] == nil {
				guardedParams[f.ID] = make(map[string]bool)
			}
			guardedParams[f.ID][varName] = true
		}
	}

	for calleeID, derefs := range derefParams {
		callee := funcByID[calleeID]
		if callee == nil {
			continue
		}

		unguardedParams := make(map[int]string)
		for _, pd := range derefs {
			if guardedParams[calleeID] != nil && guardedParams[calleeID][pd.paramName] {
				continue
			}
			unguardedParams[pd.paramIdx] = pd.paramName
		}
		if len(unguardedParams) == 0 {
			continue
		}

		for _, caller := range funcs {
			if caller.ID == calleeID {
				continue
			}
			file, _ := d.store.GetFileByID(ctx, caller.FileID)
			if file == nil {
				continue
			}
			source, err := os.ReadFile(file.Path)
			if err != nil {
				continue
			}
			tree, err := d.parser.Parse(source, file.Path)
			if err != nil {
				continue
			}
			root := tree.RootNode()

			for _, call := range root.FindAll("call_expression") {
				if call.StartLine() < caller.StartLine || call.StartLine() > caller.EndLine {
					continue
				}
				callName := extractCallName(call)
				if callName != callee.Name {
					continue
				}

				argIdx := 0
				for _, child := range call.NamedChildren() {
					if child.Kind() != "argument_list" {
						continue
					}
					for _, arg := range child.NamedChildren() {
						argVarName := ""
						if arg.Kind() == "identifier" {
							argVarName = arg.Text()
						}
						if argVarName == "" {
							argIdx++
							continue
						}

						paramName, isUnguarded := unguardedParams[argIdx]
						if !isUnguarded {
							argIdx++
							continue
						}

						nullEvents, _ := d.store.ListEventsByType(ctx, "NULL_VALUE")
						hasNullSource := false
						for _, ne := range nullEvents {
							if ne.EntityID != caller.ID {
								continue
							}
							var nprops map[string]string
							json.Unmarshal([]byte(ne.Properties), &nprops)
							if nprops["variable"] == argVarName {
								hasNullSource = true
								break
							}
						}

						if hasNullSource {
							locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine()})
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
						argIdx++
					}
				}
			}
			tree.Close()
		}
	}

	return result, nil
}

func (d *InterproceduralDetector) extractParamNames(ctx context.Context, f *db.Function) []string {
	file, _ := d.store.GetFileByID(ctx, f.FileID)
	if file == nil {
		return nil
	}
	source, err := os.ReadFile(file.Path)
	if err != nil {
		return nil
	}
	tree, err := d.parser.Parse(source, file.Path)
	if err != nil {
		return nil
	}
	defer tree.Close()

	root := tree.RootNode()
	for _, fnNode := range root.FindAll("function_definition") {
		if fnNode.StartLine() != f.StartLine {
			continue
		}
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
