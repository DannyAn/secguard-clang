package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
)

type DoubleFreeDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewDoubleFreeDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DoubleFreeDetector {
	return &DoubleFreeDetector{store: store, parser: p, logger: logger}
}

func (d *DoubleFreeDetector) Name() string { return "double_free" }

type dfFreeEvent struct {
	varName  string
	line     int
	indirect bool
	callee   string
}

func (d *DoubleFreeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("double_free: list functions: %w", err)
	}

	summaries := buildFuncSummaries(ctx, d.store, d.parser)

	for _, f := range funcs {
		file, _ := d.store.GetFileByID(ctx, f.FileID)
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

		globalStores := d.findGlobalStoredVars(f, root, summaries)
		freeEvents := d.findAllFreeEvents(f, root, summaries, globalStores)

		byVar := make(map[string][]dfFreeEvent)
		for _, fe := range freeEvents {
			byVar[fe.varName] = append(byVar[fe.varName], fe)
		}

		for varName, events := range byVar {
			if len(events) < 2 {
				continue
			}
			for i := 1; i < len(events); i++ {
				locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: events[i].line})
				props := map[string]interface{}{
					"variable":    varName,
					"first_free":  events[0].line,
					"second_free": events[i].line,
					"category":    "double_free",
				}
				if events[0].indirect || events[i].indirect {
					props["indirect"] = true
				}
				if events[0].callee != "" {
					props["first_callee"] = events[0].callee
				}
				if events[i].callee != "" {
					props["second_callee"] = events[i].callee
				}
				propsJSON, _ := json.Marshal(props)
				_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
					EventType:  "DOUBLE_FREE",
					EntityID:   f.ID,
					LocationID: locID,
					Properties: string(propsJSON),
				})
				if err == nil {
					result.EventsCreated++
				}
			}
		}

		tree.Close()
	}

	return result, nil
}

func (d *DoubleFreeDetector) findGlobalStoredVars(f *db.Function, root parser.Node, summaries summaryMap) map[string][]string {
	stores := make(map[string][]string)

	for _, decl := range root.FindAll("init_declarator") {
		if decl.StartLine() < f.StartLine || decl.StartLine() > f.EndLine {
			continue
		}
		children := decl.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]
		varName := extractVarFromDeclarator(lhs)
		if varName == "" {
			continue
		}

		if rhs.Kind() == "call_expression" {
			callName := extractCallName(rhs)
			if s, ok := summaries[callName]; ok {
				for _, g := range s.ReturnStores {
					stores[g] = append(stores[g], varName)
				}
			}
		}
	}

	for _, assign := range root.FindAll("assignment_expression") {
		if assign.StartLine() < f.StartLine || assign.StartLine() > f.EndLine {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		rhs := children[1]
		if lhs.Kind() != "identifier" {
			continue
		}
		varName := lhs.Text()

		if rhs.Kind() == "call_expression" {
			callName := extractCallName(rhs)
			if s, ok := summaries[callName]; ok {
				for _, g := range s.ReturnStores {
					stores[g] = append(stores[g], varName)
				}
			}
		}
	}

	return stores
}

func (d *DoubleFreeDetector) findAllFreeEvents(f *db.Function, root parser.Node, summaries summaryMap, globalStores map[string][]string) []dfFreeEvent {
	var events []dfFreeEvent

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		callLine := call.StartLine()

		if callName == "free" {
			args := getCallArgs(call)
			for _, arg := range args {
				if arg.Kind() == "identifier" {
					events = append(events, dfFreeEvent{varName: arg.Text(), line: callLine})
				}
			}
			continue
		}

		s, ok := summaries[callName]
		if !ok {
			continue
		}
		args := getCallArgs(call)

		for argIdx, arg := range args {
			if arg.Kind() != "identifier" {
				continue
			}
			argVar := arg.Text()

			if s.ParamDirectFrees[argIdx] {
				events = append(events, dfFreeEvent{
					varName:  argVar,
					line:     callLine,
					indirect: true,
					callee:   callName,
				})
			}
		}

		for _, globalName := range s.GlobalFrees {
			for _, storedVar := range globalStores[globalName] {
				events = append(events, dfFreeEvent{
					varName:  storedVar,
					line:     callLine,
					indirect: true,
					callee:   callName,
				})
			}
		}
	}

	return events
}
