package evidence

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
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
	field    string
	line     int
	indirect bool
	callee   string
	global   string
}

type globalDFEntry struct {
	slot       string
	line       int
	callee     string
	victims    []string
	firstFrees []int
}

func (d *DoubleFreeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	summaries := buildFuncSummaries(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		inits := root.FindAll("init_declarator")
		assigns := root.FindAll("assignment_expression")
		calls := root.FindAll("call_expression")
		macros := macroFreeSummaries(root)

		for _, f := range funcs {
			globalStores := d.findGlobalStoredVars(f, inits, assigns, summaries)
			freeEvents := d.findAllFreeEvents(f, calls, summaries, globalStores, macros)

			byVar := make(map[string][]dfFreeEvent)
			for _, fe := range freeEvents {
				key := fe.varName
				if fe.field != "" {
					if strings.HasPrefix(fe.field, fe.varName+"[") {
						key = fe.field // subscript: "a[0]" already includes the base
					} else {
						key = fe.varName + "->" + fe.field
					}
				}
				byVar[key] = append(byVar[key], fe)
			}

			// Global-slot double frees (e.g. cleanup_entries() frees g_entries[]
			// entries that release_entry() already freed) are one defect for the
			// dangling slot, not one per stored local variable. Collapse them into
			// a single event labeled with the global slot so the finding names the
			// real victim instead of a variable whose slot may have been
			// overwritten (allocator.c main: e1/e2/e3 aliasing).
			collective := make(map[string]*globalDFEntry)
			mergedVars := make(map[string]bool)
			for varName, events := range byVar {
				if len(events) < 2 {
					continue
				}
				second := events[1]
				if second.global == "" {
					continue
				}
				key := fmt.Sprintf("%s:%d", second.global, second.line)
				e := collective[key]
				if e == nil {
					e = &globalDFEntry{slot: second.global, line: second.line, callee: second.callee}
					collective[key] = e
				}
				e.victims = append(e.victims, varName)
				e.firstFrees = append(e.firstFrees, events[0].line)
				mergedVars[varName] = true
			}

			keys := make([]string, 0, len(collective))
			for key := range collective {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				e := collective[key]
				sort.Strings(e.victims)
				sort.Ints(e.firstFrees)
				props := map[string]interface{}{
					"variable":     e.slot + "[]",
					"second_free":  e.line,
					"category":     "double_free",
					"indirect":     true,
					"first_callee": e.callee,
					"victims":      strings.Join(e.victims, ","),
				}
				if len(e.firstFrees) > 0 {
					props["first_free"] = e.firstFrees[0]
					props["first_free_lines"] = joinInts(e.firstFrees)
				}
				if emitEvent(ctx, d.store, d.logger, "DOUBLE_FREE", f.ID, &db.Location{FileID: file.ID, Line: e.line}, props) {
					result.EventsCreated++
				}
			}

			for varName, events := range byVar {
				if mergedVars[varName] || len(events) < 2 {
					continue
				}
				for i := 1; i < len(events); i++ {
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
					if emitEvent(ctx, d.store, d.logger, "DOUBLE_FREE", f.ID, &db.Location{FileID: file.ID, Line: events[i].line}, props) {
						result.EventsCreated++
					}
				}
			}
		}
	})
	return result, err
}

func (d *DoubleFreeDetector) findGlobalStoredVars(f *db.Function, inits, assigns []parser.Node, summaries summaryMap) map[string][]string {
	stores := make(map[string][]string)

	for _, decl := range inits {
		if !funcLineRange(f, decl.StartLine()) {
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

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
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

func (d *DoubleFreeDetector) findAllFreeEvents(f *db.Function, calls []parser.Node, summaries summaryMap, globalStores map[string][]string, macros map[string]macroFreeSummary) []dfFreeEvent {
	var events []dfFreeEvent

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		callLine := call.StartLine()

		// A freeing function-like macro wraps a free the parser cannot see; a
		// macro that also nulls the argument (SAFE_FREE) is excluded because the
		// freed state is immediately overwritten.
		if s, ok := macros[callName]; ok && s.freesArg && !s.nullsArg {
			args := getCallArgs(call)
			if len(args) > 0 && args[0].Kind() == "identifier" {
				events = append(events, dfFreeEvent{varName: args[0].Text(), line: callLine})
			}
			continue
		}

		if callName == "free" {
			args := getCallArgs(call)
			for _, arg := range args {
				switch arg.Kind() {
				case "identifier":
					events = append(events, dfFreeEvent{varName: arg.Text(), line: callLine})
				case "field_expression":
					// free(p->msg) frees only p->msg; a second free of p->mode is a
					// different object and must not be treated as a double-free.
					if base, field := extractFieldAccess(arg); base != "" && field != "" {
						events = append(events, dfFreeEvent{varName: base, field: field, line: callLine})
					}
				case "subscript_expression":
					if base, field := subscriptAccess(arg); base != "" && field != "" {
						events = append(events, dfFreeEvent{varName: base, field: field, line: callLine})
					}
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
					global:   globalName,
				})
			}
		}
	}

	return events
}
