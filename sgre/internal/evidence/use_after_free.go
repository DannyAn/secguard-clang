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

type UseAfterFreeDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUseAfterFreeDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UseAfterFreeDetector {
	return &UseAfterFreeDetector{store: store, parser: p, logger: logger}
}

func (d *UseAfterFreeDetector) Name() string { return "use_after_free" }

type freeSite struct {
	varName  string
	field    string
	line     int
	indirect bool
	callee   string
}

func (d *UseAfterFreeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("use_after_free: list functions: %w", err)
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
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		aliases := findAliases(f, root)
		freeSites := d.findAllFreeSites(f, root, summaries, aliases)
		useSites := d.findUseSites(f, root)

		for _, fs := range freeSites {
			for _, useLine := range useSites[fs.varName] {
				if useLine > fs.line {
					locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: useLine})
					props := map[string]interface{}{
						"variable":  fs.varName,
						"free_line": fs.line,
						"use_line":  useLine,
						"category":  "use_after_free",
					}
					if fs.indirect {
						props["indirect"] = true
						props["callee"] = fs.callee
					}
					if fs.field != "" {
						props["freed_field"] = fs.field
					}
					propsJSON, _ := json.Marshal(props)
					_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
						EventType:  "USE_AFTER_FREE",
						EntityID:   f.ID,
						LocationID: locID,
						Properties: string(propsJSON),
					})
					if err == nil {
						result.EventsCreated++
					}
				}
			}
		}

		tree.Close()
	}

	return result, nil
}

func (d *UseAfterFreeDetector) findAllFreeSites(f *db.Function, root parser.Node, summaries summaryMap, aliases map[string]aliasInfo) []freeSite {
	var sites []freeSite

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
					sites = append(sites, freeSite{varName: arg.Text(), line: callLine})
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
				sites = append(sites, freeSite{
					varName:  argVar,
					line:     callLine,
					indirect: true,
					callee:   callName,
				})
			}

			for _, field := range s.ParamFieldFrees[argIdx] {
				sites = append(sites, freeSite{
					varName:  argVar,
					field:    field,
					line:     callLine,
					indirect: true,
					callee:   callName,
				})

				for aliasVar, ai := range aliases {
					if ai.baseVar == argVar && ai.field == field {
						sites = append(sites, freeSite{
							varName:  aliasVar,
							line:     callLine,
							indirect: true,
							callee:   callName,
						})
					}
				}
			}
		}
	}

	return sites
}

func (d *UseAfterFreeDetector) findUseSites(f *db.Function, root parser.Node) map[string][]int {
	useSites := make(map[string][]int)

	addUse := func(varName string, line int) {
		if varName != "" {
			useSites[varName] = append(useSites[varName], line)
		}
	}

	for _, deref := range root.FindAll("pointer_expression") {
		if deref.StartLine() < f.StartLine || deref.StartLine() > f.EndLine {
			continue
		}
		text := deref.Text()
		if strings.HasPrefix(text, "*") {
			varName := strings.TrimSpace(text[1:])
			addUse(varName, deref.StartLine())
		}
	}

	for _, field := range root.FindAll("field_expression") {
		if field.StartLine() < f.StartLine || field.StartLine() > f.EndLine {
			continue
		}
		children := field.NamedChildren()
		if len(children) > 0 && children[0].Kind() == "identifier" {
			addUse(children[0].Text(), field.StartLine())
		}
	}

	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName == "free" {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() == "argument_list" {
				for _, arg := range child.NamedChildren() {
					if arg.Kind() == "identifier" {
						addUse(arg.Text(), call.StartLine())
					}
				}
			}
		}
	}

	return useSites
}
