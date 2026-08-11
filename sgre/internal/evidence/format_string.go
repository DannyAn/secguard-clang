package evidence

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kongan/secguard-lite/internal/db"
	"github.com/kongan/secguard-lite/internal/log"
	"github.com/kongan/secguard-lite/internal/parser"
)

type FormatStringDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewFormatStringDetector(store db.Store, p *parser.Parser, logger *log.Logger) *FormatStringDetector {
	return &FormatStringDetector{store: store, parser: p, logger: logger}
}

func (d *FormatStringDetector) Name() string { return "format_string" }

var printfFamily = map[string]bool{
	"printf": true, "fprintf": true, "sprintf": true, "snprintf": true,
	"vprintf": true, "vfprintf": true, "vsprintf": true, "vsnprintf": true,
	"syslog": true, "err": true, "warn": true, "errx": true, "warnx": true,
}

func (d *FormatStringDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("format_string: list functions: %w", err)
	}

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

		for _, call := range root.FindAll("call_expression") {
			if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
				continue
			}
			callName := extractCallName(call)
			if !printfFamily[callName] {
				continue
			}

			formatArg := d.extractFormatArg(call)
			if formatArg == "" {
				continue
			}
			if d.isStringLiteral(formatArg) {
				continue
			}

			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
			props, _ := json.Marshal(map[string]string{
				"function":   callName,
				"format_arg": formatArg,
				"expression": call.Text(),
				"category":   "format_string",
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "FORMAT_STRING",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
			}
		}

		tree.Close()
	}

	return result, nil
}

func (d *FormatStringDetector) extractFormatArg(call parser.Node) string {
	callName := extractCallName(call)
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			args := child.NamedChildren()
			formatIdx := 0
			switch callName {
			case "fprintf", "vfprintf", "syslog":
				formatIdx = 1
			case "sprintf", "vsprintf":
				formatIdx = 1
			case "snprintf", "vsnprintf":
				formatIdx = 2
			}
			if len(args) <= formatIdx {
				return ""
			}
			return args[formatIdx].Text()
		}
	}
	return ""
}

func (d *FormatStringDetector) isStringLiteral(text string) bool {
	return strings.HasPrefix(text, "\"") || strings.HasPrefix(text, "L\"")
}
