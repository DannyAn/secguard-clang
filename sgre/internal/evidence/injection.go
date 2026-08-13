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

type InjectionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewInjectionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *InjectionDetector {
	return &InjectionDetector{store: store, parser: p, logger: logger}
}

func (d *InjectionDetector) Name() string { return "injection" }

var commandInjectionSinks = map[string]bool{
	"system":           true,
	"popen":            true,
	"CreateProcessA":   true,
	"CreateProcessW":   true,
	"CreateProcessAsA": true,
	"CreateProcessAsW": true,
	"ShellExecuteA":    true,
	"ShellExecuteW":    true,
	"ShellExecuteEx":   true,
	"ShellExecuteExA":  true,
	"ShellExecuteExW":  true,
	"execl":            true,
	"execlp":           true,
	"execle":           true,
	"execv":            true,
	"execvp":           true,
	"execve":           true,
}

func (d *InjectionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	funcs, err := d.store.ListFunctions(ctx)
	if err != nil {
		return result, fmt.Errorf("injection: list functions: %w", err)
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
		tree, err := d.parser.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		root := tree.RootNode()

		d.detectCommandInjection(ctx, f, file, root, &result)
		d.detectTaintFlowInjection(ctx, f, file, root, &result)
		d.detectSQLInjection(ctx, f, file, root, &result)

		tree.Close()
	}

	return result, nil
}

func (d *InjectionDetector) detectCommandInjection(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if !commandInjectionSinks[callName] {
			continue
		}

		taint := "none"
		if !isConstantCommandArg(call) {
			taint = "flow"
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   "command_injection",
			"taint":      taint,
			"expression": call.Text(),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "INJECTION",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}
}

func (d *InjectionDetector) detectSQLInjection(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	calls := root.FindAll("call_expression")
	for _, call := range calls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName != "sqlite3_exec" {
			continue
		}

		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   "sql_injection",
			"expression": call.Text(),
		})
		_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
			EventType:  "INJECTION",
			EntityID:   f.ID,
			LocationID: locID,
			Properties: string(props),
		})
		if err == nil {
			result.EventsCreated++
		}
	}

	sprintfCalls := root.FindAll("call_expression")
	for _, call := range sprintfCalls {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if callName != "sprintf" && callName != "snprintf" {
			continue
		}
		text := call.Text()
		if strings.Contains(text, "SELECT") || strings.Contains(text, "INSERT") ||
			strings.Contains(text, "UPDATE") || strings.Contains(text, "DELETE") {
			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine()})
			props, _ := json.Marshal(map[string]string{
				"function":   callName,
				"category":   "sql_injection",
				"expression": text,
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "INJECTION",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
			}
		}
	}
}

func (d *InjectionDetector) detectTaintFlowInjection(ctx context.Context, f *db.Function, file *db.File, root parser.Node, result *DetectResult) {
	formattedBuffers := make(map[string]int)

	wsprintfNames := map[string]bool{"wsprintfA": true, "wsprintfW": true, "sprintf": true, "snprintf": true}
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if !wsprintfNames[callName] {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 2 {
			continue
		}
		bufName := args[0]
		fmtStr := args[1]
		if strings.Contains(fmtStr, "%s") || strings.Contains(fmtStr, "%d") ||
			strings.Contains(fmtStr, "%i") || strings.Contains(fmtStr, "%u") ||
			strings.Contains(fmtStr, "%x") || strings.Contains(fmtStr, "%c") {
			formattedBuffers[bufName] = call.StartLine()
		}
	}

	processSinks := map[string]bool{"CreateProcessA": true, "CreateProcessW": true, "CreateProcessAsA": true, "CreateProcessAsW": true}
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() < f.StartLine || call.StartLine() > f.EndLine {
			continue
		}
		callName := extractCallName(call)
		if !processSinks[callName] {
			continue
		}
		args := extractCallArgs(call)
		cmdArgIdx := 1
		if len(args) <= cmdArgIdx {
			continue
		}
		cmdArg := strings.TrimSpace(args[cmdArgIdx])
		if _, isTainted := formattedBuffers[cmdArg]; isTainted {
			locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()})
			props, _ := json.Marshal(map[string]string{
				"function":   callName,
				"category":   "command_injection",
				"taint":      "flow",
				"source":     "wsprintf",
				"expression": call.Text(),
			})
			_, err := d.store.InsertEvent(ctx, &db.SecurityEvent{
				EventType:  "INJECTION",
				EntityID:   f.ID,
				LocationID: locID,
				Properties: string(props),
			})
			if err == nil {
				result.EventsCreated++
			}
		}
	}
}

func isConstantCommandArg(call parser.Node) bool {
	args := extractCallArgs(call)
	if len(args) == 0 {
		return true
	}
	arg := strings.TrimSpace(args[0])
	if len(arg) >= 2 && arg[0] == '"' {
		return true
	}
	for _, c := range arg {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			return false
		}
	}
	return true
}

func extractCallArgs(call parser.Node) []string {
	var args []string
	for _, child := range call.NamedChildren() {
		if child.Kind() == "argument_list" {
			for _, arg := range child.NamedChildren() {
				args = append(args, arg.Text())
			}
		}
	}
	return args
}
