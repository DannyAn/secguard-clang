package evidence

import (
	"context"
	"encoding/json"
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

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			d.detectCommandInjection(ctx, f, file, calls, &result)
			d.detectTaintFlowInjection(ctx, f, file, calls, &result)
			d.detectSQLInjection(ctx, f, file, calls, &result)
		}
	})
	return result, err
}

func (d *InjectionDetector) detectCommandInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
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
		// variable: the sink argument when it is a bare identifier, so the
		// planner's taint filter can track it (system(buf) -> variable "buf").
		props, _ := json.Marshal(map[string]string{
			"function":   callName,
			"category":   "command_injection",
			"taint":      taint,
			"expression": call.Text(),
			"variable":   bareCommandArg(call),
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

func (d *InjectionDetector) detectSQLInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName != "sqlite3_exec" {
			continue
		}
		// sqlite3_exec(db, sql, cb, arg, errmsg): a literal SQL argument is
		// constant (or uses ? placeholders), so no value can be interpolated
		// into it — it is never injection. Only a variable or concatenated SQL
		// argument can carry attacker-controlled text and is a candidate.
		if args := extractCallArgs(call); len(args) >= 2 && isStringLiteral(args[1]) {
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

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName != "sprintf" && callName != "snprintf" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 2 {
			continue
		}
		// sprintf(buf, fmt, ...): only a format string that BOTH builds SQL and
		// interpolates a value (has a % specifier) is injectable. sprintf(buf,
		// "SELECT ...") with no % is a constant string copy, not injection.
		fmtStr := args[1]
		if !hasSQLKeyword(fmtStr) || !hasFormatSpecifier(fmtStr) {
			continue
		}
		locID, _ := d.store.InsertLocation(ctx, &db.Location{FileID: file.ID, Line: call.StartLine()})
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
}

// isStringLiteral reports whether an argument is a plain C string literal (a
// leading double quote). Such an argument is a compile-time constant and cannot
// be attacker-influenced.
func isStringLiteral(arg string) bool {
	t := strings.TrimSpace(arg)
	return len(t) >= 2 && t[0] == '"'
}

// hasSQLKeyword reports whether a format string contains a SQL statement verb
// (case-insensitive), the signal that sprintf is building a SQL query.
func hasSQLKeyword(s string) bool {
	up := strings.ToUpper(s)
	return strings.Contains(up, "SELECT") || strings.Contains(up, "INSERT") ||
		strings.Contains(up, "UPDATE") || strings.Contains(up, "DELETE")
}

// hasFormatSpecifier reports whether a format string interpolates a value. A
// literal '%' (no following conversion) is not valid printf, so its presence is
// a reliable proxy for "this sprintf substitutes runtime values".
func hasFormatSpecifier(s string) bool {
	return strings.Contains(s, "%")
}

func (d *InjectionDetector) detectTaintFlowInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	formattedBuffers := make(map[string]int)

	wsprintfNames := map[string]bool{"wsprintfA": true, "wsprintfW": true, "sprintf": true, "snprintf": true}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
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
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
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

// bareCommandArg returns the first argument of a command-injection sink when it
// is a bare identifier (system(buf) -> "buf"), else "".
func bareCommandArg(call parser.Node) string {
	args := extractCallArgs(call)
	if len(args) == 0 {
		return ""
	}
	arg := strings.TrimSpace(args[0])
	for i, c := range arg {
		if !(c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')) {
			return ""
		}
	}
	if arg == "" {
		return ""
	}
	return arg
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
