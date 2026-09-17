package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type LogInjectionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewLogInjectionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *LogInjectionDetector {
	return &LogInjectionDetector{store: store, parser: p, logger: logger}
}

func (d *LogInjectionDetector) Name() string { return "log_injection" }

func (d *LogInjectionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			d.detectLogInjection(ctx, f, file, calls, &result)
		}
	})
	return result, err
}

func (d *LogInjectionDetector) detectLogInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		args := extractCallArgs(call)

		variable := ""
		if apikb.IsLogSink(callName) {
			variable = logTaintVariable(callName, args)
		} else if apikb.IsLogSinkCandidate(callName) && len(args) >= 2 {
			fileVarName := ioStreamVarName(callName, args)
			formatStr := ""
			if len(args) > 1 {
				formatStr = args[1]
			}
			if isProtocolHeaderContext(fileVarName, formatStr) {
				continue
			}
			if !isLogContextByHeuristic(fileVarName, callName) {
				continue
			}
			variable = logTaintVariable(callName, args)
		}
		if variable == "" {
			continue
		}

		if isStructuredLogAPI(callName) {
			continue
		}

		if emitEvent(ctx, d.store, d.logger, "INJECTION", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
			"function":   callName,
			"category":   "log_injection",
			"variable":   variable,
			"expression": call.Text(),
		}) {
			result.EventsCreated++
		}
	}
}

func logTaintVariable(callName string, args []string) string {
	switch callName {
	case "syslog", "vsyslog":
		for i := 2; i < len(args); i++ {
			arg := strings.TrimSpace(args[i])
			if isStringLiteral(arg) {
				continue
			}
			if v := bareIdentString(arg); v != "" {
				return v
			}
			return strings.TrimSpace(arg)
		}
	case "fprintf":
		for i := 2; i < len(args); i++ {
			arg := strings.TrimSpace(args[i])
			if isStringLiteral(arg) {
				continue
			}
			if v := bareIdentString(arg); v != "" {
				return v
			}
			return strings.TrimSpace(arg)
		}
	case "fputs":
		if len(args) >= 1 {
			arg := strings.TrimSpace(args[0])
			if !isStringLiteral(arg) {
				return bareIdentString(arg)
			}
		}
	case "fwrite":
		if len(args) >= 1 {
			arg := strings.TrimSpace(args[0])
			if !isStringLiteral(arg) {
				return bareIdentString(arg)
			}
		}
	}
	return ""
}

func isStructuredLogAPI(name string) bool {
	switch name {
	case "log_structured", "json_log", "log_field_set":
		return true
	}
	return false
}

// ioStreamVarName returns the FILE*/stream argument of a stdio sink whose NAME
// signals the sink context (protocol header vs log file vs data file). The
// argument position differs per call — fprintf takes the stream first, fputs
// second (fputs(str, stream)), fwrite fourth (fwrite(data, size, nmemb, stream))
// — so a uniform args[0] read mislabels fputs/fwrite and silences them. Returns
// "" for calls with no nameable stream.
func ioStreamVarName(callName string, args []string) string {
	idx := -1
	switch callName {
	case "fprintf":
		idx = 0
	case "fputs":
		idx = 1
	case "fwrite":
		idx = 3
	}
	if idx < 0 || idx >= len(args) {
		return ""
	}
	return bareIdentString(args[idx])
}
