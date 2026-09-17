package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type CRLFInjectionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewCRLFInjectionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *CRLFInjectionDetector {
	return &CRLFInjectionDetector{store: store, parser: p, logger: logger}
}

func (d *CRLFInjectionDetector) Name() string { return "crlf_injection" }

func (d *CRLFInjectionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			d.detectCRLFInjection(ctx, f, file, calls, root, &result)
		}
	})
	return result, err
}

func (d *CRLFInjectionDetector) detectCRLFInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, root parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if !apikb.IsCRLFSinkCandidate(callName) {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 2 {
			continue
		}

		fileVarName := bareIdentString(args[0])
		formatStr := ""
		if len(args) > 1 {
			formatStr = args[1]
		}

		if isLogContextByHeuristic(fileVarName, callName) {
			continue
		}
		if !isProtocolHeaderContext(fileVarName, formatStr) {
			if variable := traceSnprintfCRLF(root, f, callName, args, call.StartLine()); variable != "" {
				if emitEvent(ctx, d.store, d.logger, "INJECTION", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function":   callName,
					"category":   "crlf_injection",
					"variable":   variable,
					"expression": call.Text(),
				}) {
					result.EventsCreated++
				}
			}
			continue
		}

		variable := crlfTaintVariable(callName, args)
		if variable == "" {
			continue
		}

		if emitEvent(ctx, d.store, d.logger, "INJECTION", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
			"function":   callName,
			"category":   "crlf_injection",
			"variable":   variable,
			"expression": call.Text(),
		}) {
			result.EventsCreated++
		}
	}
}

// traceSnprintfCRLF handles the snprintf→send/write pattern: a buffer is
// formatted by snprintf with a CRLF-bearing format string and tainted input,
// then sent over a socket. When the send/write call itself has no CRLF in its
// arguments, we look backward for a matching snprintf and return the tainted
// variable from that call.
func traceSnprintfCRLF(root parser.Node, f *db.Function, sinkCallName string, sinkArgs []string, sinkLine int) string {
	if sinkCallName != "send" && sinkCallName != "write" {
		return ""
	}
	if len(sinkArgs) < 2 {
		return ""
	}
	bufVar := bareIdentString(sinkArgs[1])
	if bufVar == "" {
		return ""
	}
	for _, call := range root.FindAll("call_expression") {
		if call.StartLine() >= sinkLine {
			continue
		}
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		if name != "snprintf" && name != "sprintf" &&
			name != "snprintf_s" && name != "sprintf_s" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 3 {
			continue
		}
		if bareIdentString(args[0]) != bufVar {
			continue
		}
		fmtIdx := 1
		if name == "snprintf" || name == "snprintf_s" || name == "sprintf_s" {
			fmtIdx = 2
		}
		if len(args) <= fmtIdx {
			continue
		}
		formatStr := args[fmtIdx]
		if !isProtocolHeaderContext(bufVar, formatStr) {
			continue
		}
		for i := fmtIdx + 1; i < len(args); i++ {
			arg := strings.TrimSpace(args[i])
			if isStringLiteral(arg) {
				continue
			}
			if v := bareIdentString(arg); v != "" {
				return v
			}
		}
	}
	return ""
}

func crlfTaintVariable(callName string, args []string) string {
	switch callName {
	case "fprintf", "snprintf":
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
	case "send", "write":
		if len(args) >= 2 {
			arg := strings.TrimSpace(args[1])
			if !isStringLiteral(arg) {
				return bareIdentString(arg)
			}
		}
	}
	return ""
}

func isProtocolHeaderContext(fileVarName, formatStr string) bool {
	lower := strings.ToLower(fileVarName)
	if strings.Contains(lower, "sock") || strings.Contains(lower, "conn") ||
		strings.Contains(lower, "socket") || strings.Contains(lower, "resp") ||
		strings.Contains(lower, "header") {
		return true
	}
	return strings.Contains(formatStr, "\\r\\n") || strings.Contains(formatStr, "\r\n") ||
		strings.Contains(formatStr, "HTTP/") || strings.Contains(formatStr, "Header:") ||
		strings.Contains(formatStr, "Set-Cookie:") || strings.Contains(formatStr, "Content-Type:")
}

func isLogContextByHeuristic(fileVarName, callName string) bool {
	if apikb.IsLogSink(callName) {
		return true
	}
	lower := strings.ToLower(fileVarName)
	return strings.Contains(lower, "log") || strings.Contains(lower, "logfile") ||
		strings.Contains(lower, "audit") || strings.Contains(lower, "fp_log")
}
