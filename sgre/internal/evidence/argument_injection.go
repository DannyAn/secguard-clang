package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type ArgumentInjectionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewArgumentInjectionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *ArgumentInjectionDetector {
	return &ArgumentInjectionDetector{store: store, parser: p, logger: logger}
}

func (d *ArgumentInjectionDetector) Name() string { return "argument_injection" }

func (d *ArgumentInjectionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			d.detectArgumentInjection(ctx, f, file, calls, &result)
		}
	})
	return result, err
}

func (d *ArgumentInjectionDetector) detectArgumentInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		argvIdx, ok := apikb.ArgumentInjectionArgvIdx(callName)
		if !ok {
			continue
		}
		args := extractCallArgs(call)
		if len(args) <= argvIdx {
			continue
		}

		variable := argumentInjectionVariable(callName, args, argvIdx)
		if variable == "" {
			continue
		}

		if emitEvent(ctx, d.store, d.logger, "INJECTION", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
			"function":   callName,
			"category":   "argument_injection",
			"variable":   variable,
			"expression": call.Text(),
		}) {
			result.EventsCreated++
		}
	}
}

// argumentInjectionVariable returns the bare identifier of the first non-constant
// argument-array element, or "" when all elements are compile-time constants.
// For execv*/posix_spawn the argv parameter is a single array-pointer argument
// (args[argvIdx]); a bare identifier is a variable (tainted), a compound literal
// like (char*[]){"ls","-l",NULL} is constant. For execl* the arguments from
// argvIdx onward are variadic; each is checked individually.
func argumentInjectionVariable(callName string, args []string, argvIdx int) string {
	if isExecvArrayForm(callName) {
		arg := strings.TrimSpace(args[argvIdx])
		return bareIdentString(arg)
	}
	for i := argvIdx; i < len(args); i++ {
		arg := strings.TrimSpace(args[i])
		if isConstantVariadicArg(arg) {
			continue
		}
		if v := bareIdentString(arg); v != "" {
			return v
		}
	}
	return ""
}

func isExecvArrayForm(name string) bool {
	switch name {
	case "execv", "execvp", "execve", "posix_spawn", "posix_spawnp":
		return true
	}
	return false
}

func isConstantVariadicArg(arg string) bool {
	if arg == "NULL" || arg == "0" || arg == "(char*)NULL" || arg == "(char *)NULL" {
		return true
	}
	if isStringLiteral(arg) {
		return true
	}
	return false
}
