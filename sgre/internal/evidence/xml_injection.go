package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type XMLInjectionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewXMLInjectionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *XMLInjectionDetector {
	return &XMLInjectionDetector{store: store, parser: p, logger: logger}
}

func (d *XMLInjectionDetector) Name() string { return "xml_injection" }

func (d *XMLInjectionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			d.detectXMLInjection(ctx, f, file, calls, &result)
		}
	})
	return result, err
}

func (d *XMLInjectionDetector) detectXMLInjection(ctx context.Context, f *db.Function, file *db.File, calls []parser.Node, result *DetectResult) {
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		spec, ok := apikb.XMLInjectionSinkSpecByName(callName)
		if !ok {
			continue
		}
		args := extractCallArgs(call)
		if len(args) <= spec.TaintArgIdx {
			continue
		}
		taintArg := strings.TrimSpace(args[spec.TaintArgIdx])
		if isStringLiteral(taintArg) {
			continue
		}
		if callName == "xmlXPathCompiledEval" {
			continue
		}
		variable := bareIdentString(taintArg)
		if emitEvent(ctx, d.store, d.logger, "INJECTION", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
			"function":   callName,
			"category":   spec.Category,
			"variable":   variable,
			"expression": call.Text(),
		}) {
			result.EventsCreated++
		}
	}
}
