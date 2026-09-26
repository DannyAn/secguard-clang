package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
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
	// Annex K `_s` variants carry the same non-literal-format risk as their
	// unchecked counterparts (FS-02).
	"printf_s": true, "fprintf_s": true, "sprintf_s": true, "snprintf_s": true,
	"vprintf_s": true, "vfprintf_s": true, "vsprintf_s": true, "vsnprintf_s": true,
}

func (d *FormatStringDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		for _, f := range funcs {
			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
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

				if emitEvent(ctx, d.store, d.logger, "FORMAT_STRING", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, map[string]string{
					"function":   callName,
					"format_arg": formatArg,
					"expression": call.Text(),
					"category":   "format_string",
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
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
			case "err", "errx":
				// err(eval, fmt, ...) / errx(eval, fmt, ...): args[0] is the eval
				// exit code, args[1] is the format (FS-01). warn/warnx put the
				// format at args[0], so they keep the default.
				formatIdx = 1
			case "sprintf", "vsprintf":
				formatIdx = 1
			case "sprintf_s", "vsprintf_s":
				// C11 Annex K: sprintf_s(s, n, format, ...) — format is args[2].
				formatIdx = 2
			case "snprintf", "vsnprintf":
				formatIdx = 2
			case "snprintf_s", "vsnprintf_s":
				// C11 Annex K: snprintf_s(s, n, format, ...) — format is args[2].
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
	t := strings.TrimSpace(text)
	// C string literal prefixes: L (wide), u8/u/U (C11 UTF), and a plain string.
	// A UTF/wide literal is still a compile-time literal, not a tainted format
	// (FS-03).
	for _, p := range []string{`u8"`, `u"`, `U"`, `L"`, `"`} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}
