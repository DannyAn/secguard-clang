package evidence

import (
	"context"
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

	summaries := buildFuncSummaries(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		inits := root.FindAll("init_declarator")
		assigns := root.FindAll("assignment_expression")
		ptrs := root.FindAll("pointer_expression")
		fields := root.FindAll("field_expression")
		macros := macroFreeSummaries(root)

		for _, f := range funcs {
			aliases := findAliases(f, inits, assigns)
			freeSites := d.findAllFreeSites(f, calls, summaries, aliases, macros)
			useSites := d.findUseSites(f, ptrs, fields, calls)

			for _, fs := range freeSites {
				for _, use := range useSites[fs.varName] {
					if use.line <= fs.line {
						continue
					}
					// A whole-variable free (free(p)) dangles every later use of p
					// and its fields; a field free (free(p->msg) directly or via a
					// callee) only dangles later uses of THAT field — reading
					// p->mode after free(p->msg) is not a use-after-free.
					if fs.field != "" && use.field != fs.field {
						continue
					}
					props := map[string]interface{}{
						"variable":  fs.varName,
						"free_line": fs.line,
						"use_line":  use.line,
						"category":  "use_after_free",
					}
					if fs.indirect {
						props["indirect"] = true
						props["callee"] = fs.callee
					}
					if fs.field != "" {
						props["freed_field"] = fs.field
					}
					if emitEvent(ctx, d.store, d.logger, "USE_AFTER_FREE", f.ID, &db.Location{FileID: file.ID, Line: use.line}, props) {
						result.EventsCreated++
					}
				}
			}
		}
	})
	return result, err
}

func (d *UseAfterFreeDetector) findAllFreeSites(f *db.Function, calls []parser.Node, summaries summaryMap, aliases map[string]aliasInfo, macros map[string]macroFreeSummary) []freeSite {
	var sites []freeSite

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		callLine := call.StartLine()

		// A freeing function-like macro (`#define my_free(p) free(p)`) wraps a
		// free the parser cannot see; treat the call as a free of its first
		// argument. A macro that ALSO nulls the argument (SAFE_FREE) is excluded:
		// there the freed state is immediately overwritten, so a later use is a
		// null-deref, not a use-after-free.
		if s, ok := macros[callName]; ok && s.freesArg && !s.nullsArg {
			args := getCallArgs(call)
			if len(args) > 0 && args[0].Kind() == "identifier" {
				sites = append(sites, freeSite{varName: args[0].Text(), line: callLine})
			}
			continue
		}

		if callName == "free" {
			args := getCallArgs(call)
			for _, arg := range args {
				switch arg.Kind() {
				case "identifier":
					name := arg.Text()
					sites = append(sites, freeSite{varName: name, line: callLine})
					// free(p) also invalidates every pointer into p's block:
					// a direct alias (q = p) and a field alias (q = p->f) both
					// dangle. Without this, `q = p; free(p); use(q)` was missed.
					for aliasVar, ai := range aliases {
						if ai.baseVar == name {
							sites = append(sites, freeSite{varName: aliasVar, line: callLine})
						}
					}
				case "field_expression":
					// free(p->msg) dangles only p->msg (and aliases of it), not the
					// whole struct p. The field is matched against the use's field,
					// so reading p->mode after free(p->msg) is not a use-after-free.
					if base, field := extractFieldAccess(arg); base != "" && field != "" {
						sites = append(sites, freeSite{varName: base, field: field, line: callLine})
					}
				case "subscript_expression":
					// free(a[0]) dangles only a[0]; the constant index keeps a[0]
					// distinct from a[1].
					if base, field := subscriptAccess(arg); base != "" && field != "" {
						sites = append(sites, freeSite{varName: base, field: field, line: callLine})
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

// isFieldWrite reports whether a field_expression node is a write target (the
// LHS of an assignment or the declarator of an initializer), so `s->msg = NULL`
// addresses the field without reading it and must not count as a use.
func isFieldWrite(node parser.Node) bool {
	p := node.Parent()
	if p == nil {
		return false
	}
	switch p.Kind() {
	case "assignment_expression", "init_declarator":
		children := p.NamedChildren()
		return len(children) >= 1 && children[0].Text() == node.Text()
	}
	return false
}

// useSite is one use of a base variable: a whole-variable use (`*p`, `p` as a
// call argument) has field == "", a field read (`p->mode`) names that field.
type useSite struct {
	line  int
	field string
}

func (d *UseAfterFreeDetector) findUseSites(f *db.Function, ptrs, fields, calls []parser.Node) map[string][]useSite {
	useSites := make(map[string][]useSite)

	addUse := func(varName, field string, line int) {
		if varName != "" {
			useSites[varName] = append(useSites[varName], useSite{line: line, field: field})
		}
	}

	// useTarget reduces a dereference operand or a field access to its base
	// variable plus the field being touched ("" for a whole-variable use).
	var useTarget func(parser.Node) (string, string)
	useTarget = func(node parser.Node) (string, string) {
		switch node.Kind() {
		case "identifier":
			return node.Text(), ""
		case "field_expression":
			return extractFieldAccess(node)
		case "subscript_expression":
			return subscriptAccess(node)
		case "parenthesized_expression":
			for _, c := range node.NamedChildren() {
				if b, fld := useTarget(c); b != "" {
					return b, fld
				}
			}
		}
		return "", ""
	}

	for _, deref := range ptrs {
		if !funcLineRange(f, deref.StartLine()) {
			continue
		}
		if !strings.HasPrefix(deref.Text(), "*") {
			continue
		}
		for _, child := range deref.NamedChildren() {
			if base, fld := useTarget(child); base != "" {
				addUse(base, fld, deref.StartLine())
			}
		}
	}

	for _, field := range fields {
		if !funcLineRange(f, field.StartLine()) {
			continue
		}
		// A field WRITE (`s->msg = NULL`, `s->msg = malloc(...)`) addresses the
		// field without reading it, so it is not a use-after-free candidate.
		if isFieldWrite(field) {
			continue
		}
		base, fld := extractFieldAccess(field)
		addUse(base, fld, field.StartLine())
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName == "free" {
			continue
		}
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				if arg.Kind() == "identifier" {
					addUse(arg.Text(), "", call.StartLine())
				}
			}
		}
	}

	return useSites
}
