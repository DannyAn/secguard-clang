package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
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
	column   int
	indirect bool
	callee   string
}

func (d *UseAfterFreeDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	summaries := buildFuncSummaries(ctx, d.store, d.parser, d.logger)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		calls := root.FindAll("call_expression")
		inits := root.FindAll("init_declarator")
		assigns := root.FindAll("assignment_expression")
		ptrs := root.FindAll("pointer_expression")
		fields := root.FindAll("field_expression")
		returns := root.FindAll("return_statement")
		subs := root.FindAll("subscript_expression")
		macros := macroFreeSummaries(root)
		bodies := functionBodyMap(root.FindAll("function_definition"))

		for _, f := range funcs {
			aliases := findAliases(f, inits, assigns)
			freeSites := d.findAllFreeSites(f, calls, summaries, aliases, macros)
			useSites := d.findUseSites(f, ptrs, fields, calls, returns, assigns, subs, summaries)

			// The statement CFG decides free→use reachability: a loop-carried
			// `for(...) { use(p); free(p); }` has the use AFTER the free in source
			// order on the second iteration, so line order alone missed it (UF-01/06).
			cfg := graph.BuildStmtCFG(bodies[f.StartLine], f.EndLine)

			for _, fs := range freeSites {
				fsNode := cfg.NodeAt(fs.line)
				for _, use := range useSites[fs.varName] {
					// Fast path: use strictly after free in source order.
					inOrder := use.line > fs.line || (use.line == fs.line && use.column > fs.column)
					reach := inOrder
					if !inOrder && fsNode != nil {
						// Loop back-edge / goto: the free still reaches the use.
						if useNode := cfg.NodeAt(use.line); useNode != nil {
							reach = cfg.Reaches(fsNode.ID, useNode.ID)
						}
					}
					if !reach {
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

// terminalBaseVar resolves baseVar through whole-variable alias chains: while
// baseVar itself is an alias with no field selector, follow it to its base. An
// alias with a field selector (q = p->f) is not a whole-variable alias, so the
// walk stops there. A visited set guards against alias cycles.
func terminalBaseVar(aliases map[string]aliasInfo, baseVar string) string {
	visited := make(map[string]bool)
	for baseVar != "" && !visited[baseVar] {
		visited[baseVar] = true
		ai, ok := aliases[baseVar]
		if !ok || ai.field != "" {
			return baseVar
		}
		baseVar = ai.baseVar
	}
	return baseVar
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
			if len(args) > 0 {
				if a0 := unwrapCastParen(args[0]); a0.Kind() == "identifier" {
					sites = append(sites, freeSite{varName: a0.Text(), column: call.StartColumn(), line: callLine})
				}
			}
			continue
		}

		if apikb.IsDeclaredDeallocator(callName) {
			// A DECLARED deallocator (free/freeaddrinfo/freeifaddrs + registered
			// ones) frees its FIRST argument. Marking every argument would treat a
			// multi-parameter project deallocator's flags/count as a freed pointer
			// (UF-11). A heuristic-only deallocator (name ends with "free" but not
			// declared) falls through to the function-summary branch below, which
			// picks the freed parameter precisely (fail-closed).
			args := getCallArgs(call)
			for _, arg := range args[:1] {
				arg = unwrapCastParen(arg)
				switch arg.Kind() {
				case "identifier":
					name := arg.Text()
					// free(p) also invalidates every pointer into p's block: a direct
					// alias (q = p), a field alias (q = p->f), AND the terminal base
					// when p itself is an alias (p = q; free(p); use(q)) — UF-04/08.
					// Whole-variable alias chains resolve to their terminal base, which
					// is the canonical freed object.
					base := terminalBaseVar(aliases, name)
					seen := map[string]bool{name: true}
					sites = append(sites, freeSite{varName: name, column: call.StartColumn(), line: callLine})
					if base != name {
						seen[base] = true
						sites = append(sites, freeSite{varName: base, column: call.StartColumn(), line: callLine})
					}
					for aliasVar := range aliases {
						if !seen[aliasVar] && terminalBaseVar(aliases, aliasVar) == base {
							seen[aliasVar] = true
							sites = append(sites, freeSite{varName: aliasVar, column: call.StartColumn(), line: callLine})
						}
					}
				case "field_expression":
					// free(p->msg) dangles only p->msg (and aliases of it), not the
					// whole struct p. The field is matched against the use's field,
					// so reading p->mode after free(p->msg) is not a use-after-free.
					if base, field := extractFieldAccess(arg); base != "" && field != "" {
						sites = append(sites, freeSite{varName: base, field: field, column: call.StartColumn(), line: callLine})
					}
				case "subscript_expression":
					// free(a[0]) dangles only a[0]; the constant index keeps a[0]
					// distinct from a[1].
					if base, field := subscriptAccess(arg); base != "" && field != "" {
						sites = append(sites, freeSite{varName: base, field: field, column: call.StartColumn(), line: callLine})
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
			arg = unwrapCastParen(arg)
			if arg.Kind() != "identifier" {
				continue
			}
			argVar := arg.Text()

			if s.ParamDirectFrees[argIdx] {
				sites = append(sites, freeSite{
					varName:  argVar,
					line:     callLine,
					column:   call.StartColumn(),
					indirect: true,
					callee:   callName,
				})
			}

			for _, field := range s.ParamFieldFrees[argIdx] {
				sites = append(sites, freeSite{
					varName:  argVar,
					field:    field,
					line:     callLine,
					column:   call.StartColumn(),
					indirect: true,
					callee:   callName,
				})

				for aliasVar, ai := range aliases {
					if ai.baseVar == argVar && ai.field == field {
						sites = append(sites, freeSite{
							varName:  aliasVar,
							line:     callLine,
							column:   call.StartColumn(),
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

// isDeallocatorArg reports whether node is an argument to a deallocator call
// (`free(p->f)` / `free(p)`): the argument is the thing being freed, not a use
// of it. Without this, the second `free(g.data)` in a guarded error path counts
// `g.data` as a "use", so the detector reports "freed at X then used at the
// second free's own line" — a self-inflicted false use-after-free.
func isDeallocatorArg(node parser.Node) bool {
	cur := node
	for {
		p := cur.Parent()
		if p == nil {
			return false
		}
		switch p.Kind() {
		case "argument_list":
			cur = *p
		case "call_expression":
			return apikb.IsDeallocator(extractCallName(*p))
		default:
			return false
		}
	}
}

// insideSizeof reports whether a node sits inside a sizeof expression, which is
// a compile-time size query, not a read of the operand.
func insideSizeof(node parser.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "sizeof_expression":
			return true
		case "function_definition":
			return false
		}
	}
	return false
}

// isFieldWrite reports whether a field_expression node is a write target (the
// LHS of an assignment or the declarator of an initializer), so `s->msg = NULL`
// addresses the field without reading it and must not count as a use. It does
// NOT walk through a subscript: `q->msg[0] = 1` after `free(q->msg)` READS the
// dangling q->msg to index it, so it is a genuine use-after-free — only the
// direct `s->msg = ...` shape is a pure address-of write.
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
	line   int
	column int
	field  string
}

func (d *UseAfterFreeDetector) findUseSites(f *db.Function, ptrs, fields, calls, returns, assigns, subs []parser.Node, summaries summaryMap) map[string][]useSite {
	useSites := make(map[string][]useSite)

	addUse := func(varName, field string, line, column int) {
		if varName != "" {
			useSites[varName] = append(useSites[varName], useSite{line: line, column: column, field: field})
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
				addUse(base, fld, deref.StartLine(), deref.StartColumn())
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
		// A field passed to free() (`free(g.data)`) is the thing freed, not a use.
		if isDeallocatorArg(field) {
			continue
		}
		base, fld := extractFieldAccess(field)
		addUse(base, fld, field.StartLine(), field.StartColumn())
	}

	// A bare identifier (or cast) in a return hands the dangling pointer out —
	// `free(p); return p;` is the classic use-after-free (UF-05).
	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		for _, child := range ret.NamedChildren() {
			if name := argIdentifier(child); name != "" {
				addUse(name, "", ret.StartLine(), ret.StartColumn())
			}
		}
	}

	// A bare identifier (or cast) on an assignment RHS reads the pointer —
	// `free(p); q = p;` / `free(p); q = (T*)p;` (UF-05).
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		if name := argIdentifier(children[1]); name != "" {
			addUse(name, "", assign.StartLine(), assign.StartColumn())
		}
	}

	// A subscript read `p[i]` reads the base pointer to index it (UF-05).
	for _, sub := range subs {
		if !funcLineRange(f, sub.StartLine()) {
			continue
		}
		if insideSizeof(sub) || isDeallocatorArg(sub) {
			continue
		}
		if base, _ := subscriptAccess(sub); base != "" {
			addUse(base, "", sub.StartLine(), sub.StartColumn())
		}
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if apikb.IsDeclaredDeallocator(callName) {
			continue
		}
		if apikb.IsDeallocator(callName) {
			if s, ok := summaries[callName]; ok && summaryFreesAnyParam(s) {
				continue
			}
		}
		// A freeing wrapper (a callee the summary shows frees this argument,
		// whole or a field) takes the argument as the thing being freed, not as
		// a later use of it. Counting the argument would self-report `item` in
		// `pktdrp_free_tbl_res(item)` as a use-after-free of the OTHER branch's
		// free. This mirrors isDeallocatorArg, which only recognized built-in
		// deallocators and so missed wrapper functions like *free_tbl_res.
		s := summaries[callName]
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for argIdx, arg := range child.NamedChildren() {
				if arg.Kind() != "identifier" {
					continue
				}
				if s != nil && (s.ParamDirectFrees[argIdx] || len(s.ParamFieldFrees[argIdx]) > 0) {
					continue
				}
				addUse(arg.Text(), "", call.StartLine(), call.StartColumn())
			}
		}
	}

	return useSites
}

// summaryFreesAnyParam reports whether the function summary confirms the body
// frees at least one parameter (directly or a field). Used to gate the
// IsDeallocator heuristic: a name ending in "free" is only trusted when the
// summary proves the parameter is freed.
func summaryFreesAnyParam(s *FuncSummary) bool {
	for _, v := range s.ParamDirectFrees {
		if v {
			return true
		}
	}
	for _, fields := range s.ParamFieldFrees {
		if len(fields) > 0 {
			return true
		}
	}
	return false
}
