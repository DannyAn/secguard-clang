package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// stackUninitFacts is the "collect" phase output: the variables the function
// declares without an initializer, every write site those variables receive,
// and the output-parameter/macro lines after which a write is trusted.
type stackUninitFacts struct {
	uninitVars           map[string]bool
	assignSites          map[string][]int
	declsByName          map[string][]varDecl
	outputParamInitLines map[string]int
}

// stackUninitFlow is the "compute" phase output: the statement CFG and the
// loop-carried lazy-initialization facts that decide whether a read is
// dominated by a write.
type stackUninitFlow struct {
	cfg      *graph.StmtCFG
	lease    *graph.CFGLease
	cfgValid bool
	loopInit map[string]loopCarriedInit
}

func (d *UninitVariableDetector) detectStackUninit(ctx context.Context, in *uninitScanInputs) {
	facts := d.collectStackUninitFacts(in)
	flow := d.computeStackUninitFlow(ctx, in, &facts)
	if flow.lease != nil {
		defer flow.lease.Release()
	}
	d.emitStackUninitUses(ctx, in, &facts, &flow)
}

func (d *UninitVariableDetector) collectStackUninitFacts(in *uninitScanInputs) stackUninitFacts {
	f := in.f
	decls, assigns, calls, exprStmts := in.decls, in.assigns, in.calls, in.exprStmts
	ifs, asms := in.ifs, in.asms
	summaries, macroWrites, objectMacroWrites := in.summaries, in.macroWrites, in.objectMacroWrites
	bound := in.bound
	uninitVars := make(map[string]bool)
	assignSites := make(map[string][]int)
	declsByName := make(map[string][]varDecl)
	// outputParamInitLines maps a variable to the line after which it is
	// definitely written via an output parameter (`&x` passed to a writer). A
	// use before that line (e.g. inside a failure branch, TC16) stays reported;
	// a use after it is initialized. This is kept separate from assignSites
	// because hasUnassignedPath only matches assignment/declaration statements,
	// so an output-param call line would otherwise never count as an assign.
	outputParamInitLines := make(map[string]int)

	for _, decl := range decls {
		if !funcLineRange(f, decl.StartLine()) {
			continue
		}
		// A block-scope `extern` declaration is a REFERENCE to a global defined
		// elsewhere, not a definition with indeterminate storage: it can never be
		// an uninitialized local. (`extern int g_total;` inside a function was
		// reported as a certain stack-uninit read of g_total — an auto-confirmed
		// CWE-457 false positive in production.)
		isStatic := false
		hasInit := false
		for _, child := range decl.NamedChildren() {
			if child.Kind() == "storage_class_specifier" && (child.Text() == "static" || child.Text() == "extern") {
				isStatic = true
			}
			if child.Kind() == "init_declarator" {
				hasInit = true
				// Only the declarator (children[0]) is the assigned variable; the
				// value (children[1]) is a read, e.g. `int b = a;` assigns b and
				// reads a. The previous loop added every identifier (b AND a),
				// which wrongly recorded a as "assigned" and hid a copy-uninit.
				dc := child.NamedChildren()
				if len(dc) >= 1 {
					if name := extractVarName(dc[0]); name != "" {
						assignSites[varKey(name, decl.StartLine())] = append(assignSites[varKey(name, decl.StartLine())], decl.StartLine())
					}
				}
			}
		}
		if hasInit || isStatic {
			continue
		}
		scopeEnd := enclosingScopeEnd(decl)
		for _, child := range decl.NamedChildren() {
			// A pointer declarator wraps the variable name (`struct Node *node;`
			// parses as pointer_declarator[identifier]). Registering only the
			// direct `identifier` child left every pointer local invisible to the
			// uninit analysis, so `struct Node *node; if (node != 0) ...` — a read
			// of an indeterminate pointer VALUE in the condition — was never
			// reported (Issue #226, CWD-SUB-1140 sample B).
			name := ""
			switch child.Kind() {
			case "identifier":
				name = child.Text()
			case "pointer_declarator":
				// `void *buf[16]` parses as pointer_declarator[array_declarator]:
				// the variable is an ARRAY of pointers, not a scalar pointer.
				// Registering it made the array's decay (`backtrace(buf, 16)`)
				// and element reads (`buf[0]`) look like reads of an
				// indeterminate pointer VALUE — an auto-confirmed CWE-457 false
				// positive (issue #263). An array is not a scalar the stack
				// path can reason about; its element initialization is not a
				// stack-uninit fact.
				if declaratorIsArray(child) {
					continue
				}
				if n, _ := argDeclaratorVar(child); n != "" {
					name = n
				}
			}
			if name != "" && !parser.IsCTypeKeyword(name) {
				uninitVars[varKey(name, decl.StartLine())] = true
				declsByName[name] = append(declsByName[name], varDecl{name: name, declLine: decl.StartLine(), scopeEnd: scopeEnd})
			}
		}
	}

	// isValue disambiguates the `(A) & x` argument shape for the address-taken
	// recognition: `(shm_handle)&prfs_list` is a cast-to-pointer address-of when
	// A names a type, but `sink((flags) & mask)` is a plain bit-and when A names
	// a value. tree-sitter-c gives both the identical binary_expression parse,
	// so the caller must supply the scope knowledge (see
	// parser.Node.AddressTakenTargetScoped).
	isValue := func(name string) bool { return bound[name] }

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		// assignmentLHSName recovers the real write target even when a macro
		// call site glues a call_expression as the first named child and buries
		// the LHS in an ERROR node (`LIST_FOR_EACH(x, h)\n q = 1`).
		if name := assignmentLHSName(assign); name != "" {
			if key := resolveVarKey(declsByName, name, assign.StartLine()); key != "" {
				assignSites[key] = append(assignSites[key], assign.StartLine())
			}
		}
	}

	// A GNU inline-asm OUTPUT operand (`__asm__ __volatile__("rdtsc" :
	// "=a"(lo), "=d"(hi));`) writes its symbol variable when the statement
	// executes — the constraint string names a register the CPU fills. The
	// write is invisible to the assignment scan (it is not an
	// assignment_expression), so without this pass `lo`/`hi` read as never
	// written, the candidate carried init@none, and the planner's must
	// dataflow auto-confirmed a false CWE-457 (issue #263: 6 of 18
	// auto-confirm false positives were rdtsc-style asm outputs). Recording
	// the asm line as an assign site keeps the CFG path analysis honest: an
	// asm inside an if still leaves an unassigned bypass path, so the use
	// stays a suspected lead for the AI instead of being auto-confirmed.
	for _, asm := range asms {
		if !funcLineRange(f, asm.StartLine()) {
			continue
		}
		ops := asm.ChildByFieldName("output_operands")
		if ops == nil {
			continue
		}
		for _, op := range ops.NamedChildren() {
			if op.Kind() != "gnu_asm_output_operand" {
				continue
			}
			// The operand's symbol is its identifier child (the constraint
			// string is the other named child); the `symbol` FIELD binding is
			// not exposed positionally by the grammar, so match by kind.
			for _, c := range op.NamedChildren() {
				if c.Kind() != "identifier" {
					continue
				}
				if key := resolveVarKey(declsByName, c.Text(), asm.StartLine()); key != "" {
					assignSites[key] = append(assignSites[key], asm.StartLine())
				}
			}
		}
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		// A function-like macro that writes one of its parameters initializes the
		// argument passed at that position (`#define OUT(x) (x) = ...` → `OUT(v)`).
		// Record the written argument as an output-param init line so a LATER use
		// of that argument is not reported.
		if written := macros.WrittenArgs(call, macroWrites); len(written) > 0 {
			for name := range written {
				if key := resolveVarKey(declsByName, name, call.StartLine()); key != "" {
					if call.StartLine() > outputParamInitLines[key] {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// A command-init macro initializes caller locals it does not receive as
		// arguments (`#define CMD_MSG_INIT(recv) do { execId = ...; } while (0)`
		// followed by `CMD_MSG_INIT(msgRcv);`). Its body assigns those locals, so
		// they are initialized from the call line on.
		if free := macros.WrittenFree(call, macroWrites); len(free) > 0 {
			for name := range free {
				if key := resolveVarKey(declsByName, name, call.StartLine()); key != "" {
					if call.StartLine() > outputParamInitLines[key] {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// A setter macro (`SET(x, v)` → `(x) = (v)`) whose body lives in an
		// excluded third-party header writes its first bare-identifier argument;
		// WriteSummaries cannot see the body, so the name is the only signal.
		// Record it as an init line so a LATER read of the just-declared variable
		// is not reported either.
		if setterMacroName(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				if key := resolveVarKey(declsByName, args[0].Text(), call.StartLine()); key != "" {
					if call.StartLine() > outputParamInitLines[key] {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// A config/built-in iterator macro (`SLL_SCAN` in secguard.toml
		// [iterator_macros], or list_for_each_entry) writes its iterator
		// parameter(s) in the for-init clause. The definition lives outside the
		// scan tree (an SDK header), so record the written argument(s) as an init
		// line — a later read is initialized, not use-before-init.
		if iterIdxs, ok := d.iterMacros[callName]; ok {
			if args := getCallArgs(call); len(args) > 0 {
				for _, i := range iterIdxs {
					if i >= len(args) || args[i].Kind() != "identifier" {
						continue
					}
					if key := resolveVarKey(declsByName, args[i].Text(), call.StartLine()); key != "" {
						if call.StartLine() > outputParamInitLines[key] {
							outputParamInitLines[key] = call.StartLine()
						}
					}
				}
			}
		}
		// A parse/deserialize macro (`CAP_MSG_HEAD_PARSE(msg, head)`) writes its
		// by-value struct argument(s); mark them initialized so a LATER field read
		// of the struct is not reported.
		if structOutputMacroName(callName) {
			for _, arg := range getCallArgs(call) {
				if arg.Kind() != "identifier" {
					continue
				}
				if key := resolveVarKey(declsByName, arg.Text(), call.StartLine()); key != "" {
					if call.StartLine() > outputParamInitLines[key] {
						outputParamInitLines[key] = call.StartLine()
					}
				}
			}
		}
		// va_start/va_copy initialize the va_list (an array type that decays to
		// a pointer, so it is passed as an identifier, not `&ap`). Record the
		// EARLIEST initializer: a later use is initialized once any va_start has
		// run, and re-starting the same va_list (`va_end` then a second
		// `va_start`) must not move the init line past the uses in the first
		// round — that overwrite is what produced the two-round-traversal
		// certain-uninit false positives.
		if callName == "va_start" || callName == "va_copy" {
			if args := getCallArgs(call); len(args) > 0 {
				if name := extractVarName(args[0]); name != "" {
					if key := resolveVarKey(declsByName, name, call.StartLine()); key != "" {
						if cur, ok := outputParamInitLines[key]; !ok || call.StartLine() < cur {
							outputParamInitLines[key] = call.StartLine()
						}
					}
				}
			}
		}
		// A copy/init call's first argument is the DESTINATION buffer (written,
		// not read): `strncpy_s(buf, ...)`, `memcpy(dst, ...)`, `sprintf(buf,
		// ...)`. A whole array decays to a pointer, so it is passed as an
		// identifier, not `&buf`; mark it initialized so a LATER read is not
		// reported. (A field destination is handled by detectStructPartialUninit.)
		if isDestWriter(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				if key := resolveVarKey(declsByName, args[0].Text(), call.StartLine()); key != "" {
					outputParamInitLines[key] = call.StartLine()
				}
			}
		}
		// `&whole_var` passed to an output-param writer initializes the variable
		// after the call. Known initializers and local functions that write the
		// parameter on every path initialize unconditionally; a local function
		// that writes only on its success path requires the caller to guard the
		// error return (TC16); unknown/external functions are assumed to write
		// (they have no body to prove otherwise).
		summary, hasSummary := summaries[callName]
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for argIdx, arg := range child.NamedChildren() {
				target, ok := addressOfTargetScoped(arg, isValue)
				if !ok || target.Kind() != "identifier" {
					continue // only whole-variable &x, not &x.field
				}
				name := target.Text()
				key := resolveVarKey(declsByName, name, call.StartLine())
				if key == "" {
					continue
				}
				initLine := call.StartLine()
				if hasSummary && !isOutputParamInitializer(callName) {
					if summary.ParamWrites[argIdx] {
						initLine = call.StartLine() // writes on every path
					} else if summary.ParamConditionalWrites[argIdx] {
						// Writes only on its success path. With the caller's
						// error guard the initialization starts past the
						// guard, so a use INSIDE the error branch (TC16)
						// stays reported. WITHOUT a guard, trust the
						// write-back idiom: production dogfooding shows the
						// unguarded form (`pos += load(&n)`, `init(&cfg)`) is
						// overwhelmingly an out-param that assigns the
						// caller's variable, and keeping it as a potential
						// uninit flooded the reports with false positives.
						//
						// This is a deliberate false-negative trade-off, pinned
						// by TestUninit_OutputParamUnguarded: an unguarded
						// caller that truly ignores a failing conditional
						// writer is no longer reported. The guarded form
						// (TestUninit_OutputParamGuardNearErrorBranch) and the
						// struct path (TestUninit_ConditionalWriteGuard, whose
						// partial-init semantics are field-granular) keep
						// reporting, so the trade-off is scoped to the scalar
						// stack_uninit origin.
						if g := outputParamGuardLine(ifs, f, call, callName); g != 0 {
							initLine = g
						}
					} else {
						// No direct write found: a wrapper that forwards the
						// pointer to another writer (lpGet -> lpGetWithBuf), or a
						// never-writer. Assume the wrapper writes it.
						initLine = call.StartLine()
					}
				}
				if initLine > outputParamInitLines[key] {
					outputParamInitLines[key] = initLine
				}
			}
		}

		// A field passed by address to any function (`getShort(&s.f)`) is an
		// output-param: the callee writes s.f, so the base struct s is being
		// initialized field-by-field. Without this, structs filled through
		// getter/read calls were reported as wholly uninitialized. A whole
		// variable is deliberately NOT treated this way: an output-param may
		// write only on its success path (cf. TC16 init_via_ptr), so `&x` alone
		// does not prove x is initialized on every path.
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for _, arg := range child.NamedChildren() {
				target, ok := addressOfTargetScoped(arg, isValue)
				if !ok {
					continue
				}
				if target.Kind() == "field_expression" || target.Kind() == "subscript_expression" {
					if base := extractVarName(target); base != "" {
						if key := resolveVarKey(declsByName, base, call.StartLine()); key != "" {
							assignSites[key] = append(assignSites[key], call.StartLine())
						}
					}
				}
			}
		}
	}

	// Object-like macro invocation (`MSG_INIT;` right after the declarations):
	// the macro body assigns specific local variables, so the invocation writes
	// them. Record the invocation line as an output-param init line so a later
	// read of those variables is treated as initialized, not use-before-init.
	for _, es := range exprStmts {
		if !funcLineRange(f, es.StartLine()) {
			continue
		}
		name := ""
		for _, child := range es.NamedChildren() {
			if child.Kind() == "identifier" {
				name = child.Text()
				break
			}
		}
		if name == "" {
			continue
		}
		writes, ok := objectMacroWrites[name]
		if !ok {
			continue
		}
		for v := range writes {
			if key := resolveVarKey(declsByName, v, es.StartLine()); key != "" {
				if es.StartLine() > outputParamInitLines[key] {
					outputParamInitLines[key] = es.StartLine()
				}
			}
		}
	}

	return stackUninitFacts{
		uninitVars:           uninitVars,
		assignSites:          assignSites,
		declsByName:          declsByName,
		outputParamInitLines: outputParamInitLines,
	}
}

func (d *UninitVariableDetector) computeStackUninitFlow(ctx context.Context, in *uninitScanInputs, facts *stackUninitFacts) stackUninitFlow {
	f := in.f
	decls, assigns := in.decls, in.assigns
	whiles, fors := in.whiles, in.fors
	bodies, tree := in.bodies, in.tree
	declsByName, uninitVars := facts.declsByName, facts.uninitVars
	body := bodies[f.StartLine]
	cfg, lease := buildStmtCFGFromCtx(ctx, f, body, tree)
	if lease != nil {
		defer lease.Release()
	}
	cfgValid := body.Kind() == "compound_statement"
	if !cfgValid && d.logger != nil {
		d.logger.Debug("uninit: CFG construction degenerate, using conservative fallback",
			"function", f.Name,
		)
	}

	// Loop-carried lazy init: `while (...) { if (g == NULL) { v = ...; g = ...; }
	// ... use(v) ... }`. The guard is true on the first pass (g is null/zero
	// before the loop), so v is written before every in-loop use. Record it so a
	// use after the guard block, still inside the loop, is treated as
	// initialized.
	loopInit := make(map[string]loopCarriedInit)
	for _, loop := range append(append([]parser.Node{}, whiles...), fors...) {
		if !funcLineRange(f, loop.StartLine()) {
			continue
		}
		body := loop.ChildByFieldName("body")
		if body == nil {
			continue
		}
		guardIf := firstIfInLoopBody(*body)
		if guardIf == nil || guardIf.ChildByFieldName("alternative") != nil {
			continue
		}
		g := nullZeroGuardVar(guardIf.ChildByFieldName("condition"))
		if g == "" || !nullZeroInitializedBefore(g, loop.StartLine(), decls, assigns) {
			continue
		}
		cons := guardIf.ChildByFieldName("consequence")
		if cons == nil {
			continue
		}
		for name := range straightLinePrefixAssignedVars(*cons) {
			key := resolveVarKey(declsByName, name, cons.StartLine())
			if key == "" || !uninitVars[key] {
				continue
			}
			loopInit[key] = loopCarriedInit{blockEnd: cons.EndLine(), loopEnd: loop.EndLine()}
		}
	}

	return stackUninitFlow{cfg: cfg, lease: lease, cfgValid: cfgValid, loopInit: loopInit}
}

func (d *UninitVariableDetector) emitStackUninitUses(ctx context.Context, in *uninitScanInputs, facts *stackUninitFacts, flow *stackUninitFlow) {
	f, file, bound := in.f, in.file, in.bound
	calls, assigns, inits := in.calls, in.assigns, in.inits
	returns, ifs, whiles, fors := in.returns, in.ifs, in.whiles, in.fors
	macroWrites := in.macroWrites
	result := in.result
	declsByName, uninitVars := facts.declsByName, facts.uninitVars
	outputParamInitLines, assignSites := facts.outputParamInitLines, facts.assignSites
	cfg, cfgValid, loopInit := flow.cfg, flow.cfgValid, flow.loopInit
	isValue := func(name string) bool { return bound[name] }
	checkUse := func(useLine, useColumn int, name string) {
		if parser.IsCTypeKeyword(name) {
			return
		}
		key := resolveVarKey(declsByName, name, useLine)
		if key == "" || !uninitVars[key] {
			return
		}
		declLine := declLineFromKey(key)
		// Output-param initialization: a use after the (possibly guard-delayed)
		// write-through point is initialized. A use before it — e.g. inside the
		// failure branch of a conditional writer (TC16) — stays reported.
		if initLine, ok := outputParamInitLines[key]; ok && useLine > initLine {
			return
		}
		// Loop-carried lazy init: a use after the guard block, within the same
		// loop, reads a value written on the first iteration.
		if li, ok := loopInit[key]; ok && useLine > li.blockEnd && useLine <= li.loopEnd {
			return
		}
		sites := assignSites[key]
		if len(sites) == 0 {
			// No write site at all: the read target is provably never
			// written before the read.
			d.insertValueUseEvent(ctx, f, file, useLine, useColumn, declLine, name, "", "stack_uninit", "none", 0, "", result)
			return
		}
		if cfgValid && hasUnassignedPath(cfg, name, useLine, sites) {
			// A path bypasses every write. When every write sits inside a
			// loop body the condition may skip, the machine can still name
			// the writes; mixed/branch writes stay for the AI to trace.
			initWrite, initLine := "", 0
			if allSitesInLoops(sites, whiles, fors, f) {
				initWrite, initLine = "loop", firstSite(sites)
			}
			d.insertValueUseEvent(ctx, f, file, useLine, useColumn, declLine, name, "", "stack_uninit", initWrite, initLine, "", result)
			return
		}
		if !cfgValid {
			allInIf := true
			for _, s := range sites {
				if !isInIfRange(ifs, f, s) {
					allInIf = false
					break
				}
			}
			if allInIf {
				d.insertValueUseEvent(ctx, f, file, useLine, useColumn, declLine, name, "", "stack_uninit", "", 0, "", result)
			}
		}
	}

	// scanUses reports uses of uninitialized variables among the identifiers
	// within node at the given line. Identifiers that are the operand of an
	// address-of (`&x`) are write targets, not reads, so they are skipped;
	// skipName (e.g. the callee of a call) is also excluded. A struct VALUE's
	// base (`s` in `s.f`) is a field access handled by struct-partial-uninit,
	// not a scalar read, so it is skipped too.
	scanUses := func(node parser.Node, line int, skipName string, extraSkip map[string]bool) {
		addressed := addressedArgs(node, isValue)
		// An assignment embedded in a condition (`while ((c = *str++))`) WRITES its
		// LHS before the condition is evaluated, so the LHS identifier is not a
		// read of an uninitialized value. Skip every assignment write target
		// (chained assignments included), matching the assignment-RHS scan.
		writes := nestedAssignTargets(node)
		for _, id := range node.FindAll("identifier") {
			name := id.Text()
			if name == skipName || addressed[name] || writes[name] || extraSkip[name] || isValueFieldBase(id) || isInsideTypeExpr(id) {
				continue
			}
			checkUse(line, id.StartColumn(), name)
		}
	}

	for _, ret := range returns {
		if !funcLineRange(f, ret.StartLine()) {
			continue
		}
		scanUses(ret, ret.StartLine(), "", nil)
	}

	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		extra := macros.WrittenArgs(call, macroWrites)
		if free := macros.WrittenFree(call, macroWrites); len(free) > 0 {
			if extra == nil {
				extra = map[string]bool{}
			}
			for name := range free {
				extra[name] = true
			}
		}
		// A setter macro (`SET(x, v)` → `(x) = (v)`) whose body lives in an
		// A setter macro's first bare-identifier argument is an output, not a read
		// (the init line is recorded in the output-param pass above), so skip it
		// in the call scan.
		if len(extra) == 0 && setterMacroName(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				extra = map[string]bool{args[0].Text(): true}
			}
		}
		// A parse/deserialize macro writes its by-value struct argument, so that
		// argument is not a read of an uninitialized value — skip it like the
		// setter-macro first argument above.
		if len(extra) == 0 && structOutputMacroName(callName) {
			extra = map[string]bool{}
			for _, arg := range getCallArgs(call) {
				if arg.Kind() == "identifier" {
					extra[arg.Text()] = true
				}
			}
		}
		// va_start/va_copy's first argument is the va_list they INITIALIZE, not a
		// read of its current value. Without skipping it, the va_start line
		// reports the (just-declared, still-uninitialized) va_list as a
		// use-before-init false positive — the write target is misread as a use.
		if callName == "va_start" || callName == "va_copy" {
			if args := getCallArgs(call); len(args) > 0 {
				if name := extractVarName(args[0]); name != "" {
					if extra == nil {
						extra = map[string]bool{}
					}
					extra[name] = true
				}
			}
		}
		// A copy/init call's destination is written, not read: skip it so the
		// call line does not report the just-declared buffer as use-before-init.
		if isDestWriter(callName) {
			if args := getCallArgs(call); len(args) > 0 && args[0].Kind() == "identifier" {
				if extra == nil {
					extra = map[string]bool{}
				}
				extra[args[0].Text()] = true
			}
		}
		// A field-setter macro's argument is the base of a MEMBER write
		// (`SET_FIELD(x, 0)` → (x).field = 0), not a whole-value read; the member
		// itself is handled by the struct-partial path. Skip the base so the call
		// line does not report x as a scalar use-before-init.
		for name := range macros.WrittenFieldArgs(call, macroWrites) {
			if extra == nil {
				extra = map[string]bool{}
			}
			extra[name] = true
		}
		// A config/built-in iterator macro's iterator parameter(s) are WRITE
		// targets (the for-init assigns them), not reads — skip them so the call
		// line does not report the just-declared iterator as use-before-init.
		if iterIdxs, ok := d.iterMacros[callName]; ok {
			args := getCallArgs(call)
			for _, i := range iterIdxs {
				if i >= len(args) || args[i].Kind() != "identifier" {
					continue
				}
				if extra == nil {
					extra = map[string]bool{}
				}
				extra[args[i].Text()] = true
			}
		}
		scanUses(call, call.StartLine(), callName, extra)
	}

	// A read in an assignment/initializer RHS also uses the variable
	// (`int b = a;` reads uninitialized a). The LHS is a write target, so only
	// the RHS is scanned. This closes the copy-uninit gap (a used to initialize
	// b was previously never reported).
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		// A for-loop's update clause (`for (init; cond; child = child->next)`)
		// reads the variable it writes, but that variable is already initialized
		// by the for-init (or the previous iteration). Scanning its RHS here would
		// report `child` as use-before-init at the loop's opening line, because
		// the for-init assignment shares that line and hasUnassignedPath skips
		// any assign on the use line itself.
		if isForUpdateClause(assign) {
			continue
		}
		children := assign.NamedChildren()
		// assignmentRHSStart accounts for the macro call-site mangling that
		// shifts the RHS from children[1] to children[2] (`total += q` →
		// assignment_expression[call_expression, ERROR(total), identifier(q)]).
		rhsStart := assignmentRHSStart(assign)
		if len(children) <= rhsStart {
			continue
		}
		// A chained assignment `a = b = c = v` puts b and c in the RHS as WRITE
		// targets, not reads; only v (the value) is read. Skip nested LHS so
		// `code = first = index = 0` does not report first/index as read.
		writes := nestedAssignTargets(children[rhsStart])
		addressed := addressedArgs(children[rhsStart], isValue)
		for _, id := range children[rhsStart].FindAll("identifier") {
			name := id.Text()
			if addressed[name] || writes[name] || isValueFieldBase(id) || isInsideTypeExpr(id) {
				continue
			}
			checkUse(assign.StartLine(), id.StartColumn(), name)
		}
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		if _, rhs, ok := init.AssignParts(); ok {
			scanUses(rhs, init.StartLine(), "", nil)
		}
	}

	// Scan only the *condition* of a branch/loop, not the whole subtree. The
	// previous version scanned the entire if/while/for node, which pulled every
	// identifier in the body (including the variables being assigned there) up
	// to the statement's start line — so a variable assigned at the top of a
	// loop body looked "used before init" at the loop's opening line.
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		if cond := ifNode.ChildByFieldName("condition"); cond != nil {
			scanUses(*cond, cond.StartLine(), "", nil)
		}
	}

	for _, whileNode := range whiles {
		if !funcLineRange(f, whileNode.StartLine()) {
			continue
		}
		if cond := whileNode.ChildByFieldName("condition"); cond != nil {
			scanUses(*cond, cond.StartLine(), "", nil)
		}
	}

	for _, forNode := range fors {
		if !funcLineRange(f, forNode.StartLine()) {
			continue
		}
		cond := forNode.ChildByFieldName("condition")
		if cond == nil {
			continue
		}
		// The for-initializer runs exactly once before the condition, so a
		// variable assigned there (`for (i=0; i<n; i++)`) is definitely
		// initialized before the condition reads it — even though both the
		// initializer and condition sit on the same source line. Without this,
		// `i` was reported as use-before-init at the for-loop's opening line.
		initWrites := forInitWrites(forNode)
		addressed := addressedArgs(*cond, isValue)
		// An assignment inside the condition (`for (; (x = next()); )`) writes its
		// LHS, so the LHS identifier is not a read of an uninitialized value.
		condWrites := nestedAssignTargets(*cond)
		for _, id := range cond.FindAll("identifier") {
			if initWrites[id.Text()] || addressed[id.Text()] || condWrites[id.Text()] || isInsideTypeExpr(id) {
				continue
			}
			checkUse(cond.StartLine(), id.StartColumn(), id.Text())
		}
	}
}

// addressOfTarget is the permissive address-of recognition, for call sites with
// no scope oracle to hand (resource_leak's out-param acquirer scan). It accepts
// the ambiguous `(A) & x` shape unconditionally, so a genuine bit-and argument
// may be read as `&x`; prefer addressOfTargetScoped wherever the enclosing
// function's bound names are available.
func addressOfTarget(arg parser.Node) (parser.Node, bool) {
	return arg.AddressTakenTarget()
}

// addressOfTargetScoped resolves a `&` address-of argument, unwrapping the
// cast / parenthesis wrappers a third-party out-param call commonly spells
// (`(void *)&dst`, `(T *)&(dst)`), with the scope oracle that resolves the
// ambiguous `(A) & x` shape: A naming a value makes it a bit-and, A naming a
// type makes it a cast-to-pointer address-of (`(shm_handle)&prfs_list`).
// tree-sitter-c parses both identically, so only the caller's scope knowledge
// can tell them apart (see parser.Node.AddressTakenTargetScoped).
func addressOfTargetScoped(arg parser.Node, isValue func(string) bool) (parser.Node, bool) {
	return arg.AddressTakenTargetScoped(isValue)
}

// setterMacroName reports whether a call name carries a setter/init semantic
// (`_SET`, `_INIT`, `_ASSIGN`, ...). Third-party SDKs spell output macros this
// way; when the macro body lives in an excluded header it is invisible to
// WriteSummaries, so the name is the only signal left that the FIRST argument is
// written, not read (`ODA_GPORT_TRUNK_SET(gport, trunkid)` → `(gport) = ...`).
// getterMacroName reports whether a call name is a getter/reader (GET_/READ_/.../
// returns a _COUNT/_SIZE/_LEN), whose arguments are inputs, not outputs. A setter
// heuristic must not treat these as writing their first argument (UN-12/13).
func getterMacroName(name string) bool {
	upper := strings.ToUpper(name)
	for _, p := range []string{"GET_", "READ_", "IS_", "HAS_", "QUERY_", "PEEK_"} {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	for _, s := range []string{"_COUNT", "_SIZE", "_LEN", "_LENGTH", "_LEVEL"} {
		if strings.HasSuffix(upper, s) {
			return true
		}
	}
	return false
}

func setterMacroName(name string) bool {
	if getterMacroName(name) {
		return false
	}
	upper := strings.ToUpper(name)
	for _, kw := range []string{"_SET", "SET_", "_INIT", "INIT_", "_ASSIGN", "ASSIGN_"} {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

// structOutputMacroName reports whether a call name carries a "parse/decode/fill
// into an output struct" semantic (`CAP_MSG_HEAD_PARSE(msg, head)`, `XXX_DECODE`,
// `XXX_DESERIALIZE`, `XXX_UNPACK`). Third-party SDKs spell message/header parsing
// macros this way; the macro writes its by-value struct argument, so that
// argument is an output, not a read of an uninitialized value — the same
// invisible-body problem setterMacroName solves for `_SET`, but for the
// parse-into-struct shape where the output is a by-value struct, not the first
// `&`-less scalar.
func structOutputMacroName(name string) bool {
	if getterMacroName(name) {
		return false
	}
	upper := strings.ToUpper(name)
	for _, kw := range []string{"_PARSE", "PARSE_", "_DECODE", "DECODE_", "_DESERIALIZE", "DESERIALIZE_", "_UNPACK", "UNPACK_", "_FILL", "FILL_"} {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}

// isForUpdateClause reports whether assign is the update clause of a for-loop
// (`for (init; cond; update)`). The update clause reads the variable it writes
// (`child = child->next`), and that variable is initialized by the for-init or
// the previous iteration, so its RHS must not be scanned as a use-before-init.
func isForUpdateClause(assign parser.Node) bool {
	p := assign.Parent()
	if p == nil || p.Kind() != "for_statement" {
		return false
	}
	update := p.ChildByFieldName("update")
	return update != nil && update.StartByte() == assign.StartByte() && update.EndByte() == assign.EndByte()
}

// forInitWrites returns the set of variable names assigned in a for-loop's
// initializer clause (`for (i=0; ...)`, `for (i=0,j=0; ...)`,
// `for (int i=0; ...)`). These are write targets that precede the condition.
func forInitWrites(forNode parser.Node) map[string]bool {
	writes := make(map[string]bool)
	init := forNode.ChildByFieldName("initializer")
	if init == nil {
		return writes
	}
	for _, assign := range init.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			writes[children[0].Text()] = true
		}
	}
	for _, decl := range init.FindAll("init_declarator") {
		children := decl.NamedChildren()
		if len(children) >= 1 {
			if name := extractVarName(children[0]); name != "" {
				writes[name] = true
			}
		}
	}
	return writes
}

// assignmentLHSName returns the write-target identifier of an assignment_expression,
// recovering the real LHS from an ERROR child when a macro call site glues a
// call_expression as the first named child. For a clean `a = b` it is "a"; for
// `LIST_FOR_EACH(x, h)\n q = 1` (parsed as
// assignment_expression[call_expression, ERROR(q), number_literal]) it recovers
// "q" from the ERROR child.
func assignmentLHSName(assign parser.Node) string {
	children := assign.NamedChildren()
	if len(children) == 0 {
		return ""
	}
	if children[0].Kind() == "identifier" {
		return children[0].Text()
	}
	if len(children) >= 2 && children[0].Kind() == "call_expression" && children[1].Kind() == "ERROR" {
		return firstIdentifier(children[1])
	}
	return ""
}

// assignmentRHSStart returns the index into an assignment_expression's
// NamedChildren() where the RHS (the value) begins: 1 for a clean `a = b`, 2 for
// the macro call-site mangling `total += q` →
// assignment_expression[call_expression, ERROR(total), identifier(q)].
func assignmentRHSStart(assign parser.Node) int {
	children := assign.NamedChildren()
	if len(children) >= 3 && children[0].Kind() == "call_expression" && children[1].Kind() == "ERROR" {
		return 2
	}
	return 1
}

// hasUnassignedPath reports whether there is a control-flow path from the
// function entry to the use that avoids every assignment to varName before the
// use — i.e. the variable may be read uninitialized. It uses the statement-level
// CFG (BuildStmtCFG), replacing the old scope-tree approximation (BuildCFGFromLists).
//
// The avoid set is built from the CFG nodes whose statement ACTUALLY assigns
// varName (not cfg.NodeAt(line), which resolves to the enclosing control-flow
// header when several statements share a line, e.g. `while (c) { x = n; n--; }`).
func hasUnassignedPath(cfg *graph.StmtCFG, varName string, useLine int, assignLines []int) bool {
	if cfg == nil {
		return false
	}
	useNode := cfg.NodeAt(useLine)
	if useNode == nil {
		return false // cannot locate the use; conservative (no report here)
	}
	avoid := make(map[int]bool)
	for _, a := range assignLines {
		if a >= useLine {
			continue
		}
		for _, n := range cfg.Nodes {
			if n.Kind != "stmt" || n.StartLine != a {
				continue
			}
			if assignsVar(n.Stmt, varName) {
				avoid[n.ID] = true
			}
		}
	}
	return cfg.ReachesAvoiding(cfg.Entry, avoid, useNode.ID)
}

// assignsVar reports whether stmt directly assigns varName, covering every
// target of a chained assignment (`code = first = index = 0`), a plain
// assignment_expression (a for-init `i=0`), and a declaration initializer
// (`int x = ...`). A control-flow header that merely contains the line is not a
// match.
func assignsVar(stmt parser.Node, varName string) bool {
	var assigns []parser.Node
	switch stmt.Kind() {
	case "assignment_expression":
		assigns = []parser.Node{stmt}
	case "expression_statement":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() == "assignment_expression" {
				assigns = append(assigns, child)
			}
			// A GNU inline-asm statement writes each output operand's symbol
			// (`__asm__("rdtsc" : "=a"(lo))` assigns lo), so it is an assign
			// site for those variables on every path reaching it (issue #263).
			if child.Kind() == "gnu_asm_expression" {
				if ops := child.ChildByFieldName("output_operands"); ops != nil {
					for _, op := range ops.NamedChildren() {
						for _, c := range op.NamedChildren() {
							if c.Kind() == "identifier" && c.Text() == varName {
								return true
							}
						}
					}
				}
			}
		}
	case "declaration":
		for _, child := range stmt.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			c := child.NamedChildren()
			if len(c) >= 1 && extractVarName(c[0]) == varName {
				return true
			}
		}
		return false
	case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
		// `if ((x = f()) == -1)` / `while ((x = next()) != NULL)` assigns x every
		// time the condition is evaluated, so the control-flow header counts as an
		// assign site for x on all paths reaching it.
		if cond := stmt.ChildByFieldName("condition"); cond != nil {
			for _, a := range cond.FindAll("assignment_expression") {
				for _, name := range chainedWriteTargets(a) {
					if name == varName {
						return true
					}
				}
			}
		}
		if init := stmt.ChildByFieldName("initializer"); init != nil {
			for _, a := range init.FindAll("assignment_expression") {
				for _, name := range chainedWriteTargets(a) {
					if name == varName {
						return true
					}
				}
			}
		}
		return false
	default:
		return false
	}
	for _, a := range assigns {
		for _, name := range chainedWriteTargets(a) {
			if name == varName {
				return true
			}
		}
	}
	return false
}

// loopCarriedInit records a variable that is initialized on the first loop
// iteration and retains that value on every later iteration: the classic
// `while (...) { if (g == NULL) { v = ...; g = ...; } ... use(v) ... }`
// lazy-init idiom. The guard `g == NULL` is guaranteed TRUE on the first pass
// (g is null/zero-initialized immediately before the loop), so v is written
// before any use inside the loop. A naive CFG reachability sees the guard's
// false edge — only reachable via the back edge, i.e. after v was already
// written — and wrongly reports v as possibly uninitialized.
type loopCarriedInit struct {
	blockEnd int // end line of the guard if-block (v is written before this)
	loopEnd  int // end line of the enclosing loop (scopes the suppression)
}

// firstIfInLoopBody returns the first statement of a loop body when it is an
// `if` guard (the lazy-init guard shape), or nil. A leading declaration or other
// statement disqualifies the pattern conservatively.
func firstIfInLoopBody(body parser.Node) *parser.Node {
	if body.Kind() == "if_statement" {
		return &body
	}
	if body.Kind() != "compound_statement" {
		return nil
	}
	children := body.NamedChildren()
	if len(children) > 0 && children[0].Kind() == "if_statement" {
		return &children[0]
	}
	return nil
}

// nullZeroGuardVar returns the variable name g when cond is a positive
// "g is null/zero/false" test (`g == NULL`, `NULL == g`, `!g`, `g == 0`), the
// guard shape that is TRUE on the first pass when g is null/zero before the
// loop. It returns "" for any other condition (a bare `if (g)` truthiness guard
// is deliberately NOT matched: it does not prove g is the pre-loop sentinel).
func nullZeroGuardVar(cond *parser.Node) string {
	if cond == nil {
		return ""
	}
	t := strings.TrimSpace(cond.Text())
	t = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(t), "("), ")"))
	var g string
	switch {
	case strings.HasSuffix(t, "== NULL"):
		g = strings.TrimSpace(strings.TrimSuffix(t, "== NULL"))
	case strings.HasPrefix(t, "NULL =="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "NULL =="))
	case strings.HasSuffix(t, "== 0"):
		g = strings.TrimSpace(strings.TrimSuffix(t, "== 0"))
	case strings.HasPrefix(t, "0 =="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "0 =="))
	case strings.HasPrefix(t, "!") && !strings.HasPrefix(t, "!="):
		g = strings.TrimSpace(strings.TrimPrefix(t, "!"))
	default:
		return ""
	}
	if g == "" || strings.ContainsAny(g, " ()[]+-*/%&|^!<>=?.,;:\"'\t\n") {
		return ""
	}
	return g
}

// sizeIsWholeObject reports whether a memset/bzero size argument is a `sizeof(...)`
// expression, which covers the whole pointed-to object and thus fully initializes
// the block (vs. a variable size `n` that may only touch a prefix).
func sizeIsWholeObject(arg parser.Node) bool {
	for arg.Kind() == "parenthesized_expression" {
		ch := arg.NamedChildren()
		if len(ch) == 0 {
			return false
		}
		arg = ch[0]
	}
	return arg.Kind() == "sizeof_expression"
}

// isZeroInitAllocator reports whether an allocation function zero-initializes its
// block (calloc and calloc-family wrappers), so a read of the returned memory is
// never an uninitialized-read.
func isZeroInitAllocator(name string) bool {
	return apikb.IsZeroInitAllocator(name)
}

// isNullZeroExpr reports whether node is a literal null/zero sentinel. It
// recognizes the signed/unsigned/hex/char/pointer spellings and parenthesized
// casts, so a lazy-init guard initialized with `g = 0U` / `g = (void*)0` /
// `g = '\0'` / `g = nullptr` is still recognized.
func isNullZeroExpr(node parser.Node) bool {
	t := strings.TrimSpace(strings.Trim(node.Text(), "() \t"))
	// Strip a null-pointer cast `(void*)0` / `(void *)0`.
	for strings.HasPrefix(t, "(") && strings.HasSuffix(t, ")") {
		inner := strings.TrimSpace(t[1 : len(t)-1])
		if !balancedParens(inner) {
			break
		}
		t = inner
	}
	// Named sentinels must be checked BEFORE stripping an integer suffix (a
	// trailing `L` in `NULL` is part of the name, not a literal suffix).
	switch t {
	case "NULL", "nullptr", "false", "FALSE":
		return true
	}
	// Strip a C integer suffix (u/U/l/L) from a zero literal: `0U`, `0x0L`.
	trimmed := strings.TrimRight(t, "uUlL")
	switch trimmed {
	case "0", "0x0", "00", "'\\0'":
		return true
	}
	// A cast spelling `(void*)0` after the paren strip above becomes `void*0`,
	// not a bare literal; handle the remaining cast-operator form.
	return strings.ReplaceAll(strings.ReplaceAll(trimmed, " ", ""), "(void*)", "") == "0"
}

// balancedParens reports whether s has balanced parentheses.
func balancedParens(s string) bool {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return depth == 0
}

// nullZeroInitializedBefore reports whether g's last write before loopStart is
// a null/zero sentinel, so the lazy-init guard `g == NULL` / `!g` is TRUE when
// the loop is first entered.
func nullZeroInitializedBefore(g string, loopStart int, decls, assigns []parser.Node) bool {
	lastNull := -1
	lastWrite := -1
	for _, decl := range decls {
		if decl.StartLine() >= loopStart {
			continue
		}
		for _, child := range decl.NamedChildren() {
			if child.Kind() != "init_declarator" {
				continue
			}
			lhs, rhs, ok := child.AssignParts()
			if !ok || extractVarName(lhs) != g {
				continue
			}
			if isNullZeroExpr(rhs) {
				if decl.StartLine() > lastNull {
					lastNull = decl.StartLine()
				}
			} else if decl.StartLine() > lastWrite {
				lastWrite = decl.StartLine()
			}
		}
	}
	for _, assign := range assigns {
		if assign.StartLine() >= loopStart {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 || children[0].Kind() != "identifier" || children[0].Text() != g {
			continue
		}
		if isNullZeroExpr(children[1]) {
			if assign.StartLine() > lastNull {
				lastNull = assign.StartLine()
			}
		} else if assign.StartLine() > lastWrite {
			lastWrite = assign.StartLine()
		}
	}
	return lastNull >= 0 && lastNull > lastWrite
}

// straightLinePrefixAssignedVars returns the variable names assigned by the
// straight-line prefix of block: every statement up to (but not including) the
// first nested conditional. Those writes are unconditional whenever the block
// is entered, which is the safe subset for loop-carried initialization.
func straightLinePrefixAssignedVars(block parser.Node) map[string]bool {
	vars := make(map[string]bool)
	collect := func(node parser.Node) {
		for _, assign := range node.FindAll("assignment_expression") {
			if name := assignmentLHSName(assign); name != "" {
				vars[name] = true
			}
		}
		for _, decl := range node.FindAll("init_declarator") {
			c := decl.NamedChildren()
			if len(c) >= 1 {
				if name := extractVarName(c[0]); name != "" {
					vars[name] = true
				}
			}
		}
	}
	if block.Kind() != "compound_statement" {
		collect(block)
		return vars
	}
	for _, child := range block.NamedChildren() {
		switch child.Kind() {
		case "if_statement", "while_statement", "do_statement", "for_statement", "switch_statement":
			return vars
		}
		collect(child)
	}
	return vars
}

func isInIfRange(ifs []parser.Node, f *db.Function, line int) bool {
	for _, ifNode := range ifs {
		if ifNode.StartLine() >= f.StartLine && ifNode.StartLine() <= f.EndLine {
			if line >= ifNode.StartLine() && line <= ifNode.EndLine() {
				return true
			}
		}
	}
	return false
}
