package planner

import (
	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/macros"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// analyzeDefiniteNull runs the boolean must-null dataflow for the null definite
// tier. Its effects are derived NODE-PRECISELY from each statement's own
// assignments (not from a line-keyed source map): gen = `p = NULL`, kill = any
// other non-copy reassignment, copy = `p = q`. A line-keyed map would collide
// when a one-line `if (c) p = NULL; else p = &x;` puts both the header and its
// branches on one line, falsely assigning the NULL gen to the `p = &x` branch.
func (a *flowAnalyzer) analyzeDefiniteNull(cfg *graph.StmtCFG, fileRoot parser.Node, isValue func(string) bool, entrySeeds map[string]bool) (map[int]map[string]bool, map[int]map[string]bool) {
	macroWrites := a.macroWritesFor(fileRoot, true)
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}
		for _, p := range directAssignments(n.Stmt) {
			name := assignTargetName(p.lhs)
			if name == "" {
				continue
			}
			if p.lhs.Kind() == "identifier" {
				if e.killBase == nil {
					e.killBase = map[string]bool{}
				}
				e.killBase[name] = true
			}
			if parser.IsNullLiteral(p.rhs) {
				// A definite-null fact is only reliable for a SIMPLE local
				// (`p = NULL`, `int *p = NULL`): a field access or subscript
				// (`config.cluster_nodes = NULL`, `arr[i] = NULL`) names a
				// global/heap location a function call can reassign without the
				// address being passed, so it must not seed the must-null tier —
				// the may tier still reports it as suspected.
				if p.lhs.Kind() != "field_expression" && p.lhs.Kind() != "subscript_expression" {
					e.gen[name] = true
				}
			} else if rv := copySourceKey(p.rhs); rv != "" {
				e.copy[name] = rv
			} else {
				e.kill[name] = true
			}
		}
		addOutputParamKills(n.Stmt, e, true, macroWrites, a.iterMacros, isValue)
		effects[n.ID] = e
	}
	return runMustDataflow(cfg, effects, entrySeeds)
}

// buildEffects computes the per-statement-node transfer effects for a CFG.
func (a *flowAnalyzer) buildEffects(cfg *graph.StmtCFG, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary, isValue func(string) bool) map[int]*nodeEffects {
	effects := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		effects[n.ID] = a.collectNodeEffects(n, genByLine, killByLine, dfgByLine, nonNullKills, definiteKills, macroWrites, isValue)
	}
	return effects
}

// collectNodeEffects extracts the transfer effects for a single statement node.
func (a *flowAnalyzer) collectNodeEffects(n *graph.StmtNode, genByLine, killByLine map[int][]string, dfgByLine map[int][]copyPair, nonNullKills, definiteKills bool, macroWrites map[string]macros.WriteSummary, isValue func(string) bool) *nodeEffects {
	e := &nodeEffects{gen: map[string]bool{}, kill: map[string]bool{}, copy: map[string]string{}}

	// gen/kill/DFG from the stored graph at this line — but only for LEAF
	// statements. A control-flow header (if/while/for/switch) shares its line
	// with a one-line body, so applying the line-keyed effects to the header
	// would leak the body's source/kill onto every branch.
	if !isControlFlowHeaderStmt(n.Stmt.Kind()) {
		for _, v := range genByLine[n.StartLine] {
			e.gen[v] = true
		}
		for _, v := range killByLine[n.StartLine] {
			e.kill[v] = true
		}
		for _, cp := range dfgByLine[n.StartLine] {
			e.copy[cp.lhs] = cp.rhs
		}
	}

	// AST-level copies/kills from the node's OWN statement (never recursing into
	// a branch/loop body, whose assignments belong to their own CFG nodes).
	for _, p := range directAssignments(n.Stmt) {
		name := assignTargetName(p.lhs)
		if name == "" {
			continue
		}
		if p.lhs.Kind() == "identifier" {
			if e.killBase == nil {
				e.killBase = map[string]bool{}
			}
			e.killBase[name] = true
		}
		if rv := copySourceKey(p.rhs); rv != "" {
			e.copy[name] = rv
		} else if nonNullKills || definiteKills {
			// Any reassignment other than a variable copy replaces the old value,
			// so it kills the old source. For the may-null tier a new possibly-
			// null source arrives as a gen event (malloc / external call /
			// nullable return); for the must-null tier a non-copy reassignment
			// always clears the CERTAIN-null fact.
			e.kill[name] = true
		}
	}

	// `&x` passed to a call is an output parameter: the callee may write x
	// through the pointer, so x's null state is reset at the call site. Without
	// this, `p = NULL; init(&p); p->f` (an initialized output-param) is
	// misread as a definite null-deref. The deref-arg kill (the second half of
	// addOutputParamKills) is null-deref specific, so it is gated on
	// nonNullKills: the taint source filter reuses this engine with
	// nonNullKills=false and must not lose copy taint through memcpy/strcpy.
	addOutputParamKills(n.Stmt, e, nonNullKills, macroWrites, a.iterMacros, isValue)

	// A field/subscript-read copy (`q = p->f`, `q = (T*)p->f`) propagates the
	// base pointer's null sources to q in addition to the field location's own:
	// a value read through a possibly-null base is itself possibly-null. This is
	// the null-deref analogue of the field-sensitive whole-variable copy and is
	// what lets `tree = (T*)(resp->group_data); tree[0]` inherit resp's
	// caller-null source (the derived pointer would otherwise have no source).
	if nonNullKills {
		for lhs, rhs := range e.copy {
			if base := fieldBaseName(rhs); base != "" {
				if e.copyFieldBase == nil {
					e.copyFieldBase = make(map[string]string)
				}
				e.copyFieldBase[lhs] = base
			}
		}
	}

	return e
}

// addOutputParamKills records a kill for two shapes of call argument that prove
// a pointer's null source no longer holds at/after the call:
//
//   - `&x` passed as an argument (an output parameter): the callee may write x
//     through the pointer, resetting x's null state. This half is always on.
//   - a by-value pointer `p` passed to a library function that unconditionally
//     dereferences that argument position (`memset_s(head, ...)` writes `*head`):
//     reaching the next statement proves `p` was non-null, since the call would
//     otherwise have faulted. This half is gated on derefArgs because it is a
//     null-deref notion: the taint source filter shares this engine and its
//     memcpy/strcpy copy taint must survive (a copy is not a taint kill).
func addOutputParamKills(stmt parser.Node, e *nodeEffects, derefArgs bool, macroWrites map[string]macros.WriteSummary, iterMacros map[string][]int, isValue func(string) bool) {
	for _, call := range stmt.FindAll("call_expression") {
		children := call.NamedChildren()
		if len(children) < 2 {
			continue
		}
		argList := children[1]
		if argList.Kind() != "argument_list" {
			continue
		}
		derefIdxs, derefs := apikb.DerefArgs(callName(call))
		for i, arg := range argList.NamedChildren() {
			if name := addrTakenVar(arg, isValue); name != "" {
				e.kill[name] = true
				continue
			}
			if derefArgs && derefs && intIn(derefIdxs, i) {
				if name := rhsVarName(arg); name != "" {
					e.kill[name] = true
				}
			}
		}
		// A function-like macro that writes one of its arguments reassigns it
		// (`#define FOR_EACH(p) for ((p) = ...; (p); ...)` — a loop iterator
		// written in the init and null-checked in the condition). The previous
		// null source no longer reaches the dereference, so the written argument
		// is killed. Null-deref specific (gated on derefArgs) to match the
		// library-deref-arg kill above.
		if derefArgs {
			for name := range macros.WrittenArgs(call, macroWrites) {
				e.kill[name] = true
			}
			// A list-traversal macro (list_for_each_entry & friends from the
			// built-in apikb table, or a project-specific iterator macro
			// declared in secguard.toml [iterator_macros]) writes its iterator
			// parameter(s) in the for-init and null-guards them in the
			// condition. When the macro definition is outside the scan tree
			// (SDK header) the per-file macro analysis cannot see it, so the
			// iterator arguments are killed from the inlined knowledge base
			// merged with the config-declared set.
			if iterIdxs, ok := iterMacros[callName(call)]; ok {
				args := argList.NamedChildren()
				for _, i := range iterIdxs {
					if i >= len(args) {
						continue
					}
					if name := rhsVarName(args[i]); name != "" {
						e.kill[name] = true
					}
				}
			}

		}
	}

	// A function-like macro whose argument is a TYPE cast parses as an ERROR
	// node (a type is not an expression), so FindAll("call_expression") above
	// misses it. Recover the name + positional arguments from the ERROR form so
	// the macro-write and iterator kills still fire for `MACRO(list, iter,
	// type *)` — the iterator is written in the for-init and null-guarded by the
	// loop condition, so its null source must be killed at the call site.
	if derefArgs {
		for _, errNode := range stmt.FindAll("ERROR") {
			name, args := macroCallFromError(errNode)
			if name == "" {
				continue
			}
			for _, v := range macros.WrittenArgsInError(name, args, macroWrites) {
				e.kill[v] = true
			}
			if iterIdxs, ok := iterMacros[name]; ok {
				for _, i := range iterIdxs {
					if i >= len(args) {
						continue
					}
					if v := rhsVarName(args[i]); v != "" {
						e.kill[v] = true
					}
				}
			}

		}
		// `MACRO(args) { body }` — the same macro call, but with a braced body
		// (no type-cast argument), parses as a function_definition and so has
		// neither a call_expression nor an ERROR node. Same kill.
		if name, args := macroBlockCall(stmt); name != "" {
			for _, v := range macros.WrittenArgsInError(name, args, macroWrites) {
				e.kill[v] = true
			}
			if iterIdxs, ok := iterMacros[name]; ok {
				for _, i := range iterIdxs {
					if i >= len(args) {
						continue
					}
					if v := rhsVarName(args[i]); v != "" {
						e.kill[v] = true
					}
				}
			}

		}
	}
}

// macroCallFromError recovers a function-like macro call that tree-sitter parsed
// as an ERROR node rather than a call_expression. This happens when a macro
// argument is a TYPE cast (`SINGLE_LINKEDLIST_Scan(list, iter, type *)`): a type
// is not a valid expression, so the whole call plus its loop body becomes an
// ERROR node whose named children are [macro-name, arg0, arg1, ...] with an
// optional trailing compound_statement (the body). It returns the macro name and
// the positional arguments (body excluded), or ("", nil) when the node is not
// that shape.
func macroCallFromError(stmt parser.Node) (string, []parser.Node) {
	if stmt.Kind() != "ERROR" {
		return "", nil
	}
	children := stmt.NamedChildren()
	if len(children) == 0 || children[0].Kind() != "identifier" {
		return "", nil
	}
	name := children[0].Text()
	var args []parser.Node
	for _, c := range children[1:] {
		if c.Kind() == "compound_statement" {
			break
		}
		args = append(args, c)
	}
	if len(args) == 0 {
		return "", nil
	}
	return name, args
}

// macroBlockCall recovers the OTHER macro-invocation spelling that is not a
// call_expression: a function-like macro whose expansion opens a block,
// `MACRO(arg0, arg1) { body }`. tree-sitter has no macro expansion, so it
// models that as a FUNCTION DEFINITION (return type = the macro name,
// declarator = parenthesized_declarator, body = the trailing compound
// statement) — see the CFG builder's "function_definition" case, which already
// models it as a loop. Every collector that only walked call_expression/ERROR
// therefore MISSED the macro's argument writes: `POOL_FOR_ALL(pool_id) {
// total += pool_id; }` left pool_id "never assigned" (init@none /
// certain-uninit, auto-confirmed CWE-457 in production).
//
// A REAL nested function has a function_declarator (not parenthesized), so it
// is excluded; the caller still gates on the name being a known macro summary.
func macroBlockCall(stmt parser.Node) (string, []parser.Node) {
	if stmt.Kind() != "function_definition" {
		return "", nil
	}
	name := ""
	var decl parser.Node
	for _, c := range stmt.NamedChildren() {
		switch c.Kind() {
		case "type_identifier", "identifier":
			if name == "" {
				name = c.Text()
			}
		case "parenthesized_declarator":
			decl = c
		}
	}
	if name == "" || decl.Kind() == "" {
		return "", nil
	}
	var args []parser.Node
	for _, c := range decl.NamedChildren() {
		if c.Kind() == "identifier" {
			args = append(args, c)
		}
	}
	if len(args) == 0 {
		return "", nil
	}
	return name, args
}

// macroWritesFor returns the per-macro write summaries for a file root, or nil
// when the analysis tier does not need macro-write kills (non-null kills are
// null-deref specific; taint and freed-state flows pass nonNullKills=false and
// must not pay the whole-tree walk). When the analyzer carries a whole-tree
// merged cache (a.macroWrites), it is used instead of the per-file root so a
// macro defined in a .h header is visible at call sites in every .c source.
func (a *flowAnalyzer) macroWritesFor(root parser.Node, nonNullKills bool) map[string]macros.WriteSummary {
	if !nonNullKills {
		return nil
	}
	if a.macroWrites != nil {
		return a.macroWrites
	}
	return macros.WriteSummaries(root)
}

// constantEnvFor returns the file-level ConstantEnv for fn's file, computing it
// once per file per analyzer. CollectConstantSymbols walks the whole file root
// (preproc_def / preproc_function_def / enumerator), and buildGuardCtx used to
// issue that walk once per function — an O(functions × file) cost that dominated
// the remaining null-deref plan time after paramsOf was cached.
func (a *flowAnalyzer) constantEnvFor(fn *db.Function, fileRoot parser.Node) *parser.ConstantEnv {
	if a.constants == nil {
		a.constants = make(map[int64]*parser.ConstantEnv)
	}
	if env, ok := a.constants[fn.FileID]; ok {
		return env
	}
	var env *parser.ConstantEnv
	if fileRoot.Kind() != "" {
		env = parser.CollectConstantSymbols(fileRoot)
	}
	a.constants[fn.FileID] = env
	return env
}

// intIn reports whether v is an element of xs.
func intIn(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// addrTakenVar returns the variable whose address is taken by a call argument,
// covering the spellings parser.Node.AddressTakenTarget recognizes: `&x`,
// `&(x)`, `(void **)&x` and `(T)&x` parsed as a bit-and binary_expression
// (`(shm_handle)&prfs_list` — tree-sitter-c has no typedef table, so the
// argument has no pointer_expression child and the address-of used to be
// invisible, keeping the caller's definite null alive past the call). It
// returns "" for anything else (a by-value arg, a dereference, a field of x,
// ...): only a whole-variable address proves the callee may reassign x itself.
//
// isValue is the scope oracle that keeps a genuine bit-and argument
// (`f((flags) & p)`) from being read as `&p` and killing p's null state; see
// parser.Node.AddressTakenTargetScoped. A nil oracle falls back to the
// permissive recognition.
func addrTakenVar(arg parser.Node, isValue func(string) bool) string {
	target, ok := arg.AddressTakenTargetScoped(isValue)
	if !ok || target.Kind() != "identifier" {
		return ""
	}
	return target.Text()
}

// isControlFlowHeaderStmt reports whether a statement kind is a control-flow
// header (if/loop/switch/preprocessor conditional), as opposed to a leaf
// statement whose own line owns its effects.
func isControlFlowHeaderStmt(kind string) bool {
	switch kind {
	case "if_statement", "while_statement", "do_statement", "for_statement",
		"switch_statement", "preproc_ifdef", "preproc_ifndef", "preproc_if":
		return true
	}
	return false
}
