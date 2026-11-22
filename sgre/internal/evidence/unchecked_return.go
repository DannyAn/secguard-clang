package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// UncheckedReturnDetector flags calls to allocation / I/O functions whose
// return value is neither compared directly nor stored into a variable that is
// subsequently checked (CWE-252). This is the C analogue of "missing error
// handling": malloc can return NULL, read/recv can return -1, and ignoring that
// turns a soft failure into a crash or a corruption.
type UncheckedReturnDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewUncheckedReturnDetector(store db.Store, p *parser.Parser, logger *log.Logger) *UncheckedReturnDetector {
	return &UncheckedReturnDetector{store: store, parser: p, logger: logger}
}

func (d *UncheckedReturnDetector) Name() string { return "unchecked_return" }

func (d *UncheckedReturnDetector) Domain() string { return "boundary" }

func (d *UncheckedReturnDetector) Capabilities() []string {
	return []string{"null-return", "error-return"}
}

// uncheckedReturnAPIs are calls whose return value must be validated. The
// failure sentinel (NULL or a negative errno value) is irrelevant to the
// detection — only that the value must be checked before use.
var uncheckedReturnAPIs = map[string]bool{
	"malloc": true, "calloc": true, "realloc": true,
	"fopen": true, "fdopen": true, "opendir": true,
	"read": true, "recv": true, "write": true, "send": true,
}

func (d *UncheckedReturnDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Empty-run skip (P0-5): the detector only flags calls to an unchecked-return
	// API or an allocator. Pre-scan for that trigger; when absent, the expensive
	// passthrough-allocator fixpoint + return-type table + per-file pass are
	// provably empty and skipped.
	if !d.hasUncheckedReturnCandidate(ctx) {
		return result, nil
	}

	// User wrappers that return an unchecked allocation result (e.g.
	// `void *x_malloc(n) { return malloc(n); }`) are passthrough allocators:
	// a call to one must be NULL-checked at the call site exactly like the
	// wrapped allocator. Compute that set once so the per-file pass below
	// treats calls to them as unchecked-return sources too. The same pass
	// collects each function's entry NULL-reject parameters, which the per-file
	// pass uses to recognise a value the callee has already validated.
	summaries, err := d.funcSummaries(ctx)
	if err != nil {
		return result, err
	}
	passthrough := summaries.passthrough
	nonNullReturn := summaries.nonNullReturn

	retTypes, err := d.funcReturnTypes(ctx)
	if err != nil {
		return result, err
	}

	err = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		calls := root.FindAll("call_expression")
		returns := root.FindAll("return_statement")
		ids := root.FindAll("identifier")
		ifs := root.FindAll("if_statement")
		whiles := root.FindAll("while_statement")
		fors := root.FindAll("for_statement")
		dos := root.FindAll("do_statement")
		conds := root.FindAll("conditional_expression")
		switches := root.FindAll("switch_statement")
		inits := root.FindAll("init_declarator")
		decls := root.FindAll("declaration")

		// Function parameter names, keyed by the definition's start line. An
		// assignment target that is neither a function-local declaration nor a
		// parameter is a file-scope/global/external storage whose "checked"
		// state lives at its use sites in OTHER functions — invisible to the
		// function-scoped checked analysis below.
		paramsByLine := make(map[int]map[string]bool)
		for _, fnNode := range root.FindAll("function_definition") {
			set := make(map[string]bool)
			for _, p := range paramPositions(fnNode) {
				if p != "" {
					set[p] = true
				}
			}
			paramsByLine[fnNode.StartLine()] = set
		}

		for _, f := range funcs {
			checked := d.checkedVars(ifs, whiles, fors, dos, conds, switches, calls, returns, f)
			// A local object whose name matches a built-in unchecked-return API
			// shadows it: `int (*read)(void *, size_t, void *);` declares a
			// function pointer, so `read(buf, n, ctx)` is not POSIX read(). The
			// declaration must precede the call for it to be in scope at it.
			localDeclLines := make(map[string]int)
			noteDecl := func(node parser.Node) {
				name := extractVarFromDeclarator(node)
				if name == "" {
					return
				}
				if line, ok := localDeclLines[name]; !ok || node.StartLine() < line {
					localDeclLines[name] = node.StartLine()
				}
			}
			for _, decl := range decls {
				if !funcLineRange(f, decl.StartLine()) {
					continue
				}
				if declarator := decl.ChildByFieldName("declarator"); declarator != nil {
					noteDecl(*declarator)
				}
			}
			for _, init := range inits {
				if !funcLineRange(f, init.StartLine()) {
					continue
				}
				noteDecl(init)
			}

			for _, call := range calls {
				if !funcLineRange(f, call.StartLine()) {
					continue
				}
				callee := extractCallName(call)
				if !uncheckedReturnAPIs[callee] && !passthrough[callee] && !apikb.IsAllocator(callee) {
					continue
				}
				if apikb.IsNonNullReturning(callee) || nonNullReturn[callee] {
					continue
				}
				if line, ok := localDeclLines[callee]; ok && uncheckedReturnAPIs[callee] && line < call.StartLine() {
					continue
				}
				// A function that is neither a built-in unchecked-return API
				// nor a declared allocator must return a pointer to be an
				// unchecked-return source. This applies to passthrough wrappers
				// too: the passthrough fixpoint admits a wrapper via the broad
				// "alloc" substring heuristic (`void w(){ return is_allocated(p); }`),
				// and without a pointer return type a bare `w()` call has no
				// NULL-returning result to check. A void or scalar function whose
				// name happens to contain "alloc" (test_case_alloc,
				// check_alloc_status, is_allocated,
				// storage_spec_generator_log_allocate_size_init) is a false
				// positive, so flagging its call site is skipped. An external
				// function not in the index is likewise fail-closed: the "alloc"
				// substring heuristic is too broad to trust without a confirmed
				// pointer return type.
				// A callee that is neither a built-in unchecked-return API nor a
				// declared allocator is only a source because its NAME matches the
				// allocator heuristic (alloc/strdup/_new/_dup/...) and it returns a
				// pointer. That is a name guess, not a known failure contract:
				// contractKnown is false so the planner hands it to the AI (Hint
				// contract@unknown) instead of auto-confirming. The AI must prove
				// the callee returns a failure sentinel or dismiss.
				contractKnown := uncheckedReturnAPIs[callee] || apikb.IsDeclaredAllocator(callee) || passthrough[callee]
				if !uncheckedReturnAPIs[callee] && !apikb.IsDeclaredAllocator(callee) {
					rt, ok := retTypes[callee]
					if !ok || !strings.HasSuffix(rt, "*") {
						continue
					}
				}
				if callResultChecked(call) {
					continue
				}
				// Out-param allocators (asprintf/vasprintf/getline/getdelim):
				// the return value is a status code and a failed call leaves
				// the out-param NULL (glibc semantics). The defect's DIRECT
				// consequence is an in-function deref of that possibly-NULL
				// out-param (`asprintf(&p,...); p[0]=x;`). When the out-param
				// is only handed to callees — the NAT framework's
				// `asprintf(&err_msg,...); return fail(error, err_msg, ...)`
				// pattern — its NULL fate belongs to the null-deref chain (a
				// callee with a definition) or to the project's framework
				// contract (an external callee), never to a confirmed
				// unchecked-return verdict here.
				if outIdx, ok := apikb.IsOutParamAllocator(callee); ok {
					if v := outParamVar(call, outIdx); v != "" && !unguardedDerefAfter(v, call.StartLine(), f, ids, ifs) {
						continue
					}
				}
				// A (void) cast is the programmer's explicit "intentionally
				// ignoring this return value" annotation. For an allocator-name
				// heuristic match (not a declared allocator, not an unchecked-
				// return API, not a passthrough wrapper), the function may use an
				// out-parameter or error-code pattern where the return value is
				// not the allocation result — respect the (void) intent. Declared
				// allocators (malloc/calloc/realloc) and unchecked-return APIs
				// (fopen/read/...) still must be checked even when cast to void:
				// (void)malloc(n) is a genuine CWE-252 defect.
				if isVoidCast(call) && !uncheckedReturnAPIs[callee] && !passthrough[callee] && !apikb.IsDeclaredAllocator(callee) {
					continue
				}
				// A wrapper that hands the value straight back to its caller
				// (`void *x_malloc(size_t n) { return malloc(n); }`) is a passthrough:
				// the caller -- which sees x_malloc's return -- is responsible for the
				// NULL check, not the wrapper. Flagging the wrapper is a false
				// positive, so skip it.
				if callResultReturned(call) {
					continue
				}
				// A name-heuristic match (contract@unknown) whose result is stored to
				// a non-local (global/static/external) variable is not an
				// unchecked-return defect: the "check" for a global is cross-function
				// and invisible to this function-scoped detector, and the contract is
				// only a name guess. A genuine NULL global is caught by null-deref at
				// its use site, not by unchecked-return at the store.
				if !contractKnown && anyGlobalTarget(assignedVarsOfCall(call), localDeclLines, paramsByLine[f.StartLine]) {
					continue
				}
				if vars := assignedVarsOfCall(call); len(vars) > 0 {
					checkedAny := false
					for _, v := range vars {
						if checked[v] {
							checkedAny = true
							break
						}
					}
					if checkedAny {
						continue
					}
					// `void *p = malloc(n); return p;` is a passthrough allocator:
					// the caller checks, so the wrapper's malloc must not be flagged.
					if passthroughReturnVar(vars[0], call.StartLine(), f, returns, ids, checked) {
						continue
					}
					// A pointer whose ONLY later use is `free(p)` has no
					// unchecked-return defect: free(NULL) is a defined no-op, so
					// an unnoticed failure cannot corrupt or crash anything. The
					// classic false positive is `p = malloc(n); free(p);` (e.g.
					// tp_sizeof_pointer), which used to reach the auto-confirmed
					// tier as a confirmed CWE-252 finding.
					//
					// Only function-local storage qualifies for the
					// never-observably-used judgement: a global/external
					// target's real uses live in other functions and are
					// invisible here, so they must keep the event.
					isLocalTarget := func(v string) bool {
						if _, ok := localDeclLines[v]; ok {
							return true
						}
						return paramsByLine[f.StartLine][v]
					}
					if neverUsedAfter(vars, call, f, ids, isLocalTarget) {
						continue
					}
					// Consumer census (AND semantics): every observable use of
					// the stored result after the call is NULL-safe — free,
					// sizeof, a rebind, or an argument to a consumer whose that
					// parameter is null-safe (see nullSafeConsumerArg). A NULL
					// result then cannot misbehave anywhere in this function, so
					// the unchecked-return event is a false positive even though
					// the value itself is never compared (report shape A2:
					// `(void)filter_add(f, key)` with entry-guarded consumers).
					// One unsafe use — a dereference, an unguarded callee — keeps
					// the event, so a value validated at one consumer and
					// dereferenced at another stays reported.
					if allUsesNullSafe(vars, call, f, ids, checked, summaries, retTypes, isLocalTarget) {
						continue
					}
					// Field escape: the target is a member of a local struct that
					// is later passed (as `s` / `&s`) to a function validating
					// exactly that member path against NULL with a failure return
					// (report shape B: `para->user_filter = import_strdup(...)` +
					// `para_is_valid(&para)`). The field's NULL is handled
					// downstream by the shared validator, so the event on the
					// field store is noise.
					if fieldValidatedElsewhere(vars, call.StartLine(), f, calls, summaries.fieldNullChecks, isLocalTarget) {
						continue
					}
				}

				props := map[string]string{
					"function":       extractCallName(call),
					"expression":     call.OriginalText(),
					"category":       "unchecked_return",
					"contract_known": strconv.FormatBool(contractKnown),
				}
				// A result whose only observable use is a `(void)` cast is
				// deliberately discarded: the failure cannot be observed, but the
				// lead stays with a discard@ fact so the AI dismisses from the hint
				// without a source read. This "respect the (void) intent" reading
				// applies ONLY to a name-heuristic match (contract@unknown): the
				// function may use an out-param/error-code pattern where the return
				// value is not the allocation result. A known allocator, passthrough
				// wrapper or unchecked-return API (contract@known) still returns an
				// unchecked allocation, so `(void)p` there is a genuine CWE-252
				// defect (unchecked NULL + leaked pointer) — never a discard@.
				if !contractKnown {
					if vars := assignedVarsOfCall(call); len(vars) > 0 && resultVoidDiscarded(vars, call, f, ids) {
						props["consumed"] = "discard"
					}
				}
				if emitEvent(ctx, d.store, d.logger, "UNCHECKED_RETURN", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
					result.EventsCreated++
				}
			}
		}
	})
	return result, err
}

// checkedVars returns the set of variable names that are validated somewhere in
// f: compared against a sentinel (`p == NULL`, `ret < 0`), negated (`!p`), used
// as a bare truthiness condition (`if (p)`), or consumed as the comparison a
// return statement hands to the caller (`return f != 0;`). A condition that
// merely dereferences the variable (`if (p->len > 0)`) is NOT a null/error
// check, so it must not mark `p` checked — that would suppress a genuine
// CWE-252 defect (the allocation's failure is never handled before `p` is
// used). This mirrors the planner's ReturnCheckFilter (conditionTestsVar) so
// the detector and the convergence filter agree on what "checked" means.
