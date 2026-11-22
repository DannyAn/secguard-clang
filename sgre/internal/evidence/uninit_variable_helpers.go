package evidence

import (
	"context"
	"strconv"
	"strings"
	"unicode"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// isHeapVar reports whether name is currently tracked as a malloc'd variable.
func isHeapVar(m map[string]int, name string) bool {
	_, ok := m[name]
	return ok
}

// rhsAllocates reports whether an assignment RHS (after unwrapping a cast) is
// a heap-allocator call: `p->f = malloc(...)` stores a FRESH pointer into the
// field — the pointer value is defined, but the pointed-to content is not
// initialized, so it must not count as a content write for element reads.
func rhsAllocates(rhs parser.Node) bool {

	if rhs.Kind() == "cast_expression" {
		for _, child := range rhs.NamedChildren() {
			if child.Kind() == "call_expression" {
				rhs = child
				break
			}
		}
	}
	if rhs.Kind() == "call_expression" {
		return apikb.IsAllocator(extractCallName(rhs))
	}
	return false
}

// mentionsAnyIdentifier reports whether text references any of the given
// identifiers as a whole word (identifier-boundary tokenization), so `ptr`
// does not match `p` and `p2` does not match `p`.
func mentionsAnyIdentifier(text string, names map[string]bool) bool {
	for _, tok := range strings.FieldsFunc(text, func(r rune) bool {
		return !(r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r))
	}) {
		if names[tok] {
			return true
		}
	}
	return false
}

// isConditionalNode reports whether node sits inside a runtime BRANCH (an
// if/else consequence or alternative, or a loop/switch body), so a write there
// happens on only some paths. A loop init/condition (which runs on every path)
// is NOT conditional.
func isConditionalNode(node parser.Node) bool {
	for n := node.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "if_statement":
			cons := n.ChildByFieldName("consequence")
			alt := n.ChildByFieldName("alternative")
			if (cons != nil && nodeWithin(cons, &node)) || (alt != nil && nodeWithin(alt, &node)) {
				return true
			}
			return false
		case "while_statement", "for_statement", "do_statement", "switch_statement":
			if body := n.ChildByFieldName("body"); body != nil && nodeWithin(body, &node) {
				return true
			}
			return false
		}
	}
	return false
}

// fieldBaseName returns the ROOT identifier of a field/subscript chain
// (`p->inner->len` → `p`, `p[i]` → `p`), so a nested member read/write resolves to
// the heap/struct variable it belongs to (UN-07). The full path stays intact in
// fieldPath for field-level initialization tracking.
func fieldBaseName(n parser.Node) string {
	for n.Kind() == "field_expression" || n.Kind() == "subscript_expression" {
		children := n.NamedChildren()
		if len(children) == 0 {
			break
		}
		n = children[0]
	}
	if n.Kind() == "identifier" {
		return n.Text()
	}
	return ""
}

// fieldPath returns the canonical member path of a field or subscript access:
// `s.f` and `s.f[i]` both normalize to `s.f`. This makes field-read and
// subscript-write detection agree when an array member is written element-wise
// (`s.arr[i] = ...`) but read as a whole (`use(s.arr)`).
func fieldPath(node parser.Node) string {
	switch node.Kind() {
	case "subscript_expression":
		children := node.NamedChildren()
		if len(children) > 0 {
			return fieldPath(children[0])
		}
	case "field_expression":
		return node.Text()
	}
	return node.Text()
}

// fieldWritePaths returns the field/subscript paths that a write to lhs
// touches: the target itself plus every field base it is nested under. Writing
// `s.a.b` addresses (and thus "uses", but only as a write target) both `s.a.b`
// and its base `s.a`, so neither is a read of an uninitialized member.
func fieldWritePaths(lhs parser.Node) []string {
	var paths []string
	cur := lhs
	for {
		switch cur.Kind() {
		case "field_expression", "subscript_expression":
			paths = append(paths, fieldPath(cur))
			children := cur.NamedChildren()
			if len(children) == 0 {
				return paths
			}
			cur = children[0]
		default:
			return paths
		}
	}
}

// isFieldWriteTarget reports whether field is part of the write target of a
// plain assignment or declaration initializer. The assignment LHS is not a read
// of the uninitialized memory, including when the write sits inside a runtime
// branch; path sensitivity is handled separately by initializedFields.
func isFieldWriteTarget(field parser.Node) bool {
	for cur := field; cur.Parent() != nil; cur = *cur.Parent() {
		parent := *cur.Parent()
		switch parent.Kind() {
		case "assignment_expression":
			lhs, _, ok := parent.AssignParts()
			if !ok || !nodeWithin(&lhs, &field) {
				return false
			}
			rest := strings.TrimSpace(strings.TrimPrefix(parent.Text(), lhs.Text()))
			return strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==")
		case "init_declarator":
			decl := parent.ChildByFieldName("declarator")
			return decl != nil && nodeWithin(decl, &field)
		}
	}
	return false
}

// isAddressOnlyUse reports whether field is evaluated only to form an address
// (`&p->f`, `&s.f`). Taking the address does not read the member's value.
func isAddressOnlyUse(field parser.Node) bool {
	for cur := field; cur.Parent() != nil; cur = *cur.Parent() {
		parent := *cur.Parent()
		if parent.Kind() == "pointer_expression" && strings.HasPrefix(strings.TrimSpace(parent.Text()), "&") {
			return true
		}
	}
	return false
}

// destWriteTarget resolves the write target of a dest-writer call's first
// argument. It handles four shapes:
//   - identifier:        memcpy_s(buf, ...)           → base=buf, path="", whole=true
//   - field_expression:  memcpy_s(p->f, ...)          → base=p,  path="p->f", whole=false
//   - subscript:         memcpy_s(p[i], ...)          → base=p,  path="p[i]", whole=false
//   - pointer_expression: memcpy_s(&p->f, ...)        → base=p,  path="p->f", whole=false
//     memcpy_s(&s, sizeof(s), ...) → base=s,  path="",    whole=true
//
// The previous code split this across a memset/memset_s/bzero case (which
// handled pointer_expression but not bare field_expression) and an isDestWriter
// default branch (which handled bare field_expression but not
// pointer_expression), so memcpy_s(&p->f, ...) and memset_s(p->f, ...) both
// fell through unhandled — the dest write was mis-read as a use of the base,
// producing heap_uninit false positives (UN-15).
func destWriteTarget(arg parser.Node) (base, path string, whole bool) {
	switch arg.Kind() {
	case "identifier":
		return arg.Text(), "", true
	case "field_expression", "subscript_expression":
		return fieldBaseName(arg), fieldPath(arg), false
	case "pointer_expression":
		children := arg.NamedChildren()
		if len(children) == 0 {
			return "", "", false
		}
		inner := children[0]
		switch inner.Kind() {
		case "field_expression", "subscript_expression":
			return fieldBaseName(inner), fieldPath(inner), false
		case "identifier":
			return inner.Text(), "", true
		}
	}
	return "", "", false
}

// insertValueUseEvent is insertValueUseEventAt without a field path and
// without an init-write fact (write-path facts only attach where the detector
// proved them: stack no-write / loop-only-write / heap never-written-or-
// conditional-writer).
func (d *UninitVariableDetector) insertValueUseEvent(ctx context.Context, f *db.Function, file *db.File, line, column, declLine int, varName, allocator, origin, initWrite string, initWriteLine int, initWriter string, result *DetectResult) {
	d.insertValueUseEventAt(ctx, f, file, line, column, declLine, varName, "", allocator, origin, initWrite, initWriteLine, initWriter, result)
}

// insertValueUseEventAt is insertValueUseEvent with an optional field path: for a
// member/element read (`p->f`, `p[i]`, `s.f`) the path is the full access text, so
// the planner's definite-init filter can refine field granularity (UN-01). Whole
// reads (`*p`, `p`, scalar `v`) pass "". initWrite carries the machine-proven
// write-path fact: "none" = the read target is never written before the read
// (heap block after malloc, bare scalar with no assignment site), "loop" = the
// only writes sit inside a loop body (initWriteLine = the first such write),
// "cond" = an in-tree callee writes the storage only on some paths and the
// caller does not guard its return (initWriteLine = the call site, initWriter =
// the callee), "" = no proven fact (mixed/branch writes stay for the AI).
func (d *UninitVariableDetector) insertValueUseEventAt(ctx context.Context, f *db.Function, file *db.File, line, column, declLine int, varName, path, allocator, origin, initWrite string, initWriteLine int, initWriter string, result *DetectResult) {
	props := map[string]any{
		"variable": varName,
		"origin":   origin,
	}
	if allocator != "" {
		props["allocator"] = allocator
	}
	if path != "" {
		props["field_path"] = path
	}
	if declLine > 0 {
		props["decl_line"] = declLine
	}
	if initWrite != "" {
		props["init_write"] = initWrite
		if initWriteLine > 0 {
			props["init_write_line"] = initWriteLine
		}
	}
	if initWriter != "" {
		props["init_writer"] = initWriter
	}
	if emitEvent(ctx, d.store, d.logger, "VALUE_USE", f.ID, &db.Location{FileID: file.ID, Line: line, Column: column}, props) {
		result.EventsCreated++
	}
}

// barePointerArg returns the identifier an argument passes by value, unwrapping
// parentheses and a cast (`(char *)sql` → sql). Only a bare pointer value
// forwards the pointed-to storage to a callee; `&x` passes the variable itself
// and `x.f` passes a different pointer, so both return "".
func barePointerArg(arg parser.Node) string {
	for {
		switch arg.Kind() {
		case "parenthesized_expression":
			kids := arg.NamedChildren()
			if len(kids) == 0 {
				return ""
			}
			arg = kids[0]
		case "cast_expression":
			kids := arg.NamedChildren()
			if len(kids) == 0 {
				return ""
			}
			arg = kids[len(kids)-1]
		case "identifier":
			return arg.Text()
		default:
			return ""
		}
	}
}

// firstSite returns the smallest assignment-site line (the first write after
// the declaration), or 0 when there is none.
func firstSite(sites []int) int {
	best := 0
	for _, s := range sites {
		if s > 0 && (best == 0 || s < best) {
			best = s
		}
	}
	return best
}

// allSitesInLoops reports whether EVERY assignment site falls inside a
// while/for body span in this function. Such writes only execute when the
// loop condition admits an iteration, so a use after the loop may read an
// unwritten storage — the may-skip uninit shape. A write in the loop
// CONDITION itself (e.g. `while ((line = get()) > 0)`) sits on the header,
// which every path to a post-loop use traverses, so hasUnassignedPath has
// already filtered that shape out before this classifier runs.
func allSitesInLoops(sites []int, whiles, fors []parser.Node, f *db.Function) bool {
	if len(sites) == 0 {
		return false
	}
	inLoop := func(line int) bool {
		for _, loop := range whiles {
			if funcLineRange(f, loop.StartLine()) && line >= loop.StartLine() && line <= loop.EndLine() {
				return true
			}
		}
		for _, loop := range fors {
			if funcLineRange(f, loop.StartLine()) && line >= loop.StartLine() && line <= loop.EndLine() {
				return true
			}
		}
		return false
	}
	for _, s := range sites {
		if !inLoop(s) {
			return false
		}
	}
	return true
}

// declLineFromKey recovers the declaration line embedded in a scope-aware varKey
// ("name@declLine"), so the classifier's evidence can carry the declaration
// anchor for uninit candidates whose Code Context window cannot reach it.
func declLineFromKey(key string) int {
	if i := strings.LastIndex(key, "@"); i >= 0 && i+1 < len(key) {
		if n, err := strconv.Atoi(key[i+1:]); err == nil {
			return n
		}
	}
	return 0
}

var outputParamInitializers = map[string]bool{
	"pthread_create":        true,
	"DES_set_key_unchecked": true,
	"DES_set_key_checked":   true,
	"pthread_mutex_init":    true,
	"pthread_cond_init":     true,
	"pthread_rwlock_init":   true,
	"sem_init":              true,
	"regcomp":               true,
	"regexec":               true,
	"OpenProcessToken":      true,
	"GetTokenInformation":   true,
	"RegCreateKeyExA":       true,
	"RegCreateKeyExW":       true,
	"RegOpenKeyExA":         true,
	"RegOpenKeyExW":         true,
	"GetTempPathA":          true,
	"GetTempPathW":          true,
	"GetTempFileNameA":      true,
	"GetTempFileNameW":      true,
	"stat":                  true,
	"fstat":                 true,
	"lstat":                 true,
	"gettimeofday":          true,
	"clock_gettime":         true,
	"strtol":                true,
	"strtoul":               true,
	"wcstombs":              true,
	"memset":                true,
	"memset_s":              true,
	"bzero":                 true,
	"CreateProcessA":        true,
	"CreateProcessW":        true,
	"CreateProcessAsA":      true,
	"CreateProcessAsW":      true,
}

func isOutputParamInitializer(name string) bool {
	return outputParamInitializers[name]
}

// outputParamInitializerArgs maps a function name to the argument indices it
// WRITES. It is for functions whose pointer arguments are a mix of inputs and
// outputs — `localtime_r(&t, &tm)` reads `t` and writes `tm`, so only arg 1 is
// an output; marking the input `&t` as initialized would suppress a real
// use-before-init of `t` (CWE-457).
var outputParamInitializerArgs = map[string]map[int]bool{
	"localtime_r": {1: true},
	"gmtime_r":    {1: true},
	"localtime_s": {0: true},
	"gmtime_s":    {0: true},
	"strptime":    {2: true},
}

// destWriters lists string/memory copy and init functions whose FIRST argument
// is the destination buffer — written by the callee, never read. A destination
// array/field decays to a raw pointer (`strncpy_s(msg.name, ...)`, `memcpy(dst,
// ...)`), so it is passed WITHOUT `&` and the `&x` output-param path never sees
// it. Marking arg 0 as a write (not a read) stops a struct/array filled through
// these calls from being reported as uninitialized.
var destWriters = map[string]bool{
	"memset":      true,
	"memset_s":    true,
	"bzero":       true,
	"strcpy":      true,
	"strcpy_s":    true,
	"strncpy":     true,
	"strncpy_s":   true,
	"strlcpy":     true,
	"stpncpy":     true,
	"mempcpy":     true,
	"memcpy":      true,
	"memcpy_s":    true,
	"memmove":     true,
	"memmove_s":   true,
	"sprintf":     true,
	"sprintf_s":   true,
	"snprintf":    true,
	"snprintf_s":  true,
	"vsprintf":    true,
	"vsprintf_s":  true,
	"vsnprintf":   true,
	"vsnprintf_s": true,
}

func isDestWriter(name string) bool {
	return destWriters[name]
}

// destWriterArgs lists I/O functions whose written buffer sits at a
// NON-FIRST argument position (or whose first argument is a buffer rather
// than a copy destination): `backtrace(buf, n)` fills the symbol array
// (arg 0), `read(fd, buf, n)` / `recv(sock, buf, n)` / `fread(buf, sz, n, f)`
// fill the data buffer (arg 1). Without this contract the decayed buffer
// argument reads as a plain use, a struct member filled through
// `backtrace(fr.bt, 8)` was auto-confirmed as partial-init (issue #263), and
// a heap block filled through `read(fd, buf, n)` kept producing candidates
// for the AI to dismiss.
//
// The table is consumed by the HEAP and STRUCT paths only. A bare scalar
// POINTER passed by value (`char *p; read(fd, p, n)`) is a READ of the
// indeterminate pointer itself — a genuine CWE-457 the stack path must keep
// reporting — so the scalar stack path deliberately does not consult it.
var destWriterArgs = map[string]map[int]bool{
	"backtrace":         {0: true},
	"backtrace_symbols": {0: true},
	"read":              {1: true},
	"pread":             {1: true},
	"readv":             {1: true},
	"fread":             {1: true},
	"fread_unlocked":    {1: true},
	"recv":              {1: true},
	"recvfrom":          {1: true},
	"recvmsg":           {1: true},
	"fgets":             {0: true},
	"getcwd":            {0: true},
	"gethostname":       {0: true},
	"inet_ntop":         {2: true},
	"inet_pton":         {1: true},
}

// destWriterTargetArg returns the argument node that callName writes as its
// destination buffer, if any: arg 0 for a destWriters entry, the indexed
// argument for a destWriterArgs entry. It returns (zero, false) when the call
// is not a known writer or the indexed argument is absent.
func destWriterTargetArg(callName string, args []parser.Node) (parser.Node, bool) {
	if isDestWriter(callName) {
		if len(args) > 0 {
			return args[0], true
		}
		return parser.Node{}, false
	}
	if idxs, ok := destWriterArgs[callName]; ok {
		for idx := range idxs {
			if idx < len(args) {
				return args[idx], true
			}
		}
	}
	return parser.Node{}, false
}

// outputParamGuardLine reports the line after which a conditional output
// parameter is definitely written, given the caller guards the call's error
// return with an exit (`if (fn(&x) != OK) return;` / `rc = fn(&x); if (rc) return;`).
// It returns 0 when no such guard is found, so the caller keeps the variable as
// a potential uninit (conservative, TC16).
func outputParamGuardLine(ifs []parser.Node, f *db.Function, call parser.Node, callName string) int {
	callLine := call.StartLine()
	for _, ifNode := range ifs {
		if !funcLineRange(f, ifNode.StartLine()) {
			continue
		}
		// The guard is the error check on this call and may sit any number of
		// statements AFTER the call (`rc = fn(&x); ...; if (rc != 0) return;`).
		// There is deliberately NO fixed line window: a guard 3+ lines below the
		// call was previously missed and the output was misreported as uninit.
		if ifNode.StartLine() < callLine {
			continue
		}
		cons := ifNode.ChildByFieldName("consequence")
		cond := ifNode.ChildByFieldName("condition")
		// Form A: the call IS the guard's condition (`if (fn(...) != 0)`) — the
		// call and the if share a line. Form B: `rc = fn(...); if (rc != 0)` —
		// the call result is captured in an assignment whose left-hand variable
		// is then tested by a LATER guard's condition. The condition must
		// reference that exact variable (matched as an identifier, not a
		// substring, so `rc` does not match `rc2`); an unrelated guard
		// (`if (other) return`) does not establish the output.
		formA := cond != nil && ifNode.StartLine() == callLine && strings.Contains(cond.Text(), callName)
		formB := false
		if ifNode.StartLine() > callLine {
			if parent := call.Parent(); parent != nil && cond != nil &&
				(parent.Kind() == "assignment_expression" || parent.Kind() == "init_declarator") {
				if lhs := parent.NamedChildren(); len(lhs) > 0 {
					if v := strings.TrimSpace(lhs[0].Text()); v != "" {
						for _, id := range cond.FindAll("identifier") {
							if id.Text() == v {
								formB = true
								break
							}
						}
					}
				}
			}
		}
		if !formA && !formB {
			continue
		}
		// Error-exit guard (`if (FAIL) return;`): the output is written on the
		// fall-through, so init starts after the if.
		if cons != nil && isExitStmt(*cons) {
			return ifNode.EndLine()
		}
		// Success-block guard (`if (OK) { use }`): the output is written inside
		// the block, so init starts at the if's opening line.
		return ifNode.StartLine() - 1
	}
	return 0
}

// isExitStmt reports whether a statement (or a compound block) terminates its
// path via return/break/continue/goto — the shape of an error guard whose
// fall-through is the success continuation.
func isExitStmt(node parser.Node) bool {
	switch node.Kind() {
	case "return_statement", "break_statement", "continue_statement", "goto_statement":
		return true
	case "compound_statement":
		for _, c := range node.NamedChildren() {
			if isExitStmt(c) {
				return true
			}
		}
	}
	return false
}

// addressedArgs returns the set of variable names whose address is taken
// (`&x`) within node. Address-of parses as a pointer_expression (the same node
// as a `*p` dereference); only `&`-prefixed nodes count. A `&x` argument is a
// write target for the callee, not a read of x's current value, so it must
// never be treated as a use-before-init.
//
// isValue is the scope oracle that keeps `sink((flags) & mask)` (a bit-and)
// from being read as `&mask`; see parser.Node.AddressTakenTargetScoped.
func addressedArgs(node parser.Node, isValue func(string) bool) map[string]bool {
	addressed := make(map[string]bool)
	mark := func(target parser.Node, ok bool) {
		if !ok {
			return
		}
		if name := extractVarName(target); name != "" {
			addressed[name] = true
		}
	}
	for _, ptr := range node.FindAll("pointer_expression") {
		if !strings.HasPrefix(strings.TrimSpace(ptr.Text()), "&") {
			continue
		}
		// Unwrap parentheses/casts around the operand (`&(x)`, `(void*)&x`) so the
		// identifier is still recognized as an address-of target, not a read.
		mark(addressOfTargetScoped(ptr, isValue))
	}
	// `(T)&x` parses as a bit-and binary_expression with NO pointer_expression
	// child, so the scan above never sees it and the argument was miscounted as
	// a READ of x (a use-before-init false positive at the call line itself).
	// The cast shape is an address-of just the same. tree-sitter-c emits the
	// SAME shape for a genuine bit-and, so the oracle decides.
	for _, b := range node.FindAll("binary_expression") {
		mark(addressOfTargetScoped(b, isValue))
	}
	return addressed
}

// nestedAssignTargets returns the identifier names that are assignment LHS
// within node (including node itself when it is an assignment). These are write
// targets, not reads: in `a = b = c = v` the RHS `b = c = v` writes b and c, so
// scanning the RHS must not report b/c as use-before-init.
func nestedAssignTargets(node parser.Node) map[string]bool {
	targets := make(map[string]bool)
	for _, assign := range node.FindAll("assignment_expression") {
		children := assign.NamedChildren()
		if len(children) >= 1 && children[0].Kind() == "identifier" {
			targets[children[0].Text()] = true
		}
	}
	return targets
}

// isValueFieldBase reports whether id is the base of a DOT field access on a
// struct VALUE (`s` in `s.f`), as opposed to a pointer dereference (`p` in
// `p->f`). Reading `s.f` addresses s to reach a member, which is a partial-init
// concern (handled separately), not a scalar use-before-init of s itself — while
// `p->f` dereferences the pointer p, so an uninitialized p IS a real use.
func isValueFieldBase(id parser.Node) bool {
	p := id.Parent()
	if p == nil || p.Kind() != "field_expression" {
		return false
	}
	children := p.NamedChildren()
	if len(children) == 0 || children[0].Kind() != "identifier" || children[0].Text() != id.Text() {
		return false
	}
	// Arrow access (`p->f`) keeps the base as a pointer read; dot access
	// (`s.f`) treats the base as a struct value.
	return !strings.Contains(p.Text(), "->")
}

// outputParamInitializedVars returns (a) the struct variables within f whose
// address is passed (`&x`) to an output-parameter writer and are initialized
// unconditionally, and (b) the variables initialized only past a caller-side
// guard, mapped to the line after which the write is established. An arbitrary
// `&x` to an unknown function is conservatively kept
// (cf. TestSecurity_TC16_UninitInterprocedural).
func outputParamInitializedVars(calls, ifs []parser.Node, f *db.Function, summaries summaryMap, isValue func(string) bool) (map[string]bool, map[string]int) {
	// `&s` to a writer initializes the whole struct on three tiers, mirroring
	// the scalar path's model:
	//   - known initializer (memset, stat, ...) → writes unconditionally;
	//   - local function whose ParamWrites marks the position → every path;
	//   - local function whose ParamConditionalWrites marks the position → the
	//     caller tests the return (`while (dequeue(&s) == OK)` / `if (get(&s))`),
	//     so the guarded path is where the callee wrote its output.
	// An UNKNOWN/external `&s` is conservatively kept — a generic void* filler
	// may write only some fields (cf. tc84 FlowGetKey).
	//
	initialized := make(map[string]bool)
	initializedFrom := make(map[string]int)
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		knownInit := isOutputParamInitializer(callName)
		outArgs, hasSpecificOutArgs := outputParamInitializerArgs[callName]
		summary, hasSummary := summaries[callName]
		if !knownInit && !hasSpecificOutArgs && !hasSummary {
			continue
		}
		// Nil-summary safety: the switch below reads summary.ParamWrites /
		// summary.ParamConditionalWrites even when hasSummary is false. A call that
		// is a known output-param initializer (memset/stat/...) OR has spec'd
		// arg indices (localtime_r/gmtime_r/strptime) but has no function summary
		// reaches the switch with summary == nil; the previous code then
		// dereferenced the nil pointer and PANICKED the whole uninit detector
		// (reproduced on redis: localtime_r(&t, &tm) with arg0 not an output arg
		// fell through to `summary.ParamWrites[0]`). A zero-value summary makes
		// those reads safely return false — no candidate is invented, and the
		// remaining events are still emitted instead of being truncated by the
		// panic.
		if summary == nil {
			summary = &FuncSummary{}
		}
		guarded := callInBranchCondition(call)
		for _, child := range call.NamedChildren() {
			if child.Kind() != "argument_list" {
				continue
			}
			for argIdx, arg := range child.NamedChildren() {
				target, ok := addressOfTargetScoped(arg, isValue)
				if !ok || target.Kind() != "identifier" {
					continue
				}
				name := target.Text()
				switch {
				case knownInit:
					initialized[name] = true
				case hasSpecificOutArgs && outArgs[argIdx]:
					initialized[name] = true
				case summary.ParamWrites[argIdx]:
					initialized[name] = true
				case summary.ParamConditionalWrites[argIdx] && guarded:
					initialized[name] = true
				case summary.ParamConditionalWrites[argIdx]:
					// The caller may guard the call through the variable the
					// result was stored in (`rc = fn(&s); if (rc != 0) return;`)
					// rather than inside a branch condition. The scalar path
					// already recognizes that shape; without reusing it here a
					// correctly guarded struct write-back was reported as
					// partial-init (the failure path is already excluded).
					if g := outputParamGuardLine(ifs, f, call, callName); g != 0 {
						if g > initializedFrom[name] {
							initializedFrom[name] = g
						}
					}
				}
			}
		}
	}
	return initialized, initializedFrom
}

// callInBranchCondition reports whether call sits inside the condition of an
// enclosing if/while/do/for — i.e. the caller tests the call's return value.
// It is the caller-side guard for a conditional output-param writer: the
// consequent body / fall-through runs on the checked path, which is where the
// callee wrote its output (`while (dequeue(&s) == OK) { use(s) }`).
func callInBranchCondition(call parser.Node) bool {
	for n := call.Parent(); n != nil; n = n.Parent() {
		switch n.Kind() {
		case "if_statement", "while_statement", "do_statement", "for_statement":
			cond := n.ChildByFieldName("condition")
			return cond != nil && nodeWithin(cond, &call)
		case "parenthesized_expression", "binary_expression", "unary_expression", "conditional_expression", "call_expression", "argument_list":
			// transparent wrappers around the call; keep climbing
		default:
			return false
		}
	}
	return false
}
