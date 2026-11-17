package planner

import (
	"context"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// argShapeCounts is the per-(callee, parameter) census of in-tree call-site
// argument shapes. literal counts provably-constant arguments (string/number
// literals, address-of, compound literals — isDefinitelyUnTainted), tainted
// counts direct taint-source expressions (getenv(...), argv[1], ...),
// internalRuntime counts buffers built in-tree by a snprintf-family call with a
// fixed integer-only format (no %s/%[/%n), and variable counts everything else
// (bare identifiers, complex expressions) whose provenance the census does not
// resolve.
type argShapeCounts struct {
	literal         int
	tainted         int
	internalRuntime int
	variable        int
}

func (a *argShapeCounts) sites() int {
	if a == nil {
		return 0
	}
	return a.literal + a.tainted + a.internalRuntime + a.variable
}

// allLiteral reports whether the census PROVES the parameter cannot receive
// non-constant data in-tree: at least one call site binds it, and every one
// binds a compile-time constant.
func (a *argShapeCounts) allLiteral() bool {
	return a != nil && a.literal > 0 && a.tainted == 0 && a.internalRuntime == 0 && a.variable == 0
}

// allConstant reports whether every in-tree call site binds either a
// compile-time constant or an internally-built runtime buffer — neither can
// carry attacker-controlled format/path content.
func (a *argShapeCounts) allConstant() bool {
	return a != nil && a.literal+a.internalRuntime > 0 && a.tainted == 0 && a.variable == 0
}

// fact renders the compact census for the callsites@ hint token value:
// "3:all-literal", "3:all-constant", or "5:3-literal,2-var" (only non-zero
// classes listed, in literal/tainted/internal-runtime/var order). Empty when no
// call site binds the parameter.
func (a *argShapeCounts) fact() string {
	if a == nil || a.sites() == 0 {
		return ""
	}
	if a.allLiteral() {
		return fmt.Sprintf("%d:all-literal", a.literal)
	}
	if a.allConstant() {
		return fmt.Sprintf("%d:all-constant", a.sites())
	}
	var classes []string
	if a.literal > 0 {
		classes = append(classes, fmt.Sprintf("%d-literal", a.literal))
	}
	if a.tainted > 0 {
		classes = append(classes, fmt.Sprintf("%d-tainted", a.tainted))
	}
	if a.internalRuntime > 0 {
		classes = append(classes, fmt.Sprintf("%d-internal-runtime", a.internalRuntime))
	}
	if a.variable > 0 {
		classes = append(classes, fmt.Sprintf("%d-var", a.variable))
	}
	return fmt.Sprintf("%d:%s", a.sites(), strings.Join(classes, ","))
}

// callsiteCensus aggregates the in-tree call sites of every function: per
// (callee, parameter index) the shape of the bound argument, plus the set of
// function names whose address is taken anywhere in the scan (a function
// referenced through a pointer has callers the direct-call census cannot see).
//
// It exists because a non-static function's parameters are conservatively
// treated as attacker-reachable (an external caller may pass anything), which
// kept every "wrapper called only with literals" candidate alive as suspected
// and the AI then confirmed them from the parameter shape alone. The census
// gives both the filter (a provably all-literal parameter can be dropped) and
// the classifier (the callsites@ token names the non-constant callers worth
// inspecting) the caller-side evidence the PARAM_BINDING graph cannot express:
// literal arguments bind no variable_ref edge, so the existing fixpoint is
// silent about them.
type callsiteCensus struct {
	params    map[int64]map[int]*argShapeCounts
	addrTaken map[string]bool
	// sites is the bounded per-site breakdown backing the evidence list: keyed
	// by (callee funcID, param index), each entry one call site's file:line +
	// class. Bounded by callsiteEvidenceCap per key so a header-only wrapper
	// with hundreds of callers does not balloon the candidate file.
	sites map[int64]map[int][]CallSiteInfo
	// constVals records, per (callee funcID, param index), the integer-literal
	// value of every call site classified literal with a determinable constant.
	// It backs callerConstBound: an integer parameter whose EVERY caller passes
	// a compile-time integer constant is bounded by the largest such constant
	// (NLOG pattern 6: `pool_create(64)` where the only caller passes 64).
	constVals map[int64]map[int][]int64
	// stringMacros is the tree-wide set of object-like macros that expand to a
	// string literal. It is shared with the constant-path prover so a call-site
	// argument spelled `EXPORT_DIR` / a format spelled `FMT` is a compile-time
	// constant there too.
	stringMacros map[string]bool
}

// callsiteEvidenceCap bounds how many concrete call sites the census retains
// for evidence embedding; the SUMMARY still counts all of them.
const callsiteEvidenceCap = 10

// shapes returns the census of one (function, parameter), nil when no in-tree
// call site binds it.
func (cs *callsiteCensus) shapes(funcID int64, paramIdx int) *argShapeCounts {
	if cs == nil {
		return nil
	}
	return cs.params[funcID][paramIdx]
}

// gateDrop reports whether the census proves a non-static function's
// parameter cannot receive attacker-controlled data in-tree: the function is
// never address-taken (every caller is a direct, visible call) and every
// in-tree call site binds a compile-time constant to this parameter. Zero
// call sites does NOT gate — an external TU may still call it — matching the
// scan-tree boundary assumption every reachability filter already makes.
func (cs *callsiteCensus) gateDrop(funcID int64, funcName string, paramIdx int) (*argShapeCounts, bool) {
	if cs == nil || cs.addrTaken[funcName] {
		return nil, false
	}
	shapes := cs.shapes(funcID, paramIdx)
	if !shapes.allConstant() {
		return nil, false
	}
	return shapes, true
}

// callerConstBound returns the largest compile-time integer constant every
// in-tree caller binds to a parameter, when ALL callers bind one and the
// function is never address-taken. (max, true) means the parameter is provably
// bounded by max across the whole tree; (0, false) otherwise — a missing,
// non-literal, or non-integer argument keeps the bound unknown, which is the
// conservative outcome.
func (cs *callsiteCensus) callerConstBound(funcID int64, funcName string, paramIdx int) (int64, bool) {
	if cs == nil || cs.constVals == nil || cs.addrTaken[funcName] {
		return 0, false
	}
	shapes := cs.shapes(funcID, paramIdx)
	vals := cs.constVals[funcID][paramIdx]
	if shapes == nil || shapes.literal == 0 || shapes.tainted != 0 || shapes.variable != 0 {
		return 0, false
	}
	// Every literal must be an integer literal with a determinable value; a
	// string/address-of literal (or a constant expression the parser could not
	// fold) leaves the bound unknown.
	if len(vals) != shapes.literal {
		return 0, false
	}
	var max int64 = -1
	for _, v := range vals {
		if v > max {
			max = v
		}
	}
	return max, true
}

// factFor renders the callsites@ token value for one (function, parameter).
func (cs *callsiteCensus) factFor(funcID int64, paramIdx int) string {
	return cs.shapes(funcID, paramIdx).fact()
}

// siteList returns the bounded per-site breakdown backing the evidence list.
func (cs *callsiteCensus) siteList(funcID int64, paramIdx int) []CallSiteInfo {
	if cs == nil || cs.sites == nil {
		return nil
	}
	return cs.sites[funcID][paramIdx]
}

func classForKind(kind int) string {
	switch kind {
	case 0:
		return "literal"
	case 1:
		return "tainted"
	case 3:
		return "internal-runtime"
	}
	return "variable"
}

// computeCallsiteSummary walks every function body's call expressions and
// every file's address-of expressions, producing the call-site census. It is
// a single AST pass (no fixpoint): shapes are syntactic, so callee summaries
// cannot change them.
func (f *TaintSourceFilter) computeCallsiteSummary(ctx context.Context, tc *taintPlanCtx) (*callsiteCensus, error) {
	census := &callsiteCensus{
		params:    make(map[int64]map[int]*argShapeCounts),
		addrTaken: make(map[string]bool),
		sites:     make(map[int64]map[int][]CallSiteInfo),
		constVals: make(map[int64]map[int][]int64),
	}
	// Object-like macros that expand to a string literal are compile-time
	// constants: a caller spelled `log_msg(MSG_FMT)` must count as LITERAL, not
	// as a variable. Counting it as `2-var` kept a wrapper whose every caller
	// passes a constant format in front of the classifier, which then confirmed
	// a format-string defect that does not exist. A name defined BOTH ways
	// somewhere in the tree stays non-literal (conservative).
	stringMacro := map[string]bool{}
	nonStringMacro := map[string]bool{}
	isStringMacro := func(name string) bool {
		return stringMacro[name] && !nonStringMacro[name]
	}
	funcByName := make(map[string][]int64, len(tc.funcs))
	for _, fn := range tc.funcs {
		funcByName[fn.Name] = append(funcByName[fn.Name], fn.ID)
	}
	if len(funcByName) == 0 {
		return census, nil
	}

	cache := tc.cache
	fileByID := tc.fileByID
	// A macro constant is usually defined in a header that holds no function, so
	// the string-macro table must be built from EVERY indexed file, not only the
	// callers' files.
	for _, file := range fileByID {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		fileMacros := parser.CollectStringMacros(root)
		for name := range fileMacros {
			stringMacro[name] = true
		}
		for _, def := range root.FindAll("preproc_def") {
			name := ""
			for _, child := range def.NamedChildren() {
				if child.Kind() == "identifier" && name == "" {
					name = child.Text()
				}
			}
			if name != "" && !fileMacros[name] {
				nonStringMacro[name] = true
			}
		}
	}
	// A file-scope `static const char *NAME[N] = {"a", "b"}` is a compile-time
	// template table: NAME[expr] is always a pointer to a string literal, never
	// attacker-controlled content, so a format/path argument spelled NAME[i]
	// must count as literal (not variable). Two passes: declare first, then drop
	// any array whose element is written anywhere in the tree (a `static` array
	// cannot be written from another TU, so an in-tree write is the only way its
	// pointers can stop being the literal initializers — `const char *` keeps the
	// pointee const, NOT the pointer, so the pointer itself is reassignable).
	constStringArrays := map[string]bool{}
	for _, file := range fileByID {
		root := cache.rootForFile(file)
		if root.Kind() == "" {
			continue
		}
		for name := range collectConstStringArrays(root, isStringMacro) {
			constStringArrays[name] = true
		}
	}
	if len(constStringArrays) > 0 {
		written := map[string]bool{}
		for _, file := range fileByID {
			root := cache.rootForFile(file)
			if root.Kind() == "" {
				continue
			}
			for _, assign := range root.FindAll("assignment_expression") {
				lhs, _, ok := assign.AssignParts()
				if !ok {
					continue
				}
				if base := fieldBaseName(lhs.Text()); base != "" && constStringArrays[base] {
					written[base] = true
				}
			}
		}
		for name := range written {
			delete(constStringArrays, name)
		}
	}

	scannedRoot := make(map[int64]bool)
	// The string-macro table is complete here; publish it for the constant-path
	// prover (a no-op for the census's own classification).
	census.stringMacros = stringMacro
	for _, fn := range tc.funcs {
		file := fileByID[fn.FileID]
		if file == nil {
			continue
		}
		body, root := tc.body(fn), tc.root(fn)
		if body.Kind() != "compound_statement" {
			continue
		}

		calls := tc.calls[fn.ID]
		// Local/field string constants: an argument spelled with a variable whose
		// EVERY write in this function is a compile-time string (a literal or a
		// string macro) is a constant too — the census previously classified by
		// argument SYNTAX only, so `const char *fmt = "x"; log_msg(fmt)` counted
		// as a VARIABLE, the all-literal gate never fired, and a wrapper whose
		// callers all pass constants still reached the classifier (production:
		// format-string false positives whose callers pass a local template).
		locals := collectLocalStringConsts(body, isStringMacro)
		runtimeBufs := collectInternalRuntimeBufs(body)
		for _, call := range calls {
			name := callName(call)
			if name == "" {
				continue
			}
			calleeIDs := funcByName[name]
			if len(calleeIDs) == 0 {
				continue
			}
			for i, arg := range callArgs(call) {
				var kind int // 0 literal, 1 tainted, 2 variable, 3 internal-runtime
				switch {
				case isDefinitelyUnTainted(arg):
					kind = 0
				case arg.Kind() == "identifier" && isStringMacro(arg.Text()):
					kind = 0
				case isConstStringArraySubscript(arg, constStringArrays):
					kind = 0
				case (arg.Kind() == "identifier" || arg.Kind() == "field_expression") &&
					localConstAt(locals, compactIdentText(arg.Text()), call.StartLine(), calls):
					kind = 0
				case arg.Kind() == "identifier" &&
					internalRuntimeAt(runtimeBufs, compactIdentText(arg.Text()), call.StartLine(), calls):
					kind = 3
				case isTaintSourceExpr(arg):
					kind = 1
				default:
					kind = 2
				}
				class := classForKind(kind)
				for _, calleeID := range calleeIDs {
					if census.params[calleeID] == nil {
						census.params[calleeID] = make(map[int]*argShapeCounts)
					}
					shapes := census.params[calleeID][i]
					if shapes == nil {
						shapes = &argShapeCounts{}
						census.params[calleeID][i] = shapes
					}
					switch kind {
					case 0:
						shapes.literal++
					case 1:
						shapes.tainted++
					case 3:
						shapes.internalRuntime++
					default:
						shapes.variable++
					}
					if census.sites[calleeID] == nil {
						census.sites[calleeID] = make(map[int][]CallSiteInfo)
					}
					if len(census.sites[calleeID][i]) < callsiteEvidenceCap {
						census.sites[calleeID][i] = append(census.sites[calleeID][i], CallSiteInfo{
							File:  file.Path,
							Line:  call.StartLine(),
							Class: class,
						})
					}
					if kind == 0 {
						if v, ok := parseOOBConst(strings.TrimSpace(arg.Text())); ok {
							if census.constVals[calleeID] == nil {
								census.constVals[calleeID] = make(map[int][]int64)
							}
							census.constVals[calleeID][i] = append(census.constVals[calleeID][i], v)
						}
					}
				}
			}
		}

		// Address-taken / decay scan runs once per FILE over the whole tree:
		// any identifier that names a function but is NOT the definition's own
		// declarator and NOT a direct-call callee is a function-pointer
		// reference (`&fn`, `fp = fn`, `register(fn)`, `(cast)fn`) — the
		// function then has callers the direct-call census cannot see, so the
		// all-literal gate must not fire for it. Over-marking (a same-named
		// local/field/parameter) only keeps candidates, never drops them.
		if !scannedRoot[fn.FileID] {
			scannedRoot[fn.FileID] = true
			for _, id := range root.FindAll("identifier") {
				if len(funcByName[id.Text()]) == 0 || isDirectCallee(id) {
					continue
				}
				census.addrTaken[id.Text()] = true
			}
		}
	}
	return census, nil
}

// isDirectCallee reports whether the identifier is the callee of a direct
// call (`fn(args)`) or the function's own definition/declaration declarator
// — the two identifier positions that are NOT function-pointer references.
func isDirectCallee(id parser.Node) bool {
	parent := id.Parent()
	if parent == nil {
		return false
	}
	switch parent.Kind() {
	case "function_declarator":
		return true
	case "call_expression":
		kids := parent.NamedChildren()
		return len(kids) > 0 && kids[0].Kind() == "identifier" &&
			kids[0].StartLine() == id.StartLine() && kids[0].StartColumn() == id.StartColumn()
	}
	return false
}

// sanitizeKills returns the per-line path-taint kills introduced by
// path-sanitizer calls: `base = basename(p)` / `seg = strrchr(p, '/')` assign
// a value that cannot contain a directory component, so the assignment
// target's PATH taint is killed. The kill is deliberately path-traversal-
// only: a sanitized filename still carries format specifiers, so applying it
// to the format-string flow would turn real CWE-134 findings into drops.
func sanitizeKills(body parser.Node) map[int][]string {
	out := make(map[int][]string)
	forEachAssignment(body, func(lhs, rhs parser.Node) {
		name := assignTargetName(lhs)
		if name == "" || !isPathSanitizeCall(rhs) {
			return
		}
		out[rhs.StartLine()] = append(out[rhs.StartLine()], name)
	})
	return out
}

// isPathSanitizeCall reports whether expr is a call whose result is provably
// directory-free: basename-family (including project-declared
// [sanitize_functions] entries), or strrchr/rindex with a '/' separator (any
// other needle leaves the directory structure intact).
func isPathSanitizeCall(expr parser.Node) bool {
	if expr.Kind() != "call_expression" {
		return false
	}
	name := callName(expr)
	if name == "strrchr" || name == "rindex" {
		args := callArgs(expr)
		return len(args) >= 2 && strings.TrimSpace(args[1].Text()) == "'/'"
	}
	return apikb.IsPathSanitizer(name)
}

// mergeKills returns kill merged with extra without mutating either input.
func mergeKills(kill, extra map[int][]string) map[int][]string {
	if len(extra) == 0 {
		return kill
	}
	out := make(map[int][]string, len(kill)+len(extra))
	for line, vars := range kill {
		out[line] = append([]string(nil), vars...)
	}
	for line, vars := range extra {
		out[line] = append(out[line], vars...)
	}
	return out
}

// expandCallsiteFact renders the compact census fact for evidence text:
// "5:3-literal,2-var" → "5 call sites (3 literal, 2 var)".
func expandCallsiteFact(fact string) string {
	parts := strings.SplitN(fact, ":", 2)
	if len(parts) != 2 {
		return fact
	}
	if parts[1] == "all-literal" {
		return fmt.Sprintf("%s call sites (all literal)", parts[0])
	}
	if parts[1] == "all-constant" {
		return fmt.Sprintf("%s call sites (all constant)", parts[0])
	}
	return fmt.Sprintf("%s call sites (%s)", parts[0], parts[1])
}

// localConst describes a variable (or field chain) in ONE function whose writes
// are all compile-time strings: `literalOnly` is false as soon as any write
// assigns a non-literal, and `lastLiteralLine` is the last write's line.
type localConst struct {
	literalOnly     bool
	lastLiteralLine int
}

// collectLocalStringConsts builds the per-function constant table the call-site
// census consults. isStringMacro reports object-like macros that expand to a
// string literal.
func collectLocalStringConsts(body parser.Node, isStringMacro func(string) bool) map[string]localConst {
	out := make(map[string]localConst)
	record := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		key := compactIdentText(lhs.Text())
		// `const char *fmt = "x"` wraps the target in a pointer_declarator, so the
		// lhs text is `*fmt`; the census argument is spelled `fmt`.
		if lhs.Kind() != "identifier" && lhs.Kind() != "field_expression" {
			if name := declaratorName(lhs); name != "" {
				key = name
			}
		}
		if key == "" {
			return
		}
		cur, seen := out[key]
		if !seen {
			cur = localConst{literalOnly: true}
		}
		if isStringConstText(rhs.Text(), isStringMacro) {
			cur.lastLiteralLine = node.StartLine()
		} else {
			cur.literalOnly = false
		}
		out[key] = cur
	}
	for _, assign := range body.FindAll("assignment_expression") {
		record(assign)
	}
	for _, init := range body.FindAll("init_declarator") {
		record(init)
	}
	return out
}

// localConstAt reports whether the lvalue is a constant at this call site: every
// write in the function assigned a compile-time string, the last one sits before
// the call, and no CALL happens in between (an intervening call could mutate the
// value through an escaped pointer, which this syntactic analysis cannot see).
func localConstAt(locals map[string]localConst, key string, callLine int, calls []parser.Node) bool {
	lc, ok := locals[key]
	if !ok || !lc.literalOnly || lc.lastLiteralLine <= 0 || lc.lastLiteralLine >= callLine {
		return false
	}
	for _, call := range calls {
		line := call.StartLine()
		if line > lc.lastLiteralLine && line < callLine {
			return false
		}
	}
	return true
}

// runtimeFormatArgIdx maps a snprintf-family function to its format argument
// index (the 0-based position of the format string).
var runtimeFormatArgIdx = map[string]int{
	"snprintf": 2, "snprintf_s": 2, "vsnprintf": 2, "vsnprintf_s": 2,
}

// collectInternalRuntimeBufs returns, per buffer variable in body, the line of
// its LAST write by a qualifying snprintf-family call: a fixed format string
// with only integer-class conversions (no %s/%[/%n) and scalar integer
// arguments. Such a buffer holds digits/fixed text only, so passing it as a
// format/path cannot carry attacker-controlled format specifiers.
func collectInternalRuntimeBufs(body parser.Node) map[string]int {
	out := map[string]int{}
	for _, call := range body.FindAll("call_expression") {
		name := callName(call)
		fmtIdx, ok := runtimeFormatArgIdx[name]
		if !ok {
			continue
		}
		args := callArgs(call)
		if len(args) <= fmtIdx {
			continue
		}
		dstName := bareIdentVar(strings.TrimSpace(args[0].Text()))
		if dstName == "" {
			continue
		}
		if !isIntegerOnlyFormat(args[fmtIdx], args[fmtIdx+1:]) {
			continue
		}
		out[dstName] = call.StartLine()
	}
	return out
}

// internalRuntimeAt reports whether lvalue is an internally-built runtime buffer
// at this call site: written by a qualifying snprintf-family call before the
// call line, with no intervening call that could mutate it through an escaped
// pointer.
func internalRuntimeAt(runtimeBufs map[string]int, key string, callLine int, calls []parser.Node) bool {
	lastWrite, ok := runtimeBufs[key]
	if !ok || lastWrite <= 0 || lastWrite >= callLine {
		return false
	}
	for _, call := range calls {
		line := call.StartLine()
		if line > lastWrite && line < callLine {
			return false
		}
	}
	return true
}

// isIntegerOnlyFormat reports whether a snprintf-family call's format is a
// string literal with no %s/%[/%n conversion and every variadic argument is a
// scalar integer identifier or literal — so the produced buffer cannot carry
// attacker-controlled format specifiers.
func isIntegerOnlyFormat(fmtArg parser.Node, variadic []parser.Node) bool {
	lit, ok := stringLiteralText(fmtArg)
	if !ok || !integerOnlyConversions(lit) {
		return false
	}
	for _, a := range variadic {
		switch a.Kind() {
		case "number_literal", "identifier", "char_literal":
		default:
			return false
		}
	}
	return true
}

// stringLiteralText returns the raw content (quotes and encoding prefix
// stripped) of a single string_literal node.
func stringLiteralText(n parser.Node) (string, bool) {
	if n.Kind() != "string_literal" {
		return "", false
	}
	raw := strings.TrimSpace(n.Text())
	for _, p := range []string{"u8", "u", "U", "L"} {
		if strings.HasPrefix(raw, p) && len(raw) > len(p) && raw[len(p)] == '"' {
			raw = raw[len(p):]
			break
		}
	}
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	return raw[1 : len(raw)-1], true
}

// integerOnlyConversions reports whether a printf format string contains only
// integer-class conversions: every % specifier (other than %%) must end in a
// non-string conversion (d/i/u/o/x/X/c/f/e/g/a/p/...). %s, %[, and %n are
// rejected — the first two can inject caller-controlled bytes, the third writes
// back to an argument.
func integerOnlyConversions(fmt string) bool {
	for i := 0; i < len(fmt); i++ {
		if fmt[i] != '%' {
			continue
		}
		if i+1 < len(fmt) && fmt[i+1] == '%' {
			i++
			continue
		}
		j := i + 1
		for j < len(fmt) && strings.IndexByte("-+ #0", fmt[j]) >= 0 {
			j++
		}
		for j < len(fmt) && (fmt[j] >= '0' && fmt[j] <= '9' || fmt[j] == '*') {
			j++
		}
		if j < len(fmt) && fmt[j] == '.' {
			j++
			for j < len(fmt) && (fmt[j] >= '0' && fmt[j] <= '9' || fmt[j] == '*') {
				j++
			}
		}
		for j < len(fmt) && strings.IndexByte("hljztL", fmt[j]) >= 0 {
			j++
		}
		if j >= len(fmt) {
			return false
		}
		switch fmt[j] {
		case 's', '[', 'n':
			return false
		}
		i = j
	}
	return true
}

// isStringConstText reports whether an initializer expression is a compile-time
// string: a C string literal (adjacent literals included), an object-like macro
// that expands to one, or a CONCATENATION of the two (`BASE_DIR "/report.csv"`,
// `"a" MACRO "b"`) — the shape real code uses to build a fixed path from a
// compile-time prefix. The previous version only matched a pure literal or a
// pure single macro, so a caller binding `const char *p = BASE_DIR "/x";` was
// classified as a VARIABLE and the all-literal gate never fired (NLOG pattern 1:
// a single-literal-caller path-traversal false positive).
func isStringConstText(text string, isStringMacro func(string) bool) bool {
	s := strings.TrimSpace(text)
	for s != "" {
		if strings.HasPrefix(s, "/*") || strings.HasPrefix(s, "//") {
			return true
		}
		if rest, ok := consumeStringLiteral(s); ok {
			s = strings.TrimSpace(rest)
			continue
		}
		i := 0
		for i < len(s) && isIdentByte(s[i]) {
			i++
		}
		if i == 0 {
			return false
		}
		if !isStringMacro(s[:i]) {
			return false
		}
		s = strings.TrimSpace(s[i:])
	}
	return true
}

// consumeStringLiteral consumes ONE C string literal (with an optional u8/u/U/L
// encoding prefix) from the front of s, returning the unconsumed tail and true
// on success.
func consumeStringLiteral(s string) (string, bool) {
	for _, prefix := range []string{"u8", "u", "U", "L"} {
		if strings.HasPrefix(s, prefix) && len(s) > len(prefix) && s[len(prefix)] == '"' {
			s = s[len(prefix):]
			break
		}
	}
	if !strings.HasPrefix(s, `"`) {
		return "", false
	}
	i := 1
	for i < len(s) {
		switch s[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return s[i+1:], true
		}
		i++
	}
	return "", false
}

// compactIdentText strips whitespace from an lvalue/argument spelling so two
// spellings of one expression compare equal.
func compactIdentText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, s)
}

// isConstStringArraySubscript reports whether arg is `NAME[expr]` for a
// file-scope constant-string array NAME (see collectConstStringArrays). The
// index is deliberately NOT examined: every element of such an array is a
// string literal, so the value is a pointer to a literal regardless of expr —
// a compile-time constant that is never attacker-controlled content.
func isConstStringArraySubscript(arg parser.Node, constStringArrays map[string]bool) bool {
	if arg.Kind() != "subscript_expression" || len(constStringArrays) == 0 {
		return false
	}
	base := fieldBaseName(arg.Text())
	return base != "" && constStringArrays[base]
}

// collectConstStringArrays returns the names of file-scope constant-string
// arrays in root: `static char *NAME[N] = {"a", "b"}` (with an optional const
// qualifier) whose EVERY initializer element is a string literal or string
// macro. Such an array is a compile-time template table. The caller drops any
// array written elsewhere in the tree (see computeCallsiteSummary).
func collectConstStringArrays(root parser.Node, isStringMacro func(string) bool) map[string]bool {
	out := map[string]bool{}
	ranges := functionRanges(root)
	for _, decl := range root.FindAll("declaration") {
		if inFunction(ranges, decl.StartLine()) {
			continue
		}
		if name, ok := constStringArrayName(decl, isStringMacro); ok {
			out[name] = true
		}
	}
	return out
}

// constStringArrayName reports whether decl is a file-scope `static` array of
// pointers-to-char whose every initializer element is a string literal, and
// returns the array name. The const qualifier on the char is not required (and
// not sufficient): the write scan in computeCallsiteSummary closes the pointer
// reassignment hole instead.
func constStringArrayName(decl parser.Node, isStringMacro func(string) bool) (string, bool) {
	static := false
	char := false
	for _, child := range decl.NamedChildren() {
		switch child.Kind() {
		case "storage_class_specifier":
			if strings.TrimSpace(child.Text()) == "static" {
				static = true
			}
		case "primitive_type":
			if strings.TrimSpace(child.Text()) == "char" {
				char = true
			}
		}
	}
	if !static || !char {
		return "", false
	}
	for _, init := range decl.FindAll("init_declarator") {
		if init.FindFirst("array_declarator") == nil || init.FindFirst("pointer_declarator") == nil {
			continue
		}
		name := declaredName(init)
		if name == "" {
			continue
		}
		il := init.FindFirst("initializer_list")
		if il == nil {
			continue
		}
		if allStringLiteralInitializer(*il, isStringMacro) {
			return name, true
		}
	}
	return "", false
}

// allStringLiteralInitializer reports whether an initializer_list consists
// entirely of string literals, string macros, or nested such lists (so a
// `{ {"a"}, {"b"} }` or `{ FMT_A, FMT_B }` spelling is recognized).
func allStringLiteralInitializer(il parser.Node, isStringMacro func(string) bool) bool {
	children := il.NamedChildren()
	if len(children) == 0 {
		return false
	}
	for _, child := range children {
		switch child.Kind() {
		case "string_literal":
		case "identifier":
			if !isStringMacro(strings.TrimSpace(child.Text())) {
				return false
			}
		case "initializer_list":
			if !allStringLiteralInitializer(child, isStringMacro) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
