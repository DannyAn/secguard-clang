package planner

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// maxPathProofDepth bounds the call-chain recursion of the constant-path proof.
// A real helper chain is 1-3 hops; the bound is a safety net for mutually
// recursive builders (the visiting set already breaks the cycle, the depth cap
// keeps the recursion shallow when a chain fans out).
const maxPathProofDepth = 12

// ConstantPathFilter is the path-traversal `constant_path_proof` stage: it
// drops a candidate whose path argument provably resolves to a compile-time
// constant on every in-tree call path.
//
// The detector already suppresses a path it can prove constant INSIDE one
// function (a literal, a string-valued macro, a `static const` object, or a
// buffer assembled there from those). The gap this filter closes is the
// INTERPROCEDURAL one: the sink receives a function PARAMETER whose call-site
// census is `N:M-var` simply because every caller passes a local buffer, and
// that buffer is assembled from a fixed directory plus a constant file name
// (often through a path-building helper). Such a chain has no user-controlled
// component, yet the census cannot see it and the candidate reaches the AI,
// which then spends a review slot on it. Production CWE-22 is dominated by this
// shape.
//
// The proof is deliberately one-directional: every step must be proven
// constant, and any unprovable step (an unknown external function, an address
// taken function, a value that crosses an unmodeled write, a data-flow source)
// keeps the candidate. A path fed by user input therefore always survives — the
// one real CWE-22 in the reference production scan was exactly
// `fopen(<fixed_dir>/<json_field>)`, and `json_get_string_by_key` is not a
// constant, so it stays a candidate.
type ConstantPathFilter struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	reach  *callReachCache
	taint  *taintSummaryCache
}

// NewConstantPathFilter builds the filter. reach is the Planner's shared
// call-graph cache (caller enumeration); taint is the shared taint-summary cache
// (the call-site census's global string-macro table and the syntactic
// address-taken census). Both may be nil in a hand-built unit test: the filter
// then derives the caller graph itself and simply proves less.
func NewConstantPathFilter(store db.Store, p *parser.Parser, logger *log.Logger, reach *callReachCache, taint *taintSummaryCache) *ConstantPathFilter {
	return &ConstantPathFilter{store: store, parser: p, logger: logger, reach: reach, taint: taint}
}

func (f *ConstantPathFilter) Name() string { return "constant_path_proof" }

func (f *ConstantPathFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil || len(candidates) == 0 {
		return candidates, nil, nil
	}

	// Inputs the proof shares with the call-site census: the global
	// string-valued-macro table (a `#define` may live in a header) and the
	// syntactic address-taken census. A failure here is fail-open: the prover
	// derives the address-taken set from the graph itself and treats a missing
	// macro table as "not a known constant".
	var stringMacros map[string]bool
	var censusAddrTaken map[string]bool
	if f.taint != nil {
		if s, err := f.taint.get(ctx); err == nil && s.callsites != nil {
			stringMacros = s.callsites.stringMacros
			censusAddrTaken = s.callsites.addrTaken
		}
	}

	prover, err := newPathProver(ctx, f.store, f.parser, f.reach, stringMacros, censusAddrTaken)
	if err != nil {
		return nil, nil, err
	}

	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		// Only the traversal category carries a `../` path; the
		// permission_setting categories (world_writable_file/var) are a mode
		// defect and are judged by the chmod rules, not by path provenance.
		if c.Category != "path_traversal" || c.PathExpr == "" {
			kept = append(kept, c)
			continue
		}
		if ok, reason := prover.proveCandidate(c); ok {
			dropped = dismiss(dropped, c, f.Name(), reason)
			continue
		}
		kept = append(kept, c)
	}
	if f.logger != nil && len(dropped) > 0 {
		f.logger.Info("constant-path proof dismissed path-traversal candidates", "count", len(dropped))
	}
	return kept, dropped, nil
}

// proofKind names the memoized proof predicate.
type proofKind int

const (
	proofParamValue proofKind = iota
	proofLocalValue
	proofWrites
	proofReturns
)

type proofKey struct {
	kind proofKind
	fn   int64
	idx  int
	name string
}

type wroteResult struct {
	ok    bool
	wrote bool
}

// fnCtx is the parsed per-function state the proof walks: the body, the
// parameter-name -> index map, and the set of names declared as locals (a name
// that is neither a parameter nor a local is a global, which this proof never
// treats as constant: it may be written anywhere).
type fnCtx struct {
	id     int64
	name   string
	fileID int64
	body   parser.Node
	params map[string]int

	locals map[string]bool
}

// pathProof is the constant-path prover. Everything is memoized per Apply:
// a chain is walked once per candidate and the same helper/parameter predicate
// is frequently re-asked by several call sites.
type pathProof struct {
	cache *fileParseCache

	fnByID   map[int64]*db.Function
	fileByID map[int64]*db.File
	byName   map[string][]int64
	callers  map[int64][]int64
	// addrTaken is keyed by function ID: a function referenced through a
	// function pointer has callers the direct-call graph cannot see, so no
	// caller-side proof may conclude it is only ever called with constants.
	addrTaken map[int64]bool

	stringMacros map[string]bool
	intMacros    map[int64]map[string]bool

	ctxByFunc map[int64]*fnCtx
	memo      map[proofKey]bool
	memoWrite map[proofKey]wroteResult
	visiting  map[proofKey]bool
	depth     int
}

func newPathProver(ctx context.Context, store db.Store, p *parser.Parser, reach *callReachCache, stringMacros, censusAddrTaken map[string]bool) (*pathProof, error) {
	if reach == nil {
		reach = &callReachCache{}
	}
	res, err := reach.get(ctx, store)
	if err != nil {
		return nil, fmt.Errorf("constant path proof: call graph: %w", err)
	}
	funcs, err := store.ListFunctions(ctx)
	if err != nil {
		return nil, fmt.Errorf("constant path proof: list functions: %w", err)
	}
	fileByID := listFilesByID(ctx, store)

	nodeToFunc := make(map[int64]int64, len(res.funcNodeMap))
	fnByID := make(map[int64]*db.Function, len(funcs))
	byName := make(map[string][]int64, len(funcs))
	for _, fn := range funcs {
		fnByID[fn.ID] = fn
		byName[fn.Name] = append(byName[fn.Name], fn.ID)
	}
	for fnID, nodeID := range res.funcNodeMap {
		if _, ok := nodeToFunc[nodeID]; !ok {
			nodeToFunc[nodeID] = fnID
		}
	}

	callers := make(map[int64][]int64)
	for nodeID, callerNodes := range res.callers {
		callee := nodeToFunc[nodeID]
		if callee == 0 {
			continue
		}
		for _, cn := range callerNodes {
			caller := nodeToFunc[cn]
			if caller == 0 || caller == callee {
				continue
			}
			callers[callee] = append(callers[callee], caller)
		}
	}

	// The address-taken census is load-bearing: a function reached through a
	// pointer has callers the direct-call graph cannot see, so the proof must
	// not conclude anything about it. A read failure is fail-open (the caller
	// keeps every candidate) rather than a silent empty set.
	addrEdges, aerr := store.ListGraphEdgesByType(ctx, "ADDR_TAKEN")
	if aerr != nil {
		return nil, fmt.Errorf("constant path proof: address-taken census: %w", aerr)
	}
	addrTaken := make(map[int64]bool)
	for _, e := range addrEdges {
		if fnID := nodeToFunc[e.SrcID]; fnID != 0 {
			addrTaken[fnID] = true
		}
	}
	if len(censusAddrTaken) > 0 {
		for fnID, fn := range fnByID {
			if censusAddrTaken[fn.Name] {
				addrTaken[fnID] = true
			}
		}
	}

	return &pathProof{
		cache:        newFileParseCache(p),
		fnByID:       fnByID,
		fileByID:     fileByID,
		byName:       byName,
		callers:      callers,
		addrTaken:    addrTaken,
		stringMacros: stringMacros,
		ctxByFunc:    make(map[int64]*fnCtx),
		memo:         make(map[proofKey]bool),
		memoWrite:    make(map[proofKey]wroteResult),
		visiting:     make(map[proofKey]bool),
	}, nil
}

// proveCandidate decides whether c's path argument is a compile-time constant.
//
// Order matters: a parameter the sink's own function OVERWRITES must be judged
// by those writes (the caller's argument no longer reaches the sink), and only
// an untouched parameter is judged by its in-tree call sites.
func (p *pathProof) proveCandidate(c Candidate) (bool, string) {
	key := compactIdentText(taintLocKey(c.PathExpr))
	if key == "" {
		return false, ""
	}
	// Only a bare location (an identifier, or its trailing/integer-offset form)
	// is proven: a struct-field or array-element sink can be written through
	// another pointer the AST walk does not alias, so its provenance is not
	// provable here.
	if bareIdentVar(key) == "" {
		return false, ""
	}
	fctx := p.fnContext(c.FunctionID)
	if fctx == nil {
		return false, ""
	}
	if ok, wrote := p.writesConstant(fctx, key); wrote {
		if !ok {
			return false, ""
		}
		return true, fmt.Sprintf("path argument `%s` is assembled inside %s only from compile-time constants and internally generated numeric values", key, fctx.name)
	}
	idx, isParam := fctx.params[key]
	if !isParam {
		// A local with no visible write is uninitialized or written through an
		// unmodeled path; neither is provable.
		return false, ""
	}
	if !p.paramValueConstant(fctx.id, idx) {
		return false, ""
	}
	sites := p.siteSummary(fctx.id, idx)
	if sites == "" {
		sites = "every in-tree call site resolves to a compile-time constant"
	}
	return true, fmt.Sprintf("path argument `%s` is a parameter of %s, and every in-tree call site resolves to a compile-time constant (%s)", key, fctx.name, sites)
}

// fnContext loads and memoizes the parsed state of one function.
func (p *pathProof) fnContext(fnID int64) *fnCtx {
	if c, ok := p.ctxByFunc[fnID]; ok {
		return c
	}
	var out *fnCtx
	fn := p.fnByID[fnID]
	if fn != nil {
		if file := p.fileByID[fn.FileID]; file != nil {
			body, _ := p.cache.get(file, fn)
			if body.Kind() == "compound_statement" {
				out = &fnCtx{
					id:     fn.ID,
					name:   fn.Name,
					fileID: fn.FileID,
					body:   body,
					params: p.cache.paramsFor(file, fn),
				}
			}
		}
	}
	p.ctxByFunc[fnID] = out
	return out
}

// paramValueConstant proves that every in-tree call site of fnID passes a
// compile-time constant to parameter idx.
func (p *pathProof) paramValueConstant(fnID int64, idx int) bool {
	if p.addrTaken[fnID] {
		return false
	}
	key := proofKey{kind: proofParamValue, fn: fnID, idx: idx}
	if v, ok := p.memo[key]; ok {
		return v
	}
	if p.visiting[key] || p.depth >= maxPathProofDepth {
		return false
	}
	fn := p.fnByID[fnID]
	if fn == nil {
		return false
	}
	callers := p.callers[fnID]
	// Zero in-tree callers is the external-ABI boundary every reachability
	// filter already treats as attacker-reachable: not provable.
	if len(callers) == 0 {
		return false
	}

	p.visiting[key] = true
	p.depth++
	defer func() {
		p.depth--
		delete(p.visiting, key)
	}()

	for _, callerID := range callers {
		fctx := p.fnContext(callerID)
		if fctx == nil {
			return false
		}
		found := false
		for _, call := range fctx.body.FindAll("call_expression") {
			if callName(call) != fn.Name {
				continue
			}
			args := callArgs(call)
			if idx >= len(args) {
				return false
			}
			found = true
			if !p.exprConstant(fctx, args[idx]) {
				return false
			}
		}
		// A CALL edge without a matching call expression (macro-generated,
		// same-named static in another file, stale index) leaves the argument
		// unknown.
		if !found {
			return false
		}
	}
	p.memo[key] = true
	return true
}

// localValueConstant proves that a local (or field location) is a compile-time
// constant: it is declared in the function and every write to it is constant.
func (p *pathProof) localValueConstant(fctx *fnCtx, name string) bool {
	if !p.localDeclared(fctx, name) {
		return false
	}
	ok, wrote := p.writesConstant(fctx, name)
	return ok && wrote
}

// paramWritesConstant reports whether a function writes parameter idx and, if
// so, whether every write is a compile-time constant. A helper that does not
// modify the parameter at all preserves the caller's value, so it is
// (wrote=false, ok=true).
func (p *pathProof) paramWritesConstant(fnID int64, idx int) (bool, bool) {
	fctx := p.fnContext(fnID)
	if fctx == nil {
		return false, false
	}
	name := ""
	for n, i := range fctx.params {
		if i == idx {
			name = n
			break
		}
	}
	if name == "" {
		return false, false
	}
	ok, wrote := p.writesConstant(fctx, name)
	return wrote, ok
}

// writesConstant returns (everyWriteConstant, anyWriteFound) for one location
// name inside a function. Only writes the AST can see are considered:
//
//   - assignments / initializers whose target resolves to the location;
//   - a path-building / copy / memset call writing it;
//   - an input call (fgets/read/scanf) writing it — always unprovable;
//   - a call passing the location to an in-tree helper that writes that
//     parameter (recursively — this is the `build_export_path(..., out, n)`
//     shape);
//   - a call passing it to a function with no in-tree body, which is unprovable
//     unless the callee is a known read-only API (`strlen`, `printf`, `fopen`,
//     `stat`, ...). The proof never assumes an unmodeled function left a
//     mutable buffer untouched.
func (p *pathProof) writesConstant(fctx *fnCtx, name string) (bool, bool) {
	key := proofKey{kind: proofWrites, fn: fctx.id, name: name}
	if v, ok := p.memoWrite[key]; ok {
		return v.ok, v.wrote
	}
	if p.visiting[key] {
		return false, false
	}
	p.visiting[key] = true
	defer delete(p.visiting, key)

	// Local pointer aliases (`char *p = buf;`) make a write through p a write to
	// the location: treating p as a read would let an aliased user-controlled
	// write slip past the proof. The alias set over-approximates (a pointer that
	// ever pointed at the location stays in the set), which can only keep a
	// candidate, never drop one.
	aliases := p.locationAliases(fctx, name)

	ok, wrote := true, false
	noteWrite := func(constant bool) {
		wrote = true
		if !constant {
			ok = false
		}
	}

	for _, assign := range fctx.body.FindAll("assignment_expression") {
		if lhs, rhs, hasParts := assign.AssignParts(); hasParts && aliases[locationBase(lhs)] {
			noteWrite(p.exprConstant(fctx, rhs))
		}
	}
	for _, init := range fctx.body.FindAll("init_declarator") {
		if lhs, rhs, hasParts := init.AssignParts(); hasParts && aliases[locationBase(lhs)] {
			noteWrite(p.exprConstant(fctx, rhs))
		}
	}

	for _, call := range fctx.body.FindAll("call_expression") {
		cn := callName(call)
		if cn == "" {
			continue
		}
		args := callArgs(call)
		if len(args) == 0 {
			continue
		}
		if isPathBuilderCall(cn) || isCopyWriterCall(cn) {
			if aliases[locationBase(args[0])] {
				noteWrite(p.builderConstant(fctx, call))
			}
			continue
		}
		for _, v := range taintBufferArgVars(call) {
			if aliases[v] {
				noteWrite(false)
			}
		}
		for i, arg := range args {
			if !aliases[locationBase(arg)] {
				continue
			}
			calleeIDs := p.byName[cn]
			if len(calleeIDs) == 0 {
				if argIsReadOnly(cn, i) {
					continue
				}
				noteWrite(false)
				continue
			}
			calleeWrote, calleeConstant := false, true
			for _, calleeID := range calleeIDs {
				w, cok := p.paramWritesConstant(calleeID, i)
				if w {
					calleeWrote = true
				}
				if !cok {
					calleeConstant = false
				}
			}
			if calleeWrote {
				noteWrite(calleeConstant)
			} else if !calleeConstant {
				noteWrite(false)
			}
		}
	}

	res := wroteResult{ok: ok, wrote: wrote}
	p.memoWrite[key] = res
	return ok, wrote
}

// locationAliases returns the set of local names whose value aliases the
// tracked location: the location itself plus every local ever assigned from it
// (or from one of its arithmetic/subscript forms). The alias relation is closed
// transitively so `q = p; p = buf;` also marks q.
func (p *pathProof) locationAliases(fctx *fnCtx, name string) map[string]bool {
	out := map[string]bool{name: true}
	type assignPair struct{ lhs, rhs string }
	var pairs []assignPair
	collect := func(node parser.Node) {
		if lhs, rhs, hasParts := node.AssignParts(); hasParts {
			l := locationBase(lhs)
			if l == "" {
				return
			}
			pairs = append(pairs, assignPair{lhs: l, rhs: locationBase(rhs)})
		}
	}
	for _, assign := range fctx.body.FindAll("assignment_expression") {
		collect(assign)
	}
	for _, init := range fctx.body.FindAll("init_declarator") {
		collect(init)
	}
	for changed := true; changed; {
		changed = false
		for _, pr := range pairs {
			if pr.rhs == "" || !out[pr.rhs] || out[pr.lhs] {
				continue
			}
			out[pr.lhs] = true
			changed = true
		}
	}
	return out
}

// localDeclared reports whether the name is declared as a local in the
// function (an array/pointer/scalar declarator). Globals are excluded on
// purpose: their value can be changed from anywhere in the tree.
func (p *pathProof) localDeclared(fctx *fnCtx, name string) bool {
	if fctx.locals == nil {
		fctx.locals = make(map[string]bool)
		for _, decl := range fctx.body.FindAll("declaration") {
			for _, child := range decl.NamedChildren() {
				switch child.Kind() {
				case "init_declarator":
					if lhs, _, ok := child.AssignParts(); ok {
						if n := declaratorName(lhs); n != "" {
							fctx.locals[n] = true
						}
					}
				case "array_declarator", "pointer_declarator", "parenthesized_declarator", "identifier":
					if n := declaratorName(child); n != "" {
						fctx.locals[n] = true
					}
				}
			}
		}
	}
	return fctx.locals[name]
}

// exprConstant reports whether an expression is provably compile-time or
// internally generated (and therefore cannot carry attacker input).
func (p *pathProof) exprConstant(fctx *fnCtx, expr parser.Node) bool {
	if expr.Kind() == "" {
		return false
	}
	switch expr.Kind() {
	case "string_literal", "number_literal", "char_literal", "sizeof_expression":
		return true
	case "initializer_list", "initializer_pair", "compound_literal_expression":
		// `char path[512] = {0};` is a zero-initialized fixed-size buffer: every
		// element is a compile-time constant.
		kids := expr.NamedChildren()
		if len(kids) == 0 {
			return true
		}
		for _, kid := range kids {
			if !p.exprConstant(fctx, kid) {
				return false
			}
		}
		return true
	case "concatenated_string":
		for _, child := range expr.NamedChildren() {
			switch child.Kind() {
			case "string_literal":
				continue
			case "identifier":
				if p.stringMacros[child.Text()] {
					continue
				}
			}
			return false
		}
		return true
	case "parenthesized_expression", "cast_expression":
		kids := expr.NamedChildren()
		return len(kids) == 1 && p.exprConstant(fctx, kids[0])
	case "pointer_expression":
		// `&x` / `*x` name a location whose VALUE is what the sink consumes; the
		// address itself says nothing, so recurse into the operand.
		kids := expr.NamedChildren()
		return len(kids) == 1 && p.exprConstant(fctx, kids[0])
	case "subscript_expression":
		kids := expr.NamedChildren()
		return len(kids) >= 1 && p.exprConstant(fctx, kids[0])
	case "field_expression":
		return p.localValueConstant(fctx, compactIdentText(expr.Text()))
	case "identifier":
		return p.identConstant(fctx, expr.Text())
	case "call_expression":
		return p.callConstant(fctx, expr)
	case "binary_expression", "unary_expression":
		return p.numericConstant(fctx, expr)
	}
	return false
}

// identConstant resolves a bare identifier to its constant proof: a
// string-valued macro, a parameter with constant call sites, or a local with
// constant writes.
func (p *pathProof) identConstant(fctx *fnCtx, name string) bool {
	if name == "" {
		return false
	}
	if name == "NULL" || name == "nullptr" || name == "true" || name == "false" {
		return true
	}
	if p.stringMacros[name] {
		return true
	}
	if idx, ok := fctx.params[name]; ok {
		return p.paramValueConstant(fctx.id, idx)
	}
	return p.localValueConstant(fctx, name)
}

// callConstant reports whether a call result is provably constant: a known
// internal value generator (time/getpid/rand — their numeric text cannot carry
// a path separator), or an in-tree function whose every return is constant.
func (p *pathProof) callConstant(fctx *fnCtx, expr parser.Node) bool {
	name := callName(expr)
	if name == "" {
		return false
	}
	if internalValueFuncs[name] {
		return true
	}
	ids := p.byName[name]
	if len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if !p.returnsConstant(id) {
			return false
		}
	}
	return true
}

// returnsConstant proves that every `return` statement of a function returns a
// compile-time constant (the `asset_report_get_name()` / switch-of-literals
// name-provider shape).
func (p *pathProof) returnsConstant(fnID int64) bool {
	key := proofKey{kind: proofReturns, fn: fnID}
	if v, ok := p.memo[key]; ok {
		return v
	}
	if p.visiting[key] || p.depth >= maxPathProofDepth {
		return false
	}
	fctx := p.fnContext(fnID)
	if fctx == nil {
		return false
	}
	returns := fctx.body.FindAll("return_statement")
	if len(returns) == 0 {
		return false
	}
	p.visiting[key] = true
	p.depth++
	defer func() {
		p.depth--
		delete(p.visiting, key)
	}()
	for _, ret := range returns {
		kids := ret.NamedChildren()
		if len(kids) != 1 || !p.exprConstant(fctx, kids[0]) {
			return false
		}
	}
	p.memo[key] = true
	return true
}

// numericConstant proves an integer/float-valued expression: a numeric literal,
// sizeof, an internal value generator, or arithmetic over those. A value used
// through an integer conversion specifier cannot introduce a `/` or `.` path
// segment, which is what lets a timestamp/ESN counter sit in a fixed path.
func (p *pathProof) numericConstant(fctx *fnCtx, expr parser.Node) bool {
	switch expr.Kind() {
	case "number_literal", "sizeof_expression", "char_literal":
		return true
	case "parenthesized_expression", "cast_expression":
		kids := expr.NamedChildren()
		return len(kids) == 1 && p.numericConstant(fctx, kids[0])
	case "unary_expression", "binary_expression":
		kids := expr.NamedChildren()
		if len(kids) == 0 {
			return false
		}
		for _, kid := range kids {
			if !p.numericConstant(fctx, kid) {
				return false
			}
		}
		return true
	case "identifier":
		return p.intMacrosOf(fctx.fileID)[expr.Text()]
	case "call_expression":
		return internalValueFuncs[callName(expr)]
	}
	return false
}

// intMacrosOf returns the object-like integer macros of a file, so an
// arithmetic constant built from `#define MAX_LEN 32` stays provable.
func (p *pathProof) intMacrosOf(fileID int64) map[string]bool {
	if p.intMacros == nil {
		p.intMacros = make(map[int64]map[string]bool)
	}
	if m, ok := p.intMacros[fileID]; ok {
		return m
	}
	out := make(map[string]bool)
	if file := p.fileByID[fileID]; file != nil {
		for name := range parser.CollectMacroValues(p.cache.rootForFile(file)) {
			out[name] = true
		}
	}
	p.intMacros[fileID] = out
	return out
}

// builderConstant proves one path-building call whose destination is the tracked
// location. When the format is a literal, integer/float conversions are exempt
// (their text cannot contain a path separator) and the remaining arguments must
// be constants; when it is not, every argument must be a constant.
func (p *pathProof) builderConstant(fctx *fnCtx, call parser.Node) bool {
	cn := callName(call)
	args := callArgs(call)
	if cn == "memset" {
		return len(args) >= 2 && p.exprConstant(fctx, args[1])
	}
	if fmtIdx, ok := apikb.SQLFormatFuncFmtIdx(cn); ok {
		if len(args) <= fmtIdx {
			return false
		}
		if text, ok := cStringLiteralValue(args[fmtIdx]); ok {
			if specs, ok := formatConversions(text); ok && len(specs) == len(args)-fmtIdx-1 {
				for i, numeric := range specs {
					if numeric {
						continue
					}
					if !p.exprConstant(fctx, args[fmtIdx+1+i]) {
						return false
					}
				}
				return true
			}
		}
		for _, arg := range args[fmtIdx:] {
			if !p.exprConstant(fctx, arg) {
				return false
			}
		}
		return true
	}
	if srcIdx, ok := copyWriterSrcIdx[cn]; ok {
		return len(args) > srcIdx && p.exprConstant(fctx, args[srcIdx])
	}
	return false
}

// siteSummary renders the resolved in-tree call sites for the dismiss reason:
// `literal@export.c:40, constant@export.c:52`.
func (p *pathProof) siteSummary(fnID int64, idx int) string {
	fn := p.fnByID[fnID]
	if fn == nil {
		return ""
	}
	var parts []string
	for _, callerID := range p.callers[fnID] {
		fctx := p.fnContext(callerID)
		if fctx == nil {
			continue
		}
		for _, call := range fctx.body.FindAll("call_expression") {
			if callName(call) != fn.Name {
				continue
			}
			args := callArgs(call)
			if idx >= len(args) {
				continue
			}
			class := "constant"
			if !p.exprConstant(fctx, args[idx]) {
				class = "variable"
			}
			file := ""
			if f := p.fileByID[fctx.fileID]; f != nil {
				file = filepath.Base(f.Path)
			}
			parts = append(parts, fmt.Sprintf("%s@%s:%d", class, file, call.StartLine()))
			if len(parts) >= 8 {
				return strings.Join(parts, ", ") + ", …"
			}
		}
	}
	return strings.Join(parts, ", ")
}

// locationBase returns the base variable an expression writes/reads a location
// through: `path`, `path + 1`, `path[i]`, `&path[0]`, `*path`, `s->buf`.
func locationBase(node parser.Node) string {
	switch node.Kind() {
	case "identifier":
		return node.Text()
	case "field_expression":
		return compactIdentText(node.Text())
	case "subscript_expression", "binary_expression":
		kids := node.NamedChildren()
		if len(kids) > 0 {
			return locationBase(kids[0])
		}
	case "parenthesized_expression", "cast_expression":
		for _, kid := range node.NamedChildren() {
			if b := locationBase(kid); b != "" {
				return b
			}
		}
	case "pointer_expression":
		kids := node.NamedChildren()
		if len(kids) == 1 {
			return locationBase(kids[0])
		}
	case "array_declarator", "pointer_declarator", "init_declarator", "parenthesized_declarator":
		return declaratorName(node)
	}
	return ""
}

// copyWriterSrcIdx maps a copy call to the index of the SOURCE argument.
var copyWriterSrcIdx = map[string]int{
	"strcpy": 1, "strncpy": 1, "strlcpy": 1, "stpcpy": 1,
	"strcat": 1, "strncat": 1, "strlcat": 1,
	"strcpy_s": 2, "strncpy_s": 2, "strcat_s": 2, "strncat_s": 2,
	"memcpy": 1, "memmove": 1, "memcpy_s": 2, "memmove_s": 2,
}

func isPathBuilderCall(name string) bool {
	if _, ok := apikb.SQLFormatFuncFmtIdx(name); ok {
		return true
	}
	return name == "memset"
}

func isCopyWriterCall(name string) bool {
	_, ok := copyWriterSrcIdx[name]
	return ok
}

// internalValueFuncs return a numeric value that is generated inside the process
// (a clock reading, a pid, a random number). Their decimal/hex rendering cannot
// contain a path separator, so they may appear in a fixed path built with an
// integer conversion like `"%s/%u.json"`.
var internalValueFuncs = map[string]bool{
	"time": true, "clock": true, "getpid": true, "getppid": true, "gettid": true,
	"getuid": true, "geteuid": true, "getgid": true, "getegid": true,
	"rand": true, "random": true, "lrand48": true,
}

// readOnlyAllArgs lists functions that never write any argument buffer, so
// passing the tracked location to them does not change its value.
var readOnlyAllArgs = map[string]bool{
	"printf": true, "fprintf": true, "vprintf": true, "vfprintf": true,
	"puts": true, "fputs": true, "fputc": true, "putchar": true, "fwrite": true,
	"syslog": true, "perror": true,
	"strlen": true, "strnlen": true, "strcmp": true, "strncmp": true,
	"strcasecmp": true, "strncasecmp": true, "strcoll": true,
	"strchr": true, "strrchr": true, "strstr": true, "strpbrk": true,
	"strspn": true, "strcspn": true, "memcmp": true,
	"strdup": true, "strndup": true,
	"atoi": true, "atol": true, "atoll": true, "atof": true,
	"strtol": true, "strtoul": true, "strtoll": true, "strtoull": true, "strtod": true,
	"isdigit": true, "isalpha": true, "isalnum": true, "isspace": true,
	"toupper": true, "tolower": true, "abs": true, "labs": true,
	"basename": true, "dirname": true, "dirname_r": true,
	"system": true, "popen": true,
}

// readOnlyArgIdx lists functions where only specific argument positions are
// read-only (the path/file-name argument of a filesystem API).
var readOnlyArgIdx = map[string][]int{
	"fopen": {0}, "freopen": {0}, "open": {0}, "openat": {1}, "opendir": {0},
	"stat": {0}, "lstat": {0}, "fstatat": {1},
	"access": {0}, "faccessat": {1},
	"unlink": {0}, "unlinkat": {1}, "remove": {0}, "rename": {0, 1},
	"chmod": {0}, "fchmodat": {1}, "chown": {0}, "lchown": {0},
	"mkdir": {0}, "mkdirat": {1}, "rmdir": {0},
	"link": {0, 1}, "symlink": {0, 1},
	"realpath": {0}, "truncate": {0},
	"scandir": {0}, "glob": {0},
}

func argIsReadOnly(name string, idx int) bool {
	if readOnlyAllArgs[name] {
		return true
	}
	for _, i := range readOnlyArgIdx[name] {
		if i == idx {
			return true
		}
	}
	return false
}

// cStringLiteralValue returns the raw (still escaped) contents of a single or
// concatenated C string literal, e.g. `"%s/%u.json"`.
func cStringLiteralValue(node parser.Node) (string, bool) {
	switch node.Kind() {
	case "string_literal", "concatenated_string":
	default:
		return "", false
	}
	text := node.Text()
	var b strings.Builder
	found := false
	for i := 0; i < len(text); i++ {
		if text[i] != '"' {
			continue
		}
		found = true
		for i++; i < len(text) && text[i] != '"'; i++ {
			if text[i] == '\\' && i+1 < len(text) {
				b.WriteByte(text[i])
				i++
			}
			b.WriteByte(text[i])
		}
	}
	return b.String(), found
}

// formatConversions splits a printf format into one entry per consumed
// argument: true when the conversion can only emit digits/signs (an integer or
// float conversion), false when the emitted text may contain any byte (a
// string/char conversion). ok is false when the format cannot be analyzed
// confidently (an unknown conversion, `%n`, a `*` width/precision).
func formatConversions(format string) ([]bool, bool) {
	var out []bool
	for i := 0; i < len(format); i++ {
		switch format[i] {
		case '\\':
			i++
		case '%':
			i++
			if i < len(format) && format[i] == '%' {
				continue
			}
			for i < len(format) && strings.IndexByte("-+ #0'", format[i]) >= 0 {
				i++
			}
			if i < len(format) && format[i] == '*' {
				return nil, false
			}
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			if i < len(format) && format[i] == '.' {
				i++
				if i < len(format) && format[i] == '*' {
					return nil, false
				}
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					i++
				}
			}
			for i < len(format) && strings.IndexByte("hljztL", format[i]) >= 0 {
				i++
			}
			if i >= len(format) {
				return nil, false
			}
			switch format[i] {
			case 'd', 'i', 'o', 'u', 'x', 'X', 'f', 'F', 'e', 'E', 'g', 'G', 'a', 'A', 'p':
				out = append(out, true)
			case 's', 'S', 'c', 'C':
				out = append(out, false)
			default:
				return nil, false
			}
		}
	}
	return out, true
}
