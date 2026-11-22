package evidence

import (
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// borrowFreeSite is one releasing call on a borrowed pointer: the variable,
// the releasing call's line and API, and the borrow-source API the value
// came from.
type borrowFreeSite struct {
	variable  string
	line      int
	borrowAPI string
	freeAPI   string
}

// findFreeOnBorrowSites returns the deallocator calls whose argument
// variable still holds a borrowed pointer: the variable's most recent
// assignment before the call is a direct `var = <borrow-returning API>(...)`
// (apikb.IsBorrowReturn — cJSON_GetObjectItem, strstr, getenv, ...) with no
// intervening reassignment, and the call releases that variable. The object
// is owned elsewhere (the parent JSON tree, the input string, the
// environment), so releasing it locally is an invalid free.
func findFreeOnBorrowSites(assigns, inits, calls []parser.Node, f *db.Function) []borrowFreeSite {
	type borrowAssign struct {
		line int
		api  string
	}
	assignLines := map[string][]int{}
	borrowAssigns := map[string][]borrowAssign{}
	record := func(lhs, rhs parser.Node, line int) {
		name := assignedVariable(lhs)
		if name == "" {
			return
		}
		assignLines[name] = append(assignLines[name], line)
		if rhs.Kind() == "call_expression" {
			if api := extractCallName(rhs); api != "" && apikb.IsBorrowReturn(api) {
				borrowAssigns[name] = append(borrowAssigns[name], borrowAssign{line: line, api: api})
			}
		}
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		record(children[0], children[1], assign.StartLine())
	}
	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		children := init.NamedChildren()
		if len(children) < 2 {
			continue
		}
		record(children[0], children[1], init.StartLine())
	}
	var sites []borrowFreeSite
	seen := map[string]bool{}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		freeAPI := extractCallName(call)
		if freeAPI == "" || !apikb.IsDeallocator(freeAPI) {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		name := argIdentifier(args[0])
		if name == "" {
			continue
		}
		key := name + ":" + strconv.Itoa(call.StartLine())
		if seen[key] {
			continue
		}
		borrowList := borrowAssigns[name]
		if len(borrowList) == 0 {
			continue
		}
		borrowLine, borrowAPI := 0, ""
		for _, b := range borrowList {
			if b.line < call.StartLine() && b.line > borrowLine {
				borrowLine, borrowAPI = b.line, b.api
			}
		}
		if borrowLine == 0 {
			continue
		}
		// A reassignment between the borrow and the release means the freed
		// object may no longer be the borrowed one — stay silent rather
		// than guess (`p = strstr(...); p = malloc(n); free(p);` frees the
		// malloc'd block and is correct).
		reassigned := false
		for _, l := range assignLines[name] {
			if l > borrowLine && l < call.StartLine() {
				reassigned = true
				break
			}
		}
		if reassigned {
			continue
		}
		seen[key] = true
		sites = append(sites, borrowFreeSite{variable: name, line: call.StartLine(), borrowAPI: borrowAPI, freeAPI: freeAPI})
	}
	return sites
}

func findEscapeLines(assigns, calls, returns, ids []parser.Node, f *db.Function, varName string, localVars map[string]bool, allocVarNames map[string]bool, allocReturns map[string]bool, useEscapeFuncs bool, escapeFuncs map[string]map[int]bool) []int {
	var lines []int
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]

		if argIdentifier(rhs) == varName {
			if lhs.Kind() == "subscript_expression" || lhs.Kind() == "field_expression" {
				lines = append(lines, assign.StartLine())
			} else if lhs.Kind() == "pointer_expression" {
				base := ""
				for _, child := range lhs.NamedChildren() {
					if child.Kind() == "identifier" {
						base = child.Text()
						break
					}
				}
				// Escape through a non-local (parameter/global) base: the stored
				// pointer's ownership rides with that object, not the function's
				// frame. A base that is itself a heap allocation (`*container = p`)
				// escapes p only when the container ITSELF escapes (returned or
				// stored to a non-local); a container that is only freed at the end
				// does NOT free its members, so p still leaks (EL-01).
				if base == "" {
					continue
				}
				if !localVars[base] {
					lines = append(lines, assign.StartLine())
				} else if allocVarNames[base] && containerEscapes(assigns, calls, returns, f, base, localVars) {
					lines = append(lines, assign.StartLine())
				}
			} else if lhs.Kind() == "identifier" && !localVars[lhs.Text()] {
				lines = append(lines, assign.StartLine())
			}
		}
		// A malloc whose result is assigned directly to a non-local identifier
		// (`g = malloc()`) escapes at the allocation site itself.
		if lhs.Kind() == "identifier" && lhs.Text() == varName && !localVars[varName] && isMallocExpr(rhs, allocReturns) {
			lines = append(lines, assign.StartLine())
		}
		// A malloc assigned through a dereferenced non-local pointer
		// (`*root = malloc(...)`) escapes at the allocation site: the
		// caller owns the pointed-to object via the output parameter and
		// frees it elsewhere. A local base (`*local = malloc(...)`) still
		// leaks if never freed.
		if lhs.Kind() == "pointer_expression" && isMallocExpr(rhs, allocReturns) {
			base := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					base = child.Text()
					break
				}
			}
			if base != "" && base == varName && !localVars[base] {
				lines = append(lines, assign.StartLine())
			}
		}
		// A malloc assigned directly to a field/subscript of a NON-LOCAL base
		// (`state->in = malloc(...)` where state is a parameter) escapes into
		// the struct/array — the field is owned by the caller, which frees it
		// elsewhere (e.g. zlib's gz_state buffers freed by gzclose). A local
		// base (`local.field = malloc(...)`) still leaks if never freed.
		//
		// ML-14 tradeoff: this errs toward NO false positive for the common
		// caller-owned-field idiom. If a caller stores into the field but never
		// frees it, that leak is intra-procedurally invisible here — resolving
		// it requires interprocedural evidence that the field is (not) released
		// somewhere in the call graph, which is beyond the detector's scope.
		if (lhs.Kind() == "field_expression" || lhs.Kind() == "subscript_expression") && isMallocExpr(rhs, allocReturns) {
			base := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					base = child.Text()
					break
				}
			}
			// Only the tracked variable's own field store escapes it; an unrelated
			// `global->field = malloc()` must not suppress the leak of a different
			// local (`char *p = malloc(10); g->buf = malloc(20);`).
			if base != "" && base == varName && !localVars[base] {
				lines = append(lines, assign.StartLine())
			}
		}
	}
	if useEscapeFuncs {
		for _, call := range calls {
			if !funcLineRange(f, call.StartLine()) {
				continue
			}
			callName := extractCallName(call)
			if !apikb.IsEscapeFunction(callName) {
				continue
			}
			// Modeled transfers escape through the modeled argument only
			// (cJSON_AddItemToObject takes the item as arg 2, xmlAddChild as
			// arg 1 — the parent argument must not be dragged in). Unmodeled
			// escape-shaped helpers keep the any-argument match.
			_, argIdx, modeled := apikb.EscapeOwnership(callName)
			args := getCallArgs(call)
			matched := false
			if modeled {
				if argIdx < len(args) && argIdentifier(args[argIdx]) == varName {
					matched = true
				}
			} else {
				for _, arg := range args {
					if argIdentifier(arg) == varName {
						matched = true
						break
					}
				}
			}
			if matched {
				lines = append(lines, call.StartLine())
			}
		}
	}
	// Error-handling / comm ownership transfer (NAT production pattern):
	// `asprintf(&err_msg,...); return fail(error, err_msg, ...)` /
	// `return fail_nc_err(...)` / `return transapi_comm_with_vrp(..., path)`.
	// The external callee takes ownership of the message/path argument and
	// releases it. The shape is gated on "directly returned + the argument is
	// never used afterwards" so a framework fail that does NOT release cannot
	// silently swallow a real leak.
	if useEscapeFuncs {
		for _, call := range calls {
			if !funcLineRange(f, call.StartLine()) {
				continue
			}
			if !ownershipTakingErrorCall(call) {
				continue
			}
			for _, arg := range getCallArgs(call) {
				if argIdentifier(arg) == varName && !usedAfterLine(varName, call.StartLine(), f, ids) {
					lines = append(lines, call.StartLine())
					break
				}
			}
		}
	}
	// Callee-body evidence: a callee proven to store its idx-th parameter into
	// a non-local object takes ownership of that argument regardless of its
	// name. This is the precise complement to the naming heuristic
	// (IsEscapeFunction): `queue_write(m, ptr)` is an escape when queue_write's
	// body stores the pointer parameter into a non-local (`m->payload = p`),
	// even though the name carries no _put/_push/_queue/... token.
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		idxs := escapeFuncs[extractCallName(call)]
		if len(idxs) == 0 {
			continue
		}
		args := getCallArgs(call)
		for idx := range idxs {
			if idx < len(args) && argIdentifier(args[idx]) == varName {
				lines = append(lines, call.StartLine())
				break
			}
		}
	}
	return lines
}

// ownershipTakingErrorCall reports whether call is a directly-returned call
// to an error-handling / comm function whose name carries the semantics
// (fail / *_err* / *_comm* / *_send*).
func ownershipTakingErrorCall(call parser.Node) bool {
	if !callDirectlyReturned(call) {
		return false
	}
	lower := strings.ToLower(extractCallName(call))
	for _, tok := range []string{"fail", "_err", "_comm", "_send"} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// callDirectlyReturned reports whether call sits inside a return statement's
// value (possibly through casts/parentheses): `return fail(...)`.
func callDirectlyReturned(call parser.Node) bool {
	for p := call.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "return_statement":
			return true
		case "expression_statement", "compound_statement", "function_definition", "if_statement", "while_statement", "for_statement", "do_statement", "switch_statement":
			return false
		}
	}
	return false
}

// usedAfterLine reports whether varName appears anywhere in f after line.
func usedAfterLine(varName string, line int, f *db.Function, ids []parser.Node) bool {
	for _, id := range ids {
		if id.Text() == varName && funcLineRange(f, id.StartLine()) && id.StartLine() > line {
			return true
		}
	}
	return false
}

// containerEscapes reports whether a heap-allocated container variable escapes
// the function — returned to the caller, stored to a non-local identifier or
// field/subscript, or handed to an escape function — so a pointer stored through
// it (`*container = p`) escapes with the container's ownership rather than
// leaking on its own. A container that is merely freed at the end
// (`*c = p; free(c);`) does NOT free its members, so it does not escape p.
func containerEscapes(assigns, calls, returns []parser.Node, f *db.Function, base string, localVars map[string]bool) bool {
	if len(findReturnVarLines(base, returns, f)) > 0 {
		return true
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs, rhs := children[0], children[1]
		if argIdentifier(rhs) != base {
			continue
		}
		switch lhs.Kind() {
		case "identifier":
			if !localVars[lhs.Text()] {
				return true
			}
		case "field_expression", "subscript_expression":
			b := ""
			for _, child := range lhs.NamedChildren() {
				if child.Kind() == "identifier" {
					b = child.Text()
					break
				}
			}
			if b != "" && !localVars[b] {
				return true
			}
		}
	}
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		if !apikb.IsEscapeFunction(extractCallName(call)) {
			continue
		}
		for _, arg := range getCallArgs(call) {
			if argIdentifier(arg) == base {
				return true
			}
		}
	}
	return false
}
