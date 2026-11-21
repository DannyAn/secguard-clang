package evidence

import (
	"context"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// collectNullCheckHelpers gathers, across the whole scan tree, the "null-check
// predicate" functions: a function whose body returns true when one of its
// pointer parameters is NULL — `bool is_empty(T *p) { return p == NULL || ...; }`.
// A caller `if (is_empty(x)) { goto/return; }` therefore establishes x != NULL
// on the fall-through path. The helper's definition may live in the same .c
// (a private sub-function) or in a .h header (a static inline) — both are
// indexed as Functions, so a single cross-file pass covers both sources.
// Returns map[function name] -> 0-based parameter indices the function null-checks.
func (d *NullGuardDetector) collectNullCheckHelpers(ctx context.Context, result *DetectResult) (map[string][]int, error) {
	out := make(map[string][]int)
	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		funcDefs := root.FindAll("function_definition")
		returns := root.FindAll("return_statement")
		for _, f := range funcs {
			params := extractFunctionParamsFrom(funcDefs, f.StartLine)
			if len(params) == 0 {
				continue
			}
			seen := make(map[int]bool)
			for _, ret := range returns {
				if !funcLineRange(f, ret.StartLine()) {
					continue
				}
				for i, pn := range params {
					if pn == "" || seen[i] {
						continue
					}
					if returnNullChecksParam(ret, pn) {
						seen[i] = true
					}
				}
			}
			var checked []int
			for i := range seen {
				checked = append(checked, i)
			}
			if len(checked) == 0 {
				continue
			}
			out[f.Name] = checked
			// The helper null-checks these parameters before any deref inside
			// its body (the `p == NULL || p->f ...` short-circuit), so record a
			// NULL_GUARD for each inside the helper itself. The interprocedural
			// null-deref detector reads the callee's NULL_GUARD events to decide
			// whether a dereferenced parameter is guarded: without this, a
			// caller's `if (is_empty(p)) goto out;` call site is misreported as a
			// null-deref of p even though the helper null-checks p first.
			for _, i := range checked {
				if i >= len(params) || params[i] == "" {
					continue
				}
				if emitEvent(ctx, d.store, d.logger, "NULL_GUARD", f.ID, &db.Location{FileID: file.ID, Line: f.StartLine}, map[string]interface{}{
					"variable":    params[i],
					"condition":   "HELPER_PARAM",
					"scope_start": f.StartLine,
					"scope_end":   f.EndLine,
				}) {
					result.EventsCreated++
				}
			}
		}
	})
	return out, err
}

// returnNullChecksParam reports whether a return statement's expression
// null-checks param: `return param == NULL || ...`, `return !param || ...`,
// or the same wrapped in `( ... ) ? true : false`. A field comparison
// (`param->f == NULL`) does NOT count — only a whole-variable null test of
// param itself, since that is what establishes param != NULL on the negation.
func returnNullChecksParam(ret parser.Node, param string) bool {
	children := ret.NamedChildren()
	if len(children) == 0 {
		return false
	}
	return parser.ExprNullChecksParam(children[0], param)
}
