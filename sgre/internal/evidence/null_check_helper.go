package evidence

import (
	"context"
	"strings"

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
func (d *NullGuardDetector) collectNullCheckHelpers(ctx context.Context) map[string][]int {
	out := make(map[string][]int)
	_ = forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
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
			if len(checked) > 0 {
				out[f.Name] = checked
			}
		}
	})
	return out
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
	return exprNullChecksParam(children[0], param)
}

// exprNullChecksParam recognizes `param == NULL` / `NULL == param` / `!param`
// anywhere inside expr, recursing through parenthesized / cast / conditional /
// binary-|| containers. A field access (`param->f`) is structurally distinct
// from an identifier and so never matches, which is what excludes
// `param->content == NULL` from counting as a null-check of param.
func exprNullChecksParam(expr parser.Node, param string) bool {
	if expr.Kind() == "binary_expression" && binaryOperator(expr) == "==" {
		var hasParam, hasNull bool
		for _, op := range expr.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				hasParam = true
			}
			if isNullOperand(op) {
				hasNull = true
			}
		}
		return hasParam && hasNull
	}
	if expr.Kind() == "unary_expression" && strings.HasPrefix(strings.TrimSpace(expr.Text()), "!") {
		for _, op := range expr.NamedChildren() {
			if op.Kind() == "identifier" && op.Text() == param {
				return true
			}
		}
		return false
	}
	for _, c := range expr.NamedChildren() {
		if exprNullChecksParam(c, param) {
			return true
		}
	}
	return false
}

// isNullOperand reports whether an operand of a `==` comparison is a null
// pointer constant (NULL / nullptr / 0 / ((void*)0)). tree-sitter-c parses
// `NULL` as a `null` literal node, distinct from a plain identifier.
func isNullOperand(op parser.Node) bool {
	switch op.Kind() {
	case "null":
		return true
	case "identifier":
		return op.Text() == "nullptr"
	case "number_literal":
		return op.Text() == "0"
	case "parenthesized_expression", "cast_expression":
		for _, c := range op.NamedChildren() {
			if isNullOperand(c) {
				return true
			}
		}
	}
	return false
}
