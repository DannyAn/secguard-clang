package planner

import (
	"context"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// callSiteResolver collects, per function name, the argument texts of every
// direct call site across the project. It powers the divide-by-zero parameter
// zero-propagation: a divisor that is a function PARAMETER is traced to its
// callers to see whether any passes a literal zero (a certain divide-by-zero) or
// every caller passes a provably non-zero constant (safe). This is the
// semantic-graph (CALL + positional argument) step that the function-local
// interval analysis cannot see.
type callSiteResolver struct {
	callsByName map[string][][]string
}

func newCallSiteResolver(ctx context.Context, store db.Store, p *parser.Parser) *callSiteResolver {
	r := &callSiteResolver{callsByName: map[string][][]string{}}
	files, err := store.ListFiles(ctx)
	if err != nil {
		return r
	}
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		for _, call := range tree.RootNode().FindAll("call_expression") {
			name := callName(call)
			if name == "" {
				continue
			}
			args := callArgs(call)
			texts := make([]string, 0, len(args))
			for _, a := range args {
				texts = append(texts, a.Text())
			}
			r.callsByName[name] = append(r.callsByName[name], texts)
		}
	}
	return r
}

// paramVerdict reports, for a function name and a positional parameter index,
// whether SOME direct call passes a literal zero (zeroReachable) and whether
// EVERY direct call passes a provably non-zero constant (allNonZero). No call
// sites yields (false, false) — unknown, so the caller keeps the conservative
// "possibly zero" verdict.
func (r *callSiteResolver) paramVerdict(name string, index int) (zeroReachable, allNonZero bool) {
	sites := r.callsByName[name]
	if len(sites) == 0 {
		return false, false
	}
	allNonZero = true
	for _, args := range sites {
		if index >= len(args) {
			allNonZero = false
			continue
		}
		arg := strings.TrimSpace(args[index])
		if parser.IsZeroConstantValue(arg) {
			zeroReachable = true
		}
		if !parser.NonZeroConstantValue(arg) {
			allNonZero = false
		}
	}
	return zeroReachable, allNonZero
}
