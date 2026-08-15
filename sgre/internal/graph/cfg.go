package graph

import (
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type Scope struct {
	StartLine int
	EndLine   int
	HasExit   bool
	ExitLine  int
	Children  []*Scope
	Parent    *Scope
}

type CFG struct {
	Root *Scope
}

// BuildCFG builds a coarse, line-number-based control-flow approximation. It
// only descends into `if`/loop bodies that have a compound_statement child, so
// flat functions (no block-scoped branch bodies) yield a CFG whose Root has no
// children. Callers treat that as "degenerate" and fall back to a conservative
// path-insensitive decision rather than trusting CanReach.
//
// It collects the if/loop nodes with whole-tree FindAll calls and delegates to
// BuildCFGFromLists. Callers that already hold those nodes (e.g. a detector
// looping many functions in one file) should call BuildCFGFromLists directly
// to avoid one whole-tree FindAll per function.
func BuildCFG(root parser.Node, funcStart, funcEnd int) *CFG {
	return BuildCFGFromLists(funcStart, funcEnd,
		root.FindAll("if_statement"),
		root.FindAll("while_statement"),
		root.FindAll("for_statement"),
		root.FindAll("do_statement"))
}

// BuildCFGFromLists builds the same coarse CFG as BuildCFG, but from
// pre-collected if/while/for/do nodes shared across functions in a file. It
// filters each list by line range at the top level and by byte containment in
// recursion instead of running a whole-tree FindAll per function, which was
// the dominant uninit-detector cost (one full-file walk per function per
// control-flow kind).
func BuildCFGFromLists(funcStart, funcEnd int, ifs, whiles, fors, dos []parser.Node) *CFG {
	scopeRoot := &Scope{StartLine: funcStart, EndLine: funcEnd}
	cfg := &CFG{Root: scopeRoot}
	inside := func(n parser.Node) bool {
		return n.StartLine() >= funcStart && n.EndLine() <= funcEnd
	}
	cfg.buildScopes(scopeRoot, ifs, whiles, fors, dos, inside)
	return cfg
}

// buildScopes selects control-flow nodes matching `inside` and descends into
// their branch bodies. The predicate uses line ranges at the top level and
// byte containment in recursion: a branch body (compound_statement) starts
// strictly after its enclosing if/loop keyword, so byte containment never
// re-selects the enclosing node — the recursion cannot self-loop the way a
// line-range-only filter can when `{` shares a line with the `if` keyword.
func (cfg *CFG) buildScopes(parent *Scope, ifs, whiles, fors, dos []parser.Node, inside func(parser.Node) bool) {
	for _, ifNode := range ifs {
		if !inside(ifNode) {
			continue
		}

		var consNode, altNode parser.Node
		hasCons, hasAlt := false, false
		for _, child := range ifNode.NamedChildren() {
			if child.Kind() == "compound_statement" || child.Kind() == "expression_statement" {
				if !hasCons {
					consNode = child
					hasCons = true
				} else {
					altNode = child
					hasAlt = true
				}
			}
		}

		if hasCons {
			consScope := &Scope{
				StartLine: consNode.StartLine(),
				EndLine:   consNode.EndLine(),
				Parent:    parent,
			}
			consScope.HasExit, consScope.ExitLine = hasEarlyExit(consNode)
			parent.Children = append(parent.Children, consScope)
			cfg.buildScopes(consScope, ifs, whiles, fors, dos, within(consNode))
		}

		if hasAlt {
			altScope := &Scope{
				StartLine: altNode.StartLine(),
				EndLine:   altNode.EndLine(),
				Parent:    parent,
			}
			altScope.HasExit, altScope.ExitLine = hasEarlyExit(altNode)
			parent.Children = append(parent.Children, altScope)
			cfg.buildScopes(altScope, ifs, whiles, fors, dos, within(altNode))
		}
	}

	for _, loopList := range [][]parser.Node{whiles, fors, dos} {
		for _, loopNode := range loopList {
			if !inside(loopNode) {
				continue
			}
			for _, child := range loopNode.NamedChildren() {
				if child.Kind() == "compound_statement" {
					loopScope := &Scope{
						StartLine: child.StartLine(),
						EndLine:   child.EndLine(),
						Parent:    parent,
					}
					loopScope.HasExit, loopScope.ExitLine = hasEarlyExit(child)
					parent.Children = append(parent.Children, loopScope)
					cfg.buildScopes(loopScope, ifs, whiles, fors, dos, within(child))
				}
			}
		}
	}
}

// within reports whether node lies strictly inside the byte range of scopeNode,
// i.e. it is a descendant (or the node itself) of scopeNode. It is the hoisted
// replacement for scopeNode.FindAll(kind): byte containment, unlike line
// containment, excludes the enclosing if/loop whose body scopeNode is.
func within(scopeNode parser.Node) func(parser.Node) bool {
	start, end := scopeNode.StartByte(), scopeNode.EndByte()
	return func(n parser.Node) bool {
		return n.StartByte() >= start && n.EndByte() <= end
	}
}

func hasEarlyExit(scopeNode parser.Node) (bool, int) {
	for _, ret := range scopeNode.FindAll("return_statement") {
		return true, ret.StartLine()
	}
	for _, brk := range scopeNode.FindAll("break_statement") {
		return true, brk.StartLine()
	}
	for _, cont := range scopeNode.FindAll("continue_statement") {
		return true, cont.StartLine()
	}
	return false, 0
}

func (s *Scope) Contains(line int) bool {
	return line >= s.StartLine && line <= s.EndLine
}

func (cfg *CFG) findInnermostScope(line int) *Scope {
	return cfg.Root.findInnermost(line)
}

func (cfg *CFG) FindInnermostScope(line int) *Scope {
	return cfg.findInnermostScope(line)
}

func (s *Scope) findInnermost(line int) *Scope {
	for _, child := range s.Children {
		if child.Contains(line) {
			return child.findInnermost(line)
		}
	}
	return s
}

// CanReach answers whether a use at useLine can be reached from a free/early
// exit at freeLine using only line ranges and the presence of a return/break/
// continue inside the innermost scope. It is a conservative line-order
// heuristic, not a real dataflow: it defaults to "reachable" whenever it cannot
// prove otherwise, so a degenerate CFG never causes a true leak to be dropped.
func (cfg *CFG) CanReach(freeLine, useLine int) bool {
	freeScope := cfg.findInnermostScope(freeLine)

	if freeScope.HasExit && !freeScope.Contains(useLine) {
		return false
	}

	if freeScope.HasExit && freeScope.Contains(useLine) && useLine > freeScope.ExitLine {
		return false
	}

	return true
}
