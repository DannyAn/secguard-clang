package graph

import (
	"github.com/kongan/secguard-lite/internal/parser"
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

func BuildCFG(root parser.Node, funcStart, funcEnd int) *CFG {
	scopeRoot := &Scope{StartLine: funcStart, EndLine: funcEnd}
	cfg := &CFG{Root: scopeRoot}
	cfg.buildScopes(root, scopeRoot, funcStart, funcEnd)
	return cfg
}

func (cfg *CFG) buildScopes(root parser.Node, parent *Scope, start, end int) {
	ifNodes := root.FindAll("if_statement")
	for _, ifNode := range ifNodes {
		if ifNode.StartLine() < start || ifNode.EndLine() > end {
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
			cfg.buildScopes(consNode, consScope, consScope.StartLine, consScope.EndLine)
		}

		if hasAlt {
			altScope := &Scope{
				StartLine: altNode.StartLine(),
				EndLine:   altNode.EndLine(),
				Parent:    parent,
			}
			altScope.HasExit, altScope.ExitLine = hasEarlyExit(altNode)
			parent.Children = append(parent.Children, altScope)
			cfg.buildScopes(altNode, altScope, altScope.StartLine, altScope.EndLine)
		}
	}

	for _, loopKind := range []string{"for_statement", "while_statement", "do_statement"} {
		for _, loopNode := range root.FindAll(loopKind) {
			if loopNode.StartLine() < start || loopNode.EndLine() > end {
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
					cfg.buildScopes(child, loopScope, loopScope.StartLine, loopScope.EndLine)
				}
			}
		}
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
