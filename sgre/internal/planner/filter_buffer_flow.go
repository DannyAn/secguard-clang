package planner

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// BufferFlowFilter annotates buffer-overflow / out-of-bounds candidates with
// the diagnostic path the reviewer needs but the hint triple (buf@/cap@/idx@)
// cannot convey alone: WHERE the buffer is defined/allocated and WHERE the
// offending index / copy size originates. It is the CSA-style "small markers"
// ("here it is declared, here the value comes from, here the guard is missing,
// here it overflows") that turn a bare "there is an OOB" into a traceable
// defect. It never drops or re-tiers: it only fills evidence fields.
type BufferFlowFilter struct {
	store    db.Store
	parser   *parser.Parser
	logger   *log.Logger
	cfgCache *graph.CFGCache
}

func NewBufferFlowFilter(store db.Store, p *parser.Parser, logger *log.Logger) *BufferFlowFilter {
	return &BufferFlowFilter{store: store, parser: p, logger: logger}
}

func (f *BufferFlowFilter) SetCFGCache(c *graph.CFGCache) { f.cfgCache = c }
func (f *BufferFlowFilter) Name() string                  { return "buffer_flow" }

func (f *BufferFlowFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	if f.parser == nil || len(candidates) == 0 {
		return candidates, nil, nil
	}
	byFunc := make(map[int64][]Candidate)
	for _, c := range candidates {
		if c.Array != "" {
			byFunc[c.FunctionID] = append(byFunc[c.FunctionID], c)
		}
	}
	fnByID, fileByID := loadFuncFiles(ctx, f.store, candidateFuncIDs(byFunc))
	cache := newFileParseCache(f.parser)

	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if c.Array == "" {
			kept = append(kept, c)
			continue
		}
		fn := fnByID[c.FunctionID]
		if fn == nil {
			kept = append(kept, c)
			continue
		}
		file := fileByID[fn.FileID]
		if file == nil {
			kept = append(kept, c)
			continue
		}
		body, root := cache.get(file, fn)
		if body.Kind() != "compound_statement" {
			kept = append(kept, c)
			continue
		}
		useLine := c.Line
		c.BufferDefLine, c.BufferDefKind = findBufferDef(body, root, c.Array, useLine)
		if idx := c.Index; idx != "" {
			c.IndexOriginLine = findValueOrigin(body, idx, useLine)
		} else if idx := c.CopySize; idx != "" {
			c.IndexOriginLine = findValueOrigin(body, idx, useLine)
		} else if idx := c.SizeArgument; idx != "" {
			c.IndexOriginLine = findValueOrigin(body, idx, useLine)
		}
		kept = append(kept, c)
	}
	return kept, nil, nil
}

// findBufferDef locates the buffer's definition/declaration/allocation line and
// its kind ("array" local/file-scope declaration, "alloc" heap allocation,
// "field" struct member, "global" tree-wide fact with no local line). It mirrors
// findArraySize's scope rules loosely but only reports a line, never a verdict.
func findBufferDef(body, root parser.Node, arrName string, useLine int) (int, string) {
	name := strings.TrimSpace(arrName)
	// 1. Heap allocation: `name = malloc(N)` / `name = calloc(...)`.
	if alloc := findAllocLine(body, name, useLine); alloc > 0 {
		return alloc, "alloc"
	}
	// 2. Array declaration (local or file scope), innermost-scoped wins.
	if line := findArrayDeclLine(body, root, name, useLine); line > 0 {
		return line, "array"
	}
	// 3. Struct field: `obj->items[8]` — the array is declared as `int items[8]`
	// inside a struct (same file; a header-declared struct has no local line).
	field := name
	if i := strings.LastIndex(field, "->"); i >= 0 {
		field = strings.TrimSpace(field[i+2:])
	} else if i := strings.LastIndex(field, "."); i >= 0 {
		field = strings.TrimSpace(field[i+1:])
	}
	if line := findFieldDeclLine(root, field); line > 0 {
		return line, "field"
	}
	return 0, ""
}

func findAllocLine(body parser.Node, name string, useLine int) int {
	best := 0
	for _, node := range append(body.FindAll("assignment_expression"), body.FindAll("init_declarator")...) {
		lhs, rhs, ok := node.AssignParts()
		if !ok || assignTargetName(lhs) != name {
			continue
		}
		if rhs.Kind() == "cast_expression" {
			for _, c := range rhs.NamedChildren() {
				if c.Kind() == "call_expression" {
					rhs = c
					break
				}
			}
		}
		if rhs.Kind() != "call_expression" {
			continue
		}
		if callee := rhsCallName(rhs); callee != "" && isAllocName(callee) {
			if node.StartLine() <= useLine && node.StartLine() > best {
				best = node.StartLine()
			}
		}
	}
	return best
}

func isAllocName(name string) bool {
	switch name {
	case "malloc", "calloc", "realloc", "alloca", "strdup", "strndup",
		"xmalloc", "xcalloc", "zmalloc", "zalloc", "scalloc":
		return true
	}
	return strings.Contains(name, "alloc")
}

func findArrayDeclLine(body, root parser.Node, name string, useLine int) int {
	best := 0
	for _, scope := range []parser.Node{body, root} {
		if scope.Kind() == "" {
			continue
		}
		for _, decl := range scope.FindAll("declaration") {
			for _, ad := range decl.FindAll("array_declarator") {
				if flowDeclName(ad) != name {
					continue
				}
				// Only the declarator's own array (not a nested subscript type)
				// and only before the use.
				if decl.StartLine() > useLine {
					continue
				}
				if decl.StartLine() > best {
					best = decl.StartLine()
				}
			}
		}
	}
	return best
}

func findFieldDeclLine(root parser.Node, name string) int {
	for _, fd := range root.FindAll("field_declaration") {
		for _, ad := range fd.FindAll("array_declarator") {
			if flowDeclName(ad) == name {
				return fd.StartLine()
			}
		}
	}
	return 0
}

// flowDeclName extracts the name a declarator declares, accepting BOTH the
// ordinary `identifier` of a local/global declarator and the `field_identifier`
// tree-sitter uses for struct/union members (`int items[8]` inside a struct).
// declaratorName only recognises `identifier`, which silently missed struct
// field arrays — the exact shape of the field-index OOB flow path.
func flowDeclName(n parser.Node) string {
	if n.Kind() == "identifier" || n.Kind() == "field_identifier" {
		return n.Text()
	}
	for _, c := range n.NamedChildren() {
		if c.Kind() == "identifier" || c.Kind() == "field_identifier" {
			return c.Text()
		}
		if name := flowDeclName(c); name != "" {
			return name
		}
	}
	return ""
}

// findValueOrigin returns the line where a bare-identifier index/copy-size value
// last originates before useLine: its declaration or assignment. A compound
// expression (`n + 1`, `*p`) or a parameter returns 0 (origin outside this
// function / not a single site).
func findValueOrigin(body parser.Node, expr string, useLine int) int {
	v := strings.TrimSpace(expr)
	if v == "" || !isBareIdent(v) {
		return 0
	}
	best := 0
	for _, node := range body.FindAll("init_declarator") {
		if declaratorName(node) == v && node.StartLine() < useLine && node.StartLine() > best {
			best = node.StartLine()
		}
	}
	for _, node := range body.FindAll("assignment_expression") {
		lhs, _, ok := node.AssignParts()
		if ok && assignTargetName(lhs) == v && node.StartLine() < useLine && node.StartLine() > best {
			best = node.StartLine()
		}
	}
	return best
}
