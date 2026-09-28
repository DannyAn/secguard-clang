package planner

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// heapStructFlow is the field-granularity definite-init dataflow for
// heap_uninit and struct_partial_uninit candidates. It is the planner-side
// mirror of the detector's scope heuristic, but on the real statement CFG, so a
// field read is dropped only when the field (or the whole block) is written on
// EVERY path to the read, and confirmed only when the malloc/declaration source
// reaches on every path with no intervening write on any path (UN-01/UN-06).
//
// Three lattices:
//   - mustSrc: the uninitialized source (malloc / uninit declaration) reaches on
//     every path (the must tier for "definitely uninitialized").
//   - mayInit: some write (field/whole) reaches on some path.
//   - mustInit: some write reaches on every path (the must tier for "definitely
//     initialized", used to drop).
type heapStructFlow struct {
	cfg         *graph.StmtCFG
	mustSrc     map[int]map[string]bool
	mustSrcGen  map[int]map[string]bool
	mayInit     map[int]map[string]map[int]bool
	mayInitGen  map[int]map[string]bool
	mustInit    map[int]map[string]bool
	mustInitGen map[int]map[string]bool
}

func (h *heapStructFlow) sourceOnEveryPath(v string, line int) bool {
	n := h.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if h.mustSrc[n.ID][v] {
		return true
	}
	return h.mustSrcGen[n.ID][v]
}

func (h *heapStructFlow) initOnAnyPath(v string, line int) bool {
	n := h.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if len(h.mayInit[n.ID][v]) > 0 {
		return true
	}
	return h.mayInitGen[n.ID][v]
}

func (h *heapStructFlow) initOnEveryPath(v string, line int) bool {
	n := h.cfg.NodeAt(line)
	if n == nil {
		return false
	}
	if h.mustInit[n.ID][v] {
		return true
	}
	return h.mustInitGen[n.ID][v]
}

// buildHeapStructFlow runs the source and init lattices over fn's statement CFG.
func buildHeapStructFlow(fn *db.Function, body parser.Node) *heapStructFlow {
	cfg := graph.BuildStmtCFG(body, fn.EndLine)
	srcEff := make(map[int]*nodeEffects, len(cfg.Nodes))
	initEff := make(map[int]*nodeEffects, len(cfg.Nodes))
	for _, n := range cfg.Nodes {
		if n.Kind != "stmt" {
			continue
		}
		se := newEffects()
		ie := newEffects()
		if n.Stmt.Kind() == "declaration" && isUninitDecl(n.Stmt) {
			for _, name := range declaredNames(n.Stmt) {
				se.gen[name] = true
			}
		}
		for _, p := range directAssignments(n.Stmt) {
			applyHeapStructAssign(se, ie, p.lhs, p.rhs)
		}
		for _, call := range n.Stmt.FindAll("call_expression") {
			applyHeapStructCall(se, ie, call)
		}
		srcEff[n.ID] = se
		initEff[n.ID] = ie
	}
	mustSrc, mustSrcGen := runMustDataflow(cfg, srcEff, nil)
	mayInit := runDataflow(cfg, initEff, nil, nil)
	mayInitGen := genAt(cfg, initEff)
	mustInit, mustInitGen := runMustDataflow(cfg, initEff, nil)
	return &heapStructFlow{
		cfg:         cfg,
		mustSrc:     mustSrc,
		mustSrcGen:  mustSrcGen,
		mayInit:     mayInit,
		mayInitGen:  mayInitGen,
		mustInit:    mustInit,
		mustInitGen: mustInitGen,
	}
}

func newEffects() *nodeEffects {
	return &nodeEffects{
		gen:      map[string]bool{},
		kill:     map[string]bool{},
		copy:     map[string]string{},
		killBase: map[string]bool{},
	}
}

// applyHeapStructAssign folds one direct (lhs = rhs) assignment into the source
// (se) and init (ie) lattices.
func applyHeapStructAssign(se, ie *nodeEffects, lhs, rhs parser.Node) {
	switch lhs.Kind() {
	case "identifier", "pointer_declarator", "array_declarator", "function_declarator":
		v := assignBaseName(lhs)
		if v == "" {
			return
		}
		if name := rhsCallName(rhs); name != "" && apikb.IsAllocator(name) {
			if isZeroInitAllocName(name) {
				// calloc: the block is born zero-initialized.
				se.kill[v] = true
				se.killBase[v] = true
				ie.gen[v] = true
			} else {
				// malloc/realloc: a new uninitialized block.
				se.gen[v] = true
				ie.kill[v] = true
				ie.killBase[v] = true
			}
			return
		}
		// Non-allocator reassignment. For a struct this is a whole assign
		// (`s = other`); for a heap pointer it is a redirect (`p = &x`) that
		// abandons the allocated block. Both kill the uninitialized source. The
		// init gen (whole init) is what the struct case needs to drop a
		// conditional whole-assign; for a heap pointer the detector already drops
		// every candidate after a redirect, so the gen is inert there.
		se.kill[v] = true
		se.killBase[v] = true
		ie.gen[v] = true
	case "pointer_expression":
		// `*p = v` writes the whole pointed-to object. `*p->f = v` writes through
		// a pointer field (not the block p), so derefWholeBase returns "" for it.
		if base := derefWholeBase(lhs); base != "" {
			se.kill[base] = true
			se.killBase[base] = true
			ie.gen[base] = true
		}
	case "field_expression", "subscript_expression":
		// `p->f = v` / `s.f = v` / `p[i] = v` initializes that member/element.
		ie.gen[lhs.Text()] = true
	}
}

// applyHeapStructCall folds a memset/bzero/dest-writer call into the lattices.
// The four arg-0 shapes (identifier, field, subscript, &field) are unified
// through destWriteTargetName so memcpy_s(&p->f, ...) and memset_s(p->f, ...)
// are both recognized as member writes — previously the memset_s case only
// handled &p->f and the isDestWriter default only handled bare p->f, so each
// function had a blind spot (UN-15).
func applyHeapStructCall(se, ie *nodeEffects, call parser.Node) {
	name := callName(call)
	args := callArgs(call)
	if len(args) == 0 {
		return
	}
	if !isDestWriterName(name) {
		return
	}
	base, fieldText, whole := destWriteTargetName(args[0])
	if whole {
		// memset/memset_s/bzero with a sizeof count zeroes the whole block;
		// a fixed byte count is partial and must not count as whole init.
		if name == "memset" || name == "memset_s" || name == "bzero" {
			if len(args) >= 3 && wholeObjectSize(args[2]) {
				se.kill[base] = true
				se.killBase[base] = true
				ie.gen[base] = true
			}
		}
		return
	}
	if fieldText != "" {
		ie.gen[fieldText] = true
	}
}

// destWriteTargetName resolves the write target of a dest-writer call's first
// argument for the planner lattice. It returns (base, fieldText, whole) where
// fieldText is the full access text for a field/subscript write (for ie.gen)
// and base is the whole-variable name (for se.kill). This mirrors the
// detector-side destWriteTarget in evidence/uninit_variable.go (UN-15).
func destWriteTargetName(arg parser.Node) (base, fieldText string, whole bool) {
	switch arg.Kind() {
	case "identifier":
		return arg.Text(), "", true
	case "field_expression", "subscript_expression":
		return "", arg.Text(), false
	case "pointer_expression":
		children := arg.NamedChildren()
		if len(children) == 0 {
			return "", "", false
		}
		inner := children[0]
		switch inner.Kind() {
		case "field_expression", "subscript_expression":
			return "", inner.Text(), false
		case "identifier":
			return inner.Text(), "", true
		}
	}
	return "", "", false
}

func derefWholeBase(lhs parser.Node) string {
	if lhs.Kind() != "pointer_expression" {
		return ""
	}
	if !strings.HasPrefix(strings.TrimSpace(lhs.Text()), "*") {
		return "" // `&p` is address-of, not a write target
	}
	children := lhs.NamedChildren()
	if len(children) > 0 && children[0].Kind() == "identifier" {
		return children[0].Text()
	}
	return ""
}

func addressTakenFieldPath(arg parser.Node) string {
	if arg.Kind() != "pointer_expression" {
		return ""
	}
	if !strings.HasPrefix(strings.TrimSpace(arg.Text()), "&") {
		return ""
	}
	children := arg.NamedChildren()
	if len(children) > 0 && (children[0].Kind() == "field_expression" || children[0].Kind() == "subscript_expression") {
		return children[0].Text()
	}
	return ""
}

func isZeroInitAllocName(name string) bool {
	return strings.Contains(strings.ToLower(name), "calloc")
}

func wholeObjectSize(arg parser.Node) bool {
	for arg.Kind() == "parenthesized_expression" {
		ch := arg.NamedChildren()
		if len(ch) == 0 {
			return false
		}
		arg = ch[0]
	}
	return arg.Kind() == "sizeof_expression"
}

var destWriterNames = map[string]bool{
	"memset": true, "memset_s": true, "bzero": true,
	"strcpy": true, "strcpy_s": true, "strncpy": true, "strncpy_s": true,
	"strlcpy": true, "stpncpy": true, "mempcpy": true,
	"memcpy": true, "memcpy_s": true, "memmove": true, "memmove_s": true,
	"sprintf": true, "sprintf_s": true, "snprintf": true, "snprintf_s": true,
	"vsprintf": true, "vsprintf_s": true, "vsnprintf": true, "vsnprintf_s": true,
}

func isDestWriterName(name string) bool { return destWriterNames[name] }
