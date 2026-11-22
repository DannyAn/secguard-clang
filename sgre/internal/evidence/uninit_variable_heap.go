package evidence

import (
	"context"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// heapWriterEvidence records the earliest in-tree callee that writes a
// malloc'd block only on some paths, and whose return the caller does not guard.
type heapWriterEvidence struct {
	line   int
	callee string
}

// heapUninitFacts bundles the "collect" facts (tracked allocations and
// interprocedural conditional writers) with the "compute" write-path state
// that decides whether a heap read is uninitialized.
type heapUninitFacts struct {
	mallocVars        map[string]int
	mallocAllocator   map[string]string
	mallocDeclsByName map[string][]varDecl
	conditionalWriter map[string]heapWriterEvidence
	conditionalWhole  map[string]bool
	conditionalFields map[string]bool
	wholeInit         map[string]bool
	initializedFields map[string]bool
	contentInitFields map[string]bool
	writePaths        map[string]bool
	heapFieldWritten  map[string]bool
}

func (h *heapUninitFacts) resolve(name string, line int) string {
	return resolveVarKey(h.mallocDeclsByName, name, line)
}

// scopedPath replaces the bare base in a full access text with the scoped key
// so `p->f` on the `p` malloc'd at line L becomes `p@L->f`.
func (h *heapUninitFacts) scopedPath(key, bareBase, full string) string {
	if !strings.HasPrefix(full, bareBase) {
		return full
	}
	return key + full[len(bareBase):]
}

// heapInit returns the write-path fact for a heap read: a conditional
// out-param writer that runs BEFORE the read is the evidence tier ("cond");
// a conditional in-function write to the same target is a real may-skip
// branch ("branch"); otherwise the weak "none" tier.
func (h *heapUninitFacts) heapInit(key string, line int, path string, whole bool) (initWrite string, initLine int, writer string) {
	if w, ok := h.conditionalWriter[key]; ok && w.line < line {
		return "cond", w.line, w.callee
	}
	if whole && h.conditionalWhole[key] {
		return "branch", 0, ""
	}
	if path != "" && h.conditionalFields[path] {
		return "branch", 0, ""
	}
	return "none", 0, ""
}

func (d *UninitVariableDetector) detectHeapUninit(ctx context.Context, in *uninitScanInputs) {
	facts := d.collectHeapUninitFacts(in)
	d.computeHeapUninitWrites(in, facts)
	d.emitHeapUninitUses(ctx, in, facts)
}

func (d *UninitVariableDetector) collectHeapUninitFacts(in *uninitScanInputs) *heapUninitFacts {
	f := in.f
	decls, inits, assigns, calls := in.decls, in.inits, in.assigns, in.calls
	ifs, summaries := in.ifs, in.summaries
	// Scope-aware tracking (UN-04): mallocVars and every per-variable fact are
	// keyed by varKey(name@declLine) so two `p` in nested blocks no longer
	// collide — the previous bare-name maps let one scope's whole-init hide the
	// other scope's genuinely-uninitialized block. A `p = malloc()` ASSIGNMENT
	// adopts the DECLARATION's scope, so a conditional malloc (`if (c) p = ...`)
	// still reaches a use after the branch.
	mallocVars := make(map[string]int)         // varKey -> line of the malloc assignment
	mallocAllocator := make(map[string]string) // varKey -> allocator callee name
	mallocDeclsByName := make(map[string][]varDecl)
	declByName := localVarDecls(decls)

	checkInit := func(node parser.Node) {
		lhs, rhs, ok := node.AssignParts()
		if !ok {
			return
		}
		varName := extractVarName(lhs)
		if varName == "" {
			return
		}
		callExpr := rhs
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					callExpr = child
					break
				}
			}
		}
		if callExpr.Kind() == "call_expression" {
			callName := extractCallName(callExpr)
			// calloc (and calloc-family wrappers) ZERO-INITIALIZE the block, so a
			// read of it is never an uninitialized-read — exclude it from the
			// heap-uninit candidate set (UN-11). malloc/realloc leave the memory
			// uninitialized and are tracked.
			if apikb.IsAllocator(callName) && !isZeroInitAllocator(callName) {
				var key string
				var decl varDecl
				if node.Kind() == "init_declarator" {
					// `S *p = malloc(...)` declares p here.
					declLine := node.StartLine()
					if p := node.Parent(); p != nil && p.Kind() == "declaration" {
						declLine = p.StartLine()
					}
					decl = varDecl{name: varName, declLine: declLine, scopeEnd: enclosingScopeEnd(node)}
					key = varKey(varName, declLine)
				} else if d, ok := resolveVarDecl(declByName, varName, node.StartLine()); ok {
					// `p = malloc(...)` writes a variable declared earlier; adopt
					// the declaration's scope, not the assignment's.
					decl = d
					key = varKey(varName, d.declLine)
				} else {
					// Parameter or externally-scoped pointer: function scope.
					decl = varDecl{name: varName, declLine: f.StartLine, scopeEnd: f.EndLine}
					key = varKey(varName, f.StartLine)
				}
				mallocVars[key] = node.StartLine()
				mallocAllocator[key] = callName
				mallocDeclsByName[varName] = append(mallocDeclsByName[varName], decl)
			}
		}
	}

	for _, init := range inits {
		if !funcLineRange(f, init.StartLine()) {
			continue
		}
		checkInit(init)
	}
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		checkInit(assign)
	}

	// resolve maps a bare name at a line to the innermost malloc'd varKey in scope.
	resolve := func(name string, line int) string {
		return resolveVarKey(mallocDeclsByName, name, line)
	}

	// conditionalWriter maps a malloc varKey to the earliest in-tree callee that
	// writes the block only on SOME paths (its early return leaves the storage
	// unwritten) and whose return the caller does not guard. That is the
	// interprocedural conditional-uninit evidence: the read can happen on the
	// callee's error path, where the block was never written. Without it the
	// heap read is just the weak `init@unseen` tier (no in-function write found,
	// but a factory/memset may have initialized it) and is pre-dismissed by the
	// planner's weak-tier filter. A GUARDED call is not evidence: the success
	// continuation runs after the callee wrote the output.
	conditionalWriter := map[string]heapWriterEvidence{}
	if summaries != nil {
		for _, call := range calls {
			if !funcLineRange(f, call.StartLine()) {
				continue
			}
			callName := extractCallName(call)
			summary := summaries[callName]
			if summary == nil || len(summary.ParamConditionalWrites) == 0 {
				continue
			}
			if outputParamGuardLine(ifs, f, call, callName) != 0 {
				continue
			}
			for argIdx, arg := range getCallArgs(call) {
				if summary.ParamWrites[argIdx] || !summary.ParamConditionalWrites[argIdx] {
					continue
				}
				name := barePointerArg(arg)
				if name == "" {
					continue
				}
				key := resolve(name, call.StartLine())
				if key == "" {
					continue
				}
				if _, ok := mallocVars[key]; !ok {
					continue
				}
				if cur, seen := conditionalWriter[key]; !seen || call.StartLine() < cur.line {
					conditionalWriter[key] = heapWriterEvidence{line: call.StartLine(), callee: callName}
				}
			}
		}
	}

	return &heapUninitFacts{
		mallocVars:        mallocVars,
		mallocAllocator:   mallocAllocator,
		mallocDeclsByName: mallocDeclsByName,
		conditionalWriter: conditionalWriter,
	}
}

func (d *UninitVariableDetector) computeHeapUninitWrites(in *uninitScanInputs, facts *heapUninitFacts) {
	f := in.f
	assigns, calls := in.assigns, in.calls
	mallocVars, mallocAllocator := facts.mallocVars, facts.mallocAllocator
	resolve := facts.resolve
	scopedPath := facts.scopedPath
	// Conditional in-function writes (inside an if/loop body) do not dominate
	// the read, but they are real write paths: a read after `if (c) p->len = 1;`
	// is uninitialized on the c==0 path. Track them separately from the
	// definite (straight-line) writes so the tier is not the weak
	// "never written" init@unseen claim.
	conditionalWhole := map[string]bool{}
	conditionalFields := map[string]bool{}

	// A whole-var reassignment after the malloc (p = &x, p = other) redirects p
	// away from the allocated memory, so p is no longer an "uninitialized heap
	// block". A re-malloc (p = malloc(...) again) keeps it allocated.
	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		if lhs.Kind() != "identifier" {
			continue
		}
		key := resolve(lhs.Text(), assign.StartLine())
		mallocLine, isMalloc := mallocVars[key]
		if !isMalloc || assign.StartLine() <= mallocLine {
			continue
		}
		rhs := children[1]
		if rhs.Kind() == "cast_expression" {
			for _, child := range rhs.NamedChildren() {
				if child.Kind() == "call_expression" {
					rhs = child
					break
				}
			}
		}
		if rhs.Kind() == "call_expression" {
			if n := extractCallName(rhs); apikb.IsAllocator(n) {
				mallocVars[key] = assign.StartLine()
				mallocAllocator[key] = n
				continue
			}
		}
		delete(mallocVars, key)
	}

	// Field-sensitive initialization: the previous all-or-nothing
	// writtenThroughPtr flag let a single member write (`p->status = 1`) suppress
	// every later read of p, including a genuinely-uninitialized member
	// (`p->len`). Track per-member writes and whole-block initialization
	// separately so a read is reported only when THAT member (or the whole block)
	// has no write on any path.
	wholeInit := make(map[string]bool)         // varKey -> whole block initialized
	initializedFields := make(map[string]bool) // scoped field path -> written
	// contentInitFields records scoped field paths whose CONTENT is provably
	// written (dest-writer copy `memcpy(p->f, ...)`, scalar member assignment
	// `p->f = 0`). A pointer-only assignment `p->f = malloc(...)` defines the
	// pointer value but leaves the pointed-to block uninitialized, so it is
	// deliberately NOT recorded here: an element read `p->f[0]` right after a
	// bare malloc stays a genuine uninitialized read.
	contentInitFields := make(map[string]bool)
	writePaths := make(map[string]bool)       // scoped field write-target paths
	heapFieldWritten := make(map[string]bool) // varKey -> has any member write

	markField := func(base, path string) {
		initializedFields[path] = true
		heapFieldWritten[base] = true
	}

	// A write inside a runtime branch (if/else body, loop body) is NOT a definite
	// initialization — it happens on only some paths. Only a straight-line
	// (unconditional) write suppresses a later read here; a conditional write
	// leaves the read reported and the planner's CFG must-analysis drops it only
	// when the write covers every path (UN-06). A loop init/condition write runs
	// on every path, so it stays unconditional.
	uncond := func(n parser.Node) bool { return !isConditionalNode(n) }

	for _, assign := range assigns {
		if !funcLineRange(f, assign.StartLine()) {
			continue
		}
		children := assign.NamedChildren()
		if len(children) < 2 {
			continue
		}
		lhs := children[0]
		if !uncond(assign) {
			// Conditional write: record it as a may-skip branch fact so the
			// read after it is not mislabeled the weak "never written" tier.
			switch lhs.Kind() {
			case "field_expression", "subscript_expression":
				if base := fieldBaseName(lhs); base != "" {
					if key := resolve(base, assign.StartLine()); key != "" {
						if _, ok := mallocVars[key]; ok {
							conditionalFields[scopedPath(key, base, lhs.Text())] = true
							conditionalFields[scopedPath(key, base, fieldPath(lhs))] = true
						}
					}
				}
			case "pointer_expression":
				if name := extractVarName(lhs); name != "" {
					if key := resolve(name, assign.StartLine()); key != "" {
						if _, ok := mallocVars[key]; ok {
							conditionalWhole[key] = true
						}
					}
				}
			}
			continue
		}
		switch lhs.Kind() {
		case "field_expression", "subscript_expression":
			base := fieldBaseName(lhs)
			if base == "" {
				continue
			}
			key := resolve(base, assign.StartLine())
			if key == "" {
				continue
			}
			if _, ok := mallocVars[key]; !ok {
				continue
			}
			// Key by the FULL access text, preserving a subscript index: writing
			// `p[0]` initializes element 0 only, so a later read of `p[1]` (a
			// different element) must stay reported (UN-15).
			markField(key, scopedPath(key, base, lhs.Text()))
			for _, p := range fieldWritePaths(lhs) {
				writePaths[scopedPath(key, base, p)] = true
			}
			// A non-allocator field assignment (`p->f = 0`, `p->f = q`) writes
			// the member content at field granularity, so it covers a later
			// subscript read `p->f[i]` too. `p->f = malloc(...)` only defines
			// the pointer value and must NOT cover it (UN-05 field shape). An
			// element write `p->f[i] = x` stays element-granular (UN-15).
			if lhs.Kind() == "field_expression" && !rhsAllocates(children[1]) {
				contentInitFields[scopedPath(key, base, fieldPath(lhs))] = true
			}
		case "pointer_expression":
			// `*p = other` writes the whole pointed-to object.
			name := extractVarName(lhs)
			if name != "" {
				if key := resolve(name, assign.StartLine()); key != "" {
					if _, ok := mallocVars[key]; ok {
						wholeInit[key] = true
					}
				}
			}
		}
	}

	// memset(p, 0, sizeof(*p)) zeroes the whole block; memset(&p->f, ...) zeroes
	// one member; a dest-writer (memcpy_s/strcpy_s/strncpy_s/...) whose first
	// argument is a member or &member fills that member. The four arg-0 shapes
	// (identifier, field, subscript, &field) are unified through destWriteTarget
	// so memcpy_s(&p->f, ...) and memset_s(p->f, ...) are both recognized as
	// writes — previously the memset_s case only handled &p->f and the isDestWriter
	// default only handled bare p->f, so each function had a blind spot (UN-15).
	for _, call := range calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		name := extractCallName(call)
		if !uncond(call) {
			// A conditional dest-writer (memset/memcpy/strcpy_s) initializes
			// the target only on its branch — same may-skip fact as a plain
			// conditional assignment.
			if isDestWriter(name) || destWriterArgs[name] != nil {
				if args := getCallArgs(call); len(args) > 0 {
					if target, ok := destWriterTargetArg(name, args); ok {
						if base, path, whole := destWriteTarget(target); base != "" {
							if key := resolve(base, call.StartLine()); key != "" {
								if _, ok := mallocVars[key]; ok {
									if whole {
										conditionalWhole[key] = true
									} else {
										conditionalFields[scopedPath(key, base, path)] = true
									}
								}
							}
						}
					}
				}
			}
			continue
		}
		if !isDestWriter(name) && destWriterArgs[name] == nil {
			continue
		}
		args := getCallArgs(call)
		if len(args) == 0 {
			continue
		}
		target, ok := destWriterTargetArg(name, args)
		if !ok {
			continue
		}
		base, path, whole := destWriteTarget(target)
		if base == "" {
			continue
		}
		key := resolve(base, call.StartLine())
		if key == "" {
			continue
		}
		if _, ok := mallocVars[key]; !ok {
			continue
		}
		if whole {
			// memset/memset_s/bzero with a sizeof count zeroes the whole block;
			// a fixed byte count is partial and must not count as whole init.
			if name == "memset" || name == "memset_s" || name == "bzero" {
				if len(args) >= 3 && sizeIsWholeObject(args[2]) {
					wholeInit[key] = true
				}
			} else if destWriterArgs[name] != nil {
				// An I/O writer from destWriterArgs (read/recv/fread/...)
				// filling the whole buffer by its indexed argument initializes
				// the block; without this the filled block kept producing
				// heap_uninit candidates the AI had to dismiss (issue #263).
				wholeInit[key] = true
			}
		} else {
			// A copy/init call writes the member's CONTENT at field granularity
			// (`memcpy(p->f, ...)` fills the buffer the field points at), so it
			// also covers a later subscript read `p->f[i]` — the element read
			// used to key on the full subscript text and never matched this
			// field-level write, so a memcpy-filled member was still reported.
			scoped := scopedPath(key, base, path)
			markField(key, scoped)
			contentInitFields[scoped] = true
		}
	}

	facts.conditionalWhole = conditionalWhole
	facts.conditionalFields = conditionalFields
	facts.wholeInit = wholeInit
	facts.initializedFields = initializedFields
	facts.contentInitFields = contentInitFields
	facts.writePaths = writePaths
	facts.heapFieldWritten = heapFieldWritten
}

func (d *UninitVariableDetector) emitHeapUninitUses(ctx context.Context, in *uninitScanInputs, facts *heapUninitFacts) {
	f, file := in.f, in.file
	unarys, ptrs, fields, subscripts := in.unarys, in.ptrs, in.fields, in.subscripts
	result := in.result
	mallocVars, mallocAllocator := facts.mallocVars, facts.mallocAllocator
	wholeInit, initializedFields := facts.wholeInit, facts.initializedFields
	contentInitFields, writePaths, heapFieldWritten := facts.contentInitFields, facts.writePaths, facts.heapFieldWritten
	resolve := facts.resolve
	scopedPath := facts.scopedPath
	heapInit := facts.heapInit
	for _, unary := range unarys {
		if !funcLineRange(f, unary.StartLine()) {
			continue
		}
		if isInsideTypeExpr(unary) {
			continue
		}
		text := unary.Text()
		if !strings.HasPrefix(text, "*") {
			continue
		}
		name := strings.TrimSpace(text[1:])
		key := resolve(name, unary.StartLine())
		if key == "" {
			continue
		}
		if isHeapVar(mallocVars, key) && !wholeInit[key] && !heapFieldWritten[key] {
			// wholeInit/heapFieldWritten are the write scan: reaching this
			// emit proves the pointed-to storage was never written since the
			// allocation.
			initWrite, initLine, initWriter := heapInit(key, unary.StartLine(), "", true)
			d.insertValueUseEvent(ctx, f, file, unary.StartLine(), unary.StartColumn(), mallocVars[key], name, mallocAllocator[key], "heap_uninit", initWrite, initLine, initWriter, result)
		}
	}

	for _, ptr := range ptrs {
		if !funcLineRange(f, ptr.StartLine()) {
			continue
		}
		if isInsideTypeExpr(ptr) {
			continue
		}
		children := ptr.NamedChildren()
		if len(children) == 0 {
			continue
		}
		name := children[0].Text()
		key := resolve(name, ptr.StartLine())
		if key == "" {
			continue
		}
		if isHeapVar(mallocVars, key) && !wholeInit[key] && !heapFieldWritten[key] {
			initWrite, initLine, initWriter := heapInit(key, ptr.StartLine(), "", true)
			d.insertValueUseEvent(ctx, f, file, ptr.StartLine(), ptr.StartColumn(), mallocVars[key], name, mallocAllocator[key], "heap_uninit", initWrite, initLine, initWriter, result)
		}
	}

	for _, field := range fields {
		if !funcLineRange(f, field.StartLine()) {
			continue
		}
		if isInsideTypeExpr(field) || isFieldWriteTarget(field) || isAddressOnlyUse(field) {
			continue
		}
		children := field.NamedChildren()
		if len(children) == 0 {
			continue
		}
		base := fieldBaseName(field)
		key := resolve(base, field.StartLine())
		if key == "" {
			continue
		}
		if !isHeapVar(mallocVars, key) || wholeInit[key] {
			continue
		}
		path := scopedPath(key, base, fieldPath(field))
		if writePaths[path] {
			continue
		}
		if !initializedFields[path] {
			initWrite, initLine, initWriter := heapInit(key, field.StartLine(), scopedPath(key, base, fieldPath(field)), false)
			d.insertValueUseEventAt(ctx, f, file, field.StartLine(), field.StartColumn(), mallocVars[key], base, fieldPath(field), mallocAllocator[key], "heap_uninit", initWrite, initLine, initWriter, result)
		}
	}

	// An element read `p[i]` of a malloc'd block is an uninitialized read — the
	// previous scan only covered `*p`, `p` and `p->f`, so `int *p = malloc(...);
	// v = p[0];` was a systematic miss (UN-05).
	for _, sub := range subscripts {
		if !funcLineRange(f, sub.StartLine()) {
			continue
		}
		if isInsideTypeExpr(sub) {
			continue
		}
		children := sub.NamedChildren()
		if len(children) == 0 {
			continue
		}
		base := fieldBaseName(sub)
		key := resolve(base, sub.StartLine())
		if key == "" {
			continue
		}
		if !isHeapVar(mallocVars, key) || wholeInit[key] {
			continue
		}
		path := scopedPath(key, base, sub.Text())
		if writePaths[path] {
			continue
		}
		// An element read is covered either by an element-granular write
		// (`p->f[i] = x`, exact key) or by a field-granular CONTENT write
		// (`memcpy(p->f, ...)`, `p->f = 0`). A pointer-only assignment
		// `p->f = malloc(...)` does not count: `p->f[0]` right after it reads
		// uninitialized heap memory (UN-05 field shape).
		if initializedFields[path] || contentInitFields[scopedPath(key, base, fieldPath(sub))] {
			continue
		}
		initWrite, initLine, initWriter := heapInit(key, sub.StartLine(), scopedPath(key, base, sub.Text()), false)
		d.insertValueUseEventAt(ctx, f, file, sub.StartLine(), sub.StartColumn(), mallocVars[key], base, sub.Text(), mallocAllocator[key], "heap_uninit", initWrite, initLine, initWriter, result)
	}
}

// unionTypedefNames returns the typedef names whose definition aliases a union
// (`typedef union { ... } vlan_u;`). Enterprise code declares unions almost
// exclusively through typedefs, so the declaration site's type node is a
// type_identifier, not a union_specifier — without this map the union
// shared-storage rule never fires (issue #253 P2-1).
func unionTypedefNames(root parser.Node) map[string]bool {
	out := map[string]bool{}
	for _, td := range root.FindAll("type_definition") {
		isUnion := false
		var name string
		for _, child := range td.NamedChildren() {
			switch child.Kind() {
			case "union_specifier":
				isUnion = true
			case "type_identifier":
				name = child.Text()
			}
		}
		if isUnion && name != "" {
			out[name] = true
		}
	}
	return out
}
