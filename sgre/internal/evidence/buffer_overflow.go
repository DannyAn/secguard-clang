package evidence

import (
	"context"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/repofacts"
)

type BufferOverflowDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewBufferOverflowDetector(store db.Store, p *parser.Parser, logger *log.Logger) *BufferOverflowDetector {
	return &BufferOverflowDetector{store: store, parser: p, logger: logger}
}

func (d *BufferOverflowDetector) Name() string { return "buffer_overflow" }

func (d *BufferOverflowDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	// Struct layouts, global arrays and capacity macros usually live in headers,
	// i.e. in another file. Prefer the tree-wide census built once by the
	// pipeline (shared with the planner); fall back to building it here when the
	// pipeline did not inject one (unit tests, ad-hoc detector invocation).
	facts := repofacts.FactsFromCtx(ctx)
	if facts == nil {
		var err error
		facts, err = repofacts.Build(ctx, d.store, d.parser, d.logger)
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("buffer overflow: repository facts unavailable", "error", err)
			}
			facts = nil
		}
	}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function, tree *parser.Tree) {
		macros := buildMacroValues(root)
		if facts != nil {
			macros = mergeMacros(facts.Macros, macros)
		}
		bc := &bufCtx{
			root:       root,
			calls:      root.FindAll("call_expression"),
			subs:       root.FindAll("subscript_expression"),
			derefs:     root.FindAll("pointer_expression"),
			fieldExprs: root.FindAll("field_expression"),
			ifs:        root.FindAll("if_statement"),
			decls:      root.FindAll("declaration"),
			assigns:    root.FindAll("assignment_expression"),
			updates:    root.FindAll("update_expression"),
			fors:       root.FindAll("for_statement"),
			inits:      root.FindAll("init_declarator"),
			fields:     root.FindAll("field_declaration"),
			macros:     macros,
			facts:      facts,
		}

		// Parameter names per function: a variable copy size that is a function
		// parameter (caller-influenced) is the signal for the variable-length
		// bounded-copy overflow tier (handed to the AI agent to reason about).
		fnDefs := root.FindAll("function_definition")
		paramsByLine := make(map[int][]string)
		for _, fnNode := range fnDefs {
			paramsByLine[fnNode.StartLine()] = findParamsInDefinition(fnNode)
		}

		for _, f := range funcs {
			params := make(map[string]bool)
			for _, p := range paramsByLine[f.StartLine] {
				params[p] = true
			}
			d.detectUnsafeCalls(ctx, f, file, bc, params, &result)
			d.detectArrayOOB(ctx, f, file, bc, &result)
			d.detectUncheckedIndex(ctx, f, file, bc, fnDefs, &result)
			d.detectFormatOverflow(ctx, f, file, bc, &result)
			d.detectCastObjectOOB(ctx, f, file, bc, &result)
		}
	})
	return result, err
}

// bufCtx holds the per-file node lists a buffer-overflow scan needs, fetched
// once per file instead of once per subscript/call (the previous behavior did a
// whole-tree FindAll inside every per-node helper).
type bufCtx struct {
	root       parser.Node
	calls      []parser.Node
	subs       []parser.Node
	derefs     []parser.Node
	fieldExprs []parser.Node
	ifs        []parser.Node
	decls      []parser.Node
	assigns    []parser.Node
	updates    []parser.Node
	fors       []parser.Node
	inits      []parser.Node
	fields     []parser.Node
	macros     map[string]int
	// facts is the tree-wide fallback census: a struct member array, a global
	// array or a capacity macro declared in a header is invisible to the
	// per-file fields slice above.
	facts *repofacts.Facts
}

// buildMacroValues is the per-file macro view; the tree-wide values come from
// parser.CollectMacroValues via repofacts and are merged underneath it.
func buildMacroValues(root parser.Node) map[string]int {
	return parser.CollectMacroValues(root)
}

func (d *BufferOverflowDetector) detectUnsafeCalls(ctx context.Context, f *db.Function, file *db.File, bc *bufCtx, params map[string]bool, result *DetectResult) {
	bounds := AnalyzeBounds(IfsInFunc(bc.ifs, f.StartLine, f.EndLine), assignsInFunc(bc.assigns, f.StartLine, f.EndLine))
	for _, call := range bc.calls {
		if !funcLineRange(f, call.StartLine()) {
			continue
		}
		callName := extractCallName(call)
		if callName == "" {
			continue
		}
		// Annex K `_s` functions are conditionally safe: they trust the explicit
		// destination-capacity argument, so a lying size (larger than the real
		// buffer) overflows just like the unsafe counterpart, and a required
		// size exceeding the declared capacity is a constraint violation. Check
		// the contract before any safe-function exclusion; the check is
		// authoritative and skips the generic path either way.
		if spec, ok := apikb.SecureFunctionSpec(callName); ok {
			d.checkSecureFunction(ctx, f, file, bc, call, callName, spec, params, result)
			continue
		}
		// scanf_s/sscanf_s/fscanf_s use per-conversion buffer-size arguments, not
		// a single capacity: every %s/%c/%[ conversion is followed by a size that
		// must match the real buffer. Check each conversion before exclusion.
		if fmtIdx, ok := apikb.ScanfSecureFormatArg(callName); ok {
			d.checkScanfSecure(ctx, f, file, bc, call, callName, fmtIdx, params, result)
			continue
		}
		// strncpy/strncat/memcpy/memmove all take an explicit size, so refine the
		// size-vs-capacity before the generic path. checkBoundedCopyOverflow
		// returns true when it handled the call (emitted bounded_copy_overflow /
		// bounded_copy_var_size, or proved it fits); false means "fall through
		// to the conservative generic path" (unknown capacity, append semantics,
		// or a bounded local size).
		if apikb.IsBoundedCopy(callName) {
			if d.checkBoundedCopyOverflow(ctx, f, file, bc, call, callName, params, bounds, result) {
				continue
			}
		}
		// read/recv/fread write at most `count` bytes into the buffer, so
		// `read(fd, buf, sizeof(buf))` is safe — the previous generic path flagged
		// the sizeof(buf) idiom as a buffer overflow (BO-12).
		if callName == "read" || callName == "recv" || callName == "fread" {
			if d.suppressReadFamily(bc, f, call, callName) {
				continue
			}
		}
		if apikb.IsSafeFunction(callName) || apikb.IsSafeWrapper(callName) {
			continue
		}
		if apikb.InjectionAPIs[callName] {
			continue
		}
		if !apikb.BufferOverflowAPIs[callName] {
			continue
		}
		// A scanf-family call whose conversions are all scalar (`sscanf(s,
		// "%d", &n)`) writes to scalar variables, not buffers — there is no
		// buffer to overflow, so it must not reach the generic emit (round3
		// `dgf_scan` was a scalar %d target, handed to the AI as a false lead).
		if callName == "scanf" || callName == "sscanf" || callName == "fscanf" {
			if _, ok := genericDestArg(callNamedArguments(call), callName); !ok {
				continue
			}
		}
		if hasPrecedingBoundsCheck(bc, f, call, callName) {
			continue
		}
		if suppressConstantStringCopy(bc, f, call) {
			continue
		}
		if suppressExactFitCopy(bc, f, call) {
			continue
		}
		category := "buffer_overflow"

		props := map[string]string{
			"function":   callName,
			"category":   category,
			"expression": call.OriginalText(),
		}
		annotateGenericBufferProps(props, bc, f, call, callName)
		if emitEvent(ctx, d.store, d.logger, "BUFFER_ACCESS", f.ID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, props) {
			result.EventsCreated++
		}
	}
}

// genericDestArg locates the destination-buffer argument of a call that reached
// the generic buffer-overflow path. The bounded-copy and Annex-K checks locate
// their own destination; this covers the rest: the copy/gets/fread family
// writes arg 0, read/recv write arg 1, and the scanf family writes the vararg
// of the first buffer-consuming conversion (%s/%c/%[) — a numeric conversion's
// argument (&n) is not a buffer and must not be named as one.
func genericDestArg(args []parser.Node, callName string) (parser.Node, bool) {
	switch callName {
	case "scanf":
		return scanfBufferArg(args, 0)
	case "sscanf", "fscanf":
		if len(args) < 2 {
			return parser.Node{}, false
		}
		return scanfBufferArg(args, 1)
	case "read", "recv":
		if len(args) < 2 {
			return parser.Node{}, false
		}
		return args[1], true
	default:
		if len(args) < 1 {
			return parser.Node{}, false
		}
		return args[0], true
	}
}

// scanfBufferArg returns the vararg bound to the first buffer-consuming scanf
// conversion, or false when the format is not a plain literal, has no such
// conversion, or the argument is missing.
func scanfBufferArg(args []parser.Node, fmtIdx int) (parser.Node, bool) {
	if fmtIdx >= len(args) {
		return parser.Node{}, false
	}
	format, ok := stringLiteralContent(args[fmtIdx].Text())
	if !ok {
		return parser.Node{}, false
	}
	argIdx := fmtIdx + 1
	for _, isBuffer := range scanfConversionKinds(format) {
		if isBuffer {
			if argIdx < len(args) {
				return args[argIdx], true
			}
			return parser.Node{}, false
		}
		argIdx++
	}
	return parser.Node{}, false
}

// annotateGenericBufferProps attaches the destination-buffer facts to a generic
// buffer_overflow event so the planner hint can carry buf@/cap@/idx@ without
// the classifier opening the source: the destination argument name (array),
// its resolved capacity (size, from the array declaration, the constant
// allocation, or the field-array table for a member access like log->id), and
// — for the APIs with an explicit write bound — the count/copy-size
// expression (copy_size).
func annotateGenericBufferProps(props map[string]string, bc *bufCtx, f *db.Function, call parser.Node, callName string) {
	args := callNamedArguments(call)
	dstArg, ok := genericDestArg(args, callName)
	if !ok {
		return
	}
	dstText := strings.TrimSpace(dstArg.Text())
	if dstText == "" {
		return
	}
	dstName := extractArgName(dstArg)
	capacity := 0
	if dstName != "" {
		capacity = findArraySize(bc, f, dstName, call.StartLine())
		if capacity <= 0 {
			capacity = constantAllocationSize(bc, f, dstName)
		}
	} else {
		// A non-identifier destination is only nameable when its field-array
		// size resolves (`strcpy(log->id, ...)` against `char id[8]`).
		capacity = findFieldArraySize(bc, dstText)
		if capacity > 0 {
			dstName = dstText
		}
	}
	if dstName == "" {
		return
	}
	props["array"] = dstName
	if capacity > 0 {
		props["size"] = strconv.Itoa(capacity)
	}
	// memcpy/memmove/strncat fall through to this path with an explicit size
	// argument, and read/recv write at most their count: that expression is
	// the copy size the classifier range-judges against cap@.
	switch callName {
	case "memcpy", "memmove", "strncat", "read", "recv":
		if len(args) >= 3 {
			props["copy_size"] = strings.TrimSpace(args[2].Text())
		}
	}
	// The SOURCE buffer's capacity (strcpy/strcat/memcpy/memmove arg 1): when it
	// resolves to a fixed array/global size, the classifier can judge "the source
	// is itself bounded" (round3 `strcpy(g_dst, g_src)` — both 128-byte globals)
	// without a source read. An unknown source stays 0 (absent).
	if srcIdx := sourceArgIndex(callName); srcIdx >= 0 && srcIdx < len(args) {
		srcText := strings.TrimSpace(args[srcIdx].Text())
		if srcText != "" {
			srcName := extractArgName(args[srcIdx])
			srcCap := 0
			if srcName != "" {
				srcCap = findArraySize(bc, f, srcName, call.StartLine())
				if srcCap <= 0 {
					srcCap = constantAllocationSize(bc, f, srcName)
				}
			}
			if srcCap <= 0 {
				srcCap = findFieldArraySize(bc, srcText)
			}
			if srcCap > 0 {
				props["src_capacity"] = strconv.Itoa(srcCap)
			}
		}
	}
}

// sourceArgIndex returns the argument index of the SOURCE buffer for a copy API
// (the data being copied FROM), or -1 when the call has no single source buffer
// (sprintf/gets/scanf write to arg 0 and read from the format/stream instead).
func sourceArgIndex(callName string) int {
	switch callName {
	case "strcpy", "strcat", "strncpy", "strncat", "memcpy", "memmove", "memccpy", "bcopy":
		return 1
	}
	return -1
}
