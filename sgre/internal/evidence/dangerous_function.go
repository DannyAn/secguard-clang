package evidence

import (
	"context"
	"os"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// DangerousFunctionDetector flags calls to banned libc/runtime functions
// (CWE-676). This is a POLICY check, not a context-sensitive analysis: a call
// is a finding regardless of whether the surrounding code guards the
// destination, because the enterprise bans the function itself and mandates a
// safer replacement (typically the Annex K `_s` variants, strtol, getaddrinfo,
// ...).
//
// The ban set is layered into categories (see builtinDangerRules). Every
// category is a sound name match and is auto-confirmed by the planner EXCEPT
// `assert_usage`: whether an assert() guards caller input (a defect) or an
// internal invariant (fine) needs intent, so it is handed to the AI agent.
// A `nonMainOnly` rule (exit / pthread_exit / ExitThread / ExitProcess) fires
// only OUTSIDE the program entry point.
type DangerousFunctionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	// rules is the merged ban set: the built-in rule table PLUS the
	// project-specific [banned_functions] names from secguard.toml (which get
	// the generic `config_banned` category).
	rules map[string]dangerRule
}

// dangerRule describes one banned function's policy shape.
type dangerRule struct {
	// category is the event category, which drives the planner's per-category
	// confidence and the evidence detail.
	category string
	// replacement is the mandated safer API (best-effort, informational). It is
	// emitted on the event so a report/consumer can cite it; the AI's per-shape
	// fix text comes from the skill's category table.
	replacement string
	// nonMainOnly restricts the finding to calls OUTSIDE the program entry
	// point. exit()/ExitProcess()/pthread_exit()/ExitThread() are permitted in
	// main (they are the process/thread exit), but forbidden elsewhere: a
	// callee tearing down the whole process/thread breaks control flow and
	// resource release for its caller.
	nonMainOnly bool
	// constExempt suppresses the finding when the FIRST argument is a
	// compile-time constant. inet_addr is the only such rule: its danger is
	// injection / INADDR_NONE confusion via a runtime-controlled string, not
	// the function itself.
	constExempt bool
}

func NewDangerousFunctionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DangerousFunctionDetector {
	rules := make(map[string]dangerRule, len(builtinDangerRules)+8)
	for name, rule := range builtinDangerRules {
		rules[name] = rule
	}
	for _, name := range config.Load().BannedFunctionNames() {
		if _, exists := rules[name]; !exists {
			rules[name] = dangerRule{category: "config_banned"}
		}
	}
	return &DangerousFunctionDetector{store: store, parser: p, logger: logger, rules: rules}
}

func (d *DangerousFunctionDetector) Name() string { return "dangerous_function" }

// builtinDangerRules is the built-in ban table. Categories group functions by
// the shape of the defect and its mandated replacement; the planner maps
// `assert_usage` to `suspected` and every other category to `confirmed`.
//
// This is a POLICY table — a call to any listed function is a finding by name,
// independent of dataflow. The unbounded string/format functions here
// (strcpy/sprintf/...) intentionally OVERLAP the context-sensitive
// buffer-overflow / injection / format-string detectors: those answer "does
// THIS call overflow / inject", while this table answers the orthogonal policy
// question "is a non-`_s` API used at all". Both dimensions are reported.
var builtinDangerRules = map[string]dangerRule{
	// --- process / thread termination (禁用退出与终止函数) ---
	"exit":         {category: "process_exit", replacement: "return from the enclosing function", nonMainOnly: true},
	"ExitProcess":  {category: "process_exit", replacement: "return from main", nonMainOnly: true},
	"pthread_exit": {category: "process_exit", replacement: "return from the thread start routine", nonMainOnly: true},
	"ExitThread":   {category: "process_exit", replacement: "return from the thread start routine", nonMainOnly: true},
	"atexit":       {category: "process_exit", replacement: "release resources explicitly on each exit path"},
	"abort":        {category: "process_exit", replacement: "return an error / graceful shutdown"},

	// --- stack allocation (禁止 alloca 申请栈上内存) ---
	"alloca": {category: "stack_allocation", replacement: "malloc/free or a fixed-size buffer"},

	// --- non-local jump (禁用 setjmp/longjmp) ---
	"setjmp":  {category: "nonlocal_jump", replacement: "return-value error propagation"},
	"longjmp": {category: "nonlocal_jump", replacement: "return-value error propagation"},

	// --- memory copy / init (内存复制/初始化 → _s) ---
	"memcpy":   {category: "unsafe_memory", replacement: "memcpy_s"},
	"wmemcpy":  {category: "unsafe_memory", replacement: "wmemcpy_s"},
	"memmove":  {category: "unsafe_memory", replacement: "memmove_s"},
	"wmemmove": {category: "unsafe_memory", replacement: "wmemmove_s"},
	"memset":   {category: "unsafe_memory", replacement: "memset_s"},
	"bcopy":    {category: "unsafe_memory", replacement: "memmove_s"},
	"bzero":    {category: "unsafe_memory", replacement: "memset_s"},

	// --- string copy (字符串复制 → _s) ---
	"strcpy":  {category: "unsafe_string", replacement: "strcpy_s"},
	"wcscpy":  {category: "unsafe_string", replacement: "wcscpy_s"},
	"strncpy": {category: "unsafe_string", replacement: "strncpy_s"},
	"wcsncpy": {category: "unsafe_string", replacement: "wcsncpy_s"},

	// --- string concat (字符串连接 → _s) ---
	"strcat":  {category: "unsafe_string", replacement: "strcat_s"},
	"wcscat":  {category: "unsafe_string", replacement: "wcscat_s"},
	"strncat": {category: "unsafe_string", replacement: "strncat_s"},
	"wcsncat": {category: "unsafe_string", replacement: "wcsncat_s"},
	"bcmp":    {category: "unsafe_string", replacement: "memcmp"},

	// --- formatted output (格式化输出 → _s) ---
	"sprintf":   {category: "unsafe_format", replacement: "sprintf_s"},
	"swprintf":  {category: "unsafe_format", replacement: "swprintf_s"},
	"vsprintf":  {category: "unsafe_format", replacement: "vsprintf_s"},
	"vswprintf": {category: "unsafe_format", replacement: "vswprintf_s"},
	"snprintf":  {category: "unsafe_format", replacement: "snprintf_s"},
	"vsnprintf": {category: "unsafe_format", replacement: "vsnprintf_s"},

	// --- formatted input (格式化输入 → _s) ---
	"scanf":    {category: "unsafe_scan", replacement: "scanf_s"},
	"wscanf":   {category: "unsafe_scan", replacement: "wscanf_s"},
	"vscanf":   {category: "unsafe_scan", replacement: "vscanf_s"},
	"vwscanf":  {category: "unsafe_scan", replacement: "vwscanf_s"},
	"fscanf":   {category: "unsafe_scan", replacement: "fscanf_s"},
	"fwscanf":  {category: "unsafe_scan", replacement: "fwscanf_s"},
	"vfscanf":  {category: "unsafe_scan", replacement: "vfscanf_s"},
	"vfwscanf": {category: "unsafe_scan", replacement: "vfwscanf_s"},
	"sscanf":   {category: "unsafe_scan", replacement: "sscanf_s"},
	"swscanf":  {category: "unsafe_scan", replacement: "swscanf_s"},
	"vsscanf":  {category: "unsafe_scan", replacement: "vsscanf_s"},
	"vswscanf": {category: "unsafe_scan", replacement: "vswscanf_s"},
	"gets":     {category: "unsafe_scan", replacement: "fgets"},

	// --- unchecked string→number conversion (→ strtol family) ---
	"atoi":  {category: "unchecked_conversion", replacement: "strtol"},
	"atol":  {category: "unchecked_conversion", replacement: "strtol"},
	"atoll": {category: "unchecked_conversion", replacement: "strtoll"},
	"atof":  {category: "unchecked_conversion", replacement: "strtod"},

	// --- allocator policy (禁止 realloc，用 malloc 代替) ---
	"realloc": {category: "unsafe_alloc", replacement: "malloc + copy + free"},

	// --- assert (suspected; the planner hands this to the AI) ---
	"assert": {category: "assert_usage", replacement: "validate the caller input and return an error"},

	// --- obsolete / insecure APIs (原有清单，保留) ---
	"mktemp":        {category: "insecure_temp", replacement: "mkstemp"},
	"tmpnam":        {category: "insecure_temp", replacement: "mkstemp"},
	"tmpnam_r":      {category: "insecure_temp", replacement: "mkstemp"},
	"gethostbyname": {category: "obsolete_api", replacement: "getaddrinfo"},
	"gethostbyaddr": {category: "obsolete_api", replacement: "getnameinfo"},
	// inet_addr's CWE-676 risk is CONDITIONAL by the rule's own rationale (see
	// constExempt above): an invalid string yields INADDR_NONE, and the impact
	// depends on whether the caller controls the string and checks the sentinel.
	// It gets a category that maps to `suspected`, so the AI weighs the argument's
	// provenance instead of the pipeline asserting an unconditional defect.
	"inet_addr": {category: "obsolete_api_conditional", replacement: "inet_pton", constExempt: true},
}

func (d *DangerousFunctionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	globalConsts := buildGlobalConstants(ctx, d.store, d.parser)
	stringMacros := buildGlobalStringMacros(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		byID := make(map[int64]*db.Function, len(funcs))
		for _, f := range funcs {
			byID[f.ID] = f
		}
		for _, call := range root.FindAll("call_expression") {
			name := extractCallName(call)
			rule, ok := d.rules[name]
			if !ok {
				continue
			}
			// A nonMainOnly rule is safe inside the program entry point, where
			// the process/thread exit IS the intended control flow.
			if rule.nonMainOnly {
				if fn := byID[enclosingFuncID(call, funcs)]; fn != nil && isEntryPoint(fn.Name) {
					continue
				}
			}
			// A const-exempt rule (inet_addr) with a compile-time constant
			// argument is safe — the injection/INADDR_NONE risk requires a
			// runtime-controlled value.
			if rule.constExempt && hasConstantArg(call, globalConsts, stringMacros) {
				continue
			}
			fnID := enclosingFuncID(call, funcs)
			props := map[string]string{
				"variable":   name,
				"category":   rule.category,
				"expression": call.OriginalText(),
			}
			if rule.replacement != "" {
				props["replacement"] = rule.replacement
			}
			if emitEvent(ctx, d.store, d.logger, "DANGEROUS_FUNCTION", fnID, &db.Location{FileID: file.ID, Line: call.StartLine()}, props) {
				result.EventsCreated++
			}
		}
	})
	return result, err
}

// isEntryPoint reports whether a function name is a program entry point, where
// a process/thread exit is legitimate (so a nonMainOnly rule must not fire).
func isEntryPoint(name string) bool {
	switch name {
	case "main", "wmain", "WinMain", "wWinMain":
		return true
	}
	return false
}

// buildGlobalStringMacros parses every file in the scan tree and collects the
// object-like macro names that expand to a compile-time string: a string literal
// body (`#define NLOG_HOST_IP "192.168.0.1"`), adjacent literal concatenation
// (`#define P "/a" "/b"`), or literals combined with other string macros
// (`#define LOG DIR "/log"`). A call argument that is such a macro is a
// compile-time constant — never a runtime-controlled value — so a
// `inet_addr(NLOG_HOST_IP)` carries none of the injection/INADDR_NONE risk that
// makes inet_addr dangerous, and a filesystem sink given one cannot be
// attacker-reached. Uses ParseCached, so the parse is shared with
// buildGlobalConstants and the main detection loop.
func buildGlobalStringMacros(ctx context.Context, store db.Store, p *parser.Parser) map[string]bool {
	macros := make(map[string]bool)
	files, err := store.ListFiles(ctx)
	if err != nil {
		return macros
	}
	defs := make(map[string]string)
	for _, file := range files {
		source, err := os.ReadFile(file.Path)
		if err != nil {
			continue
		}
		tree, err := p.ParseCached(source, file.Path)
		if err != nil {
			continue
		}
		for _, def := range tree.RootNode().FindAll("preproc_def") {
			name, value := "", ""
			for _, child := range def.NamedChildren() {
				switch child.Kind() {
				case "identifier":
					if name == "" {
						name = child.Text()
					}
				case "preproc_arg":
					value = child.Text()
				}
			}
			if name == "" || value == "" {
				continue
			}
			defs[name] = value
		}
	}
	// Fixpoint over macro references so `#define LOG DIR "/log"` counts once DIR
	// is known. Bounded: a self-referential macro must not loop forever.
	for round := 0; round < 4; round++ {
		changed := false
		for name, value := range defs {
			if macros[name] {
				continue
			}
			if macroExpandsToString(value, macros) {
				macros[name] = true
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return macros
}

// macroExpandsToString reports whether a preprocessor definition's raw value is
// composed only of string literals and names already known to be string macros.
func macroExpandsToString(value string, known map[string]bool) bool {
	tokens := splitCStringTokens(value)
	if len(tokens) == 0 {
		return false
	}
	for _, tk := range tokens {
		if strings.HasPrefix(tk, "\"") || known[tk] {
			continue
		}
		return false
	}
	return true
}

// splitCStringTokens splits C source text on whitespace, keeping a quoted string
// (with escapes, and therefore embedded spaces) as a single token.
func splitCStringTokens(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		if s[i] == '"' {
			i++
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '"' {
					i++
					break
				}
				i++
			}
		} else {
			for i < len(s) && s[i] != ' ' && s[i] != '\t' && s[i] != '\n' && s[i] != '\r' {
				i++
			}
		}
		out = append(out, s[start:i])
	}
	return out
}

// hasConstantArg reports whether a call's first argument is a compile-time
// constant: a string literal, a string-valued #define macro, a non-zero integer
// #define/enum, or a zero constant.
func hasConstantArg(call parser.Node, consts *parser.ConstantEnv, stringMacros map[string]bool) bool {
	args := getCallArgs(call)
	if len(args) == 0 {
		return false
	}
	arg := strings.TrimSpace(args[0].Text())
	if isStringLiteralText(arg) {
		return true
	}
	if stringMacros[arg] {
		return true
	}
	if consts != nil && (consts.NonZero(arg) || consts.IsZero(arg)) {
		return true
	}
	return false
}
