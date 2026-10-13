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

// DangerousFunctionDetector flags calls to a fixed list of inherently dangerous
// or obsolete libc functions (CWE-676). This is a POLICY check, not a
// context-sensitive analysis: a call is a finding regardless of whether the
// surrounding code bounds the destination, because the enterprise bans the
// function itself. The list is deliberately conservative — only functions whose
// obsolescence/danger is uncontested — so the detection is sound (no false
// positives from dataflow). It is one whole-tree FindAll per file, so it is
// effectively free.
type DangerousFunctionDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
	// banned is the merged ban set: the built-in dangerous/obsolete list PLUS
	// the project-specific [banned_functions] names from secguard.toml.
	banned map[string]bool
}

func NewDangerousFunctionDetector(store db.Store, p *parser.Parser, logger *log.Logger) *DangerousFunctionDetector {
	banned := make(map[string]bool, len(bannedFunctions))
	for name := range bannedFunctions {
		banned[name] = true
	}
	for _, name := range config.Load().BannedFunctionNames() {
		banned[name] = true
	}
	return &DangerousFunctionDetector{store: store, parser: p, logger: logger, banned: banned}
}

func (d *DangerousFunctionDetector) Name() string { return "dangerous_function" }

// bannedFunctions is the built-in dangerous/obsolete function list. It is kept
// minimal and uncontested: gets (removed in C11, no bounds), the insecure temp
// file makers, and the obsolete name/network/BSD-memory APIs. The unbounded
// string/format functions (strcpy/sprintf/system) are deliberately NOT here —
// buffer-overflow and injection already handle them context-sensitively, and a
// blanket ban would duplicate noise. Extend this list (or make it configurable)
// when an enterprise policy demands a broader ban.
var bannedFunctions = map[string]bool{
	"gets":          true, // CWE-242: no bounds, removed in C11
	"mktemp":        true, // CWE-377: insecure temporary file
	"tmpnam":        true, // CWE-377
	"tmpnam_r":      true, // CWE-377
	"gethostbyname": true, // CWE-477: obsolete, replaced by getaddrinfo
	"gethostbyaddr": true, // CWE-477
	"inet_addr":     true, // CWE-477: obsolete, replaced by inet_pton
	"bcmp":          true, // CWE-477: obsolete BSD, replaced by memcmp
	"bcopy":         true, // CWE-477: obsolete BSD, replaced by memmove
	"bzero":         true, // CWE-477: obsolete BSD, replaced by memset
}

// paramSensitiveBanned lists banned functions whose risk depends on the
// argument being attacker-controlled. A call with a compile-time constant
// argument (a string literal or a #define macro) is safe — the danger of
// inet_addr is injection/overflow via a runtime-controlled IP string, not the
// function itself. gethostbyname/gethostbyaddr are NOT here: their CWE-477
// risk is API obsolescence (should migrate to getaddrinfo), independent of
// the argument. gets/mktemp/tmpnam/bcmp/bcopy/bzero are also NOT here: their
// danger is inherent.
var paramSensitiveBanned = map[string]bool{
	"inet_addr": true,
}

func (d *DangerousFunctionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}
	globalConsts := buildGlobalConstants(ctx, d.store, d.parser)
	stringMacros := buildGlobalStringMacros(ctx, d.store, d.parser)

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		for _, call := range root.FindAll("call_expression") {
			name := extractCallName(call)
			if !d.banned[name] {
				continue
			}
			// A param-sensitive ban (inet_addr, gethostbyname, ...) with a
			// compile-time constant argument is safe — the injection risk
			// requires a runtime-controlled value.
			if paramSensitiveBanned[name] && hasConstantArg(call, globalConsts, stringMacros) {
				continue
			}
			fnID := enclosingFuncID(call, funcs)
			if emitEvent(ctx, d.store, d.logger, "DANGEROUS_FUNCTION", fnID, &db.Location{FileID: file.ID, Line: call.StartLine()}, map[string]string{
				"variable":   name,
				"category":   "dangerous_function",
				"expression": call.OriginalText(),
			}) {
				result.EventsCreated++
			}
		}
	})
	return result, err
}

// buildGlobalStringMacros parses every file in the scan tree and collects the
// object-like macro names whose body is a C string literal (`#define
// NLOG_HOST_IP "192.168.0.1"`). A call argument that is such a macro is a
// compile-time constant — never a runtime-controlled value — so a
// `inet_addr(NLOG_HOST_IP)` carries none of the injection/INADDR_NONE risk
// that makes inet_addr dangerous. Uses ParseCached, so the parse is shared with
// buildGlobalConstants and the main detection loop.
func buildGlobalStringMacros(ctx context.Context, store db.Store, p *parser.Parser) map[string]bool {
	macros := make(map[string]bool)
	files, err := store.ListFiles(ctx)
	if err != nil {
		return macros
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
			if isStringLiteralText(value) {
				macros[name] = true
			}
		}
	}
	return macros
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
