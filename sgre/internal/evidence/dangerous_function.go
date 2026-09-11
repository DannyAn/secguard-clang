package evidence

import (
	"context"

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

func (d *DangerousFunctionDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFile(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		for _, call := range root.FindAll("call_expression") {
			name := extractCallName(call)
			if !d.banned[name] {
				continue
			}
			fnID := enclosingFuncID(call, funcs)
			if emitEvent(ctx, d.store, d.logger, "DANGEROUS_FUNCTION", fnID, &db.Location{FileID: file.ID, Line: call.StartLine()}, map[string]string{
				"variable":   name,
				"category":   "dangerous_function",
				"expression": call.Text(),
			}) {
				result.EventsCreated++
			}
		}
	})
	return result, err
}
