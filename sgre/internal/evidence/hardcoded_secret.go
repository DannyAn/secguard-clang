package evidence

import (
	"context"
	"math"
	"regexp"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type HardcodedSecretDetector struct {
	store  db.Store
	parser *parser.Parser
	logger *log.Logger
}

func NewHardcodedSecretDetector(store db.Store, p *parser.Parser, logger *log.Logger) *HardcodedSecretDetector {
	return &HardcodedSecretDetector{store: store, parser: p, logger: logger}
}

func (d *HardcodedSecretDetector) Name() string { return "hardcoded_secret" }

func (d *HardcodedSecretDetector) Domain() string { return "trust" }

func (d *HardcodedSecretDetector) Capabilities() []string {
	return []string{"hardcoded-password", "hardcoded-api-key", "hardcoded-token", "hardcoded-private-key"}
}

// secretVarPattern matches variable names that are conventionally secret-bearing.
// Long names match as substrings (so `db_password` is still caught), while short
// ambiguous tokens (`key`/`pin`/`salt`/`hash`) require word boundaries so they
// don't fire on `monkey`/`mapping`.
var secretVarPattern = regexp.MustCompile(`(?i)(password|passwd|pwd|secret|api_key|apikey|access_key|private_key|token|credential|auth_key|client_secret|consumer_secret|session_key|bearer|nonce|\bkey\b|\bpin\b|\bsalt\b|\bhash\b)`)

// highEntropyHints are well-known secret prefixes whose presence makes a value
// a hardcoded secret regardless of the variable name.
var highEntropyHints = []string{
	"sk-", "eyJ", "-----BEGIN", "AKIA", "ghp_", "gho_", "xoxb-", "xoxp-",
}

func (d *HardcodedSecretDetector) Detect(ctx context.Context) (DetectResult, error) {
	result := DetectResult{}

	err := forEachFileIncludingEmpty(ctx, d.store, d.parser, d.logger, func(file *db.File, root parser.Node, funcs []*db.Function) {
		// Scan every init_declarator (file-scope globals AND function locals).
		// A file-scope initializer runs at load time regardless of the call
		// graph, so it is attributed to enclosingFuncID == 0 (see call_reach,
		// which keeps function-less candidates); a function-local one is
		// attributed to its enclosing function.
		inits := root.FindAll("init_declarator")
		for _, init := range inits {
			varName := ""
			for _, id := range init.FindAll("identifier") {
				varName = id.Text()
				break
			}
			if varName == "" {
				continue
			}

			value := extractInitializerValue(init)
			if value == "" {
				continue
			}

			if !isSecretVar(varName) && !hasHighEntropyHint(value) && !looksHighEntropy(value) && !looksLikeURLCredential(value) {
				continue
			}

			if emitEvent(ctx, d.store, d.logger, "HARDCODED_SECRET", enclosingFuncID(init, funcs), &db.Location{FileID: file.ID, Line: init.StartLine(), Column: init.StartColumn()}, withValueProven(map[string]string{
				"variable": varName,
				"value":    value,
				"category": "hardcoded_secret",
			}, value)) {
				result.EventsCreated++
			}
		}

		calls := root.FindAll("call_expression")
		d.detectRegSetValueEx(ctx, calls, file, &result)
		d.detectInitializerPairs(ctx, root, file, funcs, &result)
	})
	return result, err
}

// isSecretVar reports whether the variable name is conventionally secret-bearing.
func isSecretVar(name string) bool {
	return secretVarPattern.MatchString(name)
}

// hasHighEntropyHint reports whether the value starts with a well-known secret
// prefix (API key / JWT / PEM / AWS / GitHub / Slack token forms).
func hasHighEntropyHint(value string) bool {
	for _, hint := range highEntropyHints {
		if strings.HasPrefix(value, hint) {
			return true
		}
	}
	return false
}

// secretValueProven reports whether a literal's VALUE is itself secret-shaped (a
// known token prefix, high Shannon entropy, or URL-embedded credentials), as
// opposed to a match on the variable/field name alone. A name-only match may be
// a placeholder ("REPLACE_ME") or a test credential, so the planner leaves it
// suspected for the AI rather than auto-confirming it.
func secretValueProven(value string) bool {
	return hasHighEntropyHint(value) || looksHighEntropy(value) || looksLikeURLCredential(value)
}

// withValueProven records the value_proven marker on props when the literal's
// value is itself secret-shaped. The planner's HardcodedSecretProofFilter reads
// it to auto-confirm those emissions; a name-only match carries no marker and
// stays suspected for the AI. The category is always the plain defect shape.
func withValueProven(props map[string]string, value string) map[string]string {
	if secretValueProven(value) {
		props["value_proven"] = "true"
	}
	return props
}

// secretEntropyThreshold is the Shannon-entropy bar (bits/char) above which a
// long literal is treated as a random secret. It mirrors gitleaks' generic
// entropy rule (4.5): a structured string — a URL, a sentence — sits below it,
// while a base64-ish key/token sits above.
const secretEntropyThreshold = 4.5

// looksHighEntropy reports whether a literal "looks like" a random secret by
// Shannon entropy: long (>=16 chars), non-numeric, whitespace-free, not a URL
// scheme, with per-char entropy >= 4.5 bits. This catches hardcoded keys/tokens
// whose variable name is NOT in the regex and that carry no recognized prefix —
// the previously-dead `isLongLiteral` branch now actually fires on random
// content while a URL / sentence stays below the bar.
func looksHighEntropy(value string) bool {
	if len(value) < 16 || isNumericLiteral(value) {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return false
	}
	if strings.Contains(value, "://") {
		return false
	}
	return shannonEntropy(value) >= secretEntropyThreshold
}

// shannonEntropy returns the per-character Shannon entropy (bits) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}
	var h float64
	for _, c := range freq {
		p := float64(c) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

// looksLikeURLCredential reports whether a literal is a URL/DSN with embedded
// credentials (`scheme://user:password@host`). Such a string is low-entropy
// (so the entropy trigger misses it) but is still a hardcoded credential
// (CWE-798) — e.g. "mysql://root:hunter2@db".
func looksLikeURLCredential(value string) bool {
	i := strings.Index(value, "://")
	if i < 0 {
		return false
	}
	rest := value[i+3:]
	at := strings.Index(rest, "@")
	if at <= 0 {
		return false
	}
	return strings.Contains(rest[:at], ":")
}

// enclosingFuncID returns the ID of the function whose line range contains node,
// or 0 when node is file-scope (a global initializer). A zero ID marks the event
// as function-less, which the call-reach filter keeps (file-scope code is always
// present).
func enclosingFuncID(node parser.Node, funcs []*db.Function) int64 {
	for _, f := range funcs {
		if funcLineRange(f, node.StartLine()) {
			return f.ID
		}
	}
	return 0
}

// detectInitializerPairs flags struct designated initializers
// (`.password = "admin123"`) whose field name or value is secret-bearing. A
// designated initializer is an `initializer_pair` node holding a
// `field_designator` (the field name) and a `string_literal` (the value).
func (d *HardcodedSecretDetector) detectInitializerPairs(ctx context.Context, root parser.Node, file *db.File, funcs []*db.Function, result *DetectResult) {
	for _, pair := range root.FindAll("initializer_pair") {
		var fieldName, value string
		for _, child := range pair.NamedChildren() {
			switch child.Kind() {
			case "field_designator":
				for _, id := range child.FindAll("field_identifier") {
					fieldName = id.Text()
					break
				}
			case "string_literal":
				value = extractStringLiteral(child.Text())
			}
		}
		if fieldName == "" || value == "" {
			continue
		}
		if !isSecretVar(fieldName) && !hasHighEntropyHint(value) && !looksHighEntropy(value) && !looksLikeURLCredential(value) {
			continue
		}
		if emitEvent(ctx, d.store, d.logger, "HARDCODED_SECRET", enclosingFuncID(pair, funcs), &db.Location{FileID: file.ID, Line: pair.StartLine(), Column: pair.StartColumn()}, withValueProven(map[string]string{
			"variable": fieldName,
			"value":    value,
			"category": "hardcoded_secret",
		}, value)) {
			result.EventsCreated++
		}
	}
}

func (d *HardcodedSecretDetector) detectRegSetValueEx(ctx context.Context, calls []parser.Node, file *db.File, result *DetectResult) {
	for _, call := range calls {
		callName := extractCallName(call)
		if callName != "RegSetValueExA" && callName != "RegSetValueExW" && callName != "RegSetValueEx" {
			continue
		}
		args := extractCallArgs(call)
		if len(args) < 5 {
			continue
		}
		valueName := strings.Trim(args[1], "\"")
		if !secretVarPattern.MatchString(valueName) {
			continue
		}
		// The value argument is often a cast-prefixed literal, e.g.
		// (BYTE*)"P@ssw0rd!" or (const BYTE*)"secret". Extract the string
		// literal rather than requiring the arg to start with a quote.
		valueData := extractStringLiteral(args[4])
		if valueData == "" {
			continue
		}

		funcs, _ := d.store.ListFunctions(ctx)
		var funcID int64
		for _, f := range funcs {
			if f.FileID == file.ID && call.StartLine() >= f.StartLine && call.StartLine() <= f.EndLine {
				funcID = f.ID
				break
			}
		}

		if emitEvent(ctx, d.store, d.logger, "HARDCODED_SECRET", funcID, &db.Location{FileID: file.ID, Line: call.StartLine(), Column: call.StartColumn()}, withValueProven(map[string]string{
			"api":      callName,
			"name":     valueName,
			"value":    valueData,
			"category": "hardcoded_secret",
		}, valueData)) {
			result.EventsCreated++
		}
	}
}

func extractInitializerValue(init parser.Node) string {
	for _, child := range init.NamedChildren() {
		if child.Kind() == "string_literal" {
			text := child.Text()
			text = strings.Trim(text, "\"")
			text = strings.Trim(text, "'")
			return text
		}
	}
	return ""
}

// extractStringLiteral returns the contents of the first double-quoted string
// in text, ignoring any cast prefix such as (BYTE*) or (const BYTE*). It
// returns "" when text contains no string literal.
func extractStringLiteral(text string) string {
	start := strings.IndexByte(text, '"')
	if start < 0 {
		return ""
	}
	end := strings.IndexByte(text[start+1:], '"')
	if end < 0 {
		return ""
	}
	return text[start+1 : start+1+end]
}

func isNumericLiteral(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			if c != '.' && c != '-' && c != '+' && c != 'x' && c != 'X' && c != 'a' && c != 'b' && c != 'c' && c != 'd' && c != 'e' && c != 'f' && c != 'A' && c != 'B' && c != 'C' && c != 'D' && c != 'E' && c != 'F' {
				return false
			}
		}
	}
	return true
}
