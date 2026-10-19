package planner

import (
	"fmt"
	"strings"
)

// HintTokenSpec declares ONE hint token: the canonical key (a prefix ending
// in "@" for value-bearing tokens like "src@", or an exact bare token like
// "maybe-null") and the consumer-facing description that states what the
// token means and how the classifier should act on it.
//
// This registry is the SINGLE SOURCE OF TRUTH for the Hint vocabulary. The
// _index.md legend and each candidate file's "## Pipeline Tokens" section
// are generated from it, and zz_hint_protocol_guard_test.go fails the build
// when any extension document (command-instructions.md, agent-body.md,
// SKILL.md) names a value-bearing token the registry does not carry. Before
// this registry existed the same legend was hand-copied into five places and
// drifted per type — the root cause of the "hint says X, skill says Y"
// class of classifier confusion.
//
// Adding a token: append a spec here (value-bearing keys end in "@"), emit
// it from buildHintParts, and reference it from the type's skill. Never
// hand-write the token into the markdown legend — generate it.
type HintTokenSpec struct {
	// Key is the canonical match key: "src@" (prefix, value-bearing) or
	// "maybe-null" (exact, bare).
	Key string
	// Display is the legend form shown in _index.md (e.g. "src@N",
	// "lock@<lo>-<hi>"). Empty = Key itself.
	Display string
	// Description explains the token to the classifier. "{value}" is
	// replaced with the token's value part in the per-candidate rendering.
	Description string
}

var hintTokenRegistry = []HintTokenSpec{
	// ---- shared across every type ----
	{Key: "src@", Display: "src@N", Description: "the null/taint source is assigned at line {value}"},
	{Key: "sanitizer@", Display: "sanitizer@<fn>", Description: "a caller-defined validator `<fn>` guards the sink argument — judge whether `<fn>` is a complete whitelist (dismiss) or a partial blacklist that misses `|`/`$()`/backticks (confirm); its body is in the scan"},
	{Key: "certain-null", Description: "the null is CFG-proved definite (assigned NULL, no intervening reassignment)"},
	{Key: "maybe-null", Description: "the source is possibly null — a nullable origin, NOT a proof; judge the source itself"},
	{Key: "tainted", Description: "the value is user/attacker-controlled (an injection/taint source)"},
	{Key: "taint@none", Description: "the pipeline's taint analysis did NOT connect a user source (argv/getenv/network/…) to this sink — judge from the ## Location signature whether the sink argument is a public entry-point parameter (attacker-reachable → confirm) or an internal/trusted value (dismiss); NOT 'proven safe'"},
	{Key: "weak-guard", Description: "a guard exists but only partially protects (scope misses the deref); verify its scope before dismissing"},
	{Key: "macro-context", Description: "a function-like macro is in play — verify the macro's contract before confirming; never confirm from the Source column alone"},
	{Key: "api@", Display: "api@<name>", Description: "the callee/API in play: {value}"},
	{Key: "cat@", Display: "cat@<name>", Description: "the detector's sub-category: {value}"},

	// ---- unchecked-return ----
	{Key: "contract@known", Description: "the callee's failure contract is proven (standard unchecked-return API / declared allocator / body-verified wrapper): an unchecked return is a genuine CWE-252 defect"},
	{Key: "contract@unknown", Description: "the callee is an allocator by NAME only (`alloc` substring, `*_new`/`*_dup` factory): prove it returns a failure sentinel (NULL/-1/error code) or dismiss"},
	{Key: "discard", Description: "the return value is stored then explicitly `(void)`-cast away — the programmer deliberately discards it, so the ignored failure is unobservable: dismiss from the row, no source read"},
	{Key: "callee@", Display: "callee@<file>:<line>", Description: "the callee's definition location in the scan ({value}); its body is embedded in the candidate file's `## Callee Definition`"},
	{Key: "second-callee@", Display: "second-callee@<file>:<line>", Description: "double-free: the SECOND release helper's definition ({value}) — its body is embedded in the candidate file's `## Second Callee Definition`; judge whether both frees can execute on one path from these two bodies"},

	// ---- null-deref ----
	// The nullable-origin tier replaces the flat certain-null/maybe-null pair
	// for this type: what the classifier must DO differs by tier, so the tier
	// is the first thing it reads.
	{Key: "null@cfg-proof", Description: "the CFG proves a NULL definite assignment reaches this dereference — machine-proved CWE-476, verify nothing"},
	{Key: "null@malloc-fail", Description: "the null source is a PROVEN-nullable call result (allocator / known maybe-null libc / a callee whose body returns NULL): an unchecked dereference is a textbook CWE-476"},
	{Key: "null@caller-arg", Description: "the null source is an inter-procedural caller argument (not proven non-null) — judge whether that caller can pass NULL"},
	{Key: "null@external-unknown", Description: "the ONLY null source is an unproven external call — an analyzer fail-open ASSUMPTION, not evidence: verify the callee can return NULL or dismiss"},

	// ---- crypto-misuse ----
	{Key: "reason@", Display: "reason@<text>", Description: "the detector's specific finding rationale: {value} (the algorithm/key weakness it observed — judge from this, not from the API name alone)"},
	{Key: "key-size@", Display: "key-size@N", Description: "the observed key size in bytes: {value} (below 16 bytes / 128 bits is under the modern-cipher minimum)"},

	// ---- buffer-overflow / out-of-bounds ----
	{Key: "buf@", Display: "buf@<name>", Description: "the buffer being written/read: {value} — the resolved array or allocation name"},
	{Key: "cap@", Display: "cap@N", Description: "the buffer's known capacity in elements: {value} (from the array declaration or allocation size)"},
	{Key: "idx@", Display: "idx@<expr>", Description: "the access index, copy size, or declared size argument: {value} — a constant past cap@ is detector-proved; a variable one needs your judgment of its reachable range"},
	{Key: "src-cap@", Display: "src-cap@N", Description: "the SOURCE buffer's known capacity in elements: {value} — a source that is itself a bounded fixed-size global/array cannot feed more bytes than this (a `strcpy(g_dst, g_src)` with src-cap@ ≤ cap@ is bounded, dismiss)"},

	// ---- divide-by-zero ----
	{Key: "divisor@", Display: "divisor@<shape>", Description: "the divisor's shape: {value} (`bare` = plain identifier, `call` = call result, `compound` = complex expression; `field`/`global` are auto-confirmed and never reach you)"},
	{Key: "range@", Display: "range@[lo,hi]", Description: "the range engine's provable interval for the divisor: {value} — it contains 0 (else the filter would have dropped the row); judge whether the 0 endpoint is reachable"},
	{Key: "callers@", Display: "callers@<summary>", Description: "the direct call-site census for a parameter divisor: {value} — judge the callers that pass non-constants"},

	// ---- uninit ----
	{Key: "certain-uninit", Description: "the read is provably uninitialized (three-layer converged)"},
	{Key: "maybe-uninit", Description: "the read may be uninitialized — weaker tier; trace the write paths"},

	// ---- integer-overflow ----
	{Key: "lhs@", Display: "lhs@<kind>", Description: "integer-overflow left operand provenance: {value} (param/local/global/deref/subscript/const/expr)"},
	{Key: "rhs@", Display: "rhs@<kind>", Description: "subtrahend provenance: {value} — `rhs@param`/`rhs-influenced` means externally supplied (real underflow risk)"},
	{Key: "rhs-influenced", Description: "the subtracted amount is caller/attacker-controlled"},
	{Key: "lhs-influenced", Description: "the left operand is caller/attacker-controlled"},
	{Key: "sink@", Display: "sink@<kind>", Description: "where the subtraction result flows: {value} (call_arg/assign)"},
	{Key: "guard@none", Description: "no same-function guard survived the filters (ordering guard for integer-overflow, null guard for null-deref) — machine-verified absence, do not spend a read looking for one"},

	// ---- deadlock ----
	{Key: "locks@", Display: "locks@A|B", Description: "deadlock: this function locks {value} in that order; match the inversion pair across functions"},
	{Key: "reverse@", Display: "reverse@<fn>", Description: "function {value} acquires the same locks in the opposite order"},

	// ---- race-condition ----
	{Key: "threads@", Display: "threads@<fn>", Description: "shared-data race: thread functions accessing the data: {value}"},
	{Key: "instances@", Display: "instances@N", Description: "distinct thread instances: {value}"},
	{Key: "write@", Display: "write@N", Description: "the conflicting write is at line {value}"},
	{Key: "mutex@", Display: "mutex@<name>", Description: "toctou_shared_state: mutex {value} guards the state"},
	{Key: "lock@", Display: "lock@<lo>-<hi>", Description: "the critical-section span lines {value} (the candidate's state write sits outside it)"},
	{Key: "check@", Display: "check@<fn>", Description: "TOCTOU check call: {value} (paired with the use call)"},
	{Key: "use@", Display: "use@<fn>", Description: "TOCTOU use call: {value}"},
	{Key: "arg@", Display: "arg@<expr>", Description: "the argument checked then used: {value}"},

	// ---- use-after-free / double-free / leaks ----
	{Key: "free@", Display: "free@N / free@N,M", Description: "the free site line(s): {value} (one for use-after-free, two for double-free; on a leak candidate they are the release sites that exist but do not cover the leak path)"},
	{Key: "may-free", Description: "the double-free's first release is conditional (a release helper frees only on some paths) — the verdict is possible, not proved"},
	{Key: "cond@", Display: "cond@<helper>", Description: "the conditional first release helper: {value} frees only when its own condition holds — the double free is possible, not must-proven"},

	// ---- memory-leak / resource-leak ----
	// The verdict basis for a leak: the acquire line, the certainty tier
	// (DefiniteLeak), and the ownership-release channel state. The channel
	// split is what separates the two classifier actions: "no channel at all"
	// is machine-proved loss, "a channel exists but the CFG proved a leak path
	// bypasses it" is where the judgment lives.
	{Key: "alloc@", Display: "alloc@N", Description: "the allocation site line: {value} (memory-leak)"},
	{Key: "acquire@", Display: "acquire@N", Description: "the resource acquisition site line: {value} (resource-leak)"},
	{Key: "leak@definite", Description: "no free/escape/transfer is reachable on ANY path from the allocation to function exit — machine-proved loss"},
	{Key: "leak@conditional", Description: "a release channel exists but the CFG proved a leak path bypasses it — judge that path (error/early-return) against free@/escape@"},
	{Key: "escape@return", Description: "the value is returned to the caller somewhere (an ownership transfer exists) — the leak path must be a NON-returning path"},
	{Key: "escape@store", Description: "the value is stored into a non-local (global/parameter/container) somewhere — the leak path must bypass that store"},
	{Key: "escape@none", Description: "no ownership-transfer channel exists anywhere in the function"},

	// ---- uninit (storage facts) ----
	{Key: "origin@", Display: "origin@<kind>", Description: "the uninitialized storage's kind: {value} (stack/heap/struct)"},
	{Key: "decl@", Display: "decl@N", Description: "the declaration line of the uninitialized storage: {value}"},
	{Key: "field@", Display: "field@<path>", Description: "the uninitialized read target is the member/element `{value}` — NOT the base pointer; the Code Context shows the read but NOT cross-function writes, so check the base object's factory before confirming"},
	// The write-path facts close the "trace the write paths" burden from the
	// row: init@none is machine-proved never-written (stack scalar only),
	// init@unseen is the honest weak tier for heap/struct storage whose
	// initializer may live in a callee, and init@N + may-skip reduces the
	// verdict to judging the loop condition.
	{Key: "init@", Display: "init@none / init@unseen / init@N", Description: "the initialization write state: {value} — `none` = the detector proved a stack scalar is never written before the read (confirm from the row); `unseen` = heap/struct storage with no in-function write found, but a cross-function factory/memset/output-param may have initialized it — do NOT confirm from the row alone; the ≤5-read budget covers checking the base object's factory; a line = the only write site"},
	{Key: "may-skip", Description: "the only initialization writes sit inside a loop body the condition may skip on the first pass — judge the loop condition (in the Code Context window), nothing else"},

	// ---- argument-type / data-representation ----
	{Key: "expected@", Display: "expected@<type>", Description: "the callee's declared parameter type: {value}"},
	{Key: "actual@", Display: "actual@<type>", Description: "the argument's actual pointer type before any cast: {value}"},
	{Key: "cast@", Display: "cast@<type>", Description: "the explicit cast target type: {value} — a reinterpretation between incompatible pointer types"},

	// ---- format-string ----
	{Key: "fmt-arg@", Display: "fmt-arg@<expr>", Description: "the format argument expression: {value} — a non-literal (variable) format is the CWE-134 signal; a function PARAMETER is attacker-reachable only when callsites@ shows a non-constant argument or no in-tree call site — pair with callsites@ before confirming; a constant string literal → dismissed"},

	// ---- path-traversal ----
	{Key: "path-arg@", Display: "path-arg@<expr>", Description: "the path argument expression: {value} — judge whether a caller can inject `../`: a tainted source (paired with `tainted`) or a non-constant call-site argument (see callsites@) → confirmed; an internal/trusted path or an O_NOFOLLOW/dir_fd-anchored sink → dismissed"},

	// ---- format-string / path-traversal (caller-side census) ----
	{Key: "callsites@", Display: "callsites@<census>", Description: "the in-tree call-site census for the sink parameter: {value} — `N:all-literal` means every in-tree caller passes a compile-time constant → dismiss; `N:K-literal,J-var` means the var/tainted callers are where attacker input could enter → inspect those callers before confirming; absent means no in-tree call site binds the parameter (an external TU may call it)"},

	// ---- hardcoded-secret ----
	{Key: "value-shape@", Display: "value-shape@<masked>", Description: "the literal's masked shape (4-char prefix + length): {value} — judge placeholder (REPLACE…), test value (test…), or real credential"},

	// ---- signal-handler ----
	{Key: "async-unsafe@", Display: "async-unsafe@<fn>", Description: "the non-async-signal-safe call inside the handler: {value} (off the POSIX async-signal-safe list) — a certain CWE-479"},

	// ---- implicit-contract / sizeof-misuse ----
	{Key: "subject@", Display: "subject@<name>", Description: "the entity the contract/judgment is about: {value} (the struct-pointer parameter for implicit-contract, the sizeof operand for sizeof-misuse)"},
	{Key: "self-guard@", Display: "self-guard@N", Description: "implicit-contract: the field IS null-checked at line {value}, but the reported deref sits outside that guard's scope — that scope gap is the defect; verify from the Code Context, no source read"},
	{Key: "count-field@", Display: "count-field@<name>", Description: "the count/length field gating the pointer use: {value} — the contract the function actually enforces"},
	{Key: "evidence-kind@", Display: "evidence-kind@self|caller", Description: "where the field's nullable treatment is proven: {value} (self = the function body, caller = an inter-procedural call site)"},
}

// matchHintToken resolves one emitted token against the registry: an exact
// bare-token match first, then the longest value-bearing prefix. It returns
// the spec, the value part ("" for bare tokens), and whether a spec matched.
func matchHintToken(token string) (HintTokenSpec, string, bool) {
	for _, spec := range hintTokenRegistry {
		if spec.Key == token {
			return spec, "", true
		}
	}
	for _, spec := range hintTokenRegistry {
		if strings.HasSuffix(spec.Key, "@") && strings.HasPrefix(token, spec.Key) {
			return spec, token[len(spec.Key):], true
		}
	}
	return HintTokenSpec{}, "", false
}

// DescribeHintToken renders one registry-annotated line for an emitted
// token, e.g. "`src@44` — the null/taint source is assigned at line 44". A
// token the registry does not carry renders as the bare token (never an
// empty string) so an unregistered emission stays visible in the output.
func DescribeHintToken(token string) string {
	spec, value, ok := matchHintToken(token)
	if !ok {
		return fmt.Sprintf("- `%s`", token)
	}
	desc := spec.Description
	if value != "" {
		desc = strings.ReplaceAll(desc, "{value}", value)
	}
	desc = strings.ReplaceAll(desc, "{value}", "<value>")
	return fmt.Sprintf("- `%s` — %s", token, desc)
}

// HintLegendLines renders the registry as the _index.md legend body (one
// line per token, in registry order). The workflow framing (binary verdict,
// Source-first classification, evidence-open fallback) stays in the report
// layer; this is only the token vocabulary.
func HintLegendLines() []string {
	lines := make([]string, 0, len(hintTokenRegistry))
	for _, spec := range hintTokenRegistry {
		display := spec.Display
		if display == "" {
			display = spec.Key
		}
		desc := strings.ReplaceAll(spec.Description, "{value}", "<value>")
		lines = append(lines, fmt.Sprintf("- `%s` — %s", display, desc))
	}
	return lines
}

// HintLegendForTokens renders the legend body for ONLY the registry entries a
// given emitted-token sequence actually uses (in registry order). The per-type
// _index.md legend calls this with the type's own token union instead of the
// whole registry, so a subagent reading `null-deref` never carries the
// deadlock/race/leak vocabulary — the full-registry legend was ~60 lines of
// mostly-irrelevant tokens on EVERY type's first read, the dominant context
// bloat before this. Bare tokens and value-bearing tokens both match their
// registry spec; a token the registry does not carry is skipped (the guard
// test fails the build before that can happen in a shipped build).
func HintLegendForTokens(tokens []string) []string {
	used := make(map[string]bool, len(hintTokenRegistry))
	for _, tok := range tokens {
		if spec, _, ok := matchHintToken(tok); ok {
			used[spec.Key] = true
		}
	}
	lines := make([]string, 0, len(used))
	for _, spec := range hintTokenRegistry {
		if !used[spec.Key] {
			continue
		}
		display := spec.Display
		if display == "" {
			display = spec.Key
		}
		desc := strings.ReplaceAll(spec.Description, "{value}", "<value>")
		lines = append(lines, fmt.Sprintf("- `%s` — %s", display, desc))
	}
	return lines
}

// RegisteredHintKeys returns the canonical keys (value-bearing keys keep
// their trailing "@"), for the protocol guard tests.
func RegisteredHintKeys() []string {
	keys := make([]string, 0, len(hintTokenRegistry))
	for _, spec := range hintTokenRegistry {
		keys = append(keys, spec.Key)
	}
	return keys
}
