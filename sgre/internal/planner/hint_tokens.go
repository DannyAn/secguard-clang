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
	{Key: "certain-null", Description: "the null is CFG-proved definite (assigned NULL, no intervening reassignment)"},
	{Key: "maybe-null", Description: "the source is possibly null — a nullable origin, NOT a proof; judge the source itself"},
	{Key: "tainted", Description: "the value is user/attacker-controlled (an injection/taint source)"},
	{Key: "weak-guard", Description: "a guard exists but only partially protects (scope misses the deref); verify its scope before dismissing"},
	{Key: "macro-context", Description: "a function-like macro is in play — verify the macro's contract before confirming; never confirm from the Source column alone"},
	{Key: "api@", Display: "api@<name>", Description: "the callee/API in play: {value}"},
	{Key: "cat@", Display: "cat@<name>", Description: "the detector's sub-category: {value}"},

	// ---- unchecked-return ----
	{Key: "contract@known", Description: "the callee's failure contract is proven (standard unchecked-return API / declared allocator / body-verified wrapper): an unchecked return is a genuine CWE-252 defect"},
	{Key: "contract@unknown", Description: "the callee is an allocator by NAME only (`alloc` substring, `*_new`/`*_dup` factory): prove it returns a failure sentinel (NULL/-1/error code) or dismiss"},
	{Key: "callee@", Display: "callee@<file>:<line>", Description: "the callee's definition location in the scan ({value}); its body is embedded in the candidate file's `## Callee Definition`"},

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
	{Key: "idx@", Display: "idx@<expr>", Description: "the access index or copy size expression: {value} — a constant past cap@ is detector-proved; a variable one needs your judgment of its reachable range"},

	// ---- divide-by-zero ----
	{Key: "divisor@", Display: "divisor@<shape>", Description: "the divisor's shape: {value} (`bare` = plain identifier, `call` = call result, `compound` = complex expression; `field`/`global` are auto-confirmed and never reach you)"},

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
	{Key: "may-free", Description: "the double-free's first release is conditional (a release helper frees only on some paths) — the verdict is possible, not proved"},
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

// RegisteredHintKeys returns the canonical keys (value-bearing keys keep
// their trailing "@"), for the protocol guard tests.
func RegisteredHintKeys() []string {
	keys := make([]string, 0, len(hintTokenRegistry))
	for _, spec := range hintTokenRegistry {
		keys = append(keys, spec.Key)
	}
	return keys
}
