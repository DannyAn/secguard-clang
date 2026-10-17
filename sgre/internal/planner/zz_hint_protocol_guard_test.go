package planner

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestExtensionDocsHintTokensRegistered guards the protocol half of the hint
// vocabulary: every value-bearing token (`foo@bar`, `foo@<kind>`, and the
// compound `check@<fn>→use@<fn>`) named by an extension document the AI
// classifier actually reads (command-instructions.md, agent-body.md, every
// SKILL.md) must be declared in hintTokenRegistry. Before the registry
// existed these documents each carried hand-copied token lists that drifted
// from what buildHint emits; a document naming an unregistered token now
// fails the build instead of confusing the classifier.
//
// Bare tokens (maybe-null, tainted, ...) are not checked here: in prose they
// are indistinguishable from ordinary words. They are covered structurally —
// the _index.md legend and the per-candidate "## Pipeline Tokens" section
// are generated from the registry, so there is no hand-written list left to
// drift.
func TestExtensionDocsHintTokensRegistered(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	var docs []string
	for _, rel := range []string{
		filepath.Join("extension", "shared", "command-instructions.md"),
		filepath.Join("extension", "shared", "agent-body.md"),
	} {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("protocol doc missing: %s (%v) — the guard must run inside the repo", rel, err)
		}
		docs = append(docs, rel)
	}
	skills, err := filepath.Glob(filepath.Join(repoRoot, "extension", "shared", "skills", "*", "SKILL.md"))
	if err != nil || len(skills) == 0 {
		t.Fatalf("no SKILL.md files found under extension/shared/skills: %v", err)
	}
	for _, s := range skills {
		rel, err := filepath.Rel(repoRoot, s)
		if err != nil {
			t.Fatalf("rel path: %v", err)
		}
		docs = append(docs, rel)
	}

	registered := map[string]bool{}
	for _, key := range RegisteredHintKeys() {
		registered[key] = true
	}

	backtick := regexp.MustCompile("`([^`\n]+)`")
	tokenKey := regexp.MustCompile(`^([a-z][a-z0-9-]*)@`)
	var offenders []string
	for _, rel := range docs {
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, m := range backtick.FindAllStringSubmatch(string(data), -1) {
			inner := m[1]
			// Compound forms (check@<fn>→use@<fn>) and pair listings
			// (src@N/certain-null) are split so every value-bearing half is
			// checked on its own.
			for _, frag := range strings.FieldsFunc(inner, func(r rune) bool {
				return r == '→' || r == '/' || r == '|' || r == ',' || r == ' '
			}) {
				km := tokenKey.FindStringSubmatch(frag)
				if km == nil {
					continue
				}
				// Enumerated tokens (contract@known / contract@unknown /
				// guard@none) are registered as EXACT keys — their values
				// are enum members with distinct semantics, not free-form
				// values — so an exact hit satisfies the guard directly.
				if registered[frag] {
					continue
				}
				key := km[1] + "@"
				if !registered[key] {
					offenders = append(offenders, rel+": `"+frag+"` (key "+key+" not in hintTokenRegistry)")
				}
			}
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("extension documents name hint tokens the registry does not carry —\n"+
			"register them in sgre/internal/planner/hint_tokens.go (or fix the doc typo):\n%s",
			strings.Join(offenders, "\n"))
	}
}
