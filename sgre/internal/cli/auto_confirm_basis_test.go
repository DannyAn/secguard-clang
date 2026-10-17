package cli

import "testing"

// TestAutoConfirmBasis pins the re-review basis decode (Evidence Contract v2,
// D5 fix): findings auto-confirmed with hint tokens + verdict facts carry them
// in properties, and the re-review listing surfaces them so the reviewer sees
// the SAME basis the machine verdict used. Pre-v2 findings (or unparseable
// properties) degrade to the old snippet+context-only behaviour.
func TestAutoConfirmBasis(t *testing.T) {
	t.Run("empty and legacy properties", func(t *testing.T) {
		for _, props := range []string{"", `{"auto_confirm_evidence":[]}`, "not json"} {
			hint, facts := autoConfirmBasis(props)
			if hint != "" || facts != nil {
				t.Fatalf("properties %q: hint=%q facts=%v, want empty", props, hint, facts)
			}
		}
	})

	t.Run("v2 basis decoded", func(t *testing.T) {
		props := `{"auto_confirm_evidence":[],"auto_confirm_hint_tokens":["null@malloc-fail","guard@none"],` +
			`"auto_confirm_verdict_facts":[{"Token":"null@malloc-fail","Detail":"the null source is malloc"}]}`
		hint, facts := autoConfirmBasis(props)
		if hint != "null@malloc-fail guard@none" {
			t.Fatalf("hint = %q, want the joined token sequence", hint)
		}
		if len(facts) != 1 || facts[0]["token"] != "null@malloc-fail" || facts[0]["detail"] != "the null source is malloc" {
			t.Fatalf("facts = %v, want the structured verdict fact", facts)
		}
	})
}
