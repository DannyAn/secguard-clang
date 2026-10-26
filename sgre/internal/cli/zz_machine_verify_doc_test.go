package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Step 5.5 (the bounded machine-verdict verification pass) is the safety net
// that lets `result.sarif` be filed without a human pass: production measured a
// 75% false-positive rate on the `uninit` auto-confirm tier, and those rows are
// invisible to the AI's candidate classifier. The step is documented in the
// shared workflow; this guard keeps it from silently disappearing and keeps its
// referenced surfaces real:
//
//   - the listing goes through the `findings` table with `status='auto-confirmed'`
//     (NOT --list-auto-confirmed, which is 0 by design since the machine verdict
//     is written pre-reviewed);
//   - the row's `properties` really carry the proof basis under the names the doc
//     tells the agent to read;
//   - dismissals are written with `--review-json` and the audit is re-run.
func TestMachineVerifyStepDocumented(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		t.Helper()
		data, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read %s: %v (the guard must run inside the repo)", rel, err)
		}
		return string(data)
	}

	instructions := read(filepath.Join("extension", "shared", "command-instructions.md"))
	body := read(filepath.Join("extension", "shared", "agent-body.md"))

	for _, want := range []string{
		"Step 5.5",
		"status='auto-confirmed'",
		"--review-json",
		"CWE-457",
		"CWE-476",
		"CWE-134",
		"CWE-369",
	} {
		if !strings.Contains(instructions, want) {
			t.Errorf("command-instructions.md: machine-verdict verification step is missing %q", want)
		}
	}
	if !strings.Contains(body, "verified ONCE") {
		t.Errorf("agent-body.md must state that machine verdicts are verified once before delivery")
	}

	// The proof basis the doc tells the agent to read must actually be persisted
	// by autoConfirmFindings; a rename here would make Step 5.5 unactionable.
	sources, err := filepath.Glob("*.go")
	if err != nil || len(sources) == 0 {
		t.Fatalf("no Go sources in the cli package: %v", err)
	}
	var cliSrc strings.Builder
	for _, f := range sources {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatalf("read %s: %v", f, rerr)
		}
		cliSrc.Write(data)
	}
	for _, key := range []string{"auto_confirm_evidence", "auto_confirm_hint_tokens", "auto_confirm_verdict_facts"} {
		if !strings.Contains(cliSrc.String(), key) {
			t.Errorf("auto-confirm properties key %q is no longer written by the cli package — update Step 5.5's guidance", key)
		}
		if !strings.Contains(instructions, key) {
			t.Errorf("command-instructions.md: Step 5.5 must name the %q property it reads", key)
		}
	}
}
