package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// DismissAllRunner is the dry-run / smoke-test Runner: it returns a dismissed
// verdict for every expected candidate. It proves the executor wiring (re-plan
// -> batch -> assemble -> run -> audit -> persist) end-to-end without an LLM, so
// the classify command can be exercised in CI and by a release gate before the
// real subprocess Runner is enabled.
type DismissAllRunner struct{}

func (DismissAllRunner) Run(_ context.Context, p Prompt) ([]Verdict, error) {
	out := make([]Verdict, 0, len(p.Expected))
	for _, exp := range p.Expected {
		out = append(out, Verdict{Seq: exp.Seq, Status: "dismissed", CWE: "", Reason: "dry-run dismiss"})
	}
	return out, nil
}

// SubprocessRunner runs a zero-tool worker as a subprocess: it feeds the prompt
// on stdin and parses the forced JSON output contract from stdout. The command
// is configurable (default "codeagent --print") so a production install can point
// it at its local agent binary. This is the route-B LLM call surface — it needs
// per-environment validation (binary path, auth, rate limits) before it is
// enabled via ai_stage_mode = "executor".
type SubprocessRunner struct {
	Command []string
}

func NewSubprocessRunner(command []string) *SubprocessRunner {
	if len(command) == 0 {
		command = []string{"codeagent", "--print"}
	}
	return &SubprocessRunner{Command: command}
}

func (r *SubprocessRunner) Run(ctx context.Context, p Prompt) ([]Verdict, error) {
	cmd := exec.CommandContext(ctx, r.Command[0], r.Command[1:]...)
	cmd.Stdin = bytes.NewReader([]byte(p.Text))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("worker subprocess: %w: %s", err, stderr.String())
	}

	var raw []json.RawMessage
	// The forced contract is a JSON array of verdicts; accept a leading fenced
	// block by trimming to the first '[' / last ']'.
	out := bytes.TrimSpace(stdout.Bytes())
	if i := bytes.IndexByte(out, '['); i >= 0 {
		out = out[i:]
	}
	if j := bytes.LastIndexByte(out, ']'); j >= 0 {
		out = out[:j+1]
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("worker subprocess: parse verdicts: %w (stdout=%s)", err, stdout.String())
	}

	verdicts := make([]Verdict, 0, len(raw))
	for _, rj := range raw {
		var v Verdict
		if err := json.Unmarshal(rj, &v); err != nil {
			return nil, fmt.Errorf("worker subprocess: parse verdict: %w (%s)", err, string(rj))
		}
		verdicts = append(verdicts, v)
	}
	return verdicts, nil
}
