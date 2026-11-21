package worker

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestSubprocessRunner_Run(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	r := NewSubprocessRunner([]string{"sh", "-c",
		`cat >/dev/null; printf '%s' '[{"seq":1,"status":"confirmed","cwe":"CWE-476","reason":"ok"}]'`})
	vs, err := r.Run(context.Background(), Prompt{Text: "prompt"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(vs) != 1 || vs[0].Seq != 1 || vs[0].Status != "confirmed" || vs[0].CWE != "CWE-476" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestSubprocessRunner_CommandErrorCarriesStderr(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	r := NewSubprocessRunner([]string{"sh", "-c", "echo boom >&2; exit 1"})
	_, err := r.Run(context.Background(), Prompt{Text: "prompt"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v, want stderr text", err)
	}
}

func TestSubprocessRunner_ParseError(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	r := NewSubprocessRunner([]string{"sh", "-c", "cat >/dev/null; echo not-json"})
	if _, err := r.Run(context.Background(), Prompt{Text: "prompt"}); err == nil {
		t.Fatal("expected a parse error")
	}
}
