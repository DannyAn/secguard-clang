//go:build !nosqlite

package cli

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
	"github.com/DannyAn/secguard-clang/internal/worker"
)

func TestClassifyAgentModeNoop(t *testing.T) {
	ctx := context.Background()
	stdout, _, code := captureOutput(func() int {
		return runClassifyCmd(ctx, []string{"--mode", "agent"})
	})
	if code != 0 {
		t.Fatalf("agent mode must be a no-op success, got %d: %s", code, stdout)
	}
}

func TestUpsertExecutorFinding(t *testing.T) {
	ctx := context.Background()
	s := db.NewTestStore(t)

	c := planner.EvidenceItem{
		Type:              "null_deref",
		VulnerabilityType: "null-deref",
		SuspicionLevel:    "suspected",
		Target:            planner.TargetInfo{File: "a.c", Function: "f", Line: 42, Variable: "p"},
		Hint:              "guard@none",
	}
	if err := upsertExecutorFinding(ctx, s, "sc_test", "null-deref", c, worker.Verdict{Seq: 1, Status: "confirmed", Reason: "no guard"}); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ListFindingsByScanID(ctx, "sc_test")
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "CWE-476" || findings[0].LineNumber != 42 {
		t.Fatalf("executor finding not persisted correctly: %+v", findings)
	}
}
