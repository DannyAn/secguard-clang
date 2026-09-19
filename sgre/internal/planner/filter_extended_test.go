//go:build !nosqlite

package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestSafeFunctionFilter_ArgumentInjectionBypass(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	candidates := []Candidate{
		{FunctionName: "my_func", APIName: "execve", Category: "argument_injection", VariableName: "argv", Line: 10},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("argument_injection + execve should be kept (not dropped by IsSafeFunction), got kept=%d", len(kept))
	}
	if len(dropped) != 0 {
		t.Errorf("argument_injection + execve should not be dropped, got dropped=%d", len(dropped))
	}
}

func TestSafeFunctionFilter_ArgumentInjectionSafeWrapper(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	candidates := []Candidate{
		{FunctionName: "SafeExecArg", APIName: "execve", Category: "argument_injection", VariableName: "argv", Line: 10},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 0 {
		t.Errorf("argument_injection + SafeExecArg wrapper should be dismissed, got kept=%d", len(kept))
	}
	if len(dropped) != 1 {
		t.Errorf("argument_injection + SafeExecArg wrapper should be dismissed, got dropped=%d", len(dropped))
	}
}

func TestSafeFunctionFilter_CommandInjectionExecveTaintedPathKept(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	candidates := []Candidate{
		{FunctionName: "my_func", APIName: "execve", Category: "command_injection", VariableName: "cmd", Line: 10},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("command_injection + execve with tainted path should be kept for taint-source filter, got kept=%d", len(kept))
	}
	if len(dropped) != 0 {
		t.Errorf("command_injection + execve with tainted path should not be dropped, got dropped=%d", len(dropped))
	}
}

func TestSafeFunctionFilter_CommandInjectionExecveNonBarePathKept(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	// A command_injection candidate on an execv-family call with an empty
	// VariableName is a NON-BARE path expression (e.g. execv(getenv("X"), argv)):
	// the detector already skips constant-path execv via isConstantCommandArg,
	// so an empty VariableName here can only be an attacker-controlled expression.
	// It must be kept for the taint-source filter, not dropped as a safe function.
	candidates := []Candidate{
		{FunctionName: "my_func", APIName: "execve", Category: "command_injection", VariableName: "", Line: 10},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("command_injection + execve with non-bare path should be kept for taint-source filter, got kept=%d", len(kept))
	}
	if len(dropped) != 0 {
		t.Errorf("command_injection + execve with non-bare path should not be dropped, got dropped=%d", len(dropped))
	}
}
