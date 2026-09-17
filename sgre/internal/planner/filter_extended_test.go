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

func TestSafeFunctionFilter_CommandInjectionExecveStillDropped(t *testing.T) {
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
	if len(kept) != 0 {
		t.Errorf("command_injection + execve should still be dropped by IsSafeFunction, got kept=%d", len(kept))
	}
	if len(dropped) != 1 {
		t.Errorf("command_injection + execve should still be dropped, got dropped=%d", len(dropped))
	}
}
