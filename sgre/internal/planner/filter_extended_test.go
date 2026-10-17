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

// TestSafeFunctionFilter_FormatStringUnderscoreSNotDropped pins the detector/
// filter contradiction: the Annex K `_s` printf variants (sprintf_s, snprintf_s,
// vsprintf_s, vsnprintf_s) are in SafeFunctions because they bounds-check the
// DESTINATION, but the format-string detector deliberately emits them for a
// non-literal FORMAT argument (CWE-134). IsSafeFunction firing here dropped
// 100% of them before the AI saw them. A curated safe wrapper may still dismiss.
func TestSafeFunctionFilter_FormatStringUnderscoreSNotDropped(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	candidates := []Candidate{
		{FunctionName: "sink", APIName: "sprintf_s", Category: "format_string", VariableName: "fmt", Line: 4},
		{FunctionName: "sink", APIName: "snprintf_s", Category: "format_string", VariableName: "fmt", Line: 5},
		{FunctionName: "sink", APIName: "vsprintf_s", Category: "format_string", VariableName: "fmt", Line: 6},
		{FunctionName: "sink", APIName: "vsnprintf_s", Category: "format_string", VariableName: "fmt", Line: 7},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != len(candidates) {
		t.Errorf("format_string on a _s printf variant must reach the AI (bounds safety does not cover a non-literal fmt): kept=%d want=%d", len(kept), len(candidates))
	}
	if len(dropped) != 0 {
		t.Errorf("format_string on a _s printf variant must not be dropped by IsSafeFunction, got dropped=%d", len(dropped))
	}

	// A curated project wrapper that validates the format may still dismiss.
	wrapped := []Candidate{
		{FunctionName: "validate_log", APIName: "sprintf_s", Category: "format_string", VariableName: "fmt", Line: 9},
	}
	kept, dropped, err = f.Apply(ctx, wrapped)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 0 || len(dropped) != 1 {
		t.Errorf("format_string inside a safe wrapper should be dismissed, got kept=%d dropped=%d", len(kept), len(dropped))
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

// TestSafeFunctionFilter_ResourceAcquireNotDropped pins RL-13: mkstemp is in
// SafeFunctions because it creates a temp file without the mktemp TOCTOU race,
// but the fd it returns still leaks when never closed. IsSafeFunction firing on
// the acquire dropped the candidate before the leak proof could run. A curated
// RAII wrapper may still dismiss.
func TestSafeFunctionFilter_ResourceAcquireNotDropped(t *testing.T) {
	store := db.NewTestStore(t)
	f := NewSafeFunctionFilter(store)
	ctx := context.Background()

	candidates := []Candidate{
		{FunctionName: "rl13_mkstemp_leak", APIName: "mkstemp", Category: "resource_acquire", VariableName: "fd", Line: 153, DefiniteLeak: true},
	}
	kept, dropped, err := f.Apply(ctx, candidates)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 1 {
		t.Errorf("resource_acquire via mkstemp must be kept (temp-file safety does not cover the fd lifecycle), got kept=%d", len(kept))
	}
	if len(dropped) != 0 {
		t.Errorf("resource_acquire via mkstemp must not be dropped by IsSafeFunction, got dropped=%d", len(dropped))
	}

	wrapped := []Candidate{
		{FunctionName: "ResourceHandle_create", APIName: "mkstemp", Category: "resource_acquire", VariableName: "fd", Line: 160, DefiniteLeak: true},
	}
	kept, dropped, err = f.Apply(ctx, wrapped)
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(kept) != 0 || len(dropped) != 1 {
		t.Errorf("resource_acquire inside an RAII safe wrapper should be dismissed, got kept=%d dropped=%d", len(kept), len(dropped))
	}
}
