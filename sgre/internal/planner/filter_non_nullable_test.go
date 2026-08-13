package planner

import (
	"context"
	"testing"
)

func TestNonNullableFilter_StackArraySuppressed(t *testing.T) {
	f := NewNonNullableFilter()
	candidates := []Candidate{
		{VariableName: "buf", NonNullable: true, Line: 10},
	}
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates (stack array suppressed), got %d", len(result))
	}
}

func TestNonNullableFilter_StaticArraySuppressed(t *testing.T) {
	f := NewNonNullableFilter()
	candidates := []Candidate{
		{VariableName: "buf", NonNullable: true, Line: 5},
	}
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates (static array suppressed), got %d", len(result))
	}
}

func TestNonNullableFilter_HeapPointerRetained(t *testing.T) {
	f := NewNonNullableFilter()
	candidates := []Candidate{
		{VariableName: "ptr", NonNullable: false, Line: 10},
	}
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 candidate (heap pointer retained), got %d", len(result))
	}
}

func TestNonNullableFilter_FunctionParamRetained(t *testing.T) {
	f := NewNonNullableFilter()
	candidates := []Candidate{
		{VariableName: "buf", NonNullable: false, Line: 10},
	}
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 candidate (function param retained), got %d", len(result))
	}
}

func TestNonNullableFilter_MixedCandidates(t *testing.T) {
	f := NewNonNullableFilter()
	candidates := []Candidate{
		{VariableName: "buf", NonNullable: true, Line: 10},
		{VariableName: "ptr", NonNullable: false, Line: 20},
		{VariableName: "arr", NonNullable: true, Line: 30},
		{VariableName: "p", NonNullable: false, Line: 40},
	}
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 candidates (2 non-nullable suppressed), got %d", len(result))
	}
}
