package planner

import (
	"context"
	"testing"
)

func TestTypeExprFilter_DropsSizeofPseudoDeref(t *testing.T) {
	f := NewTypeExprFilter()
	candidates := []Candidate{
		{VariableName: "p", IsTypeExpr: true, Line: 10},
		{VariableName: "q", IsTypeExpr: false, Line: 20},
	}
	kept, dropped, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(kept) != 1 || kept[0].VariableName != "q" {
		t.Errorf("expected only the non-type-expr candidate 'q' kept, got %+v", kept)
	}
	if len(dropped) != 1 || dropped[0].VariableName != "p" {
		t.Errorf("expected the is_type_expr candidate 'p' dropped, got %+v", dropped)
	}
	if dropped[0].Filter != "sizeof_pseudo_deref" {
		t.Errorf("expected dropped filter name 'sizeof_pseudo_deref', got %q", dropped[0].Filter)
	}
}

func TestTypeExprFilter_NoTagKeepsAll(t *testing.T) {
	f := NewTypeExprFilter()
	candidates := []Candidate{
		{VariableName: "p", Line: 10},
		{VariableName: "q", Line: 20},
	}
	kept, dropped, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(kept) != 2 {
		t.Errorf("expected both untagged candidates kept, got %d", len(kept))
	}
	if len(dropped) != 0 {
		t.Errorf("expected no drops without the is_type_expr tag, got %+v", dropped)
	}
}
