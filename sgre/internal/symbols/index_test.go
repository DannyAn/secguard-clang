package symbols

import (
	"reflect"
	"testing"
)

func TestMacroIndexNamesAndResolve(t *testing.T) {
	idx := &MacroIndex{
		files: 2,
		byName: map[string][]MacroDef{
			"B": {{Name: "B", File: "x.h", Line: 2}},
			"A": {
				{Name: "A", File: "x.h", Line: 1},
				{Name: "A", File: "y.h", Line: 1},
			},
		},
	}

	if got, want := idx.Names(), []string{"A", "B"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	if got := idx.Files(); got != 2 {
		t.Errorf("Files = %d, want 2", got)
	}

	// Reference order is preserved, a repeated reference is de-duplicated by
	// (file, line), and limit caps the result.
	got := idx.Resolve([]string{"A", "A", "B"}, 0)
	want := []MacroDef{
		{Name: "A", File: "x.h", Line: 1},
		{Name: "A", File: "y.h", Line: 1},
		{Name: "B", File: "x.h", Line: 2},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Resolve = %v, want %v", got, want)
	}
	if got := idx.Resolve([]string{"A", "B"}, 2); len(got) != 2 {
		t.Errorf("Resolve(limit=2) = %v, want 2 entries", got)
	}
}

func TestMacroIndexNilReceiver(t *testing.T) {
	var idx *MacroIndex
	if got := idx.Files(); got != 0 {
		t.Errorf("nil Files = %d, want 0", got)
	}
	if got := idx.Lookup("A"); got != nil {
		t.Errorf("nil Lookup = %v, want nil", got)
	}
	if got := idx.Names(); got != nil {
		t.Errorf("nil Names = %v, want nil", got)
	}
	if got := idx.Resolve([]string{"A"}, 0); got != nil {
		t.Errorf("nil Resolve = %v, want nil", got)
	}
}
