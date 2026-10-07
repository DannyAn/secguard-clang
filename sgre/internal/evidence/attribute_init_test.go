package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// TestAttributeInitDetectors locks in the tree-sitter-c v0.24.4 attribute fix:
// `int *p __attribute__((...)) = malloc(10)` inserts an attribute_specifier
// between the declarator and the value inside init_declarator. Detectors that
// read the initializer by positional index NamedChildren()[1] would read the
// attribute instead, silently dropping malloc / explicit-NULL sources. Every
// such detector must resolve the initializer by field name.
func TestAttributeInitDetectors(t *testing.T) {
	store := runIndexAndDetect(t, "tc121_attribute_init.c")
	ctx := context.Background()

	type prop struct {
		Variable string `json:"variable"`
		Origin   string `json:"origin"`
	}

	allocVars := map[string]bool{}
	if evs, err := store.ListEventsByType(ctx, "MEMORY_ALLOC"); err != nil {
		t.Fatalf("list MEMORY_ALLOC: %v", err)
	} else {
		for _, e := range evs {
			var p prop
			_ = json.Unmarshal([]byte(e.Properties), &p)
			allocVars[p.Variable] = true
		}
	}
	if !allocVars["lp"] {
		t.Errorf("ml_attr_leak: `char *lp __attribute__((aligned(16))) = malloc(10)` must be an allocation, got allocs=%v", allocVars)
	}

	nullSources := map[string]bool{} // "variable:origin"
	if evs, err := store.ListEventsByType(ctx, "NULL_VALUE"); err != nil {
		t.Fatalf("list NULL_VALUE: %v", err)
	} else {
		for _, e := range evs {
			var p prop
			_ = json.Unmarshal([]byte(e.Properties), &p)
			nullSources[p.Variable+":"+p.Origin] = true
		}
	}
	for _, want := range []string{"p:malloc", "lp:malloc", "p:explicit_null"} {
		if !nullSources[want] {
			t.Errorf("missing null source %q, got %v", want, nullSources)
		}
	}
}
