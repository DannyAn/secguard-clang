package planner

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
)

type SafeFunctionFilter struct {
	store db.Store
}

func NewSafeFunctionFilter(store db.Store) *SafeFunctionFilter {
	return &SafeFunctionFilter{store: store}
}

func (f *SafeFunctionFilter) Name() string { return "safe_function_exclude" }

func (f *SafeFunctionFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	kept := make([]Candidate, 0, len(candidates))
	var dropped []Dismissed
	for _, c := range candidates {
		reason := ""
		// Project safe wrapper: match on the containing function name.
		if apikb.IsSafeWrapper(c.FunctionName) {
			reason = fmt.Sprintf("function %s is a safe wrapper", c.FunctionName)
		} else if apikb.IsSafeFunction(c.APIName) ||
			apikb.IsSafeFunction(c.FunctionName) ||
			apikb.IsSafeFunction(c.VariableName) {
			reason = fmt.Sprintf("API %s is a known-safe function", c.APIName)
		}
		if reason != "" {
			dropped = dismiss(dropped, c, f.Name(), reason)
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// ReleaseFilter removes candidates whose resource was released in the same
// function, keyed by (function, variable). It replaces the previous
// copy-pasted MemoryReleaseFilter/ResourceReleaseFilter pair.
type ReleaseFilter struct {
	store     db.Store
	eventType string
}

func NewReleaseFilter(store db.Store, eventType string) *ReleaseFilter {
	return &ReleaseFilter{store: store, eventType: eventType}
}

func (f *ReleaseFilter) Name() string { return "has_release" }

func (f *ReleaseFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	releaseEvents, err := f.store.ListEventsByType(ctx, f.eventType)
	if err != nil {
		return nil, nil, fmt.Errorf("release filter (%s): %w", f.eventType, err)
	}

	releaseKeys := make(map[string]bool)
	for _, e := range releaseEvents {
		props := parseEventProps(e.Properties)
		if props.Variable != "" {
			key := fmt.Sprintf("%d:%s", e.EntityID, props.Variable)
			releaseKeys[key] = true
		}
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			key := fmt.Sprintf("%d:%s", c.FunctionID, c.VariableName)
			return !releaseKeys[key]
		},
		func(c Candidate) string {
			return fmt.Sprintf("variable %s is released in function %s", c.VariableName, c.FunctionName)
		},
		f.Name())
	return kept, dropped, nil
}
