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
		// The bounded-copy and secure-copy categories are the detector's explicit
		// verdict that a nominally-safe API (strncpy / memcpy_s) actually
		// overflows: the size-vs-capacity check already proved/heuristically
		// flagged it. The safe-function exclusion must not override that, or the
		// overflow is silently dropped before the AI agent ever sees it.
		if c.Category == "bounded_copy_overflow" || c.Category == "bounded_copy_var_size" ||
			c.Category == "secure_copy_overflow" || c.Category == "secure_copy_var_size" ||
			c.Category == "secure_constraint_violation" ||
			c.Category == "secure_scanf_overflow" || c.Category == "secure_scanf_var_size" {
			kept = append(kept, c)
			continue
		}
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

// HardcodedSecretProofFilter promotes a hardcoded-secret candidate whose
// literal's VALUE is itself secret-shaped (a known token prefix, high Shannon
// entropy, or URL-embedded credentials — the detector's `value_proven` marker)
// to the pipeline-confirmed tier, so it is auto-confirmed. A match on the
// variable/field name alone carries no marker and stays suspected for the AI,
// which applies the skill's placeholder / test-credential false-positive rules.
// Nothing is dropped, so the split is FN-safe.
type HardcodedSecretProofFilter struct {
	store db.Store
}

func NewHardcodedSecretProofFilter(store db.Store) *HardcodedSecretProofFilter {
	return &HardcodedSecretProofFilter{store: store}
}

func (f *HardcodedSecretProofFilter) Name() string { return "hardcoded_secret_proof" }

func (f *HardcodedSecretProofFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	events, err := f.store.ListEventsByType(ctx, "HARDCODED_SECRET")
	if err != nil {
		return nil, nil, fmt.Errorf("hardcoded secret proof: %w", err)
	}
	proven := make(map[int64]bool, len(events))
	for _, e := range events {
		if parseEventProps(e.Properties).ValueProven == "true" {
			proven[e.ID] = true
		}
	}

	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if proven[c.DerefEventID] {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, nil, nil
}
