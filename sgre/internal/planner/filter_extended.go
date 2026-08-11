package planner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type SafeFunctionFilter struct {
	store db.Store
}

func NewSafeFunctionFilter(store db.Store) *SafeFunctionFilter {
	return &SafeFunctionFilter{store: store}
}

func (f *SafeFunctionFilter) Name() string { return "safe_function_exclude" }

func (f *SafeFunctionFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	safeFuncs := map[string]bool{
		"memcpy_s": true, "strcpy_s": true, "sprintf_s": true, "strcat_s": true,
		"snprintf": true, "strncpy": true, "strlcpy": true, "strlcat": true,
		"execve":             true,
		"sqlite3_prepare_v2": true, "sqlite3_bind_text": true, "sqlite3_bind_int": true,
		"mkstemp": true, "openat": true,
	}
	safeWrappers := map[string]bool{
		"SafeCopy_copy": true, "SafeCopy_strcpy": true,
		"SafeQuery_prepare": true, "SafeQuery_bind_text": true, "SafeQuery_exec": true,
		"ResourceHandle_create": true, "ResourceHandle_destroy": true,
		"LockGuard_create": true, "LockGuard_release": true,
	}

	var result []Candidate
	for _, c := range candidates {
		if safeWrappers[c.FunctionName] {
			continue
		}
		drop := false
		for sf := range safeFuncs {
			if strings.Contains(c.VariableName, sf) {
				drop = true
				break
			}
		}
		if drop {
			continue
		}
		result = append(result, c)
	}
	return result, nil
}

type BoundsCheckFilter struct {
	store db.Store
}

func NewBoundsCheckFilter(store db.Store) *BoundsCheckFilter {
	return &BoundsCheckFilter{store: store}
}

func (f *BoundsCheckFilter) Name() string { return "bounds_check" }

func (f *BoundsCheckFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	guardEvents, err := f.store.ListEventsByType(ctx, "NULL_GUARD")
	if err != nil {
		return nil, fmt.Errorf("bounds check filter: %w", err)
	}

	type guardMeta struct {
		strength string
	}
	funcGuardStrength := make(map[int64]string)
	for _, e := range guardEvents {
		var props struct {
			Condition  string `json:"condition"`
			ScopeStart int    `json:"scope_start"`
			ScopeEnd   int    `json:"scope_end"`
			Strength   string `json:"strength"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		if props.Condition != "NULL_CHECK" && props.Condition != "TRUTH_CHECK" {
			continue
		}
		strength := props.Strength
		if strength == "" {
			strength = "weak"
		}
		if strength == "strong" {
			funcGuardStrength[e.EntityID] = "strong"
		} else if _, exists := funcGuardStrength[e.EntityID]; !exists {
			funcGuardStrength[e.EntityID] = "weak"
		}
	}

	var result []Candidate
	for _, c := range candidates {
		strength, hasGuard := funcGuardStrength[c.FunctionID]
		if !hasGuard {
			result = append(result, c)
			continue
		}
		if strength == "strong" {
			continue
		}
		c.GuardStrength = "weak"
		c.IsGuarded = true
		c.SuspicionLevel = "suspected"
		result = append(result, c)
	}
	return result, nil
}

type MemoryReleaseFilter struct {
	store db.Store
}

func NewMemoryReleaseFilter(store db.Store) *MemoryReleaseFilter {
	return &MemoryReleaseFilter{store: store}
}

func (f *MemoryReleaseFilter) Name() string { return "has_release" }

func (f *MemoryReleaseFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	releaseEvents, err := f.store.ListEventsByType(ctx, "MEMORY_RELEASE")
	if err != nil {
		return nil, fmt.Errorf("memory release filter: %w", err)
	}

	releaseKeys := make(map[string]bool)
	for _, e := range releaseEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable != "" {
			key := fmt.Sprintf("%d:%s", e.EntityID, props.Variable)
			releaseKeys[key] = true
		}
	}

	var result []Candidate
	for _, c := range candidates {
		key := fmt.Sprintf("%d:%s", c.FunctionID, c.VariableName)
		if !releaseKeys[key] {
			result = append(result, c)
		}
	}
	return result, nil
}

type ResourceReleaseFilter struct {
	store db.Store
}

func NewResourceReleaseFilter(store db.Store) *ResourceReleaseFilter {
	return &ResourceReleaseFilter{store: store}
}

func (f *ResourceReleaseFilter) Name() string { return "has_release" }

func (f *ResourceReleaseFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, error) {
	releaseEvents, err := f.store.ListEventsByType(ctx, "RESOURCE_RELEASE")
	if err != nil {
		return nil, fmt.Errorf("resource release filter: %w", err)
	}

	releaseKeys := make(map[string]bool)
	for _, e := range releaseEvents {
		var props struct {
			Variable string `json:"variable"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable != "" {
			key := fmt.Sprintf("%d:%s", e.EntityID, props.Variable)
			releaseKeys[key] = true
		}
	}

	var result []Candidate
	for _, c := range candidates {
		key := fmt.Sprintf("%d:%s", c.FunctionID, c.VariableName)
		if !releaseKeys[key] {
			result = append(result, c)
		}
	}
	return result, nil
}
