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

func isExecvFamily(name string) bool {
	switch name {
	case "execv", "execvp", "execve", "execl", "execlp", "execle",
		"posix_spawn", "posix_spawnp":
		return true
	}
	return false
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
		// argument_injection (CWE-88): execve/execv/etc. are listed in
		// SafeFunctions because they are shell-safe (no metacharacter
		// interpretation), which is correct for command_injection (CWE-78).
		// But the SAME calls are argument-injection sinks — their argv array
		// can carry attacker-controlled options — so the IsSafeFunction
		// exclusion must NOT fire for argument_injection. Only a project safe
		// wrapper (SafeExecArg etc.) may dismiss it.
		if c.Category == "argument_injection" {
			if apikb.IsSafeWrapper(c.FunctionName) {
				dropped = dismiss(dropped, c, f.Name(), fmt.Sprintf("function %s is a safe wrapper for argument injection", c.FunctionName))
				continue
			}
			kept = append(kept, c)
			continue
		}
		// path_traversal (CWE-22): openat is listed in SafeFunctions because its
		// dirfd form is a safe relative-path open, but it is ALSO a path-traversal
		// sink (a relative path built from attacker-controlled input can escape the
		// intended directory). The IsSafeFunction exclusion must NOT fire for
		// path_traversal.
		if c.Category == "path_traversal" {
			kept = append(kept, c)
			continue
		}
		if c.Category == "command_injection" && isExecvFamily(c.APIName) {
			kept = append(kept, c)
			continue
		}
		reason := ""
		// Project safe wrapper: match on the containing function name (a curated
		// list of THIS project's own framework entry points, e.g. SafeCopy_copy).
		if apikb.IsSafeWrapper(c.FunctionName) {
			reason = fmt.Sprintf("function %s is a safe wrapper", c.FunctionName)
		} else if apikb.IsSafeFunction(c.APIName) {
			reason = fmt.Sprintf("API %s is a known-safe function", c.APIName)
		}
		// NOTE: c.VariableName and c.FunctionName are deliberately NOT checked
		// against IsSafeFunction. For signal-handler / dangerous-function the
		// variable field carries the CALLED function name; and a containing
		// function merely NAMED like a libc safe API (e.g. a user's own `strncpy`)
		// is not the libc function — both are name coincidences that would
		// silently drop a candidate. Only the curated IsSafeWrapper list may
		// exempt a whole function.
		if reason != "" {
			dropped = dismiss(dropped, c, f.Name(), reason)
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped, nil
}

// ReleaseFilter removes candidates whose resource was released at the SAME
// allocation/acquire site, keyed by (function, variable, source line). The
// detector emits a release event per released source line (its `alloc_line`
// property), so a release on one site no longer drops a sibling site that
// genuinely leaks (`p = malloc(); p = malloc(); free(p)` leaks the first block
// even though the second is released).
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
			key := fmt.Sprintf("%d:%s:%d", e.EntityID, props.Variable, props.AllocLine)
			releaseKeys[key] = true
		}
	}

	kept, dropped := partition(candidates,
		func(c Candidate) bool {
			key := fmt.Sprintf("%d:%s:%d", c.FunctionID, c.VariableName, c.Line)
			return !releaseKeys[key]
		},
		func(c Candidate) string {
			return fmt.Sprintf("variable %s is released in function %s", c.VariableName, c.FunctionName)
		},
		f.Name())
	return kept, dropped, nil
}

// LeakProofFilter promotes a memory-leak candidate whose detector proved the
// pointer is DEFINITELY lost — no free/transfer/escape on any path, marked by the
// detector's `definite` property on the MEMORY_ALLOC event — to the confirmed
// tier (ML-01/18). A conditional leak (freed/escaped on some path only) carries
// no marker and stays suspected for the AI.
type LeakProofFilter struct {
	store db.Store
}

func NewLeakProofFilter(store db.Store) *LeakProofFilter {
	return &LeakProofFilter{store: store}
}

func (f *LeakProofFilter) Name() string { return "leak_proof" }

func (f *LeakProofFilter) Apply(ctx context.Context, candidates []Candidate) ([]Candidate, []Dismissed, error) {
	events, err := f.store.ListEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		return nil, nil, fmt.Errorf("leak proof: %w", err)
	}
	definite := make(map[int64]bool, len(events))
	for _, e := range events {
		if parseEventProps(e.Properties).Definite == "true" {
			definite[e.ID] = true
		}
	}
	kept := make([]Candidate, 0, len(candidates))
	for _, c := range candidates {
		if definite[c.DerefEventID] {
			c.SuspicionLevel = "confirmed"
		}
		kept = append(kept, c)
	}
	return kept, nil, nil
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
