package evidence

import (
	"context"
	"encoding/json"
	"testing"
)

// TestRaceCondition_LocksetIntersection locks in the lockset improvement: a
// shared global written under two DIFFERENT mutexes by a thread body that is
// created twice is a race (the lockset intersection is empty), even though each
// individual write is inside a lock scope. The old "any lock range" check
// treated both writes as protected and missed it.
func TestRaceCondition_LocksetIntersection(t *testing.T) {
	store := runIndexAndDetect(t, "tc56_race_lockset.c")

	events, err := store.ListEventsByType(context.Background(), "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}

	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g" && props.Category == "shared_data_race" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a shared_data_race for g (written under m1 and m2), got no matching event")
	}
}

// TestRaceCondition_ConditionalLock locks in the CFG must-hold lockset: a mutex
// acquired only on one branch does NOT protect a write that sits textually
// between the lock and unlock lines. The line-range approximation treated that
// write as held; the CFG analysis sees the lock is conditional and flags it.
func TestRaceCondition_ConditionalLock(t *testing.T) {
	store := runIndexAndDetect(t, "tc58_race_conditional_lock.c")

	events, err := store.ListEventsByType(context.Background(), "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}
	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g" && props.Category == "shared_data_race" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a shared_data_race for g (write under a conditional lock), got no matching event")
	}
}

// TestRaceCondition_CrossFunction locks in the cross-function lockset pass: two
// DIFFERENT thread functions, each created once, write the same global under
// different mutexes — a race the per-function pass missed (each function had
// only one instance).
func TestRaceCondition_CrossFunction(t *testing.T) {
	store := runIndexAndDetect(t, "tc57_race_cross_function.c")

	events, err := store.ListEventsByType(context.Background(), "RACE_CONDITION")
	if err != nil {
		t.Fatalf("list RACE_CONDITION: %v", err)
	}

	found := false
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Category string `json:"category"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Variable == "g" && props.Category == "shared_data_race" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a cross-function shared_data_race for g (t1 under m1, t2 under m2), got no matching event")
	}
}
