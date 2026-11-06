package planner

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestArrayOOBPrecedence_NullDerefSuppressed(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 20})

	loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})

	s.InsertEvent(context.Background(), &db.SecurityEvent{
		EventType:  "BUFFER_ACCESS",
		EntityID:   funcID,
		LocationID: loc,
		Properties: `{"array":"buf","index":"64","category":"buffer_overflow"}`,
	})

	candidates := []Candidate{
		{VariableName: "buf", FileID: fileID, Line: 10, NonNullable: true, LocationID: loc},
	}

	f := NewArrayOOBPrecedenceFilter(s)
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates (null-deref suppressed by buffer-overflow precedence), got %d", len(result))
	}
}

func TestArrayOOBPrecedence_HeapPointerRetained(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 20})

	loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})

	s.InsertEvent(context.Background(), &db.SecurityEvent{
		EventType:  "BUFFER_ACCESS",
		EntityID:   funcID,
		LocationID: loc,
		Properties: `{"array":"buf","index":"i","category":"buffer_overflow"}`,
	})

	candidates := []Candidate{
		{VariableName: "ptr", FileID: fileID, Line: 10, NonNullable: false, LocationID: loc},
	}

	f := NewArrayOOBPrecedenceFilter(s)
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 candidate (heap pointer retained), got %d", len(result))
	}
}

func TestArrayOOBPrecedence_NoBufferAccessEvent(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})

	loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})

	candidates := []Candidate{
		{VariableName: "buf", FileID: fileID, Line: 10, NonNullable: true, LocationID: loc},
	}

	f := NewArrayOOBPrecedenceFilter(s)
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 candidate (no BUFFER_ACCESS event → retained), got %d", len(result))
	}
}

// The events table stores one location row per event (no uniqueness), so a
// null-deref candidate and the BUFFER_ACCESS event that covers the same line
// have DIFFERENT location ids. The precedence match must be by (file,line), not
// by location id — an id-only match silently suppresses nothing.
func TestArrayOOBPrecedence_MatchesDistinctLocationRowsOnSameLine(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 20})

	eventLoc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})
	candidateLoc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: 10})
	if eventLoc == candidateLoc {
		t.Fatalf("test requires distinct location rows, both are %d", eventLoc)
	}

	s.InsertEvent(context.Background(), &db.SecurityEvent{
		EventType:  "BUFFER_ACCESS",
		EntityID:   funcID,
		LocationID: eventLoc,
		Properties: `{"array":"buf","index":"64","category":"buffer_overflow"}`,
	})

	candidates := []Candidate{
		{VariableName: "buf", FileID: fileID, Line: 10, NonNullable: true, LocationID: candidateLoc},
	}

	f := NewArrayOOBPrecedenceFilter(s)
	result, _, err := f.Apply(context.Background(), candidates)
	if err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 candidates (same file:line must be suppressed even with distinct location ids), got %d", len(result))
	}
}
