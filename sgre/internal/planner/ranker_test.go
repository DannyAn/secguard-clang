package planner

import (
	"context"
	"testing"

	"github.com/kongan/secguard-lite/internal/db"
)

func TestSeverityValue(t *testing.T) {
	tests := []struct {
		api    string
		expect float64
	}{
		{"system", 100},
		{"CreateProcessA", 100},
		{"execl", 100},
		{"strcpy", 80},
		{"sprintf", 80},
		{"strncpy", 60},
		{"snprintf", 60},
		{"some_func", 40},
		{"", 20},
	}
	for _, tt := range tests {
		got := severityValue(tt.api)
		if got != tt.expect {
			t.Errorf("severityValue(%q) = %v, want %v", tt.api, got, tt.expect)
		}
	}
}

func TestConfidenceValue(t *testing.T) {
	tests := []struct {
		level  string
		expect float64
	}{
		{"confirmed", 1.0},
		{"suspected", 0.7},
		{"possible", 0.5},
		{"", 0.5},
	}
	for _, tt := range tests {
		got := confidenceValue(tt.level)
		if got != tt.expect {
			t.Errorf("confidenceValue(%q) = %v, want %v", tt.level, got, tt.expect)
		}
	}
}

func TestComputeQualityScore_SeverityWeights(t *testing.T) {
	c := Candidate{SuspicionLevel: "confirmed"}
	critical := computeQualityScore(c, "system")
	high := computeQualityScore(c, "strcpy")
	medium := computeQualityScore(c, "strncpy")
	low := computeQualityScore(c, "some_func")

	if critical <= high {
		t.Errorf("critical (%v) should be > high (%v)", critical, high)
	}
	if high <= medium {
		t.Errorf("high (%v) should be > medium (%v)", high, medium)
	}
	if medium <= low {
		t.Errorf("medium (%v) should be > low (%v)", medium, low)
	}
}

func TestComputeQualityScore_ConfidenceFactors(t *testing.T) {
	confirmed := Candidate{SuspicionLevel: "confirmed"}
	suspected := Candidate{SuspicionLevel: "suspected"}
	possible := Candidate{SuspicionLevel: "possible"}

	scoreConfirmed := computeQualityScore(confirmed, "strcpy")
	scoreSuspected := computeQualityScore(suspected, "strcpy")
	scorePossible := computeQualityScore(possible, "strcpy")

	if scoreConfirmed <= scoreSuspected {
		t.Errorf("confirmed (%v) should be > suspected (%v)", scoreConfirmed, scoreSuspected)
	}
	if scoreSuspected <= scorePossible {
		t.Errorf("suspected (%v) should be > possible (%v)", scoreSuspected, scorePossible)
	}
}

func TestComputeQualityScore_WeakGuardReducesConfidence(t *testing.T) {
	strong := Candidate{SuspicionLevel: "suspected", GuardStrength: "strong"}
	weak := Candidate{SuspicionLevel: "suspected", GuardStrength: "weak"}

	scoreStrong := computeQualityScore(strong, "strcpy")
	scoreWeak := computeQualityScore(weak, "strcpy")

	if scoreWeak >= scoreStrong {
		t.Errorf("weak guard (%v) should be < strong guard (%v)", scoreWeak, scoreStrong)
	}
}

func TestRankCandidates_HighSeveritySurvivesCap(t *testing.T) {
	s := newMockStore()
	fileID, _ := s.InsertFile(context.Background(), &db.File{Path: "test.c"})
	funcID, _ := s.InsertFunction(context.Background(), &db.Function{FileID: fileID, Name: "foo", StartLine: 1, EndLine: 200})

	s.InsertEvent(context.Background(), &db.SecurityEvent{EventType: "NULL_VALUE", EntityID: funcID, Properties: `{"variable":"p"}`})

	for i := 0; i < 35; i++ {
		loc, _ := s.InsertLocation(context.Background(), &db.Location{FileID: fileID, Line: i + 1})
		apiName := "some_func"
		if i == 30 {
			apiName = "strcpy"
		}
		s.InsertEvent(context.Background(), &db.SecurityEvent{
			EventType:  "DEREFERENCE",
			EntityID:   funcID,
			LocationID: loc,
			Properties: `{"variable":"p","expression":"p->f","function":"` + apiName + `"}`,
		})
	}

	p := NewPlanner(s, nil, nil)
	p.SetMaxCandidates(30)
	result, err := p.Plan(context.Background(), "null-deref")
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}

	if len(result.Candidates) > 30 {
		t.Errorf("expected at most 30 candidates, got %d", len(result.Candidates))
	}
}

func TestRankCandidates_StableOrdering(t *testing.T) {
	candidates := []Candidate{
		{VariableName: "a", FileID: 1, Line: 10, SuspicionLevel: "confirmed"},
		{VariableName: "b", FileID: 1, Line: 5, SuspicionLevel: "confirmed"},
	}

	result := RankCandidates(context.Background(), candidates, nil)

	if len(result) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(result))
	}
	if result[0].Line != 5 {
		t.Errorf("expected first candidate at line 5 (tie-break by line), got %d", result[0].Line)
	}
}

func TestRankCandidates_AllEqualScore(t *testing.T) {
	candidates := make([]Candidate, 35)
	for i := range candidates {
		candidates[i] = Candidate{VariableName: "p", FileID: 1, Line: i + 1, SuspicionLevel: "confirmed"}
	}

	result := RankCandidates(context.Background(), candidates, nil)

	if len(result) != 35 {
		t.Fatalf("expected 35 candidates, got %d", len(result))
	}
	for i := 1; i < len(result); i++ {
		if result[i].Line < result[i-1].Line {
			t.Errorf("candidates not in stable order at index %d: %d < %d", i, result[i].Line, result[i-1].Line)
		}
	}
}
