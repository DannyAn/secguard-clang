package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestDataRepresentationDetector(t *testing.T) {
	store := runOneDetector(t, "tc120_data_representation.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDataRepresentationDetector(s, p, l) })
	if got := eventCount(t, store, "DATA_REPRESENTATION_MISMATCH"); got != 1 {
		t.Errorf("expected 1 DATA_REPRESENTATION_MISMATCH event (char buffer + pointer comparator), got %d", got)
	}
}

// TestDataRepresentationDetector_Properties pins the evidence fields: the event
// must carry the comparator (function), the base variable, the base element
// type (expected) and the comparator's cast target (actual).
func TestDataRepresentationDetector_Properties(t *testing.T) {
	store := runOneDetector(t, "tc120_data_representation.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDataRepresentationDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "DATA_REPRESENTATION_MISMATCH")
	if err != nil {
		t.Fatalf("list DATA_REPRESENTATION_MISMATCH events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	var props struct {
		Function string `json:"function"`
		Variable string `json:"variable"`
		Expected string `json:"expected"`
		Actual   string `json:"actual"`
	}
	if err := json.Unmarshal([]byte(events[0].Properties), &props); err != nil {
		t.Fatalf("unmarshal props: %v", err)
	}
	if props.Function != "cmp_ptr" {
		t.Errorf("function = %q, want cmp_ptr", props.Function)
	}
	if props.Variable != "buf" {
		t.Errorf("variable = %q, want buf", props.Variable)
	}
	if props.Expected != "char" {
		t.Errorf("expected (base element) = %q, want char", props.Expected)
	}
	if props.Actual != "char **" {
		t.Errorf("actual (comparator cast) = %q, want char **", props.Actual)
	}
}
