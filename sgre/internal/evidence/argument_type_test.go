package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func TestArgumentTypeDetector(t *testing.T) {
	store := runOneDetector(t, "tc119_argument_type.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewArgumentTypeDetector(s, p, l) })
	if got := eventCount(t, store, "ARGUMENT_TYPE_MISMATCH"); got != 2 {
		t.Errorf("expected 2 ARGUMENT_TYPE_MISMATCH events (bool→uint, uint32→uint64), got %d", got)
	}
}

// TestArgumentTypeDetector_Properties pins the root-cause evidence fields: the
// event must carry the callee, source variable, expected parameter type, actual
// pre-cast pointer type, and the explicit cast target, so the AI agent sees the
// contract violation rather than a bare cast.
func TestArgumentTypeDetector_Properties(t *testing.T) {
	store := runOneDetector(t, "tc119_argument_type.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewArgumentTypeDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "ARGUMENT_TYPE_MISMATCH")
	if err != nil {
		t.Fatalf("list ARGUMENT_TYPE_MISMATCH events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 ARGUMENT_TYPE_MISMATCH events, got %d", len(events))
	}

	type props struct {
		Function string `json:"function"`
		Variable string `json:"variable"`
		Expected string `json:"expected"`
		Actual   string `json:"actual"`
		Cast     string `json:"cast"`
	}
	byVar := map[string]props{}
	for _, e := range events {
		var p props
		if err := json.Unmarshal([]byte(e.Properties), &p); err != nil {
			t.Fatalf("unmarshal event props: %v", err)
		}
		byVar[p.Variable] = p
	}

	flag, ok := byVar["flag"]
	if !ok {
		t.Fatalf("missing bool→uint event, got %+v", byVar)
	}
	if flag.Function != "sink_uint" || flag.Expected != "uint *" || flag.Actual != "bool *" || flag.Cast != "uint *" {
		t.Errorf("bool→uint props wrong: %+v", flag)
	}

	x, ok := byVar["x"]
	if !ok {
		t.Fatalf("missing uint32→uint64 event, got %+v", byVar)
	}
	if x.Function != "sink_u64" || x.Expected != "uint64_t *" || x.Actual != "uint32_t *" || x.Cast != "uint64_t *" {
		t.Errorf("uint32→uint64 props wrong: %+v", x)
	}
}
