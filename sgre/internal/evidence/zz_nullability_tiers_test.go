package evidence

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestNullSource_NullabilityTiers verifies the three-state nullability model
// in detectExternalCall:
//
//  1. maybe-null libc (strchr) → NULL_VALUE with origin="strchr" (auto-confirm
//     channel, same tier as allocators)
//  2. never-null libc (strerror) → NO NULL_VALUE event (skipped, the return is
//     guaranteed non-null by contract)
//  3. unknown external (ext_ptr_func) → NULL_VALUE with origin="external_call"
//     (fail-open: suspected for the AI)
func TestNullSource_NullabilityTiers(t *testing.T) {
	store := runOneDetector(t, "tc_null_deref_nullability_tiers.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewNullSourceDetector(s, p, l) })
	events, err := store.ListEventsByType(context.Background(), "NULL_VALUE")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}

	seenStrchr := false   // maybe-null libc → origin="strchr"
	seenStrerror := false // never-null → should NOT appear
	seenExtPtr := false   // unknown → origin="external_call"
	for _, e := range events {
		var props struct {
			Variable string `json:"variable"`
			Origin   string `json:"origin"`
			Function string `json:"function"`
		}
		json.Unmarshal([]byte(e.Properties), &props)
		switch props.Origin {
		case "strchr":
			seenStrchr = true
		case "strerror":
			seenStrerror = true
		case "external_call":
			if props.Function == "ext_ptr_func" {
				seenExtPtr = true
			}
		}
	}

	if !seenStrchr {
		t.Error("strchr (maybe-null libc) did NOT produce a NULL_VALUE with origin=\"strchr\" — it should seed the auto-confirm channel")
	}
	if seenStrerror {
		t.Error("strerror (never-null) produced a NULL_VALUE event — a non-null return must not seed a null source")
	}
	if !seenExtPtr {
		t.Error("ext_ptr_func (unknown external) did NOT produce a NULL_VALUE with origin=\"external_call\" — unknown calls must fail-open")
	}
}
