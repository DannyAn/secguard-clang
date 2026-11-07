//go:build !nosqlite

package db

import (
	"context"
	"database/sql"
	"testing"
)

// The event_type / settlement status vocabulary must NOT be gated by a DB CHECK
// enum: an enumerated CHECK turns every newly registered event type or
// settlement state into a hard write failure on large repos (the production
// outage), and the vocabulary belongs to the detector registry, not storage.
// Any registered event type and any settlement status must be writable.
func TestSchemaHasNoVocabularyCheckConstraints(t *testing.T) {
	ctx := context.Background()
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := InitSchema(ctx, d); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	for _, et := range []string{"STACK_ESCAPE", "INVALID_FREE", "SWITCH_FLOW", "UNBOUNDED_LENGTH", "FUTURE_EVENT_TYPE"} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO security_events (event_type, entity_id, location_id, properties) VALUES (?, NULL, NULL, '{}')`, et); err != nil {
			t.Errorf("event_type %s must be writable without a CHECK enum: %v", et, err)
		}
	}
	for i, status := range []string{"dispatched", "done", "failed", "partial", "released", "future_state"} {
		if _, err := d.ExecContext(ctx,
			`INSERT INTO settlement_stats (scan_id, vuln_type, range_str, subagent_id, status, created_at)
			 VALUES ('sc_u', 'null-deref', ?, 'h', ?, 0)`, map[int]string{0: "a", 1: "b", 2: "c", 3: "d", 4: "e", 5: "f"}[i], status); err != nil {
			t.Errorf("settlement status %s must be writable without a CHECK enum: %v", status, err)
		}
	}
	if _, err := d.ExecContext(ctx, `UPDATE settlement_stats SET heartbeat_at = 123 WHERE scan_id = 'sc_u'`); err != nil {
		t.Errorf("heartbeat_at must be writable: %v", err)
	}
}
