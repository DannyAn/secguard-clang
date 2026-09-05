package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func (s *store) InsertEvent(ctx context.Context, e *SecurityEvent) (int64, error) {
	// Detectors run 4-up in parallel over one WAL database; a single InsertEvent
	// that exhausts busy_timeout must not be silently dropped (that is a lost
	// security event). The application-layer retry keeps event writes on the
	// same footing as InsertFinding/UpsertFinding.
	return withBusyRetryID(ctx, 3, func() (int64, error) {
		res, err := s.exec.ExecContext(ctx,
			`INSERT INTO security_events (event_type, entity_id, location_id, properties) VALUES (?, ?, ?, ?)`,
			e.EventType, e.EntityID, e.LocationID, e.Properties)
		if err != nil {
			return 0, fmt.Errorf("db: insert event: %w", err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return 0, fmt.Errorf("db: insert event: last insert id: %w", err)
		}
		return id, nil
	})
}

func (s *store) GetEventByID(ctx context.Context, id int64) (*SecurityEvent, error) {
	row := s.exec.QueryRowContext(ctx,
		`SELECT id, event_type, entity_id, location_id, properties FROM security_events WHERE id = ?`, id)
	e := &SecurityEvent{}
	if err := row.Scan(&e.ID, &e.EventType, &e.EntityID, &e.LocationID, &e.Properties); err != nil {
		return nil, fmt.Errorf("db: get event by id: %w", err)
	}
	return e, nil
}

func (s *store) ListEventsByType(ctx context.Context, eventType string) ([]*SecurityEvent, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, event_type, entity_id, location_id, properties FROM security_events WHERE event_type = ? ORDER BY id`, eventType)
	if err != nil {
		return nil, fmt.Errorf("db: list events by type: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *store) CountEventsByType(ctx context.Context, eventType string) (int, error) {
	var count int
	err := s.exec.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM security_events WHERE event_type = ?`, eventType).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("db: count events by type: %w", err)
	}
	return count, nil
}

func (s *store) ListEventsByEntity(ctx context.Context, entityID int64) ([]*SecurityEvent, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, event_type, entity_id, location_id, properties FROM security_events WHERE entity_id = ? ORDER BY id`, entityID)
	if err != nil {
		return nil, fmt.Errorf("db: list events by entity: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *store) ListEventsByTypeAndEntity(ctx context.Context, eventType string, entityID int64) ([]*SecurityEvent, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, event_type, entity_id, location_id, properties FROM security_events WHERE event_type = ? AND entity_id = ? ORDER BY id`, eventType, entityID)
	if err != nil {
		return nil, fmt.Errorf("db: list events by type and entity: %w", err)
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (s *store) ListEventsByIDs(ctx context.Context, ids []int64) (map[int64]*SecurityEvent, error) {
	result := make(map[int64]*SecurityEvent, len(ids))
	for _, chunk := range chunkIDs(ids, 500) {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := s.exec.QueryContext(ctx,
			`SELECT id, event_type, entity_id, location_id, properties FROM security_events WHERE id IN (`+placeholders+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("db: list events by ids: %w", err)
		}
		for rows.Next() {
			e := &SecurityEvent{}
			if scanErr := rows.Scan(&e.ID, &e.EventType, &e.EntityID, &e.LocationID, &e.Properties); scanErr != nil {
				rows.Close()
				return nil, fmt.Errorf("db: scan event: %w", scanErr)
			}
			result[e.ID] = e
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("db: list events by ids: %w", err)
		}
	}
	return result, nil
}

func (s *store) ClearSecurityEvents(ctx context.Context) error {
	_, err := s.exec.ExecContext(ctx, `DELETE FROM security_events`)
	if err != nil {
		return fmt.Errorf("db: clear security events: %w", err)
	}
	return nil
}

func scanEvents(rows *sql.Rows) ([]*SecurityEvent, error) {
	var events []*SecurityEvent
	for rows.Next() {
		e := &SecurityEvent{}
		if err := rows.Scan(&e.ID, &e.EventType, &e.EntityID, &e.LocationID, &e.Properties); err != nil {
			return nil, fmt.Errorf("db: scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
