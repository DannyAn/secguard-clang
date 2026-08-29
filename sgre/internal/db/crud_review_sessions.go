package db

import (
	"context"
	"database/sql"
	"fmt"
)

// UpsertReviewSession writes a review session idempotently keyed on review_id.
// Re-running the same diff (same base/head) converges on one row, so the review
// is resumable and its findings idempotent.
func (s *store) UpsertReviewSession(ctx context.Context, r *ReviewSession) error {
	if r.Status == "" {
		r.Status = "running"
	}
	if r.CreatedAt == 0 {
		r.CreatedAt = now()
	}
	r.UpdatedAt = now()

	_, err := s.exec.ExecContext(ctx,
		`INSERT INTO review_sessions (review_id, kind, base_ref, head_ref, base_sha, head_sha, changed_files, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(review_id) DO UPDATE SET
		   base_ref = excluded.base_ref,
		   head_ref = excluded.head_ref,
		   base_sha = excluded.base_sha,
		   head_sha = excluded.head_sha,
		   changed_files = excluded.changed_files,
		   updated_at = excluded.updated_at`,
		r.ReviewID, r.Kind, r.BaseRef, r.HeadRef, r.BaseSHA, r.HeadSHA, r.ChangedFiles, r.Status, r.CreatedAt, r.UpdatedAt)
	if err != nil {
		return fmt.Errorf("db: upsert review session: %w", err)
	}
	return nil
}

func (s *store) GetReviewSessionByID(ctx context.Context, reviewID string) (*ReviewSession, error) {
	row := s.exec.QueryRowContext(ctx,
		`SELECT id, review_id, kind, base_ref, head_ref, base_sha, head_sha, changed_files, status, created_at, updated_at FROM review_sessions WHERE review_id = ?`, reviewID)
	r := &ReviewSession{}
	var changedFiles sql.NullString
	if err := row.Scan(&r.ID, &r.ReviewID, &r.Kind, &r.BaseRef, &r.HeadRef, &r.BaseSHA, &r.HeadSHA, &changedFiles, &r.Status, &r.CreatedAt, &r.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("db: get review session: %w", err)
	}
	r.ChangedFiles = changedFiles.String
	return r, nil
}

func (s *store) UpdateReviewSessionStatus(ctx context.Context, reviewID, status string) error {
	_, err := s.exec.ExecContext(ctx,
		`UPDATE review_sessions SET status = ?, updated_at = ? WHERE review_id = ?`, status, now(), reviewID)
	if err != nil {
		return fmt.Errorf("db: update review session status: %w", err)
	}
	return nil
}
