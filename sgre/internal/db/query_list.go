package db

import (
	"context"
	"database/sql"
)

// queryList owns the rows lifecycle for a non-chunked List* query. Callers keep
// only their SQL and per-row scan; this removes the repeated defer/Next/Err
// template across the db package.
func queryList[T any](ctx context.Context, exec dbExec, query string, args []interface{}, scan func(*sql.Rows) (T, error)) ([]T, error) {
	rows, err := exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, scanErr := scan(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
