package db

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// listByIDs runs one chunked `IN (...)` query and scans each row into a value
// keyed by its id. The four List*ByIDs methods had copied this chunking,
// placeholder and rows lifecycle; keeping one implementation also removes the
// risk of a caller forgetting rows.Err or rows.Close.
func listByIDs[T any](ctx context.Context, exec dbExec, ids []int64, label, selectPrefix string, scan func(*sql.Rows) (int64, T, error)) (map[int64]T, error) {
	result := make(map[int64]T, len(ids))
	for _, chunk := range chunkIDs(ids, 500) {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		args := make([]interface{}, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		rows, err := exec.QueryContext(ctx, selectPrefix+placeholders+`)`, args...)
		if err != nil {
			return nil, fmt.Errorf("db: %s: %w", label, err)
		}
		for rows.Next() {
			key, value, scanErr := scan(rows)
			if scanErr != nil {
				rows.Close()
				return nil, scanErr
			}
			result[key] = value
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("db: %s: %w", label, err)
		}
	}
	return result, nil
}
