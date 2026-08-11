package cli

import (
	"context"

	"fmt"
	"strings"

	"github.com/kongan/secguard-lite/internal/db"
)

func runDbCmd(ctx context.Context, args []string) int {
	dbPath, remaining := parseDBFlag(args)

	if len(remaining) == 0 {
		WriteErrorJSON("db requires a SQL query argument")
		return 1
	}
	query := strings.Join(remaining, " ")

	queryUpper := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(queryUpper, "SELECT") && !strings.HasPrefix(queryUpper, "WITH") {
		WriteErrorJSON("db command only allows SELECT queries (read-only). Use 'secguard report --write' to persist findings.")
		return 1
	}

	if strings.Contains(strings.ToLower(query), "security_events") {
		WriteErrorJSON("Querying the 'security_events' table is prohibited. This table contains raw pre-convergence candidates. Use secguard_scan or secguard_plan to obtain converged evidence packages.")
		return 1
	}

	d, err := db.Open(ctx, dbPath)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to open database: %v", err))
		return 1
	}
	defer d.Close()

	rows, err := d.QueryContext(ctx, query)
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("query failed: %v", err))
		return 1
	}
	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		WriteErrorJSON(fmt.Sprintf("failed to get columns: %v", err))
		return 1
	}

	results := []map[string]interface{}{}
	for rows.Next() {
		values := make([]interface{}, len(columns))
		scanArgs := make([]interface{}, len(columns))
		for i := range values {
			scanArgs[i] = &values[i]
		}

		if err := rows.Scan(scanArgs...); err != nil {
			WriteErrorJSON(fmt.Sprintf("failed to scan row: %v", err))
			return 1
		}

		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			b, ok := val.([]byte)
			if ok {
				row[col] = string(b)
			} else {
				row[col] = val
			}
		}
		results = append(results, row)
	}

	if err := rows.Err(); err != nil {
		WriteErrorJSON(fmt.Sprintf("row iteration error: %v", err))
		return 1
	}

	if results == nil {
		results = []map[string]interface{}{}
	}

	WriteJSON(map[string]interface{}{
		"columns": columns,
		"rows":    results,
		"count":   len(results),
	})
	return 0
}
