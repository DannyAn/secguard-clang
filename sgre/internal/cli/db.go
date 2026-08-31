package cli

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// securityEventsPattern blocks any reference to the security_events table —
// as a table name or as a string literal argument (e.g. pragma_table_info).
// It uses word boundaries so it catches main.security_events,
// "security_events", and pragma_table_info('security_events') alike. A
// determined caller can still split the string ('security_'||'events') to
// leak only the schema (column names), not row data; that is accepted as a
// non-fatal limitation of SQL-layer filtering. The pipeline boundary is
// primarily enforced by the agent prompt + converged-evidence-only output.
var securityEventsPattern = regexp.MustCompile(`(?i)\bsecurity_events\b`)

func runDbCmd(ctx context.Context, args []string) int {
	dbPath, dbExplicit, remaining := parseDBFlag(args)

	if len(remaining) == 0 {
		WriteErrorJSON("db requires a SQL query argument")
		return 1
	}
	query := strings.Join(remaining, " ")

	dbPath = resolveDBPath(dbExplicit, dbPath, ".")

	queryUpper := strings.ToUpper(strings.TrimSpace(query))
	if !strings.HasPrefix(queryUpper, "SELECT") && !strings.HasPrefix(queryUpper, "WITH") {
		WriteErrorJSON("db command only allows SELECT queries (read-only). Use 'secguard report --write' to persist findings.")
		return 1
	}

	if securityEventsPattern.MatchString(query) {
		WriteErrorJSON("Querying the 'security_events' table is prohibited. This table contains raw pre-convergence candidates. Use secguard_scan or secguard_plan to obtain converged evidence packages.")
		return 1
	}

	// 前缀检查只是友好提示；真正的只读边界由 SQLite 引擎强制（PRAGMA query_only=1），
	// 数据修改 CTE（WITH ... DELETE）也会被拒，前缀检查无法被绕过。
	d, err := db.OpenReadOnly(ctx, dbPath)
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
