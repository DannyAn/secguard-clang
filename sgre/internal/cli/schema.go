package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

type tableSchema struct {
	Name    string      `json:"name"`
	Columns []columnDef `json:"columns"`
	Indexes []indexDef  `json:"indexes,omitempty"`
}

type columnDef struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	NotNull    bool   `json:"not_null,omitempty"`
	Default    string `json:"default,omitempty"`
	PrimaryKey bool   `json:"primary_key,omitempty"`
}

type indexDef struct {
	Name   string `json:"name"`
	Unique bool   `json:"unique,omitempty"`
}

var agentSchemaTables = map[string][]columnDef{
	"findings": {
		{Name: "id", Type: "INTEGER", PrimaryKey: true},
		{Name: "rule_id", Type: "TEXT", NotNull: true},
		{Name: "severity", Type: "TEXT"},
		{Name: "confidence", Type: "REAL"},
		{Name: "evidence", Type: "TEXT"},
		{Name: "status", Type: "TEXT"},
		{Name: "file_path", Type: "TEXT"},
		{Name: "line_number", Type: "INTEGER"},
		{Name: "function_name", Type: "TEXT"},
		{Name: "properties", Type: "TEXT"},
		{Name: "scan_id", Type: "TEXT"},
		{Name: "created_at", Type: "INTEGER"},
	},
	"scan_stats": {
		{Name: "id", Type: "INTEGER", PrimaryKey: true},
		{Name: "scan_id", Type: "TEXT", NotNull: true},
		{Name: "vuln_type", Type: "TEXT", NotNull: true},
		{Name: "seed_count", Type: "INTEGER", NotNull: true},
		{Name: "final_count", Type: "INTEGER", NotNull: true},
		{Name: "filter_chain", Type: "TEXT"},
		{Name: "created_at", Type: "INTEGER"},
	},
	"files": {
		{Name: "id", Type: "INTEGER", PrimaryKey: true},
		{Name: "path", Type: "TEXT", NotNull: true},
		{Name: "language", Type: "TEXT"},
		{Name: "checksum", Type: "TEXT"},
		{Name: "loc", Type: "INTEGER"},
		{Name: "created_at", Type: "INTEGER"},
	},
	"functions": {
		{Name: "id", Type: "INTEGER", PrimaryKey: true},
		{Name: "file_id", Type: "INTEGER", NotNull: true},
		{Name: "name", Type: "TEXT"},
		{Name: "signature", Type: "TEXT"},
		{Name: "return_type", Type: "TEXT"},
		{Name: "is_static", Type: "BOOLEAN"},
		{Name: "start_line", Type: "INTEGER"},
		{Name: "end_line", Type: "INTEGER"},
	},
	"security_events": {
		{Name: "id", Type: "INTEGER", PrimaryKey: true},
		{Name: "event_type", Type: "TEXT", NotNull: true},
		{Name: "entity_id", Type: "INTEGER"},
		{Name: "location_id", Type: "INTEGER"},
		{Name: "properties", Type: "TEXT"},
	},
}

var agentSchemaNotes = map[string]string{
	"findings":        "AI agent output. Query by file_path and line_number (NOT file/line). rule_id is CWE (e.g. CWE-476). status: open/confirmed/suspected/dismissed.",
	"scan_stats":      "Pipeline metrics per scan per vuln type. vuln_type is the kebab-case type name (NOT a column called vulnerability_type).",
	"files":           "Layer 1 program facts. Query by path.",
	"functions":       "Layer 1 program facts. Join to files via file_id.",
	"security_events": "Layer 3 raw evidence. DO NOT query this table — it contains pre-convergence candidates that bypass the pipeline.",
}

func runSchemaCmd(args []string) int {
	tableNames := make([]string, 0, len(agentSchemaTables))
	for name := range agentSchemaTables {
		tableNames = append(tableNames, name)
	}
	sort.Strings(tableNames)

	if len(args) > 0 && args[0] != "" {
		tableName := strings.ToLower(args[0])
		cols, ok := agentSchemaTables[tableName]
		if !ok {
			WriteErrorJSON(fmt.Sprintf("unknown table %q; available: %s", tableName, strings.Join(tableNames, ", ")))
			return 1
		}
		WriteJSON(map[string]interface{}{
			"table":   tableName,
			"columns": cols,
			"note":    agentSchemaNotes[tableName],
		})
		return 0
	}

	tables := make([]tableSchema, 0, len(tableNames))
	for _, name := range tableNames {
		tables = append(tables, tableSchema{
			Name:    name,
			Columns: agentSchemaTables[name],
		})
	}

	WriteJSON(map[string]interface{}{
		"tables": tables,
		"notes":  agentSchemaNotes,
		"examples": []string{
			"secguard db \"SELECT rule_id, severity, status, file_path, line_number FROM findings WHERE status = 'confirmed' ORDER BY severity\"",
			"secguard db \"SELECT scan_id, vuln_type, seed_count, final_count FROM scan_stats ORDER BY scan_id\"",
			"secguard db \"SELECT path, loc FROM files ORDER BY loc DESC LIMIT 10\"",
		},
	})
	return 0
}

var _ = os.Stdout
