package db

import (
	"strings"
	"testing"
)

func schemaHasTable(ddl, table string) bool {
	return strings.Contains(ddl, "CREATE TABLE IF NOT EXISTS "+table) ||
		strings.Contains(ddl, "CREATE TABLE "+table)
}

func TestSchemaDDL_ContainsAllLayer1Tables(t *testing.T) {
	tables := []string{"files", "functions", "function_declarations", "variables", "expressions", "types", "locations"}
	for _, table := range tables {
		if !schemaHasTable(SchemaDDL, table) {
			t.Errorf("SchemaDDL missing Layer 1 table: %s", table)
		}
	}
}

func TestSchemaDDL_ContainsLayer2Tables(t *testing.T) {
	tables := []string{"graph_nodes", "graph_edges"}
	for _, table := range tables {
		if !schemaHasTable(SchemaDDL, table) {
			t.Errorf("SchemaDDL missing Layer 2 table: %s", table)
		}
	}
}

func TestSchemaDDL_ContainsLayer3Table(t *testing.T) {
	if !schemaHasTable(SchemaDDL, "security_events") {
		t.Error("SchemaDDL missing Layer 3 table: security_events")
	}
}

func TestSchemaDDL_ContainsLayer4Table(t *testing.T) {
	if !schemaHasTable(SchemaDDL, "findings") {
		t.Error("SchemaDDL missing Layer 4 table: findings")
	}
}

func TestSchemaDDL_ContainsFunctionSummaryTable(t *testing.T) {
	if !schemaHasTable(SchemaDDL, "function_summary") {
		t.Error("SchemaDDL missing function_summary table")
	}
	if !schemaHasTable(SchemaDDL, "settlement_stats") {
		t.Error("SchemaDDL missing settlement_stats table")
	}
}

func TestSchemaDDL_EdgeTypeCheckConstraint(t *testing.T) {
	edgeTypes := []string{"CALL", "DATA_FLOW", "OWNERSHIP_TRANSFER", "RELEASE", "ALIAS", "PARAM_BINDING", "RETURN", "LOCK_ORDER", "GLOBAL_ACCESS", "ADDR_TAKEN"}
	for _, et := range edgeTypes {
		if !strings.Contains(SchemaDDL, et) {
			t.Errorf("SchemaDDL missing edge_type enum value: %s", et)
		}
	}
}

// TestSchemaDDL_EventTypeHasNoCheckEnum pins the ROOT-CAUSE fix: event_type is
// an internal vocabulary owned by the detector registry, and an enumerated
// CHECK turned every newly registered event type into a hard write failure on
// large repos. The constraint must NOT come back — storage holds vocabulary,
// the registry validates semantics.
func TestSchemaDDL_EventTypeHasNoCheckEnum(t *testing.T) {
	ddl := SchemaDDL
	start := strings.Index(ddl, "CREATE TABLE IF NOT EXISTS security_events")
	if start < 0 {
		t.Fatal("SchemaDDL must contain security_events")
	}
	seg := ddl[start:]
	if end := strings.Index(seg, ");"); end >= 0 {
		seg = seg[:end]
	}
	if strings.Contains(seg, "CHECK (") || strings.Contains(seg, "CHECK(") {
		t.Errorf("security_events.event_type must not carry a CHECK enum; the detector registry owns the vocabulary, not storage: %s", seg)
	}
	if !strings.Contains(seg, "event_type") {
		t.Errorf("security_events must have an event_type column: %s", seg)
	}
}

func TestSchemaDDL_StorageClassCheckConstraint(t *testing.T) {
	classes := []string{"auto", "static", "register", "heap"}
	for _, sc := range classes {
		if !strings.Contains(SchemaDDL, sc) {
			t.Errorf("SchemaDDL missing storage_class value: %s", sc)
		}
	}
}

func TestSchemaDDL_ContainsForeignKeys(t *testing.T) {
	if !strings.Contains(SchemaDDL, "FOREIGN KEY") {
		t.Error("SchemaDDL missing FOREIGN KEY constraints")
	}
}

func TestSchemaDDL_ContainsPerformanceIndexes(t *testing.T) {
	if !strings.Contains(SchemaDDL, "CREATE INDEX") {
		t.Error("SchemaDDL missing performance indexes")
	}
}

func TestSchemaDDL_ContainsPragmas(t *testing.T) {
	pragmas := []string{"foreign_keys", "journal_mode", "synchronous"}
	for _, p := range pragmas {
		if !strings.Contains(SchemaDDL, p) {
			t.Errorf("SchemaDDL missing PRAGMA: %s", p)
		}
	}
}
