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
	tables := []string{"files", "functions", "variables", "expressions", "types", "locations"}
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
}

func TestSchemaDDL_EdgeTypeCheckConstraint(t *testing.T) {
	edgeTypes := []string{"CALL", "DATA_FLOW", "OWNERSHIP_TRANSFER", "RELEASE", "ALIAS", "PARAM_BINDING", "RETURN"}
	for _, et := range edgeTypes {
		if !strings.Contains(SchemaDDL, et) {
			t.Errorf("SchemaDDL missing edge_type enum value: %s", et)
		}
	}
}

func TestSchemaDDL_EventTypeCheckConstraint(t *testing.T) {
	eventTypes := []string{
		"NULL_VALUE", "DEREFERENCE", "NULL_GUARD",
		"MEMORY_ALLOC", "MEMORY_RELEASE",
		"RESOURCE_ACQUIRE", "RESOURCE_RELEASE",
		"VARIABLE_DECLARE", "VALUE_USE", "VALUE_INIT",
		"BUFFER_ACCESS", "INTEGER_OP", "INJECTION",
		"USE_AFTER_FREE", "DOUBLE_FREE", "FORMAT_STRING",
		"INTEGER_OVERFLOW", "RACE_CONDITION", "HARDCODED_SECRET",
		"DEADLOCK", "CRYPTO_MISUSE",
		"DIVIDE_BY_ZERO", "UNCHECKED_RETURN", "PATH_TRAVERSAL",
		"SIZEOF_MISUSE", "SIGNED_COMPARE",
	}
	for _, et := range eventTypes {
		if !strings.Contains(SchemaDDL, et) {
			t.Errorf("SchemaDDL missing event_type enum value: %s", et)
		}
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
