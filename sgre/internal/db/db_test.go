package db

import (
	"context"
	"testing"
)

func TestOpenInMemory_SchemaInitialized(t *testing.T) {
	ctx := context.Background()
	db, err := OpenInMemory(ctx)
	if err != nil {
		t.Fatalf("OpenInMemory failed: %v", err)
	}
	defer db.Close()

	tables := []string{
		"files", "functions", "variables", "expressions", "types", "locations",
		"graph_nodes", "graph_edges", "security_events", "findings", "function_summary",
	}
	for _, table := range tables {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found after schema init: %v", table, err)
		}
	}
}

func TestNewTestStore_AllTablesPresent(t *testing.T) {
	s := NewTestStore(t)
	tables := []string{
		"files", "functions", "variables", "expressions", "types", "locations",
		"graph_nodes", "graph_edges", "security_events", "findings", "function_summary",
	}
	for _, table := range tables {
		AssertTableExists(t, s, table)
	}
}

func TestStore_InsertAndGetFile(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	id, err := s.InsertFile(ctx, &File{Path: "test.c", LOC: 100})
	if err != nil {
		t.Fatalf("InsertFile failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero file ID")
	}

	f, err := s.GetFileByPath(ctx, "test.c")
	if err != nil {
		t.Fatalf("GetFileByPath failed: %v", err)
	}
	if f == nil {
		t.Fatal("file not found")
	}
	if f.Path != "test.c" {
		t.Errorf("expected path 'test.c', got %q", f.Path)
	}
	if f.Language != "c" {
		t.Errorf("expected language 'c', got %q", f.Language)
	}
	if f.LOC != 100 {
		t.Errorf("expected LOC 100, got %d", f.LOC)
	}
}

func TestStore_InsertAndGetFunction(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	fileID, _ := s.InsertFile(ctx, &File{Path: "test.c"})
	funcID, err := s.InsertFunction(ctx, &Function{
		FileID:     fileID,
		Name:       "my_func",
		Signature:  "int my_func(void)",
		ReturnType: "int",
		IsStatic:   true,
		StartLine:  1,
		EndLine:    10,
	})
	if err != nil {
		t.Fatalf("InsertFunction failed: %v", err)
	}
	if funcID == 0 {
		t.Error("expected non-zero function ID")
	}

	f, err := s.GetFunctionByName(ctx, "my_func")
	if err != nil {
		t.Fatalf("GetFunctionByName failed: %v", err)
	}
	if f == nil {
		t.Fatal("function not found")
	}
	if !f.IsStatic {
		t.Error("expected IsStatic=true")
	}
}

func TestStore_InsertGraphEdge_RejectsInvalidEdgeType(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	srcID, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 1})
	dstID, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 2})

	_, err := s.InsertGraphEdge(ctx, &GraphEdge{
		SrcID:    srcID,
		DstID:    dstID,
		EdgeType: "INVALID_TYPE",
	})
	if err == nil {
		t.Error("expected error for invalid edge_type, got nil")
	}
}

func TestStore_InsertEvent_RejectsInvalidEventType(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	_, err := s.InsertEvent(ctx, &SecurityEvent{
		EventType: "INVALID_EVENT",
	})
	if err == nil {
		t.Error("expected error for invalid event_type, got nil")
	}
}

func TestStore_InsertFinding_EnforcesConfidenceRange(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	_, err := s.InsertFinding(ctx, &Finding{
		RuleID:     "CWE-476",
		Confidence: 1.5,
	})
	if err == nil {
		t.Error("expected error for confidence > 1.0, got nil")
	}

	_, err = s.InsertFinding(ctx, &Finding{
		RuleID:     "CWE-476",
		Confidence: -0.1,
	})
	if err == nil {
		t.Error("expected error for confidence < 0.0, got nil")
	}

	id, err := s.InsertFinding(ctx, &Finding{
		RuleID:     "CWE-476",
		Severity:   "high",
		Confidence: 0.95,
	})
	if err != nil {
		t.Fatalf("valid finding insert failed: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero finding ID")
	}
}

func TestStore_ReachableFromEntry(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	nodeA, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 1})
	nodeB, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 2})
	nodeC, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 3})

	s.InsertGraphEdge(ctx, &GraphEdge{SrcID: nodeA, DstID: nodeB, EdgeType: "CALL"})
	s.InsertGraphEdge(ctx, &GraphEdge{SrcID: nodeB, DstID: nodeC, EdgeType: "CALL"})

	reachable, err := s.ReachableFromEntry(ctx, nodeA, "CALL")
	if err != nil {
		t.Fatalf("ReachableFromEntry failed: %v", err)
	}
	if len(reachable) != 3 {
		t.Errorf("expected 3 reachable nodes (A, B, C), got %d: %v", len(reachable), reachable)
	}
}

func TestStore_ReachableFromEntries(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	// Two disjoint entry components: A->B and X->Y->Z.
	nodeA, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 1})
	nodeB, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 2})
	nodeX, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 3})
	nodeY, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 4})
	nodeZ, _ := s.InsertGraphNode(ctx, &GraphNode{EntityType: "function", EntityID: 5})

	s.InsertGraphEdge(ctx, &GraphEdge{SrcID: nodeA, DstID: nodeB, EdgeType: "CALL"})
	s.InsertGraphEdge(ctx, &GraphEdge{SrcID: nodeX, DstID: nodeY, EdgeType: "CALL"})
	s.InsertGraphEdge(ctx, &GraphEdge{SrcID: nodeY, DstID: nodeZ, EdgeType: "CALL"})

	reachable, err := s.ReachableFromEntries(ctx, []int64{nodeA, nodeX}, "CALL")
	if err != nil {
		t.Fatalf("ReachableFromEntries failed: %v", err)
	}
	got := make(map[int64]bool, len(reachable))
	for _, id := range reachable {
		got[id] = true
	}
	for _, want := range []int64{nodeA, nodeB, nodeX, nodeY, nodeZ} {
		if !got[want] {
			t.Errorf("expected node %d reachable, got %v", want, reachable)
		}
	}
	if len(reachable) != 5 {
		t.Errorf("expected 5 reachable nodes across two components, got %d: %v", len(reachable), reachable)
	}

	// Empty seed set returns empty.
	if empty, err := s.ReachableFromEntries(ctx, nil, "CALL"); err != nil || len(empty) != 0 {
		t.Errorf("expected empty result for no entries, got %v err=%v", empty, err)
	}
}

func TestMigrateGraphEdgesTable_AddsInterprocEdgeTypes(t *testing.T) {
	ctx := context.Background()
	db, err := OpenInMemory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Simulate an old DB: replace graph_edges with the pre-PARAM_BINDING/RETURN schema.
	if _, err := db.ExecContext(ctx, `DROP TABLE graph_edges`); err != nil {
		t.Fatal(err)
	}
	old := `CREATE TABLE graph_edges (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		src_id INTEGER NOT NULL,
		dst_id INTEGER NOT NULL,
		edge_type TEXT NOT NULL CHECK (edge_type IN ('CALL','DATA_FLOW','OWNERSHIP_TRANSFER','RELEASE','BRANCH','ALIAS')),
		properties TEXT,
		FOREIGN KEY(src_id) REFERENCES graph_nodes(id) ON DELETE CASCADE,
		FOREIGN KEY(dst_id) REFERENCES graph_nodes(id) ON DELETE CASCADE
	)`
	if _, err := db.ExecContext(ctx, old); err != nil {
		t.Fatal(err)
	}

	src, err := db.ExecContext(ctx, `INSERT INTO graph_nodes (entity_type, entity_id, properties) VALUES ('function', 1, '')`)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := db.ExecContext(ctx, `INSERT INTO graph_nodes (entity_type, entity_id, properties) VALUES ('function', 2, '')`)
	if err != nil {
		t.Fatal(err)
	}
	srcID, _ := src.LastInsertId()
	dstID, _ := dst.LastInsertId()
	if _, err := db.ExecContext(ctx, `INSERT INTO graph_edges (src_id, dst_id, edge_type) VALUES (?, ?, 'CALL')`, srcID, dstID); err != nil {
		t.Fatal(err)
	}

	if err := migrateGraphEdgesTable(ctx, db); err != nil {
		t.Fatalf("migrateGraphEdgesTable failed: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM graph_edges WHERE edge_type='CALL'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("legacy CALL edge not preserved: n=%d err=%v", n, err)
	}

	if _, err := db.ExecContext(ctx, `INSERT INTO graph_edges (src_id, dst_id, edge_type) VALUES (?, ?, 'PARAM_BINDING')`, srcID, dstID); err != nil {
		t.Errorf("PARAM_BINDING should be accepted after migration: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO graph_edges (src_id, dst_id, edge_type) VALUES (?, ?, 'RETURN')`, srcID, dstID); err != nil {
		t.Errorf("RETURN should be accepted after migration: %v", err)
	}
}

func TestStore_WithTx_RollbackOnError(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	err := s.WithTx(ctx, func(txStore Store) error {
		_, err := txStore.InsertFile(ctx, &File{Path: "tx_test.c"})
		if err != nil {
			return err
		}
		return context.DeadlineExceeded
	})
	if err == nil {
		t.Fatal("expected error from WithTx")
	}

	f, _ := s.GetFileByPath(ctx, "tx_test.c")
	if f != nil {
		t.Error("expected file to be rolled back, but it exists")
	}
}

func TestStore_WithTx_CommitOnSuccess(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	err := s.WithTx(ctx, func(txStore Store) error {
		_, err := txStore.InsertFile(ctx, &File{Path: "tx_commit.c"})
		return err
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}

	f, _ := s.GetFileByPath(ctx, "tx_commit.c")
	if f == nil {
		t.Error("expected file to exist after successful tx commit")
	}
}

func TestStore_FunctionSummary_Upsert(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	fileID, _ := s.InsertFile(ctx, &File{Path: "test.c"})
	funcID, _ := s.InsertFunction(ctx, &Function{FileID: fileID, Name: "f"})

	err := s.UpsertSummary(ctx, &FunctionSummary{
		FunctionID:     funcID,
		ReturnNullable: true,
		SummaryJSON:    `{"return": {"nullable": true}}`,
	})
	if err != nil {
		t.Fatalf("UpsertSummary failed: %v", err)
	}

	sum, err := s.GetSummaryByFunction(ctx, funcID)
	if err != nil {
		t.Fatalf("GetSummaryByFunction failed: %v", err)
	}
	if sum == nil {
		t.Fatal("summary not found")
	}
	if !sum.ReturnNullable {
		t.Error("expected ReturnNullable=true")
	}

	err = s.UpdateReturnNullable(ctx, funcID, false)
	if err != nil {
		t.Fatalf("UpdateReturnNullable failed: %v", err)
	}
	sum, _ = s.GetSummaryByFunction(ctx, funcID)
	if sum.ReturnNullable {
		t.Error("expected ReturnNullable=false after update")
	}
}
