package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

func (s *store) InsertGraphNode(ctx context.Context, n *GraphNode) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO graph_nodes (entity_type, entity_id, properties) VALUES (?, ?, ?)`,
		n.EntityType, n.EntityID, n.Properties)
	if err != nil {
		return 0, fmt.Errorf("db: insert graph node: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert graph node: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) GetGraphNodeByID(ctx context.Context, id int64) (*GraphNode, error) {
	n := &GraphNode{}
	err := s.exec.QueryRowContext(ctx,
		`SELECT id, entity_type, entity_id, properties FROM graph_nodes WHERE id = ?`, id).
		Scan(&n.ID, &n.EntityType, &n.EntityID, &n.Properties)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("db: get graph node by id: %w", err)
	}
	return n, nil
}

func (s *store) GetOrCreateGraphNode(ctx context.Context, entityType string, entityID int64, properties string) (int64, error) {
	// Atomic upsert: INSERT OR IGNORE relies on the UNIQUE(entity_type, entity_id,
	// properties) constraint to deduplicate concurrent inserts. Then SELECT
	// returns the surviving row's id. This eliminates the SELECT-then-INSERT
	// race that produced duplicate nodes when graph builders ran in parallel.
	if _, err := s.exec.ExecContext(ctx,
		`INSERT OR IGNORE INTO graph_nodes (entity_type, entity_id, properties) VALUES (?, ?, ?)`,
		entityType, entityID, properties); err != nil {
		return 0, fmt.Errorf("db: get or create graph node: insert: %w", err)
	}
	var id int64
	err := s.exec.QueryRowContext(ctx,
		`SELECT id FROM graph_nodes WHERE entity_type = ? AND entity_id = ? AND properties = ? LIMIT 1`, entityType, entityID, properties).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("db: get or create graph node: %w", err)
	}
	return id, nil
}

func (s *store) ListGraphNodesByEntity(ctx context.Context, entityType string, entityID int64) ([]*GraphNode, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, entity_type, entity_id, properties FROM graph_nodes WHERE entity_type = ? AND entity_id = ?`, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("db: list graph nodes by entity: %w", err)
	}
	defer rows.Close()
	var nodes []*GraphNode
	for rows.Next() {
		n := &GraphNode{}
		if err := rows.Scan(&n.ID, &n.EntityType, &n.EntityID, &n.Properties); err != nil {
			return nil, fmt.Errorf("db: scan graph node: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (s *store) ListGraphNodesByEntityType(ctx context.Context, entityType string) ([]*GraphNode, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, entity_type, entity_id, properties FROM graph_nodes WHERE entity_type = ?`, entityType)
	if err != nil {
		return nil, fmt.Errorf("db: list graph nodes by entity type: %w", err)
	}
	defer rows.Close()
	var nodes []*GraphNode
	for rows.Next() {
		n := &GraphNode{}
		if err := rows.Scan(&n.ID, &n.EntityType, &n.EntityID, &n.Properties); err != nil {
			return nil, fmt.Errorf("db: scan graph node: %w", err)
		}
		nodes = append(nodes, n)
	}
	return nodes, rows.Err()
}

func (s *store) InsertGraphEdge(ctx context.Context, e *GraphEdge) (int64, error) {
	res, err := s.exec.ExecContext(ctx,
		`INSERT INTO graph_edges (src_id, dst_id, edge_type, properties) VALUES (?, ?, ?, ?)`,
		e.SrcID, e.DstID, e.EdgeType, e.Properties)
	if err != nil {
		return 0, fmt.Errorf("db: insert graph edge: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: insert graph edge: last insert id: %w", err)
	}
	return id, nil
}

func (s *store) ListGraphEdgesByType(ctx context.Context, edgeType string) ([]*GraphEdge, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, src_id, dst_id, edge_type, properties FROM graph_edges WHERE edge_type = ? ORDER BY id`, edgeType)
	if err != nil {
		return nil, fmt.Errorf("db: list graph edges by type: %w", err)
	}
	defer rows.Close()
	return scanGraphEdges(rows)
}

func (s *store) ListGraphEdgesFromNode(ctx context.Context, srcID int64, edgeType string) ([]*GraphEdge, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, src_id, dst_id, edge_type, properties FROM graph_edges WHERE src_id = ? AND edge_type = ?`, srcID, edgeType)
	if err != nil {
		return nil, fmt.Errorf("db: list graph edges from node: %w", err)
	}
	defer rows.Close()
	return scanGraphEdges(rows)
}

func (s *store) ListGraphEdgesToNode(ctx context.Context, dstID int64, edgeType string) ([]*GraphEdge, error) {
	rows, err := s.exec.QueryContext(ctx,
		`SELECT id, src_id, dst_id, edge_type, properties FROM graph_edges WHERE dst_id = ? AND edge_type = ?`, dstID, edgeType)
	if err != nil {
		return nil, fmt.Errorf("db: list graph edges to node: %w", err)
	}
	defer rows.Close()
	return scanGraphEdges(rows)
}

func (s *store) ReachableFromEntry(ctx context.Context, entryNodeID int64, edgeType string) ([]int64, error) {
	return s.ReachableFromEntries(ctx, []int64{entryNodeID}, edgeType)
}

func (s *store) ReachableFromEntries(ctx context.Context, entryNodeIDs []int64, edgeType string) ([]int64, error) {
	if len(entryNodeIDs) == 0 {
		return nil, nil
	}
	seeds, err := json.Marshal(entryNodeIDs)
	if err != nil {
		return nil, fmt.Errorf("db: reachable from entries: marshal seeds: %w", err)
	}
	rows, err := s.exec.QueryContext(ctx, `
		WITH RECURSIVE reach(node) AS (
			SELECT CAST(value AS INTEGER) FROM json_each(?)
			UNION
			SELECT ge.dst_id FROM graph_edges ge JOIN reach r ON ge.src_id = r.node WHERE ge.edge_type = ?
		) SELECT DISTINCT node FROM reach`, string(seeds), edgeType)
	if err != nil {
		return nil, fmt.Errorf("db: reachable from entries: %w", err)
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("db: reachable from entries: scan: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func scanGraphEdges(rows *sql.Rows) ([]*GraphEdge, error) {
	var edges []*GraphEdge
	for rows.Next() {
		e := &GraphEdge{}
		if err := rows.Scan(&e.ID, &e.SrcID, &e.DstID, &e.EdgeType, &e.Properties); err != nil {
			return nil, fmt.Errorf("db: scan graph edge: %w", err)
		}
		edges = append(edges, e)
	}
	return edges, rows.Err()
}
