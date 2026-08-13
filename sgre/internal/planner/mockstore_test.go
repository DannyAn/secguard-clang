package planner

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type mockStore struct {
	files     []*db.File
	funcs     []*db.Function
	events    []*db.SecurityEvent
	edges     []*db.GraphEdge
	nodes     []*db.GraphNode
	locs      []*db.Location
	findings  []*db.Finding
	summaries map[int64]*db.FunctionSummary
	nextID    int64
}

func newMockStore() *mockStore {
	return &mockStore{
		summaries: make(map[int64]*db.FunctionSummary),
		nextID:    1,
	}
}

func (s *mockStore) InsertFile(ctx context.Context, f *db.File) (int64, error) {
	f.ID = s.nextID
	s.nextID++
	s.files = append(s.files, f)
	return f.ID, nil
}
func (s *mockStore) GetFileByID(ctx context.Context, id int64) (*db.File, error) {
	for _, f := range s.files {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, nil
}
func (s *mockStore) GetFileByPath(ctx context.Context, path string) (*db.File, error) {
	for _, f := range s.files {
		if f.Path == path {
			return f, nil
		}
	}
	return nil, nil
}
func (s *mockStore) ListFiles(ctx context.Context) ([]*db.File, error) { return s.files, nil }
func (s *mockStore) UpdateFileChecksum(ctx context.Context, id int64, checksum string, loc int) error {
	return nil
}

func (s *mockStore) InsertFunction(ctx context.Context, f *db.Function) (int64, error) {
	f.ID = s.nextID
	s.nextID++
	s.funcs = append(s.funcs, f)
	return f.ID, nil
}
func (s *mockStore) GetFunctionByID(ctx context.Context, id int64) (*db.Function, error) {
	for _, f := range s.funcs {
		if f.ID == id {
			return f, nil
		}
	}
	return nil, nil
}
func (s *mockStore) GetFunctionByName(ctx context.Context, name string) (*db.Function, error) {
	for _, f := range s.funcs {
		if f.Name == name {
			return f, nil
		}
	}
	return nil, nil
}
func (s *mockStore) ListFunctionsByFile(ctx context.Context, fileID int64) ([]*db.Function, error) {
	var result []*db.Function
	for _, f := range s.funcs {
		if f.FileID == fileID {
			result = append(result, f)
		}
	}
	return result, nil
}
func (s *mockStore) ListFunctions(ctx context.Context) ([]*db.Function, error) { return s.funcs, nil }

func (s *mockStore) DeleteFunctionsByFile(ctx context.Context, fileID int64) error {
	kept := s.funcs[:0]
	for _, f := range s.funcs {
		if f.FileID != fileID {
			kept = append(kept, f)
		}
	}
	s.funcs = kept
	return nil
}

func (s *mockStore) InsertVariable(ctx context.Context, v *db.Variable) (int64, error) {
	return s.nextID, nil
}
func (s *mockStore) GetVariableByID(ctx context.Context, id int64) (*db.Variable, error) {
	return nil, nil
}
func (s *mockStore) ListVariablesByFunction(ctx context.Context, fid int64) ([]*db.Variable, error) {
	return nil, nil
}
func (s *mockStore) ListPointerVariables(ctx context.Context) ([]*db.Variable, error) {
	return nil, nil
}

func (s *mockStore) InsertExpression(ctx context.Context, e *db.Expression) (int64, error) {
	return s.nextID, nil
}
func (s *mockStore) ListExpressionsByFunction(ctx context.Context, fid int64) ([]*db.Expression, error) {
	return nil, nil
}

func (s *mockStore) InsertType(ctx context.Context, t *db.Type) (int64, error) { return s.nextID, nil }
func (s *mockStore) GetTypeByName(ctx context.Context, name string) (*db.Type, error) {
	return nil, nil
}
func (s *mockStore) ListTypes(ctx context.Context) ([]*db.Type, error) { return nil, nil }

func (s *mockStore) InsertLocation(ctx context.Context, l *db.Location) (int64, error) {
	l.ID = s.nextID
	s.nextID++
	s.locs = append(s.locs, l)
	return l.ID, nil
}
func (s *mockStore) GetLocationByID(ctx context.Context, id int64) (*db.Location, error) {
	for _, l := range s.locs {
		if l.ID == id {
			return l, nil
		}
	}
	return nil, nil
}
func (s *mockStore) ListLocationsByFile(ctx context.Context, fid int64) ([]*db.Location, error) {
	return nil, nil
}

func (s *mockStore) InsertGraphNode(ctx context.Context, n *db.GraphNode) (int64, error) {
	n.ID = s.nextID
	s.nextID++
	s.nodes = append(s.nodes, n)
	return n.ID, nil
}
func (s *mockStore) GetGraphNodeByID(ctx context.Context, id int64) (*db.GraphNode, error) {
	return nil, nil
}
func (s *mockStore) GetOrCreateGraphNode(ctx context.Context, et string, eid int64, props string) (int64, error) {
	for _, n := range s.nodes {
		if n.EntityType == et && n.EntityID == eid {
			return n.ID, nil
		}
	}
	return s.InsertGraphNode(ctx, &db.GraphNode{EntityType: et, EntityID: eid, Properties: props})
}
func (s *mockStore) ListGraphNodesByEntity(ctx context.Context, et string, eid int64) ([]*db.GraphNode, error) {
	var result []*db.GraphNode
	for _, n := range s.nodes {
		if n.EntityType == et && n.EntityID == eid {
			result = append(result, n)
		}
	}
	return result, nil
}

func (s *mockStore) InsertGraphEdge(ctx context.Context, e *db.GraphEdge) (int64, error) {
	e.ID = s.nextID
	s.nextID++
	s.edges = append(s.edges, e)
	return e.ID, nil
}
func (s *mockStore) ListGraphEdgesByType(ctx context.Context, et string) ([]*db.GraphEdge, error) {
	var result []*db.GraphEdge
	for _, e := range s.edges {
		if e.EdgeType == et {
			result = append(result, e)
		}
	}
	return result, nil
}
func (s *mockStore) ListGraphEdgesFromNode(ctx context.Context, src int64, et string) ([]*db.GraphEdge, error) {
	return nil, nil
}
func (s *mockStore) ListGraphEdgesToNode(ctx context.Context, dst int64, et string) ([]*db.GraphEdge, error) {
	return nil, nil
}
func (s *mockStore) ReachableFromEntry(ctx context.Context, entry int64, et string) ([]int64, error) {
	visited := make(map[int64]bool)
	var result []int64
	var dfs func(node int64)
	dfs = func(node int64) {
		if visited[node] {
			return
		}
		visited[node] = true
		result = append(result, node)
		for _, e := range s.edges {
			if e.EdgeType == et && e.SrcID == node {
				dfs(e.DstID)
			}
		}
	}
	dfs(entry)
	return result, nil
}

func (s *mockStore) InsertEvent(ctx context.Context, e *db.SecurityEvent) (int64, error) {
	e.ID = s.nextID
	s.nextID++
	s.events = append(s.events, e)
	return e.ID, nil
}
func (s *mockStore) GetEventByID(ctx context.Context, id int64) (*db.SecurityEvent, error) {
	for _, e := range s.events {
		if e.ID == id {
			return e, nil
		}
	}
	return nil, fmt.Errorf("event not found: %d", id)
}
func (s *mockStore) ListEventsByType(ctx context.Context, et string) ([]*db.SecurityEvent, error) {
	var result []*db.SecurityEvent
	for _, e := range s.events {
		if e.EventType == et {
			result = append(result, e)
		}
	}
	return result, nil
}
func (s *mockStore) ListEventsByEntity(ctx context.Context, eid int64) ([]*db.SecurityEvent, error) {
	return nil, nil
}
func (s *mockStore) ListEventsByTypeAndEntity(ctx context.Context, et string, eid int64) ([]*db.SecurityEvent, error) {
	return nil, nil
}
func (s *mockStore) ClearSecurityEvents(ctx context.Context) error {
	s.events = nil
	return nil
}

func (s *mockStore) InsertFinding(ctx context.Context, f *db.Finding) (int64, error) {
	f.ID = s.nextID
	s.nextID++
	s.findings = append(s.findings, f)
	return f.ID, nil
}
func (s *mockStore) ListFindings(ctx context.Context) ([]*db.Finding, error) { return s.findings, nil }
func (s *mockStore) ListFindingsByStatus(ctx context.Context, status string) ([]*db.Finding, error) {
	return nil, nil
}

func (s *mockStore) UpsertSummary(ctx context.Context, sum *db.FunctionSummary) error {
	s.summaries[sum.FunctionID] = sum
	return nil
}
func (s *mockStore) GetSummaryByFunction(ctx context.Context, fid int64) (*db.FunctionSummary, error) {
	return s.summaries[fid], nil
}
func (s *mockStore) UpdateReturnNullable(ctx context.Context, fid int64, nullable bool) error {
	if sum, ok := s.summaries[fid]; ok {
		sum.ReturnNullable = nullable
	} else {
		s.summaries[fid] = &db.FunctionSummary{FunctionID: fid, ReturnNullable: nullable}
	}
	return nil
}

func (s *mockStore) Close() error                                              { return nil }
func (s *mockStore) DB() *sql.DB                                               { return nil }
func (s *mockStore) WithTx(ctx context.Context, fn func(db.Store) error) error { return fn(s) }

func (s *mockStore) InsertScanStat(ctx context.Context, stat *db.ScanStat) (int64, error) {
	return 0, nil
}
func (s *mockStore) ListScanStats(ctx context.Context, scanID string) ([]*db.ScanStat, error) {
	return nil, nil
}
func (s *mockStore) GetLatestScanID(ctx context.Context) (string, error) {
	return "", nil
}
func (s *mockStore) CountFindingsByScanAndStatus(ctx context.Context, scanID, status string) (int, error) {
	return 0, nil
}
func (s *mockStore) ListFindingsByScanID(ctx context.Context, scanID string) ([]*db.Finding, error) {
	return nil, nil
}

var _ = fmt.Sprintf
