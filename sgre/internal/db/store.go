package db

import (
	"context"
	"database/sql"
)

type FileStore interface {
	InsertFile(ctx context.Context, f *File) (int64, error)
	GetFileByID(ctx context.Context, id int64) (*File, error)
	GetFileByPath(ctx context.Context, path string) (*File, error)
	ListFiles(ctx context.Context) ([]*File, error)
	UpdateFileChecksum(ctx context.Context, id int64, checksum string, loc int) error
}

type FunctionStore interface {
	InsertFunction(ctx context.Context, f *Function) (int64, error)
	GetFunctionByID(ctx context.Context, id int64) (*Function, error)
	GetFunctionByName(ctx context.Context, name string) (*Function, error)
	ListFunctionsByFile(ctx context.Context, fileID int64) ([]*Function, error)
	ListFunctions(ctx context.Context) ([]*Function, error)
	// ListFunctionsByIDs returns the functions with the given IDs keyed by ID,
	// in a single batched query (chunked) instead of one query per ID.
	ListFunctionsByIDs(ctx context.Context, ids []int64) (map[int64]*Function, error)
	DeleteFunctionsByFile(ctx context.Context, fileID int64) error
}

type VariableStore interface {
	InsertVariable(ctx context.Context, v *Variable) (int64, error)
	GetVariableByID(ctx context.Context, id int64) (*Variable, error)
	ListVariablesByFunction(ctx context.Context, functionID int64) ([]*Variable, error)
	ListPointerVariables(ctx context.Context) ([]*Variable, error)
}

type ExpressionStore interface {
	InsertExpression(ctx context.Context, e *Expression) (int64, error)
	ListExpressionsByFunction(ctx context.Context, functionID int64) ([]*Expression, error)
}

type TypeStore interface {
	InsertType(ctx context.Context, ty *Type) (int64, error)
	GetTypeByName(ctx context.Context, name string) (*Type, error)
	ListTypes(ctx context.Context) ([]*Type, error)
}

type LocationStore interface {
	InsertLocation(ctx context.Context, loc *Location) (int64, error)
	GetLocationByID(ctx context.Context, id int64) (*Location, error)
	ListLocationsByFile(ctx context.Context, fileID int64) ([]*Location, error)
	// ListLocationsByIDs returns the locations with the given IDs keyed by ID,
	// in a single batched query (chunked) instead of one query per ID.
	ListLocationsByIDs(ctx context.Context, ids []int64) (map[int64]*Location, error)
}

type GraphNodeStore interface {
	InsertGraphNode(ctx context.Context, n *GraphNode) (int64, error)
	GetGraphNodeByID(ctx context.Context, id int64) (*GraphNode, error)
	GetOrCreateGraphNode(ctx context.Context, entityType string, entityID int64, properties string) (int64, error)
	ListGraphNodesByEntity(ctx context.Context, entityType string, entityID int64) ([]*GraphNode, error)
	// ListGraphNodesByEntityType returns every graph node of a given entity
	// type in one query. It exists so callers building an entity->node map
	// (e.g. the call-reach filter) avoid one query per entity.
	ListGraphNodesByEntityType(ctx context.Context, entityType string) ([]*GraphNode, error)
	// ClearGraph removes every graph node and edge so a scan rebuilds the
	// semantic graph from scratch. The graph has no incremental update path and
	// graph_edges has no UNIQUE constraint, so without this each scan would
	// re-insert the full edge set on top of the previous scan's rows (plus leave
	// stale nodes for functions that were deleted), bloating the DB linearly in
	// scan count and slowing every ListGraphEdgesByType consumer.
	ClearGraph(ctx context.Context) error
}

type GraphEdgeStore interface {
	InsertGraphEdge(ctx context.Context, e *GraphEdge) (int64, error)
	ListGraphEdgesByType(ctx context.Context, edgeType string) ([]*GraphEdge, error)
	ListGraphEdgesFromNode(ctx context.Context, srcID int64, edgeType string) ([]*GraphEdge, error)
	ListGraphEdgesToNode(ctx context.Context, dstID int64, edgeType string) ([]*GraphEdge, error)
	ReachableFromEntry(ctx context.Context, entryNodeID int64, edgeType string) ([]int64, error)
	// ReachableFromEntries returns the union of nodes reachable from any of the
	// given entry nodes over edges of edgeType, in a single graph traversal.
	// It is the multi-source form of ReachableFromEntry and exists so the
	// call-reach filter can avoid one recursive query per entry function.
	ReachableFromEntries(ctx context.Context, entryNodeIDs []int64, edgeType string) ([]int64, error)
}

type SecurityEventStore interface {
	InsertEvent(ctx context.Context, e *SecurityEvent) (int64, error)
	GetEventByID(ctx context.Context, id int64) (*SecurityEvent, error)
	ListEventsByType(ctx context.Context, eventType string) ([]*SecurityEvent, error)
	ListEventsByEntity(ctx context.Context, entityID int64) ([]*SecurityEvent, error)
	ListEventsByTypeAndEntity(ctx context.Context, eventType string, entityID int64) ([]*SecurityEvent, error)
	// ListEventsByIDs returns the events with the given IDs keyed by ID, in a
	// single batched query (chunked) instead of one query per ID.
	ListEventsByIDs(ctx context.Context, ids []int64) (map[int64]*SecurityEvent, error)
	ClearSecurityEvents(ctx context.Context) error
}

type FindingStore interface {
	InsertFinding(ctx context.Context, f *Finding) (int64, error)
	UpsertFinding(ctx context.Context, f *Finding) (int64, error)
	ListFindings(ctx context.Context) ([]*Finding, error)
	ListFindingsByStatus(ctx context.Context, status string) ([]*Finding, error)
	GetFindingByID(ctx context.Context, id int64) (*Finding, error)
	UpdateFindingReview(ctx context.Context, id int64, reviewStatus, reviewReasoning string) error
	// ListFingerprintsExcludingScanID returns the set of distinct non-empty
	// finding fingerprints across every scan except excludeScanID. It is the
	// incremental-review baseline: a candidate whose fingerprint is already
	// present (from a full scan or a prior review) is not new and is filtered.
	ListFingerprintsExcludingScanID(ctx context.Context, excludeScanID string) (map[string]bool, error)
}

type ReviewSessionStore interface {
	UpsertReviewSession(ctx context.Context, r *ReviewSession) error
	GetReviewSessionByID(ctx context.Context, reviewID string) (*ReviewSession, error)
	UpdateReviewSessionStatus(ctx context.Context, reviewID, status string) error
}

type ScanStatStore interface {
	InsertScanStat(ctx context.Context, stat *ScanStat) (int64, error)
	ListScanStats(ctx context.Context, scanID string) ([]*ScanStat, error)
	GetLatestScanID(ctx context.Context) (string, error)
	CountFindingsByScanAndStatus(ctx context.Context, scanID, status string) (int, error)
	ListFindingsByScanID(ctx context.Context, scanID string) ([]*Finding, error)
	ListPerTypeStatus(ctx context.Context, scanID string, cweForType func(string) string) ([]*PerTypeStatus, error)
}

type FunctionSummaryStore interface {
	UpsertSummary(ctx context.Context, s *FunctionSummary) error
	GetSummaryByFunction(ctx context.Context, functionID int64) (*FunctionSummary, error)
	// ListSummariesByFunctionIDs returns the summaries for the given function IDs
	// keyed by function ID, in a single batched query (chunked) instead of one
	// query per function.
	ListSummariesByFunctionIDs(ctx context.Context, functionIDs []int64) (map[int64]*FunctionSummary, error)
	UpdateReturnNullable(ctx context.Context, functionID int64, nullable bool) error
}

type Store interface {
	FileStore
	FunctionStore
	VariableStore
	ExpressionStore
	TypeStore
	LocationStore
	GraphNodeStore
	GraphEdgeStore
	SecurityEventStore
	FindingStore
	ScanStatStore
	FunctionSummaryStore
	ReviewSessionStore
	Close() error
	WithTx(ctx context.Context, fn func(Store) error) error
	DB() *sql.DB
}
