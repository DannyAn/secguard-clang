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
	ClearSecurityEvents(ctx context.Context) error
}

type FindingStore interface {
	InsertFinding(ctx context.Context, f *Finding) (int64, error)
	ListFindings(ctx context.Context) ([]*Finding, error)
	ListFindingsByStatus(ctx context.Context, status string) ([]*Finding, error)
}

type ScanStatStore interface {
	InsertScanStat(ctx context.Context, stat *ScanStat) (int64, error)
	ListScanStats(ctx context.Context, scanID string) ([]*ScanStat, error)
	GetLatestScanID(ctx context.Context) (string, error)
	CountFindingsByScanAndStatus(ctx context.Context, scanID, status string) (int, error)
	ListFindingsByScanID(ctx context.Context, scanID string) ([]*Finding, error)
}

type FunctionSummaryStore interface {
	UpsertSummary(ctx context.Context, s *FunctionSummary) error
	GetSummaryByFunction(ctx context.Context, functionID int64) (*FunctionSummary, error)
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
	Close() error
	WithTx(ctx context.Context, fn func(Store) error) error
	DB() *sql.DB
}
