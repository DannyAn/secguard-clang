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
	DeleteFile(ctx context.Context, id int64) error
}

type MetaStore interface {
	GetMeta(ctx context.Context, key string) (value string, ok bool, err error)
	SetMeta(ctx context.Context, key, value string) error
}

type FunctionStore interface {
	InsertFunction(ctx context.Context, f *Function) (int64, error)
	GetFunctionByID(ctx context.Context, id int64) (*Function, error)
	GetFunctionByName(ctx context.Context, name string) (*Function, error)
	ListFunctionsByFile(ctx context.Context, fileID int64) ([]*Function, error)
	ListFunctions(ctx context.Context) ([]*Function, error)
	// CountFunctions returns the indexed function count without loading the
	// rows: report headers need only the scale figure.
	CountFunctions(ctx context.Context) (int, error)
	// ListFunctionsByIDs returns the functions with the given IDs keyed by ID,
	// in a single batched query (chunked) instead of one query per ID.
	ListFunctionsByIDs(ctx context.Context, ids []int64) (map[int64]*Function, error)
	DeleteFunctionsByFile(ctx context.Context, fileID int64) error
}

type FunctionDeclarationStore interface {
	InsertFunctionDeclaration(ctx context.Context, d *FunctionDeclaration) (int64, error)
	ListFunctionDeclarations(ctx context.Context) ([]*FunctionDeclaration, error)
	DeleteFunctionDeclarationsByFile(ctx context.Context, fileID int64) error
}

type VariableStore interface {
	InsertVariable(ctx context.Context, v *Variable) (int64, error)
	GetVariableByID(ctx context.Context, id int64) (*Variable, error)
	ListVariablesByFunction(ctx context.Context, functionID int64) ([]*Variable, error)
	ListPointerVariables(ctx context.Context) ([]*Variable, error)
}

type FileScopeVariableStore interface {
	InsertFileScopeVariable(ctx context.Context, v *FileScopeVariable) (int64, error)
	ListFileScopeVariables(ctx context.Context) ([]*FileScopeVariable, error)
	DeleteFileScopeVariablesByFile(ctx context.Context, fileID int64) error
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
	// InsertGraphEdgeBatch inserts all edges in one BEGIN IMMEDIATE transaction,
	// a single write-lock acquisition + fsync instead of one autocommit per edge.
	// A mid-batch error rolls the whole batch back. Returns the number inserted.
	InsertGraphEdgeBatch(ctx context.Context, edges []GraphEdge) (int, error)
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
	// InsertEventBatch inserts the events (each with its own location) in one
	// BEGIN IMMEDIATE transaction — a single SQLite write-lock acquisition
	// instead of one autocommit write per event+location.
	InsertEventBatch(ctx context.Context, events []BatchEvent) (int, error)
	GetEventByID(ctx context.Context, id int64) (*SecurityEvent, error)
	ListEventsByType(ctx context.Context, eventType string) ([]*SecurityEvent, error)
	// CountEventsByType returns the number of events of eventType without
	// loading the rows (SELECT COUNT(*)). The status command needs only the
	// count; loading every event just to len() it is wasteful on large trees.
	CountEventsByType(ctx context.Context, eventType string) (int, error)
	ListEventsByEntity(ctx context.Context, entityID int64) ([]*SecurityEvent, error)
	ListEventsByTypeAndEntity(ctx context.Context, eventType string, entityID int64) ([]*SecurityEvent, error)
	// ListEventsByIDs returns the events with the given IDs keyed by ID, in a
	// single batched query (chunked) instead of one query per ID.
	ListEventsByIDs(ctx context.Context, ids []int64) (map[int64]*SecurityEvent, error)
	// ListEventLocationKeysByType returns the set of "fileID:line" location keys
	// that carry at least one event of eventType. It streams only the joined
	// (file_id, line) pairs instead of materializing the event rows, so a filter
	// can match a candidate's location by file/line without loading the type's
	// full event set (BUFFER_ACCESS can hold tens of thousands of large rows on a
	// large tree; that materialization was the plan-stage OOM trigger).
	//
	// Location rows are per event (locations has no uniqueness constraint), so a
	// candidate and an event at the same file:line have different location ids;
	// the (file_id,line) key is the identity that must be compared.
	ListEventLocationKeysByType(ctx context.Context, eventType string) (map[string]bool, error)
	ClearSecurityEvents(ctx context.Context) error
}

type FindingStore interface {
	InsertFinding(ctx context.Context, f *Finding) (int64, error)
	UpsertFinding(ctx context.Context, f *Finding) (int64, error)
	// FindingIDByLocationKey returns the id of the finding with the same
	// (scan_id, rule_id, file_path, line_number, variable) identity, so a write
	// can report a duplicate update instead of silently adding a second row.
	FindingIDByLocationKey(ctx context.Context, scanID, ruleID, filePath string, line int, variable string) (int64, bool, error)
	ListFindings(ctx context.Context) ([]*Finding, error)
	ListFindingsByStatus(ctx context.Context, status string) ([]*Finding, error)
	GetFindingByID(ctx context.Context, id int64) (*Finding, error)
	UpdateFindingReview(ctx context.Context, id int64, reviewStatus, reviewReasoning string) error
	// UpdateFindingReviewWithProperties records the second-round AI re-review
	// verdict AND merges the structured review audit into properties (the
	// auto_confirm_evidence key is preserved). This is the persist path for the
	// auto-confirmed re-review; the verdict lands in review_status where
	// EffectiveStatus/FinalStatus map it (false_positive → dismissed).
	UpdateFindingReviewWithProperties(ctx context.Context, id int64, reviewStatus, reviewReasoning, properties string) error
	// ListAutoConfirmedForReview returns auto-confirmed findings with no review
	// verdict yet (review_status NULL/''). This is the re-review selection set;
	// an errored review writes no verdict, so the finding stays here and is
	// retried on the next run.
	ListAutoConfirmedForReview(ctx context.Context, scanID string, ruleIDs []string, limit int) ([]*Finding, error)
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
	ListPerTypeStatus(ctx context.Context, scanID string, cwesForType func(string) []string) ([]*PerTypeStatus, error)
	MarkAIStageDone(ctx context.Context, scanID, vulnType string) error
}

type ScanRunStore interface {
	// UpsertScanRun inserts or replaces the scan-level metrics row for a scan_id.
	// Re-running a scan into the same --output-dir overwrites the prior row.
	UpsertScanRun(ctx context.Context, r *ScanRun) error
	// BeginScanRun inserts a 'running' row at scan start (resetting a prior row
	// for the same scan_id), so an OOM-killed scan is visible as interrupted
	// instead of absent.
	BeginScanRun(ctx context.Context, scanID string) error
	GetScanRun(ctx context.Context, scanID string) (*ScanRun, error)
	// ListScanRuns returns the most recent runs first, capped at limit (0 = all).
	ListScanRuns(ctx context.Context, limit int) ([]*ScanRun, error)
	// SetScanRunAIDuration records the AI-classification wall-clock written by
	// `report --audit --ai-duration-ms` at the end of the AI stage.
	SetScanRunAIDuration(ctx context.Context, scanID string, ms int64, source string) error
	// SetScanRunCompletionState updates the scan's completion state (running,
	// complete, incomplete, limited, failed) — the unified checkpoint semantics.
	SetScanRunCompletionState(ctx context.Context, scanID, state string) error
	// MarkStaleRunningAsFailed flips leftover 'running' scans to 'failed',
	// excluding the scan that is starting now. Called at scan start to clean up
	// records from crashed/interrupted scans without touching a live one.
	MarkStaleRunningAsFailed(ctx context.Context, excludeScanID string) (int, error)
	// StaleRunningScanIDs returns the scan IDs currently in 'running' state,
	// excluding the scan that is starting now. It is the read-half of the stale
	// sweep: the scan command uses it to write a .failed marker into each
	// leftover scan directory (an OOM-killed process never runs the normal
	// failure finalizer, so the directory would otherwise stay unmarked).
	StaleRunningScanIDs(ctx context.Context, excludeScanID string) ([]string, error)
	InsertIncompleteTask(ctx context.Context, task *ScanIncompleteTask) error
	ListIncompleteTasks(ctx context.Context, scanID string) ([]*ScanIncompleteTask, error)
}

type InlineSuppressionStore interface {
	// ReplaceInlineSuppressions atomically replaces a file's suppression rows.
	ReplaceInlineSuppressions(ctx context.Context, fileID int64, suppressions []InlineSuppression) error
	// ListInlineSuppressions returns every collected suppression directive.
	ListInlineSuppressions(ctx context.Context) ([]InlineSuppression, error)
}

type FuncPtrWriteStore interface {
	// ReplaceFuncPtrWrites atomically replaces the whole func_ptr_writes table.
	ReplaceFuncPtrWrites(ctx context.Context, writes []FuncPtrWrite) error
	// ListFuncPtrWrites returns every function-pointer slot -> target wiring.
	ListFuncPtrWrites(ctx context.Context) ([]FuncPtrWrite, error)
}

type CandidateVerdictStore interface {
	// UpsertCandidateVerdict idempotently records an AI verdict (dismissed).
	UpsertCandidateVerdict(ctx context.Context, v *CandidateVerdict) (int64, error)
	// ListCandidateVerdicts returns every AI verdict row for a scan.
	ListCandidateVerdicts(ctx context.Context, scanID string) ([]CandidateVerdict, error)
	// CountCandidateVerdictsByType returns the dismissed count per vuln type.
	CountCandidateVerdictsByType(ctx context.Context, scanID string) (map[string]int, error)
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

type SettlementStatStore interface {
	UpsertSettlementStat(ctx context.Context, s *SettlementStat) error
	// GetSettlementStat returns the row for one (scan, type, range), or nil when
	// the batch has never been claimed/settled.
	GetSettlementStat(ctx context.Context, scanID, vulnType, rangeStr string) (*SettlementStat, error)
	// ClaimSettlementRange atomically reserves (scan_id, vuln_type, range_str)
	// for one worker before dispatch. A fresh 'dispatched' row held by another
	// holder loses the claim; a done row is only taken over when reclaim is true
	// (a deliberate needs_context re-review); a 'failed' or stale 'dispatched'
	// row (created_at < staleBefore) is taken over and retry_count bumped.
	ClaimSettlementRange(ctx context.Context, scanID, vulnType, rangeStr, holder string, staleBefore int64, reclaim bool) (*SettlementClaim, error)
	// MarkSettlementStatus updates a settlement row's task status (the
	// executor's dispatched → done/failed lifecycle).
	MarkSettlementStatus(ctx context.Context, scanID, vulnType, rangeStr, subagentID, status string) error
	// IncrementSettlementRetry bumps a settlement row's retry_count and re-marks
	// it dispatched (the executor's retry state machine).
	IncrementSettlementRetry(ctx context.Context, scanID, vulnType, rangeStr, subagentID string) error
	ListSettlementStatsByScan(ctx context.Context, scanID string) ([]*SettlementStat, error)
	// ListSettlementStatsByType returns the most recent settlements for a vuln
	// type across scans (newest first), capped at limit (0 = all). It is the
	// engine's r_type sample: sum(evidence_opens)/sum(written+dismissed).
	ListSettlementStatsByType(ctx context.Context, vulnType string, limit int) ([]*SettlementStat, error)
}

type Store interface {
	FileStore
	FunctionStore
	FunctionDeclarationStore
	VariableStore
	FileScopeVariableStore
	ExpressionStore
	TypeStore
	LocationStore
	GraphNodeStore
	GraphEdgeStore
	SecurityEventStore
	FindingStore
	ScanStatStore
	ScanRunStore
	FunctionSummaryStore
	SettlementStatStore
	ReviewSessionStore
	InlineSuppressionStore
	FuncPtrWriteStore
	CandidateVerdictStore
	MetaStore
	Close() error
	WithTx(ctx context.Context, fn func(Store) error) error
	// WithImmediateTx runs fn in a transaction that acquires the SQLite write
	// lock up front (BEGIN IMMEDIATE). Concurrent writers therefore serialize
	// at BEGIN — a single busy_timeout wait — instead of each row re-waiting the
	// busy_timeout and the app-layer retry. The batch --write-json path uses it.
	WithImmediateTx(ctx context.Context, fn func(Store) error) error
	DB() *sql.DB
}
