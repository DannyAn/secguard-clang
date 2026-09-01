package db

import "encoding/json"

// applyStructuredFromProperties fills Summary/Reasoning/FixStrategy/ExceptionCheck
// from the free-form properties JSON when the dedicated fields are empty. This
// lets the agent carry multi-line reasoning and fix code inside a single-line
// JSON payload (newlines are escaped by JSON encoding), so it survives argument
// passing regardless of the invoking shell.
func (f *Finding) ApplyStructuredFromProperties() {
	if f.Properties == "" {
		return
	}
	var p struct {
		Summary        string `json:"summary"`
		Reasoning      string `json:"reasoning"`
		FixStrategy    string `json:"fix_strategy"`
		ExceptionCheck string `json:"exception_check"`
	}
	if err := json.Unmarshal([]byte(f.Properties), &p); err != nil {
		return
	}
	if f.Summary == "" {
		f.Summary = p.Summary
	}
	if f.Reasoning == "" {
		f.Reasoning = p.Reasoning
	}
	if f.FixStrategy == "" {
		f.FixStrategy = p.FixStrategy
	}
	if f.ExceptionCheck == "" {
		f.ExceptionCheck = p.ExceptionCheck
	}
}

// StatusAutoConfirmed is the status of a finding the convergence pipeline wrote
// directly (suspicion_level "confirmed", proved by a flow filter or detector)
// with no AI review. It is a first-class verdict: EffectiveStatus/FinalStatus
// map it to "confirmed" so it reaches every export, but it is excluded from the
// per-type `written_count` (which counts AI-written verdicts only), so the
// orchestrator's resume check still detects "suspected/possible candidates the
// AI never classified" rather than being masked by the machine rows.
const StatusAutoConfirmed = "auto-confirmed"

// EffectiveStatus returns the post-A5 final verdict for a finding. The
// second-round review (ReviewStatus) overrides the first-pass classification:
// confirmed/dismissed/suspected-kept map to confirmed/dismissed/suspected, and a
// finding that was never reviewed keeps its original Status. This is the single
// source of truth for developer-facing counts (audit-report.md and result.sarif).
func (f *Finding) EffectiveStatus() string {
	switch f.ReviewStatus {
	case "confirmed":
		return "confirmed"
	case "dismissed":
		return "dismissed"
	case "suspected-kept":
		return "suspected"
	}
	if f.Status == StatusAutoConfirmed {
		return "confirmed"
	}
	return f.Status
}

// FinalStatus returns the verdict that is allowed to reach the final export
// (result.sarif / result.xlsx / report.md / findings/). The A5 second round has
// been folded into the single-pass classification, so a first-pass verdict is
// final: a plain `suspected` is exportable as `suspected`, exactly like
// `confirmed`/`dismissed`. `review_status` remains an OPTIONAL post-hoc override
// (confirmed/dismissed/suspected-kept) for fixing an individual finding.
//
// The returned value is "", "confirmed", "suspected", or "dismissed". "" means
// "not part of the final result" (e.g. the DB default "open") and must be
// filtered out by every exporter.
func (f *Finding) FinalStatus() string {
	switch f.ReviewStatus {
	case "confirmed":
		return "confirmed"
	case "dismissed":
		return "dismissed"
	case "suspected-kept":
		return "suspected"
	}
	switch f.Status {
	case "confirmed", StatusAutoConfirmed:
		return "confirmed"
	case "suspected":
		return "suspected"
	case "dismissed":
		return "dismissed"
	}
	return ""
}

type File struct {
	ID        int64
	Path      string
	Language  string
	Checksum  string
	LOC       int
	CreatedAt int64
}

type Function struct {
	ID         int64
	FileID     int64
	Name       string
	Signature  string
	ReturnType string
	IsStatic   bool
	StartLine  int
	EndLine    int
}

type Variable struct {
	ID              int64
	FunctionID      int64
	Name            string
	Type            string
	StorageClass    string
	DeclarationLine int
	IsPointer       bool
	IsNullable      bool
	SourceKind      string
}

type Expression struct {
	ID         int64
	FunctionID int64
	Text       string
	Line       int
	ExprType   string
}

type Type struct {
	ID   int64
	Name string
	Kind string
}

type Location struct {
	ID     int64
	FileID int64
	Line   int
	Column int
}

type GraphNode struct {
	ID         int64
	EntityType string
	EntityID   int64
	Properties string
}

type GraphEdge struct {
	ID         int64
	SrcID      int64
	DstID      int64
	EdgeType   string
	Properties string
}

type SecurityEvent struct {
	ID         int64
	EventType  string
	EntityID   int64
	LocationID int64
	Properties string
}

type Finding struct {
	ID              int64   `json:"id"`
	RuleID          string  `json:"rule_id"`
	Severity        string  `json:"severity"`
	Confidence      float64 `json:"confidence"`
	Evidence        string  `json:"evidence"`
	Status          string  `json:"status"`
	FilePath        string  `json:"file_path"`
	LineNumber      int     `json:"line_number"`
	FunctionName    string  `json:"function_name"`
	Properties      string  `json:"properties,omitempty"`
	Summary         string  `json:"summary,omitempty"`
	Reasoning       string  `json:"reasoning,omitempty"`
	FixStrategy     string  `json:"fix_strategy,omitempty"`
	ExceptionCheck  string  `json:"exception_check,omitempty"`
	ReviewStatus    string  `json:"review_status,omitempty"`
	ReviewReasoning string  `json:"review_reasoning,omitempty"`
	ScanID          string  `json:"scan_id,omitempty"`
	// Fingerprint is a content-addressed, scan-independent identity for a
	// finding (rule_id + file + function + sink-statement text). It lets the
	// incremental-review pipeline dedup a finding across scans and against a
	// full-scan baseline even when the line number drifts.
	Fingerprint string  `json:"fingerprint,omitempty"`
	CreatedAt   int64   `json:"created_at"`
}

type ReviewSession struct {
	ID           int64  `json:"id"`
	ReviewID     string `json:"review_id"`
	Kind         string `json:"kind"`
	BaseRef      string `json:"base_ref"`
	HeadRef      string `json:"head_ref"`
	BaseSHA      string `json:"base_sha"`
	HeadSHA      string `json:"head_sha"`
	ChangedFiles string `json:"changed_files,omitempty"`
	Status       string `json:"status"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type ScanStat struct {
	ID          int64  `json:"id"`
	ScanID      string `json:"scan_id"`
	VulnType    string `json:"vuln_type"`
	SeedCount   int    `json:"seed_count"`
	FinalCount  int    `json:"final_count"`
	FilterChain string `json:"filter_chain"`
	CreatedAt   int64  `json:"created_at"`
}

// PerTypeStatus is the per-vulnerability-type progress record for the
// `secguard status --per-type` resume-scan view. CandidateCount comes from
// scan_stats.final_count (the convergence pipeline's candidate output);
// WrittenCount is the live COUNT over findings for that (scan_id, rule_id);
// TerminalState is derived: done / in-progress / pending / unknown. It is the
// authoritative resume state — the orchestrator queries it to decide which
// types still need classification after an interrupted scan.
type PerTypeStatus struct {
	VulnType       string `json:"vuln_type"`
	CWE            string `json:"cwe"`
	CandidateCount int    `json:"candidate_count"`
	WrittenCount   int    `json:"written_count"`
	TerminalState  string `json:"terminal_state"`
}

type FunctionSummary struct {
	FunctionID        int64
	ReturnNullable    bool
	ParameterNullable string
	SideEffect        string
	SummaryJSON       string
}
