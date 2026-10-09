package review

import (
	"github.com/DannyAn/secguard-clang/internal/db"
)

type ReviewPayload struct {
	SchemaVersion      string         `json:"schema_version"`
	ReviewID           string         `json:"review_id"`
	Finding            FindingMeta    `json:"finding"`
	Source             SourceInfo     `json:"source"`
	Evidence           EvidenceBundle `json:"evidence"`
	ReviewRequirements ReviewReqs     `json:"review_requirements"`
}

type FindingMeta struct {
	FindingID      int64  `json:"finding_id"`
	Detector       string `json:"detector"`
	OriginalStatus string `json:"original_status"`
	Severity       string `json:"severity"`
	Message        string `json:"message"`
	File           string `json:"file"`
	LineStart      int    `json:"line_start"`
	LineEnd        int    `json:"line_end"`
	Symbol         string `json:"symbol"`
}

type SourceInfo struct {
	// Revision is the source revision the finding was produced from (the
	// scan-time scan_runs.source_revision). Empty for historical scans.
	Revision string `json:"revision"`
	// ReviewedRevision is the revision the code excerpt was actually read from
	// (usually the current HEAD). It may differ from Revision.
	ReviewedRevision string `json:"reviewed_revision,omitempty"`
	// RevisionVerified is true when the reviewed source is proven to match the
	// scan-time source (same non-empty revision and a clean working tree).
	RevisionVerified bool   `json:"revision_verified"`
	CodeExcerpt      string `json:"code_excerpt"`
	Truncated        bool   `json:"truncated,omitempty"`
}

type EvidenceBundle struct {
	TriggerEvidence  []EvidenceFragment `json:"trigger_evidence"`
	ControlFlow      []string           `json:"control_flow"`
	RelatedCalls     []string           `json:"related_calls"`
	DetectorMetadata map[string]string  `json:"detector_metadata"`
	EvidenceSource   string             `json:"evidence_source"`
}

type EvidenceFragment struct {
	Type   string `json:"type"`
	Role   string `json:"role,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type ReviewReqs struct {
	RuleAssumptions  []string `json:"rule_assumptions"`
	RequiredEvidence []string `json:"required_evidence"`
	KnownLimitations []string `json:"known_limitations"`
}

type Verdict struct {
	FindingID             int64    `json:"finding_id"`
	Verdict               string   `json:"verdict"`
	Rationale             string   `json:"rationale"`
	SupportingEvidence    []string `json:"supporting_evidence"`
	ContradictingEvidence []string `json:"contradicting_evidence"`
	MissingEvidence       []string `json:"missing_evidence"`
	Confidence            float64  `json:"confidence"`
}

type ReviewAudit struct {
	ModelProvider    string  `json:"model_provider"`
	Model            string  `json:"model,omitempty"`
	PromptVersion    string  `json:"prompt_version"`
	SchemaVersion    string  `json:"schema_version"`
	SourceRevision   string  `json:"source_revision"`
	ReviewedRevision string  `json:"reviewed_revision"`
	RevisionVerified bool    `json:"revision_verified"`
	DurationMs       int64   `json:"duration_ms"`
	Confidence       float64 `json:"confidence"`
	ReviewedAt       int64   `json:"reviewed_at"`
}

type ReviewTarget struct {
	Finding          *db.Finding
	ScanSourceRev    string
	ReviewedRev      string
	RevisionVerified bool
}

type RunFilter struct {
	ScanID    string
	VulnTypes []string
	Limit     int
}

type RunOptions struct {
	DryRun           bool
	ProjectRoot      string
	OutputJSON       string
	ScanSourceRev    string
	ReviewedRevision string
	TreeDirty        bool
}

type RunResult struct {
	Total              int                       `json:"total"`
	ByVerdict          map[string]int            `json:"by_verdict"`
	ByDetector         map[string]map[string]int `json:"by_detector"`
	AIStats            AICallStats               `json:"ai_stats"`
	EvidenceSources    map[string]int            `json:"evidence_sources"`
	RevisionMismatches int                       `json:"revision_mismatches"`
	DurationMs         int64                     `json:"duration_ms"`
}

type AICallStats struct {
	TotalCalls      int   `json:"total_calls"`
	Successful      int   `json:"successful"`
	Failed          int   `json:"failed"`
	TotalDurationMs int64 `json:"total_duration_ms"`
}

type ReviewRecord struct {
	FindingID        int64  `json:"finding_id"`
	ScanID           string `json:"scan_id"`
	RuleID           string `json:"rule_id"`
	Verdict          string `json:"verdict"`
	Rationale        string `json:"rationale"`
	ModelProvider    string `json:"model_provider"`
	SourceRevision   string `json:"source_revision"`
	ReviewedRevision string `json:"reviewed_revision"`
	RevisionVerified bool   `json:"revision_verified"`
	ReviewedAt       int64  `json:"reviewed_at"`
	DurationMs       int64  `json:"duration_ms"`
}

const (
	VerdictAIConfirmed       = "ai_confirmed"
	VerdictFalsePositive     = "false_positive"
	VerdictNeedsMoreEvidence = "needs_more_evidence"
	VerdictReviewError       = "review_error"
)

const (
	EvidenceSourceAutoConfirm = "auto_confirm_evidence"
	EvidenceSourceFallback    = "fallback"
	EvidenceSourceMissing     = "missing"
)
