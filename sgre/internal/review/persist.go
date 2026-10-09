package review

import (
	"context"
	"encoding/json"
	"fmt"
)

// findingReviewWriter is the narrow store surface the persister needs.
type findingReviewWriter interface {
	UpdateFindingReviewWithProperties(ctx context.Context, id int64, reviewStatus, reviewReasoning, properties string) error
}

type ResultPersister struct {
	store findingReviewWriter
}

func NewResultPersister(store findingReviewWriter) *ResultPersister {
	return &ResultPersister{store: store}
}

// reviewAuditRecord is the structured review result persisted into the finding's
// properties under the "review" key. It keeps the full verdict — rationale plus
// the supporting/contradicting/missing evidence arrays — so a later
// false-positive analysis can audit WHY the model rejected a finding.
type reviewAuditRecord struct {
	Verdict               string   `json:"verdict"`
	Rationale             string   `json:"rationale"`
	SupportingEvidence    []string `json:"supporting_evidence,omitempty"`
	ContradictingEvidence []string `json:"contradicting_evidence,omitempty"`
	MissingEvidence       []string `json:"missing_evidence,omitempty"`
	Confidence            float64  `json:"confidence,omitempty"`
	ModelProvider         string   `json:"model_provider,omitempty"`
	Model                 string   `json:"model,omitempty"`
	PromptVersion         string   `json:"prompt_version,omitempty"`
	SchemaVersion         string   `json:"schema_version,omitempty"`
	SourceRevision        string   `json:"source_revision,omitempty"`
	ReviewedRevision      string   `json:"reviewed_revision,omitempty"`
	RevisionVerified      bool     `json:"revision_verified"`
	DurationMs            int64    `json:"duration_ms,omitempty"`
	ReviewedAt            int64    `json:"reviewed_at,omitempty"`
}

// Persist writes the AI verdict into the finding's existing second-round review
// fields: review_status (mapped by EffectiveStatus/FinalStatus, so
// false_positive → dismissed) and review_reasoning (the rationale). The full
// structured verdict is merged into properties under "review" without clobbering
// the auto_confirm_evidence the pipeline stored there.
func (p *ResultPersister) Persist(ctx context.Context, target ReviewTarget, verdict *Verdict, audit *ReviewAudit) error {
	if verdict == nil {
		return fmt.Errorf("review: persist verdict: nil verdict")
	}
	// review_error is not a verdict — it is a call failure, logged by the
	// coordinator and left unreviewed. It must never reach review_status.
	if verdict.Verdict == VerdictReviewError {
		return fmt.Errorf("review: persist verdict: review_error is not a persisted verdict")
	}
	f := target.Finding
	if f == nil {
		return fmt.Errorf("review: persist verdict: nil finding")
	}
	if audit == nil {
		audit = &ReviewAudit{}
	}
	rec := reviewAuditRecord{
		Verdict:               verdict.Verdict,
		Rationale:             verdict.Rationale,
		SupportingEvidence:    verdict.SupportingEvidence,
		ContradictingEvidence: verdict.ContradictingEvidence,
		MissingEvidence:       verdict.MissingEvidence,
		Confidence:            verdict.Confidence,
		ModelProvider:         audit.ModelProvider,
		Model:                 audit.Model,
		PromptVersion:         audit.PromptVersion,
		SchemaVersion:         audit.SchemaVersion,
		SourceRevision:        target.ScanSourceRev,
		ReviewedRevision:      target.ReviewedRev,
		RevisionVerified:      target.RevisionVerified,
		DurationMs:            audit.DurationMs,
		ReviewedAt:            audit.ReviewedAt,
	}
	recJSON, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("review: marshal audit: %w", err)
	}
	merged, err := MergeProperties(f.Properties, string(recJSON))
	if err != nil {
		return fmt.Errorf("review: merge properties: %w", err)
	}
	return p.store.UpdateFindingReviewWithProperties(ctx, f.ID, verdict.Verdict, verdict.Rationale, merged)
}

// MergeProperties merges the review audit JSON into the finding's existing
// properties under the "review" key, preserving every other key (notably
// auto_confirm_evidence).
func MergeProperties(existing string, reviewJSON string) (string, error) {
	var base map[string]json.RawMessage
	if existing != "" {
		if err := json.Unmarshal([]byte(existing), &base); err != nil {
			return "", fmt.Errorf("parse existing properties: %w", err)
		}
	}
	if base == nil {
		base = make(map[string]json.RawMessage)
	}
	if reviewJSON != "" {
		base["review"] = json.RawMessage(reviewJSON)
	}
	out, err := json.Marshal(base)
	if err != nil {
		return "", fmt.Errorf("marshal merged properties: %w", err)
	}
	return string(out), nil
}
