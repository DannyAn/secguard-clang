package review

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

type PayloadBuilder struct {
	projectRoot   string
	contextLines  int
	maxBytes      int
	promptVersion string
	schemaVersion string
}

func NewPayloadBuilder(projectRoot, promptVersion, schemaVersion string) *PayloadBuilder {
	return &PayloadBuilder{
		projectRoot:   projectRoot,
		contextLines:  10,
		maxBytes:      32768,
		promptVersion: promptVersion,
		schemaVersion: schemaVersion,
	}
}

func (b *PayloadBuilder) BuildPayload(ctx context.Context, target ReviewTarget) (*ReviewPayload, error) {
	f := target.Finding
	if f == nil {
		return nil, fmt.Errorf("review: build payload: nil finding")
	}
	excerpt, truncated, err := b.readSourceExcerpt(f.FilePath, f.LineNumber)
	if err != nil {
		return nil, fmt.Errorf("review: read source excerpt: %w", err)
	}
	evidence := b.loadEvidence(f)
	vulnType := planner.TypeForCWE(f.RuleID)
	reqs := b.loadReviewRequirements(vulnType)
	payload := &ReviewPayload{
		SchemaVersion: "1",
		ReviewID:      buildReviewID(f.ID, target.ScanSourceRev, b.promptVersion, b.schemaVersion),
		Finding: FindingMeta{
			FindingID:      f.ID,
			Detector:       vulnType,
			OriginalStatus: f.Status,
			Severity:       f.Severity,
			Message:        f.Summary,
			File:           f.FilePath,
			LineStart:      f.LineNumber,
			LineEnd:        f.LineNumber,
			Symbol:         f.FunctionName,
		},
		Source: SourceInfo{
			Revision:         target.ScanSourceRev,
			ReviewedRevision: target.ReviewedRev,
			RevisionVerified: target.RevisionVerified,
			CodeExcerpt:      excerpt,
			Truncated:        truncated,
		},
		Evidence:           evidence,
		ReviewRequirements: reqs,
	}
	return payload, nil
}

// buildReviewID is the deterministic identity of a review: the same finding +
// source revision + prompt/schema version maps to the same review_id, so a
// re-run converges on one review row instead of charging the model again and
// duplicating audit history. A new revision or prompt therefore invalidates the
// old conclusion by producing a new review_id.
func buildReviewID(findingID int64, sourceRevision, promptVersion, schemaVersion string) string {
	return fmt.Sprintf("rv_%d_%s_%s_%s", findingID, sourceRevision, promptVersion, schemaVersion)
}

func (b *PayloadBuilder) readSourceExcerpt(path string, centerLine int) (string, bool, error) {
	if path == "" || centerLine <= 0 {
		return "", false, nil
	}
	fullPath, err := b.resolveSourceFile(path)
	if err != nil {
		return "", false, err
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return "", false, err
	}
	lines := bytes.Split(data, []byte("\n"))
	start := centerLine - b.contextLines
	if start < 1 {
		start = 1
	}
	end := centerLine + b.contextLines
	if end > len(lines) {
		end = len(lines)
	}
	var buf bytes.Buffer
	for i := start - 1; i < end; i++ {
		fmt.Fprintf(&buf, "%d: %s\n", i+1, string(lines[i]))
	}
	truncated := false
	if buf.Len() > b.maxBytes {
		buf.Truncate(b.maxBytes)
		truncated = true
	}
	return buf.String(), truncated, nil
}

// resolveSourceFile maps a finding's file path to a readable absolute path.
// Findings written by the pipeline carry ABSOLUTE paths (the indexer walks an
// absolute root); findings the agent wrote may be repo-relative. Absolute paths
// are trusted (they come from our own DB) and used as-is. Relative paths are
// joined to the project root and containment-checked so a "../" or malformed
// path cannot escape the repository.
func (b *PayloadBuilder) resolveSourceFile(path string) (string, error) {
	if filepath.IsAbs(path) {
		clean := filepath.Clean(path)
		if !isRegularFile(clean) {
			return "", fmt.Errorf("review: source file not found: %s", path)
		}
		return clean, nil
	}
	full := filepath.Join(b.projectRoot, path)
	absFull, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	absRoot, err := filepath.Abs(b.projectRoot)
	if err != nil {
		return "", err
	}
	if absFull != absRoot && !strings.HasPrefix(absFull, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path traversal detected: %q escapes project root", path)
	}
	return absFull, nil
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func (b *PayloadBuilder) loadEvidence(f *db.Finding) EvidenceBundle {
	if f.Properties != "" {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(f.Properties), &raw); err == nil {
			if evBytes, ok := raw["auto_confirm_evidence"]; ok {
				var fragments []EvidenceFragment
				if err := json.Unmarshal(evBytes, &fragments); err == nil {
					return EvidenceBundle{TriggerEvidence: fragments, EvidenceSource: EvidenceSourceAutoConfirm}
				}
			}
		}
	}
	// Fallback: the pipeline's own summary is the minimum review input when the
	// structured auto_confirm_evidence is absent (e.g. findings persisted before
	// evidence retention was added). It is marked fallback, never fabricated.
	if f.Summary != "" {
		return EvidenceBundle{
			TriggerEvidence: []EvidenceFragment{{Type: "summary", Detail: f.Summary}},
			EvidenceSource:  EvidenceSourceFallback,
		}
	}
	return EvidenceBundle{EvidenceSource: EvidenceSourceMissing}
}

func (b *PayloadBuilder) loadReviewRequirements(vulnType string) ReviewReqs {
	if vulnType == "" {
		return ReviewReqs{}
	}
	spec, err := planner.GetVulnTypeSpec(vulnType)
	if err != nil {
		return ReviewReqs{}
	}
	return ReviewReqs{
		RuleAssumptions:  spec.ReviewAssumptions,
		RequiredEvidence: spec.RequiredEvidence,
		KnownLimitations: spec.KnownLimitations,
	}
}
