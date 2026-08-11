package agent

import (
	"context"
	"fmt"

	"github.com/DannyAn/secguard-clang/internal/db"
)

type FindingInput struct {
	RuleID     string  `json:"rule_id"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Evidence   string  `json:"evidence"`
	Status     string  `json:"status"`
}

func WriteFinding(ctx context.Context, store db.Store, input *FindingInput) (int64, error) {
	finding := &db.Finding{
		RuleID:     input.RuleID,
		Severity:   input.Severity,
		Confidence: input.Confidence,
		Evidence:   input.Evidence,
		Status:     input.Status,
	}
	id, err := store.InsertFinding(ctx, finding)
	if err != nil {
		return 0, fmt.Errorf("agent: write finding: %w", err)
	}
	return id, nil
}
