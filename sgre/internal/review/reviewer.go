package review

import (
	"context"
	"fmt"
)

type Reviewer interface {
	Review(ctx context.Context, payload *ReviewPayload) (*Verdict, error)
}

type MockReviewer struct {
	VerdictFn func(*ReviewPayload) (*Verdict, error)
}

func (m *MockReviewer) Review(ctx context.Context, payload *ReviewPayload) (*Verdict, error) {
	if m.VerdictFn == nil {
		return nil, fmt.Errorf("mock reviewer: VerdictFn not set")
	}
	return m.VerdictFn(payload)
}
