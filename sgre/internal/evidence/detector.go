package evidence

import "context"

type Detector interface {
	Name() string
	Detect(ctx context.Context) (DetectResult, error)
}

type DetectResult struct {
	EventsCreated int
	Summary       string
}

type DomainAware interface {
	Domain() string
	Capabilities() []string
}
