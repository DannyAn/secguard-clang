package worker

import (
	"context"
	"sort"
	"sync"
)

// Verdict is one worker's judgment for one candidate: binary (confirmed /
// dismissed) or inconclusive when the preloaded facts cannot settle it. The
// executor escalates batches that lean too inconclusive.
type Verdict struct {
	Seq    int    `json:"seq"`
	Status string `json:"status"` // confirmed | dismissed | inconclusive
	CWE    string `json:"cwe"`
	Reason string `json:"reason"`
}

// Runner produces verdicts for one assembled batch prompt. The real
// implementation shells out to an LLM; tests use a deterministic fake. It must
// be safe for concurrent use (the executor calls it from a sliding-window pool).
type Runner interface {
	Run(ctx context.Context, p Prompt) ([]Verdict, error)
}

// BatchResult is the executor's per-batch outcome, in submission order.
type BatchResult struct {
	Type     string    `json:"type"`
	Range    string    `json:"range"`
	Verdicts []Verdict `json:"verdicts"`
	// Inconclusive is the count of inconclusive verdicts in this batch.
	Inconclusive int `json:"inconclusive"`
	// Escalate is true when the inconclusive fraction exceeds the escalation
	// threshold — the batch is handed back to agent-mode deep-dive (route B's
	// fallback) instead of being forced to a binary verdict.
	Escalate bool `json:"escalate,omitempty"`
	Err      string `json:"error,omitempty"`
	// MissingSeqs is the conservation-audit gap: expected candidates that got no
	// verdict back. A non-empty value means the worker under-reported, and the
	// caller must re-dispatch exactly these candidates.
	MissingSeqs []int `json:"missing_seqs,omitempty"`
}

// ExecutorConfig tunes the deterministic scheduler.
type ExecutorConfig struct {
	// Concurrency is the sliding-window width (complete-one, dispatch-one). 0
	// defaults to 1.
	Concurrency int
	// InconclusiveEscalation is the inconclusive fraction (0..1) above which a
	// batch is flagged Escalate. 0 disables escalation (never escalate).
	InconclusiveEscalation float64
}

// Executor runs batches through a Runner with a sliding window and audits each
// batch against its expected candidates. It is the route-B deterministic
// scheduler: no LLM orchestrator, no wave barrier — the state machine is code.
type Executor struct {
	runner Runner
	cfg    ExecutorConfig
}

func NewExecutor(runner Runner, cfg ExecutorConfig) *Executor {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1
	}
	return &Executor{runner: runner, cfg: cfg}
}

// Run dispatches every batch, keeping the concurrency window full as
// completions arrive, and returns one BatchResult per batch in submission order.
func (e *Executor) Run(ctx context.Context, batches []Batch) []BatchResult {
	results := make([]BatchResult, len(batches))
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.cfg.Concurrency)
	for i, b := range batches {
		wg.Add(1)
		go func(i int, b Batch) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[i] = BatchResult{Type: b.Type, Err: ctx.Err().Error()}
				return
			}
			p := Assemble(b, Options{})
			verdicts, err := e.runner.Run(ctx, p)
			results[i] = e.audit(b, p, verdicts, err)
		}(i, b)
	}
	wg.Wait()
	return results
}

func (e *Executor) audit(b Batch, p Prompt, verdicts []Verdict, runErr error) BatchResult {
	res := BatchResult{Type: b.Type, Range: p.Range, Verdicts: verdicts}
	if runErr != nil {
		res.Err = runErr.Error()
		return res
	}

	got := make(map[int]bool, len(verdicts))
	for _, v := range verdicts {
		got[v.Seq] = true
		if v.Status == "inconclusive" {
			res.Inconclusive++
		}
	}
	for _, exp := range p.Expected {
		if !got[exp.Seq] {
			res.MissingSeqs = append(res.MissingSeqs, exp.Seq)
		}
	}
	sort.Ints(res.MissingSeqs)

	if e.cfg.InconclusiveEscalation > 0 && p.CandidateCount > 0 &&
		float64(res.Inconclusive)/float64(p.CandidateCount) > e.cfg.InconclusiveEscalation {
		res.Escalate = true
	}
	return res
}
