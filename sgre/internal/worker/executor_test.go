package worker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/planner"
)

func candidateBatch(typ string, n int) Batch {
	b := Batch{Type: typ, RangeStart: 0, RangeEnd: n}
	for i := 0; i < n; i++ {
		b.Candidates = append(b.Candidates, planner.EvidenceItem{
			Type:              typ,
			VulnerabilityType: typ,
			SuspicionLevel:    "suspected",
			Target:            planner.TargetInfo{File: "a.c", Function: "f", Line: i + 1, Variable: "p"},
			Hint:              "—",
		})
	}
	return b
}

// fakeRunner returns one verdict per expected candidate, with an optional
// overrides map (seq -> status) and an optional drop of a set of seqs.
type fakeRunner struct {
	mu        sync.Mutex
	active    int
	maxActive int
	overrides map[int]string
	drop      map[int]bool
	delay     time.Duration
}

func (f *fakeRunner) Run(ctx context.Context, p Prompt) ([]Verdict, error) {
	f.mu.Lock()
	f.active++
	if f.active > f.maxActive {
		f.maxActive = f.active
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.active--
		f.mu.Unlock()
	}()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var out []Verdict
	for _, exp := range p.Expected {
		if f.drop[exp.Seq] {
			continue
		}
		status := "confirmed"
		if f.overrides != nil {
			if s, ok := f.overrides[exp.Seq]; ok {
				status = s
			}
		}
		out = append(out, Verdict{Seq: exp.Seq, Status: status, CWE: "CWE-476", Reason: "test"})
	}
	return out, nil
}

func TestExecutorProducesAllBatchesInOrder(t *testing.T) {
	runner := &fakeRunner{}
	ex := NewExecutor(runner, ExecutorConfig{Concurrency: 3})

	batches := []Batch{candidateBatch("null-deref", 3), candidateBatch("uninit", 2), candidateBatch("leak", 4)}
	res := ex.Run(context.Background(), batches)

	if len(res) != 3 {
		t.Fatalf("got %d results, want 3", len(res))
	}
	for i, r := range res {
		if r.Type != batches[i].Type {
			t.Errorf("result %d type = %q, want %q (order must be preserved)", i, r.Type, batches[i].Type)
		}
		if r.Err != "" {
			t.Errorf("result %d unexpected error: %s", i, r.Err)
		}
		if len(r.MissingSeqs) != 0 {
			t.Errorf("result %d missing seqs = %v, want none", i, r.MissingSeqs)
		}
	}
	if res[0].Range != "1-3" || res[2].Range != "1-4" {
		t.Errorf("range strings wrong: %q %q", res[0].Range, res[2].Range)
	}
}

func TestExecutorConservationAudit(t *testing.T) {
	runner := &fakeRunner{drop: map[int]bool{2: true}}
	ex := NewExecutor(runner, ExecutorConfig{Concurrency: 2})

	res := ex.Run(context.Background(), []Batch{candidateBatch("null-deref", 4)})
	if len(res[0].MissingSeqs) != 1 || res[0].MissingSeqs[0] != 2 {
		t.Errorf("missing seqs = %v, want [2]", res[0].MissingSeqs)
	}
}

func TestExecutorEscalation(t *testing.T) {
	runner := &fakeRunner{overrides: map[int]string{1: "inconclusive", 2: "inconclusive", 3: "inconclusive", 4: "confirmed"}}
	ex := NewExecutor(runner, ExecutorConfig{Concurrency: 1, InconclusiveEscalation: 0.5})

	res := ex.Run(context.Background(), []Batch{candidateBatch("null-deref", 4)})
	if res[0].Inconclusive != 3 {
		t.Errorf("inconclusive = %d, want 3", res[0].Inconclusive)
	}
	if !res[0].Escalate {
		t.Errorf("3/4 inconclusive should escalate at threshold 0.5")
	}

	ex2 := NewExecutor(runner, ExecutorConfig{Concurrency: 1, InconclusiveEscalation: 0.9})
	res2 := ex2.Run(context.Background(), []Batch{candidateBatch("null-deref", 4)})
	if res2[0].Escalate {
		t.Errorf("3/4 inconclusive must NOT escalate at threshold 0.9")
	}
}

func TestExecutorRespectsConcurrencyWindow(t *testing.T) {
	runner := &fakeRunner{delay: 20 * time.Millisecond}
	ex := NewExecutor(runner, ExecutorConfig{Concurrency: 4})

	batches := make([]Batch, 8)
	for i := range batches {
		batches[i] = candidateBatch("null-deref", 2)
	}
	ex.Run(context.Background(), batches)

	if runner.maxActive > 4 {
		t.Errorf("max concurrent = %d, must never exceed window 4", runner.maxActive)
	}
	if runner.maxActive < 2 {
		t.Errorf("max concurrent = %d, parallelism was not exercised", runner.maxActive)
	}
}

func TestExecutorContextCancellation(t *testing.T) {
	runner := &fakeRunner{delay: 200 * time.Millisecond}
	ex := NewExecutor(runner, ExecutorConfig{Concurrency: 1})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := ex.Run(ctx, []Batch{candidateBatch("null-deref", 1)})
	if res[0].Err == "" {
		t.Errorf("a cancelled context must surface an error, got %+v", res[0])
	}
}
