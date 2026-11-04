// Package concurrency provides the resizable admission gate used by the scan
// stages to participate in memory backpressure.
package concurrency

import (
	"context"
	"sync"
)

// Gate limits the number of in-flight tasks. Its limit is 1 while pressured is
// true and max otherwise; shrinking takes effect for NEW admissions (tasks
// already running are never killed), so the stage drains to one task instead of
// merely pausing new work.
type Gate struct {
	max       int
	pressured func() bool

	mu       sync.Mutex
	inflight int
	notify   chan struct{}
}

// NewGate creates a gate with the given maximum parallelism. max < 1 is
// clamped to 1; a nil pressured predicate means "never pressured".
func NewGate(max int, pressured func() bool) *Gate {
	if max < 1 {
		max = 1
	}
	return &Gate{max: max, pressured: pressured, notify: make(chan struct{})}
}

// Acquire blocks until a slot is available or ctx is canceled. It reports
// whether the slot was acquired.
func (g *Gate) Acquire(ctx context.Context) bool {
	for {
		g.mu.Lock()
		limit := g.max
		if g.pressured != nil && g.pressured() {
			limit = 1
		}
		if g.inflight < limit {
			g.inflight++
			g.mu.Unlock()
			return true
		}
		ch := g.notify
		g.mu.Unlock()

		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}

// Release returns a slot and wakes every waiter so it can re-evaluate the
// current limit.
func (g *Gate) Release() {
	g.mu.Lock()
	if g.inflight > 0 {
		g.inflight--
	}
	g.wakeLocked()
	g.mu.Unlock()
}

func (g *Gate) wakeLocked() {
	close(g.notify)
	g.notify = make(chan struct{})
}
