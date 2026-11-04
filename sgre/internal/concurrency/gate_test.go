package concurrency

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateShrinksTo1UnderPressure(t *testing.T) {
	var pressured atomic.Bool
	g := NewGate(4, pressured.Load)
	ctx := context.Background()

	for i := 0; i < 4; i++ {
		if !g.Acquire(ctx) {
			t.Fatalf("acquire %d failed", i)
		}
	}
	acquired := make(chan struct{}, 1)
	go func() {
		if g.Acquire(ctx) {
			acquired <- struct{}{}
		}
	}()
	select {
	case <-acquired:
		t.Fatal("gate admitted a 5th task above max")
	case <-time.After(50 * time.Millisecond):
	}

	pressured.Store(true)
	g.Release()
	g.Release()
	g.Release()
	g.Release()
	select {
	case <-acquired:
	case <-time.After(time.Second):
		t.Fatal("gate did not admit one task after draining under pressure")
	}

	// The fifth is now the only in-flight task; a sixth must wait at limit 1.
	blocked := make(chan struct{}, 1)
	go func() {
		if g.Acquire(ctx) {
			blocked <- struct{}{}
		}
	}()
	select {
	case <-blocked:
		t.Fatal("gate admitted a second task while pressured")
	case <-time.After(50 * time.Millisecond):
	}

	pressured.Store(false)
	g.Release() // wake the sixth with the restored limit
	select {
	case <-blocked:
	case <-time.After(time.Second):
		t.Fatal("gate did not restore parallelism after pressure cleared")
	}
	g.Release()
	g.Release()
	g.Release()
}

func TestGateAcquireCanceled(t *testing.T) {
	g := NewGate(1, func() bool { return false })
	if !g.Acquire(context.Background()) {
		t.Fatal("first acquire failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if g.Acquire(ctx) {
		t.Fatal("acquire with canceled context succeeded")
	}
	g.Release()
}
