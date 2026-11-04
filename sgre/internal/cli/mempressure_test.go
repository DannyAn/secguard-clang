package cli

import (
	"context"
	"testing"
	"time"
)

func TestMemoryMonitor_DisabledByDefault(t *testing.T) {
	m := NewMemoryMonitor(0, 0)
	if m.Pressured() {
		t.Fatal("zero high watermark should never signal pressure")
	}
}

func TestMemoryMonitor_NilSafe(t *testing.T) {
	var m *MemoryMonitor
	if m.Pressured() {
		t.Fatal("nil monitor should not signal pressure")
	}
	if m.Current() != 0 {
		t.Fatal("nil monitor Current should return 0")
	}
	m.Stop()
}

func TestReadMemoryBytes_NonZero(t *testing.T) {
	v := readMemoryBytes()
	if v <= 0 {
		t.Fatalf("readMemoryBytes returned %d, want > 0", v)
	}
}

func TestMemoryMonitor_InvalidLowWatermarkAdjusted(t *testing.T) {
	m := NewMemoryMonitor(1000, 0)
	if m.lowBytes <= 0 || m.lowBytes >= m.highBytes {
		t.Fatalf("low=%d high=%d, want 0 < low < high", m.lowBytes, m.highBytes)
	}
	m2 := NewMemoryMonitor(1000, 2000)
	if m2.lowBytes >= m2.highBytes {
		t.Fatalf("low=%d high=%d, want low < high", m2.lowBytes, m2.highBytes)
	}
}

func TestMemoryMonitor_WaitReturnsOnCancel(t *testing.T) {
	m := NewMemoryMonitor(1, 0)
	m.pressured.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() {
		m.Wait(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after ctx cancellation")
	}
}

func TestMemoryMonitor_StartSamplesImmediately(t *testing.T) {
	m := NewMemoryMonitor(1, 0)
	defer m.Stop()
	m.Start(5*time.Millisecond, nil)
	deadline := time.Now().Add(time.Second)
	for !m.Pressured() {
		if time.Now().After(deadline) {
			t.Fatal("monitor never observed the first sample")
		}
		time.Sleep(time.Millisecond)
	}
	if m.Current() <= 0 {
		t.Fatalf("current=%d, want > 0", m.Current())
	}
}
