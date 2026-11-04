package cli

import (
	"testing"
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
