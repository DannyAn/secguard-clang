//go:build !nosqlite

package db

import (
	"context"
	"testing"
)

func TestStore_MetaGetSet(t *testing.T) {
	ctx := context.Background()
	s := NewTestStore(t)

	val, ok, err := s.GetMeta(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("GetMeta missing key: %v", err)
	}
	if ok {
		t.Fatal("GetMeta missing key should return ok=false")
	}
	if val != "" {
		t.Fatalf("GetMeta missing key should return empty value, got %q", val)
	}

	if err := s.SetMeta(ctx, "config_checksum", "abc123"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	val, ok, err = s.GetMeta(ctx, "config_checksum")
	if err != nil {
		t.Fatalf("GetMeta after SetMeta: %v", err)
	}
	if !ok {
		t.Fatal("GetMeta after SetMeta should return ok=true")
	}
	if val != "abc123" {
		t.Fatalf("GetMeta after SetMeta should return %q, got %q", "abc123", val)
	}

	if err := s.SetMeta(ctx, "config_checksum", "def456"); err != nil {
		t.Fatalf("SetMeta overwrite: %v", err)
	}
	val, _, err = s.GetMeta(ctx, "config_checksum")
	if err != nil {
		t.Fatalf("GetMeta after overwrite: %v", err)
	}
	if val != "def456" {
		t.Fatalf("GetMeta after overwrite should return %q, got %q", "def456", val)
	}

	if err := s.SetMeta(ctx, "graph_build_complete", "true"); err != nil {
		t.Fatalf("SetMeta second key: %v", err)
	}
	val, _, err = s.GetMeta(ctx, "graph_build_complete")
	if err != nil {
		t.Fatalf("GetMeta second key: %v", err)
	}
	if val != "true" {
		t.Fatalf("GetMeta second key should return %q, got %q", "true", val)
	}
	val, _, err = s.GetMeta(ctx, "config_checksum")
	if err != nil {
		t.Fatalf("GetMeta first key after second: %v", err)
	}
	if val != "def456" {
		t.Fatalf("GetMeta first key should still return %q, got %q", "def456", val)
	}
}
