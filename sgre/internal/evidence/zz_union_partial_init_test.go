//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
)

// Issue #253 P2-1: a union member write must initialize the shared storage for
// the partial-init model, while a struct keeps its per-field semantics.
func TestUninitUnionMemberWriteInitializesSharedStorage(t *testing.T) {
	store, p := setupDetector(t, "zz_union_partial_init.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewUninitVariableDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(context.Background(), "VALUE_USE")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	partialByFunc := map[string]bool{}
	for _, e := range events {
		var props struct {
			Origin string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin != "struct_partial_uninit" {
			continue
		}
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		partialByFunc[fn.Name] = true
	}
	if partialByFunc["union_member_write_read_other"] {
		t.Error("union: writing u.vlan must initialize the shared storage — u.id/u.isBd reads are not partial-init defects")
	}
	if !partialByFunc["struct_member_write_read_other"] {
		t.Error("struct control: s.a = 1 must NOT initialize s.b (per-field semantics preserved)")
	}
}

// Issue #253 P2-1a: the union typedef usually lives in a HEADER and the .c only
// includes it. Tree-sitter does not expand the include, so the per-file map
// never saw the typedef and the shared-storage rule silently stopped firing in
// the exact production layout (header + source). The typedef set is now
// collected tree-wide from the indexed header files.
func TestUninitUnionHeaderTypedefSharedStorage(t *testing.T) {
	store, p := setupDetector(t, "zz_union_header")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewUninitVariableDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("detect: %v", err)
	}
	events, err := store.ListEventsByType(context.Background(), "VALUE_USE")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	partialByFunc := map[string]bool{}
	for _, e := range events {
		var props struct {
			Origin string `json:"origin"`
		}
		_ = json.Unmarshal([]byte(e.Properties), &props)
		if props.Origin != "struct_partial_uninit" {
			continue
		}
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		partialByFunc[fn.Name] = true
	}
	if partialByFunc["header_union_member_write_read_other"] {
		t.Error("header union: writing u.vlan must initialize the shared storage — u.id/u.isBd reads are not partial-init defects")
	}
	if !partialByFunc["header_struct_member_write_read_other"] {
		t.Error("header struct control: s.a = 1 must NOT initialize s.b (per-field semantics preserved)")
	}
}
