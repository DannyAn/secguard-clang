//go:build !nosqlite

package evidence

import (
	"context"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestMergeSummaryJSON(t *testing.T) {
	got, err := mergeSummaryJSON("", "a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"a":1}` {
		t.Errorf("empty merge = %q", got)
	}

	got, err = mergeSummaryJSON(`{"existing":true}`, "bounded_return_cap_arg", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"existing":true`) || !strings.Contains(got, `"bounded_return_cap_arg":2`) {
		t.Errorf("merge must preserve existing keys: %q", got)
	}

	got, err = mergeSummaryJSON(`not-json`, "b", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"b":3`) {
		t.Errorf("non-object existing must be discarded and replaced: %q", got)
	}
}

func TestPersistBoundedReturnSummary(t *testing.T) {
	ctx := context.Background()
	s := db.NewTestStore(t)
	fileID, err := s.InsertFile(ctx, &db.File{Path: "a.c"})
	if err != nil {
		t.Fatal(err)
	}
	fid, err := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "add_x"})
	if err != nil {
		t.Fatal(err)
	}

	if err := persistBoundedReturnSummary(ctx, s, boundedReturnSummary{"add_x": 1}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSummaryByFunction(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !strings.Contains(got.SummaryJSON, `"bounded_return_cap_arg":1`) {
		t.Fatalf("bounded return not persisted: %+v", got)
	}
}

func TestPersistBoundedReturnSummaryEmpty(t *testing.T) {
	ctx := context.Background()
	s := db.NewTestStore(t)
	if err := persistBoundedReturnSummary(ctx, s, boundedReturnSummary{}); err != nil {
		t.Fatalf("empty summary must be a no-op: %v", err)
	}
}
