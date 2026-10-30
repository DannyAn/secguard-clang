//go:build !nosqlite

package evidence

import (
	"context"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
)

func TestIntKeys(t *testing.T) {
	got := intKeys(map[int]bool{2: true, 0: true, 1: true})
	if len(got) != 3 || got[0] != 0 || got[1] != 1 || got[2] != 2 {
		t.Errorf("intKeys = %v, want [0 1 2]", got)
	}
}

func TestPersistFuncSummaries(t *testing.T) {
	ctx := context.Background()
	s := db.NewTestStore(t)
	fileID, err := s.InsertFile(ctx, &db.File{Path: "a.c"})
	if err != nil {
		t.Fatal(err)
	}
	fid, err := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "fill"})
	if err != nil {
		t.Fatal(err)
	}

	summary := summaryMap{
		"fill": {
			ParamWrites:            map[int]bool{0: true},
			ParamConditionalWrites: map[int]bool{1: true},
		},
	}
	if err := persistFuncSummaries(ctx, s, summary); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetSummaryByFunction(ctx, fid)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || !strings.Contains(got.SummaryJSON, `"outparam_writes":[0]`) {
		t.Fatalf("out-param writes not persisted: %+v", got)
	}
	if !strings.Contains(got.SummaryJSON, `"outparam_conditional_writes":[1]`) {
		t.Fatalf("conditional writes not persisted: %+v", got)
	}
}

func TestPersistFuncSummariesSkipsNoWrites(t *testing.T) {
	ctx := context.Background()
	s := db.NewTestStore(t)
	fileID, err := s.InsertFile(ctx, &db.File{Path: "a.c"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertFunction(ctx, &db.Function{FileID: fileID, Name: "noop"}); err != nil {
		t.Fatal(err)
	}
	// A summary with no out-param writes must not create a row.
	if err := persistFuncSummaries(ctx, s, summaryMap{"noop": {}}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSummariesByFunctionIDs(ctx, []int64{1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("no-write function must not be persisted, got %d rows", len(rows))
	}
}
