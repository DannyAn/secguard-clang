package evidence

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_ConsumerCensus pins the consumer-census rule for the
// unchecked-return false positives reported against an IDM-style repository
// (25/25 misclassified): the value's failure sentinel is never compared in
// the storing function, but every consumer of the value is NULL-safe, so a
// NULL result cannot misbehave anywhere.
//
//   - a discarded int result whose consumer entry-guards through a CAST ALIAS
//     of the parameter (filter_add) is safe — report shape A2, which the old
//     "result must be checked OR callee returns void" gate missed;
//   - a field store validated downstream by a shared validator
//     (para_is_valid) is safe — report shape 4.2 field escape;
//   - one unsafe consumer (a dereference, an unguarded callee) keeps the
//     event — the census is AND, not OR;
//   - a callee that merely stashes the pointer (no guard, no dereference) is
//     NOT null-safe: the value escapes unchecked;
//   - the true-positive control (blob_dup dereferenced directly) stays
//     reported.
func TestUncheckedReturn_ConsumerCensus(t *testing.T) {
	store := runOneDetector(t, "tc_unchecked_return_consumer_census.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })

	events, err := store.ListEventsByType(context.Background(), "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	byFunc := make(map[string]int)
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	expect := map[string]int{
		"query_by_name":         0,
		"query_by_name2":        0,
		"fill_and_run":          0,
		"process":               1,
		"neg_discard_unsafe":    1,
		"neg_census_and":        1,
		"pos_void_guarded_body": 0,
		"neg_stash_escape":      1,
		"filter_new":            0,
		"filter_add":            0,
		"filter_free":           0,
		"filter_traverse":       0,
		"filter_touch_unsafe":   0,
		"import_strdup":         0,
		"para_is_valid":         0,
		"para_free":             0,
		"blob_dup":              0,
		"guarded_consumer":      0,
		"stash_ptr":             0,
	}
	for name, want := range expect {
		if got := byFunc[name]; got != want {
			t.Errorf("%s: expected %d UNCHECKED_RETURN event(s), got %d", name, want, got)
		}
	}
}
