//go:build !nosqlite

package evidence

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/apikb"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_NeverNullReturnExcluded pins the fix for the
// aspf_safe_malloc false positive: a function declared as never-null
// ([nullability.non_null_returns], e.g. xmalloc/g_malloc/aspf_safe_malloc)
// has an abort-on-failure contract and cannot return NULL, so an unchecked
// return is not a CWE-252 defect. The unchecked-return detector must consume
// apikb.IsNonNullReturning at both the source gate and the passthrough fixpoint
// — otherwise a never-null wrapper is reported as confirmed (the null-source
// detector already skips these; unchecked-return was the lone holdout).
func TestUncheckedReturn_NeverNullReturnExcluded(t *testing.T) {
	apikb.RegisterNonNullReturning("sg_test_never_null_malloc")
	apikb.RegisterNonNullReturning("sg_test_never_null_wrapper")

	store := runOneDetector(t, "tc_unchecked_return_never_null.c",
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

	for _, name := range []string{"call_never_null_unchecked", "call_never_null_wrapper_unchecked"} {
		if byFunc[name] != 0 {
			t.Errorf("%s: a never-null return ([nullability.non_null_returns]) must not be an unchecked-return source, got %d event(s)", name, byFunc[name])
		}
	}
	if byFunc["call_real_alloc_checked"] != 0 {
		t.Errorf("call_real_alloc_checked: malloc result is checked, expected 0 events, got %d", byFunc["call_real_alloc_checked"])
	}
}
