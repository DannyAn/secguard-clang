package evidence

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_IndirectGuard pins the indirect-guard rule: a value passed
// to a call whose CALLEE rejects it at entry with a failure return, and whose
// result the caller checks, has been handled — so the unchecked-return event on
// the value's own allocation is a false positive. The rule must not fire when
// the callee merely dereferences the argument (`strlen(p)`), reports success on
// a NULL argument, or is only non-NULL-guarded.
func TestUncheckedReturn_IndirectGuard(t *testing.T) {
	store := runOneDetector(t, "tc_unchecked_return_indirect_guard.c",
		func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })

	byFunc := make(map[string]int)
	events, err := store.ListEventsByType(context.Background(), "UNCHECKED_RETURN")
	if err != nil {
		t.Fatalf("list UNCHECKED_RETURN: %v", err)
	}
	for _, e := range events {
		fn, err := store.GetFunctionByID(context.Background(), e.EntityID)
		if err != nil || fn == nil {
			continue
		}
		byFunc[fn.Name]++
	}

	for _, name := range []string{"indirect_check_assign", "indirect_check_inline"} {
		if byFunc[name] != 0 {
			t.Errorf("%s: callee entry-guards the argument and the result is checked, expected no event, got %d", name, byFunc[name])
		}
	}
	for _, name := range []string{
		"no_entry_guard",
		"success_on_null_guard",
		"nonnull_branch_guard",
		"deref_not_guard",
		"no_check_unsafe",
	} {
		if byFunc[name] != 1 {
			t.Errorf("%s: expected exactly 1 UNCHECKED_RETURN event, got %d", name, byFunc[name])
		}
	}
}
