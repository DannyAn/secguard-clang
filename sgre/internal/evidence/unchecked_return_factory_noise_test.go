//go:build !nosqlite

package evidence

import (
	"context"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestUncheckedReturn_NameHeuristicAllProduceLeads pins the name-heuristic
// policy: a call to a function whose name matches the allocator heuristic
// (alloc/strdup/_new/_dup/_mem_create) is a source by NAME only, not by failure
// contract. contract_known is false, so the planner hands it to the AI (Hint
// contract@unknown) instead of auto-confirming. The AI must prove the callee
// returns a failure sentinel or dismiss. A never-null wrapper (xmalloc/
// aspf_safe_malloc) is excluded via [nullability.non_null_returns].
func TestUncheckedReturn_NameHeuristicAllProduceLeads(t *testing.T) {
	store := runOneDetector(t, "tc_unchecked_return_factory_noise.c",
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

	for _, name := range []string{"call_factory_new", "call_factory_db", "call_copy_dup", "call_mem_create", "call_nat_alloc"} {
		if byFunc[name] != 1 {
			t.Errorf("%s: an allocator-name heuristic match should produce a lead (contract@unknown), expected 1 event, got %d", name, byFunc[name])
		}
	}
}
