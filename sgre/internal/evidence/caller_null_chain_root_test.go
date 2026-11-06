package evidence

import (
	"testing"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
)

// TestChainRootName_CyclicFwdByNeverLoops pins the issue #238 sibling: when two
// functions mutually forward a parameter (a(p) -> b(p) -> a(p)), fwdBy forms a
// 2-cycle and chainRootName used to loop forever (CPU 100%, no OOM — the body
// does not append). The fix adds a visited set + depth cap so the traversal
// terminates with a bounded root lookup.
func TestChainRootName_CyclicFwdByNeverLoops(t *testing.T) {
	// fwdBy[b][0] = edge(a->b), fwdBy[a][0] = edge(b->a)  → 2-cycle.
	fwdBy := map[int64]map[int]fwdEdge{
		1: {0: {callerID: 2, callerParam: 0, calleeID: 1, calleeParam: 0}},
		2: {0: {callerID: 1, callerParam: 0, calleeID: 2, calleeParam: 0}},
	}
	infoByFnID := map[int64]calleeParamInfo{
		1: {fn: &db.Function{ID: 1, Name: "a"}},
		2: {fn: &db.Function{ID: 2, Name: "b"}},
	}

	done := make(chan struct{})
	go func() {
		_ = chainRootName(1, 0, fwdBy, infoByFnID)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chainRootName hung on cyclic fwdBy (mutual parameter forwarding 2-cycle)")
	}
}

func TestChainRootName_LinearChainResolvesRoot(t *testing.T) {
	// main(0) -> a(0) -> b(0): fwdBy[b][0]=edge(a->b), fwdBy[a][0]=edge(main->a).
	// chainRootName(b, 0) should walk b -> a -> main and return "main".
	fwdBy := map[int64]map[int]fwdEdge{
		2: {0: {callerID: 1, callerParam: 0, calleeID: 2, calleeParam: 0}}, // b's forwarder is a
		1: {0: {callerID: 3, callerParam: 0, calleeID: 1, calleeParam: 0}}, // a's forwarder is main
	}
	infoByFnID := map[int64]calleeParamInfo{
		1: {fn: &db.Function{ID: 1, Name: "a"}},
		2: {fn: &db.Function{ID: 2, Name: "b"}},
		3: {fn: &db.Function{ID: 3, Name: "main"}},
	}
	if got := chainRootName(2, 0, fwdBy, infoByFnID); got != "main" {
		t.Errorf("chainRootName = %q, want main", got)
	}
}

func TestChainRootName_SelfForwardingBreaks(t *testing.T) {
	// A self-forwarding edge (a forwards its param to itself) — degenerate but
	// must not loop.
	fwdBy := map[int64]map[int]fwdEdge{
		1: {0: {callerID: 1, callerParam: 0, calleeID: 1, calleeParam: 0}},
	}
	infoByFnID := map[int64]calleeParamInfo{
		1: {fn: &db.Function{ID: 1, Name: "a"}},
	}
	done := make(chan struct{})
	go func() {
		_ = chainRootName(1, 0, fwdBy, infoByFnID)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("chainRootName hung on self-forwarding edge")
	}
}
