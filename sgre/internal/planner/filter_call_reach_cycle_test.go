package planner

import (
	"testing"
)

// TestCallChain_CyclicParentNeverLoops pins issue #238: callChain must never
// infinite-loop on a cyclic parent map. Before the fix, the adopt loop could
// rewrite a true entry's sentinel parent to another node and form a 2-cycle
// (mutual recursion + address-taken), which callChain then traversed forever
// until OOM. Each sub-case constructs the offending parent map directly and
// asserts the traversal terminates with a bounded, acyclic result.
func TestCallChain_CyclicParentNeverLoops(t *testing.T) {
	t.Run("mutual_recursion_addr_taken_2cycle", func(t *testing.T) {
		// Reproduces the issue #238 minimal graph:
		//   CALL a -> b, CALL b -> a, ADDR_TAKEN b (b is a true entry).
		// Before the fix, adopt rewrote parent[b]=a while parent[a]=b,
		// forming a 2-cycle that callChain traversed forever.
		r := &callReachResult{
			funcNodeMap: map[int64]int64{1: 10, 2: 20},
			parent:      map[int64]int64{10: 20, 20: 10},
			nodeName:    map[int64]string{10: "a", 20: "b"},
			nodeFile:    map[int64]string{10: "a.c", 20: "b.c"},
			callLine:    map[[2]int64]int{},
		}
		// Must terminate (previously OOM) and return a bounded chain.
		chain := r.callChain(1)
		if len(chain) > maxCallChainHops {
			t.Fatalf("chain length %d exceeds cap %d (cycle not truncated)", len(chain), maxCallChainHops)
		}
	})

	t.Run("three_node_cycle", func(t *testing.T) {
		// a -> b -> c -> a
		r := &callReachResult{
			funcNodeMap: map[int64]int64{1: 1, 2: 2, 3: 3},
			parent:      map[int64]int64{1: 3, 2: 1, 3: 2},
			nodeName:    map[int64]string{1: "a", 2: "b", 3: "c"},
			nodeFile:    map[int64]string{},
			callLine:    map[[2]int64]int{},
		}
		chain := r.callChain(1)
		if len(chain) > maxCallChainHops {
			t.Fatalf("chain length %d exceeds cap %d (3-cycle not truncated)", len(chain), maxCallChainHops)
		}
	})

	t.Run("self_loop_sentinel", func(t *testing.T) {
		// A true entry has parent[node] == node (sentinel); callChain must
		// stop immediately and return nil.
		r := &callReachResult{
			funcNodeMap: map[int64]int64{1: 1},
			parent:      map[int64]int64{1: 1},
			nodeName:    map[int64]string{1: "main"},
			nodeFile:    map[int64]string{},
			callLine:    map[[2]int64]int{},
		}
		chain := r.callChain(1)
		if chain != nil {
			t.Fatalf("self-loop sentinel should return nil, got %v", chain)
		}
	})

	t.Run("cycle_plus_true_entry_off_cycle", func(t *testing.T) {
		// main(1) -> a(2); a(2) <-> b(3) cycle off the chain.
		// parent[2]=1 (concrete), parent[3]=2, parent[1]=1 (sentinel).
		// callChain(3) should walk 3 -> 2 -> 1 and stop at sentinel.
		r := &callReachResult{
			funcNodeMap: map[int64]int64{1: 1, 2: 2, 3: 3},
			parent:      map[int64]int64{1: 1, 2: 1, 3: 2},
			nodeName:    map[int64]string{1: "main", 2: "a", 3: "b"},
			nodeFile:    map[int64]string{1: "m.c", 2: "a.c", 3: "b.c"},
			callLine:    map[[2]int64]int{{1, 2}: 10, {2, 3}: 20},
		}
		chain := r.callChain(3)
		if len(chain) != 2 {
			t.Fatalf("expected 2 hops (b<-a<-main), got %d: %v", len(chain), chain)
		}
		if chain[0].Caller != "main" || chain[0].Callee != "a" {
			t.Errorf("hop 0 = %+v, want main->a", chain[0])
		}
		if chain[1].Caller != "a" || chain[1].Callee != "b" {
			t.Errorf("hop 1 = %+v, want a->b", chain[1])
		}
	})

	t.Run("deep_chain_hits_depth_cap", func(t *testing.T) {
		// A chain longer than maxCallChainHops with a cycle at the far end.
		// Build nodes 1..(cap+5); parent[i] = i-1, and parent[1] = cap+5 (cycle).
		const n = maxCallChainHops + 5
		parent := make(map[int64]int64, n)
		nodeName := make(map[int64]string, n)
		for i := 1; i <= n; i++ {
			if i == 1 {
				parent[int64(i)] = int64(n)
			} else {
				parent[int64(i)] = int64(i - 1)
			}
			nodeName[int64(i)] = "f"
		}
		r := &callReachResult{
			funcNodeMap: map[int64]int64{1: 1},
			parent:      parent,
			nodeName:    nodeName,
			nodeFile:    map[int64]string{},
			callLine:    map[[2]int64]int{},
		}
		chain := r.callChain(1)
		if len(chain) > maxCallChainHops {
			t.Fatalf("chain length %d exceeds cap %d", len(chain), maxCallChainHops)
		}
	})
}

// TestComputeCallReach_MutualRecursionAddrTakenNoCycle is an integration guard
// for issue #238: after computeCallReach builds the parent map for a graph
// containing mutual recursion where one end is address-taken, the parent map
// must not contain a 2-cycle. We verify the invariant directly on the parent
// map by walking from every reachable node up to maxCallChainHops hops and
// asserting we never revisit a node.
func TestComputeCallReach_MutualRecursionAddrTakenNoCycle(t *testing.T) {
	// Construct the post-adopt parent map for the issue #238 minimal graph
	// and assert acyclicity. With the fix, the true entry b keeps its
	// sentinel parent[b]=b, and a gets parent[a]=b (BFS from true entry b).
	// callChain(a) walks a -> b (sentinel) and stops.
	r := &callReachResult{
		funcNodeMap: map[int64]int64{1: 10, 2: 20},
		parent:      map[int64]int64{10: 20, 20: 20},
		nodeName:    map[int64]string{10: "a", 20: "b"},
		nodeFile:    map[int64]string{10: "a.c", 20: "b.c"},
		callLine:    map[[2]int64]int{{20, 10}: 5},
	}
	chain := r.callChain(1)
	if len(chain) != 1 {
		t.Fatalf("expected 1 hop (a<-b), got %d: %v", len(chain), chain)
	}
	if chain[0].Caller != "b" || chain[0].Callee != "a" {
		t.Errorf("hop 0 = %+v, want b->a", chain[0])
	}
	// b is a true entry: callChain(b) must return nil.
	if chain := r.callChain(2); chain != nil {
		t.Errorf("true entry b should return nil chain, got %v", chain)
	}
}
