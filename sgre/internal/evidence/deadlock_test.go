package evidence

import (
	"sort"
	"testing"
)

func TestTarjanSCC_FindsTransitiveCycle(t *testing.T) {
	adj := map[string]map[string]bool{
		"a": {"b": true},
		"b": {"c": true},
		"c": {"a": true},
		"d": {"e": true}, // d -> e is not a cycle
		"e": {},
	}
	sccs := tarjanSCC(adj)

	found3 := false
	for _, scc := range sccs {
		if len(scc) == 3 {
			sorted := append([]string(nil), scc...)
			sort.Strings(sorted)
			if sorted[0] == "a" && sorted[1] == "b" && sorted[2] == "c" {
				found3 = true
			}
		}
	}
	if !found3 {
		t.Errorf("expected a 3-node SCC {a,b,c}, got %v", sccs)
	}
}

func TestTarjanSCC_TwoCycle(t *testing.T) {
	adj := map[string]map[string]bool{
		"a": {"b": true},
		"b": {"a": true},
	}
	sccs := tarjanSCC(adj)
	if len(sccs) != 1 || len(sccs[0]) != 2 {
		t.Errorf("expected one 2-node SCC, got %v", sccs)
	}
}

func TestDeadlockDetector_TransitiveCycle(t *testing.T) {
	store := runIndexAndDetect(t, "tc55_deadlock_transitive.c")
	assertHasEvent(t, store, "DEADLOCK", "tc55_deadlock_transitive")
}
