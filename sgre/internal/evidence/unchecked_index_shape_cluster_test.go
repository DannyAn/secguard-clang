//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// TestUncheckedIndexShapeCluster pins Issue #216 item 3: the unchecked
// external-index family — a fixed-size array indexed by a struct field with no
// in-code bounds check — is ONE external-bound judgment per (file, index-source
// field, capacity, access flavor). Same-shape sites fold into one representative
// that lists them; a different capacity stays its own shape; a guarded access is
// not seeded at all. The candidate carries `external-bound@unverified` so the
// classifier knows the bound must be confirmed outside the code.
func TestUncheckedIndexShapeCluster(t *testing.T) {
	store, p := setupDetector(t, "tc_unchecked_index_cluster.c")
	logger := log.New(io.Discard, log.LevelWarn)
	if _, err := NewBufferOverflowDetector(store, p, logger).Detect(context.Background()); err != nil {
		t.Fatalf("buffer detect: %v", err)
	}

	ctx := context.Background()
	pl := planner.NewPlanner(store, p, logger)

	oob, err := pl.Plan(ctx, "out-of-bounds")
	if err != nil {
		t.Fatalf("plan out-of-bounds: %v", err)
	}
	readCovered := map[string]bool{}
	var readRep *planner.EvidenceItem
	var small *planner.EvidenceItem
	for i := range oob.Candidates {
		c := &oob.Candidates[i]
		readCovered[c.Target.Function] = true
		for _, site := range c.ClusterSites {
			readCovered[strings.SplitN(site, ":", 2)[0]] = true
		}
		switch c.Target.Function {
		case "other_capacity_read":
			small = c
		default:
			if readRep != nil {
				t.Fatalf("the same read shape must fold into one candidate, got a second: %s", c.Target.Function)
			}
			readRep = c
		}
	}

	if readRep == nil {
		t.Fatalf("the read family must yield one representative, got %v", candidateFuncs(oob))
	}
	for _, fn := range []string{"cluster_read_a", "cluster_read_b", "cluster_read_c"} {
		if !readCovered[fn] {
			t.Errorf("read family site %s must be covered by the representative, got %v", fn, readCovered)
		}
	}
	if readCovered["guarded_read"] {
		t.Errorf("guarded_read (entry check against the capacity symbol) must not be seeded, got %v", readCovered)
	}
	if len(readRep.ClusterSites) != 2 || len(readRep.DerefLines) != 3 {
		t.Errorf("read representative must fold 2 sites over 3 sink lines, got cluster=%v deref=%v",
			readRep.ClusterSites, readRep.DerefLines)
	}
	if !hasHintToken(*readRep, "external-bound@unverified") {
		t.Errorf("read representative must carry external-bound@unverified, got %v", readRep.HintTokens)
	}
	if !hasHintToken(*readRep, "shape-cluster@2") {
		t.Errorf("read representative must carry shape-cluster@2, got %v", readRep.HintTokens)
	}

	if small == nil {
		t.Fatalf("other_capacity_read (capacity 2) must stay its own candidate, got %v", candidateFuncs(oob))
	}
	if len(small.ClusterSites) != 0 {
		t.Errorf("a different capacity is a different shape; other_capacity_read must not be folded, got %v", small.ClusterSites)
	}
	if len(oob.Candidates) != 2 || oob.Summary.ShapeFolded != 2 {
		t.Errorf("expected 2 read candidates folding 2 sites, got %d candidates / shape_folded=%d (%v)",
			len(oob.Candidates), oob.Summary.ShapeFolded, candidateFuncs(oob))
	}

	bo, err := pl.Plan(ctx, "buffer-overflow")
	if err != nil {
		t.Fatalf("plan buffer-overflow: %v", err)
	}
	writeCovered := map[string]bool{}
	var writeRep *planner.EvidenceItem
	for i := range bo.Candidates {
		c := &bo.Candidates[i]
		writeCovered[c.Target.Function] = true
		for _, site := range c.ClusterSites {
			writeCovered[strings.SplitN(site, ":", 2)[0]] = true
		}
		writeRep = c
	}
	for _, fn := range []string{"cluster_write_a", "cluster_write_b", "cluster_write_c"} {
		if !writeCovered[fn] {
			t.Errorf("write family site %s must be covered, got %v", fn, writeCovered)
		}
	}
	if writeCovered["guarded_write"] {
		t.Errorf("guarded_write (entry check against the capacity symbol) must not be seeded, got %v", writeCovered)
	}
	if len(bo.Candidates) != 1 || bo.Summary.ShapeFolded != 2 {
		t.Fatalf("expected 1 write candidate folding 2 sites, got %d candidates / shape_folded=%d (%v)",
			len(bo.Candidates), bo.Summary.ShapeFolded, candidateFuncs(bo))
	}
	if writeRep == nil || len(writeRep.DerefLines) != 3 {
		t.Errorf("write representative must keep all 3 sink lines, got %+v", writeRep)
	}
	if !hasHintToken(*writeRep, "shape-cluster@2") {
		t.Errorf("write representative must carry shape-cluster@2, got %v", writeRep.HintTokens)
	}
}

func candidateFuncs(res *planner.PlanResult) []string {
	names := make([]string, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		names = append(names, c.Target.Function)
	}
	return names
}

func hasHintToken(c planner.EvidenceItem, token string) bool {
	for _, tok := range c.HintTokens {
		if tok == token {
			return true
		}
	}
	return false
}
