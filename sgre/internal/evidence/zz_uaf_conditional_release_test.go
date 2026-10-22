//go:build !nosqlite

package evidence

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/planner"
)

// uafEventProps decodes the props of every USE_AFTER_FREE event whose
// variable matches.
func uafEventProps(t *testing.T, store db.Store, variable string) []map[string]any {
	t.Helper()
	events, err := store.ListEventsByType(context.Background(), "USE_AFTER_FREE")
	if err != nil {
		t.Fatalf("list USE_AFTER_FREE: %v", err)
	}
	var out []map[string]any
	for _, e := range events {
		var props map[string]any
		if err := json.Unmarshal([]byte(e.Properties), &props); err != nil {
			continue
		}
		if variable == "" || props["variable"] == variable {
			out = append(out, props)
		}
	}
	return out
}

// TestUAF_ConditionalReleaseUse locks the user-provided cbwl_tbl.c form
// (PATTERN-02 free-then-indirect-access + PATTERN-07 macro-wrapped use):
// a defensive release wrapper (`if (node != NULL) free(node)`) followed by a
// macro-wrapped use (`cbwl_nodeinfo(add_node)` -> cbwl_dfx_node_info
// dereferencing node->key) must surface a may-free use-after-free event
// carrying the helper's name — never silence the whole defensive-release
// idiom.
func TestUAF_ConditionalReleaseUse(t *testing.T) {
	store := runUAFDetectors(t, "tc_uaf_conditional_release_use.c")
	props := uafEventProps(t, store, "add_node")
	if len(props) == 0 {
		t.Fatal("cbwl_tbl_destory(add_node) then cbwl_nodeinfo(add_node) must surface a USE_AFTER_FREE event (conditional release, macro-wrapped use)")
	}
	foundMay, foundMust := false, false
	for _, p := range props {
		switch p["callee"] {
		case "cbwl_tbl_destory":
			foundMay = true
			if p["free_line"].(float64) != 61 || p["use_line"].(float64) != 63 {
				t.Errorf("may variant: free_line/use_line = %v/%v, want 61/63", p["free_line"], p["use_line"])
			}
			if p["may_free"] != "true" {
				t.Errorf(`may variant: may_free = %v, want "true" (the wrapper frees only when node != NULL)`, p["may_free"])
			}
		case "cbwl_tbl_destory_unconditional":
			foundMust = true
			if p["may_free"] == "true" {
				t.Errorf("must variant: may_free must not be set (unconditional free in the wrapper body)")
			}
		}
	}
	if !foundMay {
		t.Error("the conditional (defensive wrapper) release variant must surface a may_free event")
	}
	if !foundMust {
		t.Error("the unconditional wrapper release variant must surface a must event")
	}
}

// TestUAF_ConditionalReleaseFixedForm locks the user remediation: logging
// BEFORE the release (use first, free last) produces no use-after-free on
// any channel.
func TestUAF_ConditionalReleaseFixedForm(t *testing.T) {
	store := runUAFDetectors(t, "tc_uaf_conditional_release_use.c")
	// The fixed form's release is the LAST statement; its use precedes it,
	// so the cbwl_fixed_form function must contribute no event. Its release
	// sits at line 95 (after the use at 93-94) — no event may reference it.
	for _, p := range uafEventProps(t, store, "add_node") {
		if p["free_line"].(float64) >= 95 {
			t.Errorf("cbwl_fixed_form (use before free) must not produce a use-after-free event, got props %v", p)
		}
	}
}

// TestUAF_ConditionalReleasePlannerTier locks the planner convergence for the
// user-provided cbwl form end-to-end: the may-free candidate (defensive
// wrapper release) stays SUSPECTED for the AI — the lifetime filter must not
// auto-confirm a conditional release — while the unconditional-wrapper
// variant is machine-proved and confirmed.
func TestUAF_ConditionalReleasePlannerTier(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	if _, err := idx.Index(ctx, fixturePath("tc_uaf_conditional_release_use.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	graph.NewAliasBuilder(store, p, logger).Build(ctx)
	graph.NewOwnershipBuilder(store, p, logger).Build(ctx)
	NewUseAfterFreeDetector(store, p, logger).Detect(ctx)

	pl := planner.NewPlanner(store, p, logger)
	res, err := pl.Plan(ctx, "use-after-free")
	if err != nil {
		t.Fatalf("plan use-after-free: %v", err)
	}
	sawMaySuspected, sawMustConfirmed := false, false
	for _, c := range res.Candidates {
		if c.Target.Function != "cbwl_tbl_ha_add_node" && c.Target.Function != "cbwl_must_variant" {
			continue
		}
		if c.Target.Function == "cbwl_tbl_ha_add_node" {
			sawMaySuspected = true
			if c.SuspicionLevel != "suspected" {
				t.Errorf("may-free (defensive wrapper release) must stay suspected for the AI, got %q", c.SuspicionLevel)
			}
			hasToken := false
			for _, tok := range c.HintTokens {
				if tok == "may-free" || tok == "cond@cbwl_tbl_destory" {
					hasToken = true
				}
			}
			if !hasToken {
				t.Errorf("may-free candidate must carry the may-free/cond@ hint tokens, got %v", c.HintTokens)
			}
		}
		if c.Target.Function == "cbwl_must_variant" {
			sawMustConfirmed = true
			if c.SuspicionLevel != "confirmed" {
				t.Errorf("unconditional wrapper release + use is machine-proved, want confirmed, got %q", c.SuspicionLevel)
			}
		}
	}
	if !sawMaySuspected {
		t.Error("the conditional-release variant must survive the planner as a suspected candidate")
	}
	if !sawMustConfirmed {
		t.Error("the unconditional-release variant must be confirmed by the lifetime filter")
	}
	// The fixed form never surfaces.
	for _, c := range res.Candidates {
		if c.Target.Function == "cbwl_fixed_form" {
			t.Errorf("cbwl_fixed_form (use before release) must not surface a candidate, got %s at line %d", c.SuspicionLevel, c.Target.Line)
		}
	}
}
