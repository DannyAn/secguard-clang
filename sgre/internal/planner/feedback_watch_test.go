//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// feedbackWatchFixture is the Issue #226 capability fixture root.
var feedbackWatchFixture = filepath.Join("..", "..", "testdata", "feedback_watch")

// TestFeedbackWatchCapabilityMatrix pins the capability-confirmation results for
// the four external defect reports in Issue #226 (see the fixture README):
//
//   - CWD-SUB-1031: a file-scope static pointer that only ever holds NULL is a
//     null source for every function that dereferences it;
//   - CWD-SUB-1140: scalar/pointer/struct-field/switch-join condition reads are
//     reported, while initialized and static-zero controls are not;
//   - CWD-SUB-1038: a constant-size allocation cast to a struct with a one-level
//     field access beyond the allocation is detected as layout_oob_read/write
//     (suspected); packed/bitfield/array/nested/reassigned controls stay quiet;
//   - CWD-SUB-1029: the external-offset shape is still NOT detected (documented
//     gap in the README); only its safe controls must stay quiet.
//
// Deliberately absent: assertions that the known-gap positives stay quiet. A
// future detector should start reporting them without a test that encodes the
// absence.
func TestFeedbackWatchCapabilityMatrix(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	err := filepath.WalkDir(feedbackWatchFixture, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || filepath.Ext(path) != ".c" {
			return nil
		}
		if _, err := idx.Index(ctx, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}

	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	for _, d := range []evidence.Detector{
		evidence.NewNullSourceDetector(store, p, logger),
		evidence.NewDereferenceDetector(store, p, logger),
		evidence.NewUninitVariableDetector(store, p, logger),
		evidence.NewBufferOverflowDetector(store, p, logger),
	} {
		if _, err := d.Detect(ctx); err != nil {
			t.Fatalf("detect %s: %v", d.Name(), err)
		}
	}

	pl := NewPlanner(store, p, logger)
	uninit, err := pl.Plan(ctx, "uninit")
	if err != nil {
		t.Fatalf("plan uninit: %v", err)
	}
	nullDeref, err := pl.Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan null-deref: %v", err)
	}

	assertCandidate := func(t *testing.T, typeName string, items []EvidenceItem, function string, line int) {
		t.Helper()
		for _, c := range items {
			if c.Target.Function == function && c.Target.Line == line {
				return
			}
		}
		var got []string
		for _, c := range items {
			got = append(got, c.Target.Function)
		}
		t.Errorf("%s: expected a candidate at %s:%d, got functions %v", typeName, function, line, got)
	}
	assertNoCandidateFor := func(t *testing.T, typeName string, items []EvidenceItem, function string) {
		t.Helper()
		for _, c := range items {
			if c.Target.Function == function {
				t.Errorf("%s: expected no candidate for the safe control %s, got %s:%d", typeName, function, function, c.Target.Line)
			}
		}
	}

	// CWD-SUB-1140 positives.
	assertCandidate(t, "uninit", uninit.Candidates, "check_state", 9)
	assertCandidate(t, "uninit", uninit.Candidates, "check_config", 12)
	assertCandidate(t, "uninit", uninit.Candidates, "check_node", 9)
	assertCandidate(t, "uninit", uninit.Candidates, "check_mode", 16)
	// CWD-SUB-1140 safe controls: fully initialized, static zero-init.
	assertNoCandidateFor(t, "uninit", uninit.Candidates, "check_state_safe")
	assertNoCandidateFor(t, "uninit", uninit.Candidates, "check_global_state")

	// CWD-SUB-1031: the static NULL pointer is a source for the dereference;
	// the guarded local alias is not.
	assertCandidate(t, "null-deref", nullDeref.Candidates, "get_session_state", 11)
	assertNoCandidateFor(t, "null-deref", nullDeref.Candidates, "get_session_state_safe")

	// The central safety claim of the global-null tier: it is SUSPECTED, never
	// auto-confirmed, and the index row names both the tier and the declaration
	// line (src@) so the AI can judge the macro-write caveat.
	for _, c := range nullDeref.Candidates {
		if c.Target.Function != "get_session_state" {
			continue
		}
		if c.SuspicionLevel != "suspected" {
			t.Errorf("global-null candidate suspicion = %q, want suspected (never auto-confirm a closed-world census)", c.SuspicionLevel)
		}
		if !strings.Contains(c.Hint, "null@global-null") {
			t.Errorf("global-null candidate hint = %q, want null@global-null", c.Hint)
		}
		if !strings.Contains(c.Hint, "src@") {
			t.Errorf("global-null candidate hint = %q, want the declaration line as src@N", c.Hint)
		}
	}

	// CWD-SUB-1029 / CWD-SUB-1038 safe controls must not be misreported by the
	// buffer channels while the target shapes remain documented gaps.
	for _, typeName := range []string{"buffer-overflow", "out-of-bounds"} {
		result, err := pl.Plan(ctx, typeName)
		if err != nil {
			t.Fatalf("plan %s: %v", typeName, err)
		}
		for _, fn := range []string{"read_byte_safe", "read_record_safe"} {
			assertNoCandidateFor(t, typeName, result.Candidates, fn)
		}
	}
}
