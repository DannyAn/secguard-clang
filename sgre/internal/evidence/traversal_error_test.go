//go:build !nosqlite

package evidence

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// traversalErrStore fails ListFunctions on the configured 1-based call and
// ListFiles unconditionally. The embedded nil db.Store is never reached: the
// traversal helpers only list functions/files before any other store call.
type traversalErrStore struct {
	db.Store
	err    error
	calls  int
	failOn int
}

func newTraversalErrStore(err error, failOn int) *traversalErrStore {
	return &traversalErrStore{err: err, failOn: failOn}
}

func (s *traversalErrStore) ListFunctions(ctx context.Context) ([]*db.Function, error) {
	s.calls++
	if s.failOn <= 0 || s.calls >= s.failOn {
		return nil, s.err
	}
	return nil, nil
}

func (s *traversalErrStore) ListFiles(ctx context.Context) ([]*db.File, error) {
	return nil, s.err
}

func newTraversalTestTools(t *testing.T) (*parser.Parser, *log.Logger) {
	t.Helper()
	p := parser.NewParser()
	t.Cleanup(p.CloseAll)
	return p, log.New(io.Discard, log.LevelWarn)
}

// The three whole-tree collect passes must surface a traversal failure instead
// of returning a partial fact set. A dropped ListFunctions/ListFiles error used
// to make unchecked-return / contract-gap detection silently under-report.

func TestCollectNoreturnFuncsPropagatesTraversalError(t *testing.T) {
	want := errors.New("list functions failed")
	p, logger := newTraversalTestTools(t)
	got, err := collectNoreturnFuncs(context.Background(), newTraversalErrStore(want, 1), p, logger)
	if !errors.Is(err, want) {
		t.Fatalf("collectNoreturnFuncs error = %v, want %v", err, want)
	}
	if got != nil {
		t.Fatalf("collectNoreturnFuncs returned partial result on error: %v", got)
	}
}

func TestCollectNonNullReturnsPropagatesTraversalError(t *testing.T) {
	want := errors.New("list functions failed")
	p, logger := newTraversalTestTools(t)
	got, err := collectNonNullReturns(context.Background(), newTraversalErrStore(want, 1), p, logger, map[string]bool{})
	if !errors.Is(err, want) {
		t.Fatalf("collectNonNullReturns error = %v, want %v", err, want)
	}
	if got != nil {
		t.Fatalf("collectNonNullReturns returned partial result on error: %v", got)
	}
}

func TestCollectSiblingContractsPropagatesTraversalError(t *testing.T) {
	want := errors.New("list functions failed")
	p, logger := newTraversalTestTools(t)
	d := NewContractGapDetector(newTraversalErrStore(want, 1), p, logger)
	got, err := d.collectSiblingContracts(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("collectSiblingContracts error = %v, want %v", err, want)
	}
	if got.sameFile != nil || got.crossFile != nil {
		t.Fatalf("collectSiblingContracts returned partial result on error: %+v", got)
	}
}

func TestFuncSummariesPropagatesCollectTraversalError(t *testing.T) {
	want := errors.New("list functions failed")
	p, logger := newTraversalTestTools(t)
	// First ListFunctions (funcSummaries' own pass) succeeds empty; the second
	// (collectNoreturnFuncs) fails and must abort funcSummaries.
	d := NewUncheckedReturnDetector(newTraversalErrStore(want, 2), p, logger)
	if _, err := d.funcSummaries(context.Background()); !errors.Is(err, want) {
		t.Fatalf("funcSummaries error = %v, want %v", err, want)
	}
}

func TestContractGapDetectPropagatesCollectTraversalError(t *testing.T) {
	want := errors.New("list functions failed")
	p, logger := newTraversalTestTools(t)
	// First pass succeeds empty; collectSiblingContracts' pass fails and must
	// abort Detect instead of returning a partial sibling contract index.
	d := NewContractGapDetector(newTraversalErrStore(want, 2), p, logger)
	if _, err := d.Detect(context.Background()); !errors.Is(err, want) {
		t.Fatalf("ContractGap.Detect error = %v, want %v", err, want)
	}
}
