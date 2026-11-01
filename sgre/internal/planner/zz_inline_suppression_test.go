//go:build !nosqlite

package planner

import (
	"context"
	"io"
	"path/filepath"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/evidence"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestInlineSuppression_DropsCandidate pins GAP-11: a
// `// secguard-disable-next-line: null-deref` comment suppresses the candidate
// on the next line (and only that line), so a suppressed defect never reaches
// the AI while its unsuppressed sibling does.
func TestInlineSuppression_DropsCandidate(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()

	idx := indexer.NewIndexer(store, logger)
	idx.SetValidVulnTypes(AllVulnTypes())
	if _, err := idx.Index(ctx, filepath.Join("..", "..", "testdata", "tc176_suppression.c")); err != nil {
		t.Fatalf("index: %v", err)
	}
	graph.NewCallGraphBuilder(store, p, logger).Build(ctx)
	graph.NewDataFlowBuilder(store, p, logger).Build(ctx)
	if _, err := evidence.NewDereferenceDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect deref: %v", err)
	}
	if _, err := evidence.NewNullSourceDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("detect null source: %v", err)
	}

	res, err := NewPlanner(store, p, logger).Plan(ctx, "null-deref")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	funcs := map[string]bool{}
	for _, c := range res.Candidates {
		funcs[c.Target.Function] = true
	}
	if funcs["suppressed_func"] {
		t.Errorf("suppressed_func must be dropped by the suppression directive")
	}
	if !funcs["kept_func"] {
		t.Errorf("kept_func must survive (no suppression on its line)")
	}
}

// TestParseSuppressionComment pins the directive parser (line + block comment,
// wildcard + list + reason).
func TestParseSuppressionComment(t *testing.T) {
	cases := []struct {
		text     string
		nextLine bool
		types    []string
		reason   string
		ok       bool
	}{
		{"// secguard-disable-next-line: null-deref reason=contract", true, []string{"null-deref"}, "contract", true},
		{"// secguard-disable-line: null-deref, buffer-overflow", false, []string{"null-deref", "buffer-overflow"}, "", true},
		{"/* secguard-disable-next-line: all */", true, []string{"all"}, "", true},
		{"// not a suppression", false, nil, "", false},
	}
	for _, c := range cases {
		dir, ok := parser.ParseSuppressionComment(c.text)
		if ok != c.ok {
			t.Errorf("ParseSuppressionComment(%q) ok = %v, want %v", c.text, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if dir.NextLine != c.nextLine {
			t.Errorf("%q: NextLine = %v, want %v", c.text, dir.NextLine, c.nextLine)
		}
		if len(dir.Types) != len(c.types) || (len(dir.Types) > 0 && dir.Types[0] != c.types[0]) {
			t.Errorf("%q: Types = %v, want %v", c.text, dir.Types, c.types)
		}
		if dir.Reason != c.reason {
			t.Errorf("%q: Reason = %q, want %q", c.text, dir.Reason, c.reason)
		}
	}
}
