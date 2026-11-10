//go:build !nosqlite

package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/config"
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

// The reuse fingerprint must cover every GRAPH input, not just the config
// file: two tool versions, two exclusion sets, and two compile_commands files
// must never share a reuse decision. The skip-detectors set is deliberately
// NOT an input (issue #253): skipping a detector changes no AST, so a skip run
// reuses the graph and only re-checks the completed-detector set — it can
// never masquerade as a full run because detectorsComplete requires every
// newly-required detector in the recorded done set.
func TestReuseFingerprintCoversAnalyzerInputs(t *testing.T) {
	root := t.TempDir()
	base := reuseFingerprint(root, nil, nil)
	if again := reuseFingerprint(root, nil, nil); again != base {
		t.Fatal("identical inputs must yield the identical fingerprint")
	}
	variants := map[string]string{
		"exclude-dirs":  reuseFingerprint(root, []string{"vendor"}, nil),
		"exclude-paths": reuseFingerprint(root, nil, []string{"third_party"}),
	}
	for name, fp := range variants {
		if fp == base {
			t.Errorf("%s must change the reuse fingerprint (a partial analyzer run must not be reused as a full one)", name)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "compile_commands.json"), []byte(`[{"command":"gcc -DFOO=1 a.c"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	withCC := reuseFingerprint(root, nil, nil)
	if withCC == base {
		t.Error("adding compile_commands.json must change the fingerprint")
	}
	if err := os.WriteFile(filepath.Join(root, "compile_commands.json"), []byte(`[{"command":"gcc -DFOO=2 a.c"}]`), 0644); err != nil {
		t.Fatal(err)
	}
	if other := reuseFingerprint(root, nil, nil); other == withCC {
		t.Error("a -D flag change in compile_commands must change the fingerprint")
	}
}

// The completed-detector bitset: a missing detector forces a re-run, a complete
// set allows reuse, an empty set (event loss) is always incomplete.
func TestDetectorsCompleteBitset(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	if detectorsComplete(ctx, store, map[string]bool{}) {
		t.Fatal("no detectors_done must not read complete")
	}
	required := requiredDetectors(map[string]bool{})
	if len(required) == 0 {
		t.Fatal("registry must have detectors")
	}
	if err := store.SetMeta(ctx, "detectors_done", required[0]); err != nil {
		t.Fatal(err)
	}
	if detectorsComplete(ctx, store, map[string]bool{}) {
		t.Fatal("a single completed detector out of many must not read complete")
	}
	if err := store.SetMeta(ctx, "detectors_done", strings.Join(required, ",")); err != nil {
		t.Fatal(err)
	}
	if !detectorsComplete(ctx, store, map[string]bool{}) {
		t.Fatal("the full required set must read complete")
	}
	// A skip set that excludes the still-missing detector is fine.
	if err := store.SetMeta(ctx, "detectors_done", required[0]); err != nil {
		t.Fatal(err)
	}
	skipAll := map[string]bool{}
	for _, name := range required[1:] {
		skipAll[name] = true
	}
	if !detectorsComplete(ctx, store, skipAll) {
		t.Fatal("when every other detector is skipped, the one completed detector suffices")
	}
}

// End-to-end reuse state machine over a real fixture:
//  1. full first scan completes graph+detectors;
//  2. an UNCHANGED second scan reuses them (phase skipped);
//  3. a simulated detector failure (detectors_done invalidated) re-runs
//     detectors on the next scan and restores the completed set;
//  4. a simulated mid-rebuild crash (graph_build_complete=false) forces a
//     graph rebuild instead of reusing a half-built graph.
func TestRescanReuseStateMachine(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := "int main(void) { int *p = 0; *p = 1; return 0; }\n"
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	store := db.NewTestStore(t)
	logger := log.New(&bytes.Buffer{}, log.LevelError)

	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("first pipeline: %v", err)
	}
	if !graphBuildComplete(ctx, store) {
		t.Fatal("first scan must record graph_build_complete=true")
	}
	if !detectorsComplete(ctx, store, map[string]bool{}) {
		t.Fatal("first scan must record the full completed-detector set")
	}

	var logBuf bytes.Buffer
	logger = log.New(&logBuf, log.LevelInfo)
	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("second pipeline: %v", err)
	}
	if !strings.Contains(logBuf.String(), "phase skipped") {
		t.Fatalf("an unchanged second scan must reuse graph+detectors (phase skipped), log=%q", logBuf.String())
	}

	// Simulate a prior detector failure: the completed set is gone even though
	// graph_build_complete is still true. The next scan MUST re-run detectors
	// and restore the completed set — never read the types as "0 candidates".
	if err := store.SetMeta(ctx, "detectors_done", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("third pipeline: %v", err)
	}
	if !detectorsComplete(ctx, store, map[string]bool{}) {
		t.Fatal("a prior detector failure must re-run detectors and restore the completed set")
	}

	// Simulate a crash mid graph rebuild: the completion flag is false, so the
	// next scan must rebuild the graph and re-mark it complete.
	if err := store.SetMeta(ctx, "graph_build_complete", "false"); err != nil {
		t.Fatal(err)
	}
	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("fourth pipeline: %v", err)
	}
	if !graphBuildComplete(ctx, store) {
		t.Fatal("a crashed rebuild must be rebuilt and re-marked complete, not reused")
	}
}

// Issue #253 P0-5: a detector-stage crash used to invalidate the whole reuse
// decision twice over — graph_build_complete was only recorded AFTER the
// detectors, and the fingerprint covered the skip set, so the retry with
// --skip-detectors rebuilt the graph again. The graph must now be recorded
// complete BEFORE the detector stage, and a changed skip set must reuse the
// graph while re-running only the detectors.
func TestRescanAfterDetectorCrashReusesGraph(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	src := "int main(void) { int *p = 0; *p = 1; return 0; }\n"
	if err := os.WriteFile(filepath.Join(root, "a.c"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}
	store := db.NewTestStore(t)
	var logBuf bytes.Buffer
	logger := log.New(&logBuf, log.LevelInfo)

	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("first pipeline: %v", err)
	}
	// Simulate the crash: the process died mid-detectors, before detectors_done
	// was recorded. graph_build_complete stays true (written at graph end).
	if err := store.SetMeta(ctx, "detectors_done", ""); err != nil {
		t.Fatal(err)
	}
	config.SetSkipDetectorsOverride("unchecked_return")
	defer config.SetSkipDetectorsOverride("")
	logBuf.Reset()
	if _, err := runPipeline(ctx, store, logger, root, nil, nil); err != nil {
		t.Fatalf("retry with --skip-detectors: %v", err)
	}
	logs := logBuf.String()
	if !strings.Contains(logs, `"phase","graph"`) && !strings.Contains(logs, "phase skipped") {
		t.Fatalf("the retry must skip the graph stage and only re-run detectors, log=%q", logs)
	}
	if strings.Contains(logs, "graph_builders_parallel") {
		t.Fatalf("the retry must NOT rebuild the graph, log=%q", logs)
	}
	if !detectorsComplete(ctx, store, map[string]bool{"unchecked_return": true}) {
		t.Fatal("the retry must record the completed set for the reduced required detectors")
	}
}
