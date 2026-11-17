//go:build !nosqlite

package planner

import (
	"os"
	"path/filepath"
	"testing"
)

func fsFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(data)
}

// TestFormatString_InternalRuntimeBufferDropped locks the internal_runtime
// census classification (issue #289 T5): a non-static format wrapper whose only
// in-tree caller passes a buffer built by snprintf from a fixed integer-only
// format must not surface a candidate.
func TestFormatString_InternalRuntimeBufferDropped(t *testing.T) {
	res := planType(t, fsFixture(t, "tc_fs_internal_runtime.c"), "format-string")
	if c, ok := res["diag_out"]; ok {
		t.Errorf("diag_out: the sole caller passes an internally-built runtime buffer, must not be a candidate (hint=%v)", c.Hint)
	}
}

// TestFormatString_ExternalPassthroughKept locks the reverse case: a caller that
// passes a parameter straight through keeps the wrapper a candidate.
func TestFormatString_ExternalPassthroughKept(t *testing.T) {
	res := planType(t, fsFixture(t, "tc_fs_external_passthrough.c"), "format-string")
	if _, ok := res["diag_out"]; !ok {
		t.Errorf("diag_out: the caller passes external input, must stay a candidate")
	}
}

// TestFormatString_PercentSConstructionKept locks the second reverse case: a
// buffer built with a %s conversion still keeps the candidate (string content
// can carry caller-controlled bytes).
func TestFormatString_PercentSConstructionKept(t *testing.T) {
	res := planType(t, fsFixture(t, "tc_fs_internal_pct_s.c"), "format-string")
	if _, ok := res["diag_out"]; !ok {
		t.Errorf("diag_out: the buffer is built with %%s, must stay a candidate")
	}
}
