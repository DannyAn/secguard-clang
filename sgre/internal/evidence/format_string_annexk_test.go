//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/indexer"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// TestFormatString_AnnexKFormatIndex pins the fprintf_s / vfprintf_s format
// argument index. Both take (FILE*, fmt, ...) — the format is args[1], not
// args[0]. The detector read args[0] (the FILE*), so a literal format was
// reported as a non-literal format-string sink (false positive) and a variable
// format's evidence named the stream instead of the format expression.
func TestFormatString_AnnexKFormatIndex(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	defer p.CloseAll()

	if _, err := indexer.NewIndexer(store, logger).Index(ctx, fixturePath("tc132_format_string_annexk.c")); err != nil {
		t.Fatalf("index failed: %v", err)
	}
	if _, err := NewFormatStringDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("format-string detect failed: %v", err)
	}

	byFunc, _ := countEventsByFunction(t, store, "FORMAT_STRING", "FORMAT_STRING")

	if n := byFunc["literal_fprintf_s"]; n != 0 {
		t.Errorf("literal_fprintf_s: a literal format must not be a format-string candidate, got %d", n)
	}
	if n := byFunc["literal_vfprintf_s"]; n != 0 {
		t.Errorf("literal_vfprintf_s: a literal format must not be a format-string candidate, got %d", n)
	}
	if n := byFunc["var_fprintf_s"]; n == 0 {
		t.Errorf("var_fprintf_s: a non-literal format at args[1] must be reported, got 0")
	}
	if n := byFunc["var_vfprintf_s"]; n == 0 {
		t.Errorf("var_vfprintf_s: a non-literal format at args[1] must be reported, got 0")
	}
}
