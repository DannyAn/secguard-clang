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

// TestFormatString_SnprintfSFormatIndex pins the snprintf_s / vsnprintf_s
// format slot. The MSVC signature is (buf, size, count, fmt, ...) so the
// format is args[3]; the detector used to read args[2] (the count), turning a
// literal MSVC format into a phantom non-literal sink. The C11 Annex K layout
// (s, n, fmt, ...) puts the format at args[2] — the literal probe covers both.
func TestFormatString_SnprintfSFormatIndex(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	defer p.CloseAll()

	if _, err := indexer.NewIndexer(store, logger).Index(ctx, fixturePath("tc135_format_string_snprintf_s.c")); err != nil {
		t.Fatalf("index failed: %v", err)
	}
	if _, err := NewFormatStringDetector(store, p, logger).Detect(ctx); err != nil {
		t.Fatalf("format-string detect failed: %v", err)
	}

	byFunc, _ := countEventsByFunction(t, store, "FORMAT_STRING", "FORMAT_STRING")

	for _, fn := range []string{"literal_snprintf_s_msvc", "literal_truncate_snprintf_s_msvc", "literal_snprintf_s_annexk", "literal_vsnprintf_s_msvc"} {
		if n := byFunc[fn]; n != 0 {
			t.Errorf("%s: a literal format (MSVC args[3] / Annex K args[2]) must not be a format-string candidate, got %d", fn, n)
		}
	}
	for _, fn := range []string{"var_snprintf_s_msvc", "var_snprintf_s_annexk", "var_vsnprintf_s_msvc"} {
		if n := byFunc[fn]; n == 0 {
			t.Errorf("%s: a non-literal format must be reported, got 0", fn)
		}
	}
}
