package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func runCRLFInjectionDetector(t *testing.T, store db.Store) {
	t.Helper()
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	det := NewCRLFInjectionDetector(store, p, logger)
	if _, err := det.Detect(ctx); err != nil {
		t.Fatalf("crlf injection detect failed: %v", err)
	}
}

func runLogInjectionDetector(t *testing.T, store db.Store) {
	t.Helper()
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	det := NewLogInjectionDetector(store, p, logger)
	if _, err := det.Detect(ctx); err != nil {
		t.Fatalf("log injection detect failed: %v", err)
	}
}

func TestCRLFInjection_TP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_crlf_injection_tp.c")
	runCRLFInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "crlf_injection")
}

func TestCRLFInjection_FP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_crlf_injection_fp.c")
	runCRLFInjectionDetector(t, store)
	assertNoInjectionEventWithCategory(t, store, "crlf_injection")
}

func TestLogInjection_TP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_log_injection_tp.c")
	runLogInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "log_injection")
}

func TestLogInjection_FP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_log_injection_fp.c")
	runLogInjectionDetector(t, store)
	assertNoInjectionEventWithCategory(t, store, "log_injection")
}
