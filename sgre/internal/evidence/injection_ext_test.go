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

// TestCRLFInjection_FputsTP pins the fputs(str, stream) argument order: the
// stream is the SECOND argument, so `fputs(user_input, sock)` must read "sock"
// as the sink stream (not "user_input") and emit a crlf_injection event.
func TestCRLFInjection_FputsTP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_crlf_injection_fputs_tp.c")
	runCRLFInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "crlf_injection")
}

// TestLogInjection_FputsFwriteTP pins the log-context argument order for
// fputs(str, stream) and fwrite(data, size, nmemb, stream): the stream is the
// second / fourth argument, so a log-file stream must still be recognized.
func TestLogInjection_FputsFwriteTP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_log_injection_fputs_tp.c")
	runLogInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "log_injection")
}
