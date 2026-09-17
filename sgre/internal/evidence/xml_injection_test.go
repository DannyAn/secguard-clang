package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

func runXMLInjectionDetector(t *testing.T, store db.Store) {
	t.Helper()
	ctx := context.Background()
	logger := log.New(io.Discard, log.LevelWarn)
	p := parser.NewParser()
	det := NewXMLInjectionDetector(store, p, logger)
	if _, err := det.Detect(ctx); err != nil {
		t.Fatalf("xml injection detect failed: %v", err)
	}
}

func TestXMLInjection_TP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_xml_injection_tp.c")
	runXMLInjectionDetector(t, store)
	assertHasInjectionEventWithCategory(t, store, "xml_xpath_injection")
	assertHasInjectionEventWithCategory(t, store, "xml_injection")
}

func TestXMLInjection_FP(t *testing.T) {
	store := indexFixtureForInjection(t, "tc_xml_injection_fp.c")
	runXMLInjectionDetector(t, store)
	assertNoInjectionEventWithCategory(t, store, "xml_xpath_injection")
	assertNoInjectionEventWithCategory(t, store, "xml_injection")
}
