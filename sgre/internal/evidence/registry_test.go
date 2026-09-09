package evidence

import (
	"context"
	"errors"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type panicDetector struct{}

func (panicDetector) Name() string { return "zz_test_panic_detector" }
func (panicDetector) Detect(ctx context.Context) (DetectResult, error) {
	panic("boom")
}

type errorDetector struct{}

func (errorDetector) Name() string { return "zz_test_error_detector" }
func (errorDetector) Detect(ctx context.Context) (DetectResult, error) {
	return DetectResult{}, errors.New("expected test failure")
}

// TestRunAllDetectors_SurfacesFailuresWithoutAborting locks in the fail-tolerant
// detector contract: a panicking or erroring detector is captured as a
// DetectorError and returned, never turned into a fatal error that aborts the
// whole run (the "one detector bug wastes the entire 3-hour scan" failure).
func TestRunAllDetectors_SurfacesFailuresWithoutAborting(t *testing.T) {
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return panicDetector{} })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return errorDetector{} })

	store := db.NewTestStore(t)
	p := parser.NewParser()
	defer p.CloseAll()

	errs := RunAllDetectors(context.Background(), store, p, log.Default())

	var sawPanic, sawError bool
	for _, de := range errs {
		switch de.Detector {
		case "zz_test_panic_detector":
			sawPanic = true
			if de.Err == nil || de.Err.Error() == "" {
				t.Errorf("panic detector: expected a non-empty error, got %v", de.Err)
			}
		case "zz_test_error_detector":
			sawError = true
			if de.Err == nil || de.Err.Error() != "expected test failure" {
				t.Errorf("error detector: got unexpected error %v", de.Err)
			}
		}
	}
	if !sawPanic {
		t.Error("panicking detector was not surfaced as a DetectorError")
	}
	if !sawError {
		t.Error("erroring detector was not surfaced as a DetectorError")
	}
}
