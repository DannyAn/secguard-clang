package evidence

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type DetectorFactory func(store db.Store, p *parser.Parser, logger *log.Logger) Detector

// DetectorError records one detector's failure (panic or returned error) so the
// caller can surface it per-detector instead of only as a combined fatal error.
type DetectorError struct {
	Detector string
	Err      error
}

var detectorFactories []DetectorFactory

func RegisterDetector(factory DetectorFactory) {
	detectorFactories = append(detectorFactories, factory)
}

func AllDetectors(store db.Store, p *parser.Parser, logger *log.Logger) []Detector {
	detectors := make([]Detector, len(detectorFactories))
	for i, factory := range detectorFactories {
		detectors[i] = factory(store, p, logger)
	}
	return detectors
}

// RunAllDetectors runs every registered detector (the interprocedural one last,
// so it can consume the edges the others emit). A detector failure is NOT fatal:
// detectors are independent, so one panicking/erroring detector must not discard
// the other 21 evidence streams and the whole index+graph investment (a "3-hour
// run lost to one detector bug" failure). Every failure is logged and returned
// so the caller can surface it — a failed detector is never silently dropped,
// which is what would otherwise make its vuln types read as a genuine "0
// candidates".
func RunAllDetectors(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) []DetectorError {
	return RunAllDetectorsWithCache(ctx, store, p, logger, nil)
}

// RunAllDetectorsWithCache is RunAllDetectors with a shared per-scan
// *graph.CFGCache injected into every detector's ctx. Detectors that build
// statement CFGs hit the cache instead of rebuilding per function per
// detector. A nil cache preserves the legacy behavior (each detector builds
// its own CFGs).
func RunAllDetectorsWithCache(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger, cfgCache *graph.CFGCache) []DetectorError {
	if cfgCache != nil {
		ctx = withCFGCache(ctx, cfgCache)
	}
	// Batch the detector phase: emitEvent buffers into a shared batch, flushed
	// once per phase in a single transaction instead of one autocommit write per
	// event+location. The flag is reset on every exit so a direct detector call
	// (tests) stays write-through.
	batchMode.Store(true)
	defer batchMode.Store(false)
	all := AllDetectors(store, p, logger)

	var deferred []Detector
	var independent []Detector
	for _, det := range all {
		// interprocedural must run after every other evidence stream (it
		// consults their events). It is the only order-dependent detector:
		// caller_null's open-chain fixpoint is computed inside its own single
		// Detect pass, and opaque_null reads no detector output.
		if det.Name() == "interprocedural" {
			deferred = append(deferred, det)
			continue
		}
		independent = append(independent, det)
	}

	const maxConcurrent = 8
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []DetectorError
	run := func(d Detector) {
		defer func() {
			if r := recover(); r != nil {
				// The stack is the ONLY record of WHERE the panic happened: the
				// recovered value alone ("invalid memory address or nil pointer
				// dereference") identifies no line, so a panic in a real scan
				// could not be diagnosed or reproduced from the log. Log the
				// full stack; keep the short message in the returned data.
				stack := string(debug.Stack())
				if logger != nil {
					logger.Warn("detector panicked", "detector", d.Name(), "panic", r, "stack", stack)
				}
				mu.Lock()
				errs = append(errs, DetectorError{Detector: d.Name(), Err: fmt.Errorf("panicked: %v", r)})
				mu.Unlock()
			}
		}()
		if _, err := d.Detect(ctx); err != nil {
			if logger != nil {
				logger.Warn("detector failed", "detector", d.Name(), "error", err)
			}
			mu.Lock()
			errs = append(errs, DetectorError{Detector: d.Name(), Err: err})
			mu.Unlock()
		}
	}

	for _, det := range independent {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			run(d)
			if logger != nil {
				logger.Info("detector timing", "detector", d.Name(), "elapsed_ms", time.Since(start).Milliseconds())
			}
		}(det)
	}
	wg.Wait()

	// Flush the independent detectors' buffered events before the deferred
	// detector runs: interprocedural reads the events they emitted.
	flushEventBatch(ctx, store, logger)

	for _, det := range deferred {
		start := time.Now()
		run(det)
		if logger != nil {
			logger.Info("detector timing", "detector", det.Name(), "elapsed_ms", time.Since(start).Milliseconds())
		}
	}

	// Flush the deferred detector's own buffered events.
	flushEventBatch(ctx, store, logger)

	return errs
}

func init() {
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewNullSourceDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDereferenceDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewNullGuardDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewInterproceduralDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewBufferOverflowDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewMemoryLeakDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewInjectionDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewResourceLeakDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUninitVariableDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUseAfterFreeDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDoubleFreeDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewFormatStringDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewIntegerOverflowDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewRaceConditionDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewHardcodedSecretDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDeadlockDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewCryptoMisuseDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewDivideByZeroDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewUncheckedReturnDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewPathTraversalDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSizeofMisuseDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignedCompareDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewSignalHandlerDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector {
		return NewDangerousFunctionDetector(s, p, l)
	})
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector {
		return NewArgumentInjectionDetector(s, p, l)
	})
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewXMLInjectionDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewCRLFInjectionDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewLogInjectionDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewArgumentTypeDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector {
		return NewDataRepresentationDetector(s, p, l)
	})
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewCallerNullDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewOpaqueNullDetector(s, p, l) })
	RegisterDetector(func(s db.Store, p *parser.Parser, l *log.Logger) Detector { return NewContractGapDetector(s, p, l) })
}
