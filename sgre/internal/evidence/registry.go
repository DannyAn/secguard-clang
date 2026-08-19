package evidence

import (
	"context"
	"sync"
	"time"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

type DetectorFactory func(store db.Store, p *parser.Parser, logger *log.Logger) Detector

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

func RunAllDetectors(ctx context.Context, store db.Store, p *parser.Parser, logger *log.Logger) {
	all := AllDetectors(store, p, logger)

	var deferred []Detector
	var independent []Detector
	for _, det := range all {
		if det.Name() == "interprocedural" {
			deferred = append(deferred, det)
			continue
		}
		independent = append(independent, det)
	}

	const maxConcurrent = 4
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, det := range independent {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			start := time.Now()
			d.Detect(ctx)
			if logger != nil {
				logger.Info("detector timing", "detector", d.Name(), "elapsed_ms", time.Since(start).Milliseconds())
			}
		}(det)
	}
	wg.Wait()

	for _, det := range deferred {
		start := time.Now()
		det.Detect(ctx)
		if logger != nil {
			logger.Info("detector timing", "detector", det.Name(), "elapsed_ms", time.Since(start).Milliseconds())
		}
	}
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
}
