package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
)

type Level int

const (
	LevelDebug Level = Level(slog.LevelDebug) // -4
	LevelInfo  Level = Level(slog.LevelInfo)  // 0
	LevelWarn  Level = Level(slog.LevelWarn)  // 4
	LevelError Level = Level(slog.LevelError) // 8
)

var (
	defaultLogger     *Logger
	defaultLoggerOnce sync.Once
)

type Logger struct {
	slogger *slog.Logger
}

func New(w io.Writer, level Level) *Logger {
	opts := &slog.HandlerOptions{
		Level:     slog.Level(level),
		AddSource: false,
	}
	handler := slog.NewJSONHandler(w, opts)
	return &Logger{slogger: slog.New(handler)}
}

// NewMultiWriter creates a Logger that writes identical JSON log lines to both
// w1 and w2. If w2 is nil, it falls back to writing to w1 only.
//
// The returned io.Closer closes w2 only (never w1, which is typically os.Stderr).
// The caller MUST defer-call Close() to flush w2.
func NewMultiWriter(w1, w2 io.Writer, level Level) (*Logger, io.Closer) {
	if w2 == nil {
		return New(w1, level), nopCloser{}
	}
	mw := io.MultiWriter(w1, w2)
	if c, ok := w2.(io.Closer); ok {
		return New(mw, level), &closer{c: c}
	}
	return New(mw, level), nopCloser{}
}

type closer struct{ c io.Closer }

func (c *closer) Close() error { return c.c.Close() }

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func Default() *Logger {
	defaultLoggerOnce.Do(func() {
		defaultLogger = New(os.Stderr, LevelInfo)
	})
	return defaultLogger
}

// NewSplit creates a Logger that routes records by level: WARN/ERROR (≥ warnLevel)
// go to warnWriter, and every record ≥ infoLevel goes to infoWriter (typically a
// file). It is the scan logger shape — the full INFO trail lands in scan.log while
// only warnings/errors reach stderr, so `secguard scan` no longer floods the
// agent's context with per-phase/filter INFO noise. The returned io.Closer closes
// infoWriter only (never warnWriter, which is typically os.Stderr).
func NewSplit(warnWriter, infoWriter io.Writer, warnLevel, infoLevel Level) (*Logger, io.Closer) {
	warn := slog.NewJSONHandler(warnWriter, &slog.HandlerOptions{Level: slog.Level(warnLevel), AddSource: false})
	info := slog.NewJSONHandler(infoWriter, &slog.HandlerOptions{Level: slog.Level(infoLevel), AddSource: false})
	var closeFn io.Closer = nopCloser{}
	if c, ok := infoWriter.(io.Closer); ok {
		closeFn = &closer{c: c}
	}
	return &Logger{slogger: slog.New(splitHandler{warn: warn, info: info})}, closeFn
}

// splitHandler fans a record out to two handlers filtered by their own levels.
type splitHandler struct {
	warn slog.Handler
	info slog.Handler
}

func (h splitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.warn.Enabled(ctx, level) || h.info.Enabled(ctx, level)
}

func (h splitHandler) Handle(ctx context.Context, r slog.Record) error {
	var err error
	if h.warn.Enabled(ctx, r.Level) {
		err = h.warn.Handle(ctx, r)
	}
	if h.info.Enabled(ctx, r.Level) {
		if e := h.info.Handle(ctx, r); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (h splitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return splitHandler{warn: h.warn.WithAttrs(attrs), info: h.info.WithAttrs(attrs)}
}

func (h splitHandler) WithGroup(name string) slog.Handler {
	return splitHandler{warn: h.warn.WithGroup(name), info: h.info.WithGroup(name)}
}

func (l *Logger) Debug(msg string, args ...any) {
	l.slogger.Debug(msg, args...)
}

func (l *Logger) Info(msg string, args ...any) {
	l.slogger.Info(msg, args...)
}

func (l *Logger) Warn(msg string, args ...any) {
	l.slogger.Warn(msg, args...)
}

func (l *Logger) Error(msg string, args ...any) {
	l.slogger.Error(msg, args...)
}

func (l *Logger) With(args ...any) *Logger {
	return &Logger{slogger: l.slogger.With(args...)}
}
