package log

import (
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
