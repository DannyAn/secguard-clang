package log

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	if l == nil {
		t.Fatal("New returned nil")
	}
}

func TestDefault(t *testing.T) {
	l := Default()
	if l == nil {
		t.Fatal("Default returned nil")
	}
}

func TestInfo_LogsToWriterWithLevelAndMsg(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Info("test message", "key", "val")

	output := buf.String()
	if !strings.Contains(output, "test message") {
		t.Errorf("log output missing message: %s", output)
	}
	if !strings.Contains(output, "INFO") {
		t.Errorf("log output missing level INFO: %s", output)
	}
	if !strings.Contains(output, "key") || !strings.Contains(output, "val") {
		t.Errorf("log output missing context key-value: %s", output)
	}
}

func TestInfo_JSONFormat(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Info("test message", "key", "val")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Errorf("log output is not valid JSON: %v\noutput: %s", err, buf.String())
	}
	if entry["msg"] != "test message" {
		t.Errorf("expected msg='test message', got %v", entry["msg"])
	}
	if entry["level"] != "INFO" {
		t.Errorf("expected level=INFO, got %v", entry["level"])
	}
	if entry["key"] != "val" {
		t.Errorf("expected key=val, got %v", entry["key"])
	}
	if _, ok := entry["time"]; !ok {
		t.Error("log output missing timestamp field")
	}
}

func TestWarn(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Warn("warning msg", "ctx", "data")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Errorf("log output is not valid JSON: %v", err)
	}
	if entry["level"] != "WARN" {
		t.Errorf("expected level=WARN, got %v", entry["level"])
	}
}

func TestError(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Error("error msg", "code", 42)

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Errorf("log output is not valid JSON: %v", err)
	}
	if entry["level"] != "ERROR" {
		t.Errorf("expected level=ERROR, got %v", entry["level"])
	}
}

func TestDebug_FilteredByLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelInfo)
	l.Debug("debug msg")

	if buf.Len() > 0 {
		t.Errorf("debug should be filtered at Info level, got output: %s", buf.String())
	}
}

func TestDebug_AtDebugLevel(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, LevelDebug)
	l.Debug("debug msg")

	var entry map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Errorf("log output is not valid JSON: %v", err)
	}
	if entry["level"] != "DEBUG" {
		t.Errorf("expected level=DEBUG, got %v", entry["level"])
	}
}

func TestNewMultiWriter_WritesToBoth(t *testing.T) {
	var buf1, buf2 bytes.Buffer
	logger, closer := NewMultiWriter(&buf1, &buf2, LevelInfo)
	logger.Info("test", "key", "value")

	if !strings.Contains(buf1.String(), "test") {
		t.Errorf("w1 missing log output: %s", buf1.String())
	}
	if !strings.Contains(buf2.String(), "test") {
		t.Errorf("w2 missing log output: %s", buf2.String())
	}

	var entry1, entry2 map[string]interface{}
	if err := json.Unmarshal(buf1.Bytes(), &entry1); err != nil {
		t.Errorf("w1 output not valid JSON: %v", err)
	}
	if err := json.Unmarshal(buf2.Bytes(), &entry2); err != nil {
		t.Errorf("w2 output not valid JSON: %v", err)
	}
	if entry1["msg"] != "test" || entry2["msg"] != "test" {
		t.Errorf("expected msg=test in both writers")
	}
	if entry1["key"] != "value" || entry2["key"] != "value" {
		t.Errorf("expected key=value in both writers")
	}

	if err := closer.Close(); err != nil {
		t.Errorf("closer.Close() returned error: %v", err)
	}
}

func TestNewMultiWriter_NilW2FallsBack(t *testing.T) {
	var buf1 bytes.Buffer
	logger, closer := NewMultiWriter(&buf1, nil, LevelInfo)
	logger.Info("fallback test", "num", 42)

	if !strings.Contains(buf1.String(), "fallback test") {
		t.Errorf("w1 missing log output: %s", buf1.String())
	}

	if err := closer.Close(); err != nil {
		t.Errorf("nopCloser.Close() returned error: %v", err)
	}
}
