package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestWithBusyRetryID_ImmediateSuccess(t *testing.T) {
	ctx := context.Background()
	calls := 0
	id, err := withBusyRetryID(ctx, 3, func() (int64, error) {
		calls++
		return 42, nil
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if id != 42 {
		t.Errorf("expected id 42, got %d", id)
	}
	if calls != 1 {
		t.Errorf("expected 1 call, got %d", calls)
	}
}

func TestWithBusyRetryID_RetryThenSuccess(t *testing.T) {
	ctx := context.Background()
	calls := 0
	id, err := withBusyRetryID(ctx, 3, func() (int64, error) {
		calls++
		if calls < 3 {
			return 0, fmt.Errorf("database is locked")
		}
		return 7, nil
	})
	if err != nil {
		t.Fatalf("expected success after retry, got %v", err)
	}
	if id != 7 {
		t.Errorf("expected id 7, got %d", id)
	}
	if calls != 3 {
		t.Errorf("expected 3 calls (2 retries), got %d", calls)
	}
}

func TestWithBusyRetryID_Exhausted(t *testing.T) {
	ctx := context.Background()
	calls := 0
	_, err := withBusyRetryID(ctx, 3, func() (int64, error) {
		calls++
		return 0, fmt.Errorf("SQLITE_BUSY: database is locked")
	})
	if err == nil {
		t.Fatal("expected error on exhaustion, got nil")
	}
	if !strings.Contains(err.Error(), "busy retry exhausted") {
		t.Errorf("error should mention exhaustion, got: %v", err)
	}
	if calls != 4 {
		t.Errorf("expected 4 total attempts (1 + 3 retries), got %d", calls)
	}
}

func TestWithBusyRetryID_NonBusyNoRetry(t *testing.T) {
	ctx := context.Background()
	calls := 0
	sentinel := errors.New("constraint violation")
	_, err := withBusyRetryID(ctx, 3, func() (int64, error) {
		calls++
		return 0, sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Errorf("expected sentinel error, got %v", err)
	}
	if calls != 1 {
		t.Errorf("non-BUSY error must not retry, expected 1 call, got %d", calls)
	}
}

func TestWithBusyRetryID_ContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := withBusyRetryID(ctx, 3, func() (int64, error) {
		return 0, fmt.Errorf("database is locked")
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestWithBusyRetryID_BackoffDoubles(t *testing.T) {
	ctx := context.Background()
	start := time.Now()
	calls := 0
	_, _ = withBusyRetryID(ctx, 2, func() (int64, error) {
		calls++
		return 0, fmt.Errorf("database is locked")
	})
	elapsed := time.Since(start)
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("backoff 50+100=150ms expected before exhaustion, elapsed %v", elapsed)
	}
}
