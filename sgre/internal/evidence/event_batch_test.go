//go:build !nosqlite

package evidence

import (
	"context"
	"io"
	"testing"

	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/log"
)

func TestEventBatch_AutoFlush(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)

	fileID, err := store.InsertFile(ctx, &db.File{Path: "test.c", Language: "c"})
	if err != nil {
		t.Fatalf("InsertFile: %v", err)
	}

	SetEventBatchSize(3)
	defer SetEventBatchSize(0)

	batchMode.Store(true)
	defer batchMode.Store(false)

	loc := &db.Location{FileID: fileID, Line: 1, Column: 1}
	for i := 0; i < 7; i++ {
		emitEvent(ctx, store, logger, "NULL_VALUE", int64(i+1), loc, map[string]int{"i": i})
	}
	flushEventBatch(ctx, store, logger)

	count, err := store.CountEventsByType(ctx, "NULL_VALUE")
	if err != nil {
		t.Fatalf("CountEventsByType: %v", err)
	}
	if count != 7 {
		t.Errorf("expected 7 events in DB, got %d", count)
	}
}

func TestEventBatch_NoAutoFlushByDefault(t *testing.T) {
	ctx := context.Background()
	store := db.NewTestStore(t)
	logger := log.New(io.Discard, log.LevelWarn)

	fileID, err := store.InsertFile(ctx, &db.File{Path: "test2.c", Language: "c"})
	if err != nil {
		t.Fatalf("InsertFile: %v", err)
	}

	SetEventBatchSize(0)

	batchMode.Store(true)
	defer batchMode.Store(false)

	loc := &db.Location{FileID: fileID, Line: 1, Column: 1}
	for i := 0; i < 100; i++ {
		emitEvent(ctx, store, logger, "MEMORY_ALLOC", int64(i+1), loc, nil)
	}

	eventBatch.mu.Lock()
	buffered := len(eventBatch.events)
	eventBatch.mu.Unlock()
	if buffered != 100 {
		t.Errorf("with maxBatch=0, all 100 events must stay buffered, got %d", buffered)
	}

	flushEventBatch(ctx, store, logger)

	eventBatch.mu.Lock()
	buffered = len(eventBatch.events)
	eventBatch.mu.Unlock()
	if buffered != 0 {
		t.Errorf("after flush, buffer must be empty, got %d", buffered)
	}

	count, err := store.CountEventsByType(ctx, "MEMORY_ALLOC")
	if err != nil {
		t.Fatalf("CountEventsByType: %v", err)
	}
	if count != 100 {
		t.Errorf("expected 100 events in DB after flush, got %d", count)
	}
}
